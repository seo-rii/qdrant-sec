# Private HNSW ORAM backup and recovery runbook

This runbook is the production gate for backing up and recovering collections
using `vector/private-hnsw-oram@v1` or `vector/private-hnsw-oram@v2`, with an
optional private result ORAM. It supplements the security and protocol contract
in [ckks.md](ckks.md).

The central rule is:

> A Qdrant snapshot is not a complete Private ORAM backup. Keep the client
> recovery state and all client keys outside Qdrant and bind them to the exact
> Qdrant snapshot with a signed external-recovery checkpoint.

Never upload an RK, signing private key, checkpoint key, position map, stash,
entry node, token map, or encrypted client-state body to a Qdrant collection,
Qdrant snapshot directory, snapshot object-store prefix, or Qdrant recovery
upload. Qdrant receives only the digest of the complete encrypted client
recovery artifact.

## Scope and current limits

The coordinated external recovery API currently supports the same source peer
identity recorded in the checkpoint, automatic sharding, replication factor 1,
and exactly one or two shards for which that peer is the sole `Active` owner.
Healthy or degraded RF=2, custom sharding, split-owner layouts, recovery onto a
different peer identity, and arbitrary point-in-time rollback are not supported
by this runbook.

The current protocol is also not a bare-metal bootstrap path. The collection,
stable UUID, consensus recovery authority, exact topology, and source peer
identity must still exist so `begin` can validate the signed checkpoint against
them.

The external recovery protocol restores an exact consensus-bound state. It is
not a mechanism for forcing an older epoch/root over a live collection that has
advanced. If the business requirement is arbitrary point-in-time restore after
later private ORAM commits, this production gate does not pass.

All backup and restore operations require global `manage` authorization. The
examples below use the REST API implemented in
[`private_oram_recovery_api.rs`](../src/actix/api/private_oram_recovery_api.rs).
Qdrant responses use the normal `{ "result": ... }` response envelope.

## S3-compatible object-storage drill

Gate 3 uses isolated MinIO containers and the staging Qdrant binary. The
default server and client images are pinned by digest in
`tests/consensus_tests/test_private_oram_s3_snapshot.py`; override them only
with reviewed immutable image references through
`QDRANT_PRIVATE_ORAM_MINIO_SERVER_IMAGE` and
`QDRANT_PRIVATE_ORAM_MINIO_CLIENT_IMAGE`.

Run the drill from the repository root after building `qdrant` with the
`staging` feature:

```bash
QDRANT_RUN_PRIVATE_ORAM_MINIO_SNAPSHOT=1 \
  tests/.venv/bin/pytest -q -o addopts= \
  tests/consensus_tests/test_private_oram_s3_snapshot.py
```

The gate requires Docker and gives the MinIO data directory an isolated 2 GiB
tmpfs. It verifies all of the following against a three-peer RF=1 automatic
sharding collection:

- a forced post-prepare validation failure publishes no object;
- a full snapshot publishes one self-contained object and no child collection
  snapshot object;
- the bytes downloaded through MinIO and Qdrant are identical;
- an acknowledged mutation V2 generation produces an external recovery object
  whose size and SHA-256 match the signed checkpoint;
- the complete encrypted client recovery artifact is absent from both server
  snapshot objects;
- external restore commits and the next mutation generation is acknowledged;
- deleting both snapshots leaves the bucket empty.

Qdrant computes the checksum before S3 multipart upload and includes it in the
immediate successful create/export response. Later S3 list or HEAD responses do
not carry that checksum, so the restore workflow must use the signed checkpoint
and independently hash downloaded bytes. A failure after multipart upload but
before local cleanup or post-upload HEAD completion can still leave an orphan
object. This drill does not simulate that window or substitute MinIO behavior
for an AWS S3 qualification run.

The MinIO object is only the server half of a recovery generation. Keep the
encrypted client recovery artifact and key custody material in the independent
stores described below; never place them in the tested snapshot prefix.

## Recovery set

A recoverable generation contains all of the following. Treat the generation
as indivisible; never combine files from different rows or generations.

| Object | Required contents | Storage owner | Sensitivity |
| --- | --- | --- | --- |
| Resource key backup | Exact RK bytes or an HSM/KMS recovery reference, `rk_id`, and `rk_epoch` for every HNSW/result index | Client key vault | Secret |
| Signing-key backup | Private material or HSM recovery procedure for each current index owner signer and the external-recovery signer | Client key vault | Secret |
| Checkpoint-key backup | Client-only key supplied to `seal_private_oram_append_client_checkpoint_v2`, preferably envelope-wrapped by a separately recoverable KEK | Client key vault | Secret |
| Encrypted client recovery artifact | HNSW position map and stash, result token position map and stash when configured, HNSW entry node, point-token mapping, generation records, immutable manifest bundle, and signed state bundle | Client backup store | Confidential and tamper-sensitive |
| Qdrant collection snapshot | Encrypted HNSW/result buckets, manifests, Merkle data, epoch files, point storage, and collection metadata | Snapshot backup store | Ciphertext and sensitive metadata |
| Signed external-recovery bundle | `PrivateOramExternalRecoveryCheckpoint` and `PrivateOramRecoverySignature` | Backup catalog | Public but tamper-sensitive |
| Generation inventory | Exact artifact hashes, key ids/epochs, collection UUID, source peer/shards, layout generation/digest, state sequence, and every index epoch/root/writeback digest | Append-only backup catalog | Sensitive metadata |
| Runtime recovery policy | Provider options, public verifier registries, external-recovery limits, binary/version identity, and peer identity recovery procedure | Configuration backup | Public keys and sensitive metadata only |

Do not assume that possession of any one row compensates for another:

- An RK cannot reconstruct a lost ORAM position map or stash.
- A Qdrant snapshot cannot reconstruct the HNSW entry node or token map.
- An encrypted client artifact cannot be opened without its checkpoint key and
  relevant RK lineage.
- A signed checkpoint cannot repair a snapshot or client artifact whose digest
  does not match.
- In `ids_visible` mode, losing the point-token-to-visible-point-id map makes
  otherwise valid search hits unusable.

### Client-state formats

For V2 mutable indexes, use `PrivateOramEncryptedAppendClientCheckpointV2` as
the primary client backup. Its encrypted plaintext is
`PrivateOramAppendClientCheckpointV2`, which includes:

- one `PrivateOramAppendClientIndexCheckpointV2::Hnsw` per HNSW index, including
  `index_epoch`, `root_hash`, optional `entry_node_id`, position map, stash, and
  node/point generation records;
- an optional `PrivateOramAppendClientIndexCheckpointV2::Result`, including the
  result token position map, stash, and payload-token/point generation records;
- the point ledger, whose records contain `visible_point_id` only for
  `ids_visible`, or `payload_fetch_token` only for
  `private_payload_oram_required`;
- `collection_id`, immutable `manifest_digest`, `layout_generation`, and
  `state_sequence`.

The public V2 helpers are in
[`private_oram_append_client.rs`](../lib/crypto/src/private_oram_append_client.rs):

- `validate_private_oram_append_client_checkpoint_v2`
- `seal_private_oram_append_client_checkpoint_v2`
- `private_oram_append_client_checkpoint_v2_digest`
- `bind_private_oram_append_client_checkpoint_v2`
- `open_private_oram_append_client_checkpoint_v2`

The digest returned by `private_oram_append_client_checkpoint_v2_digest` is the
value bound by `PrivateOramSignedStateV2.client_state_digest`. It is not
automatically the external checkpoint's `client_recovery_state_digest`. The
latter is base64url-no-pad SHA-256 over the exact complete encrypted client
recovery artifact bytes retained by the operator. Define one deterministic SDK
container, hash the bytes actually stored, and do not reserialize it between
hashing and restore.

For a read-only V1 index without the V2 aggregate checkpoint, the public helper
pairs are:

- `PrivateHnswOramClientState::to_snapshot` / `from_snapshot` and
  `seal_private_hnsw_oram_client_state_snapshot` /
  `open_private_hnsw_oram_client_state_snapshot` in
  [`private_hnsw_client.rs`](../lib/crypto/src/private_hnsw_client.rs);
- `PrivateResultOramClientState::to_snapshot` / `from_snapshot` and
  `seal_private_result_oram_client_state_snapshot` /
  `open_private_result_oram_client_state_snapshot` in
  [`private_result_oram.rs`](../lib/crypto/src/private_result_oram.rs).

Those component snapshots contain position maps and stashes only. The SDK must
also protect the HNSW entry node and point-token map in the complete encrypted
artifact. A set of independently encrypted component files without one digest
over the complete set is not accepted by this runbook.

## Key custody

Maintain a key inventory keyed by stable `collection_id`, index name, `rk_id`,
`rk_epoch`, and signing key id. Collection display names are not stable crypto
identities and must not be used as the sole lookup key.

1. Keep RKs and signing private keys in an HSM/KMS or an encrypted client-side
   vault. Qdrant configuration contains only RK lineage metadata and Ed25519
   public verifier keys.
2. Keep at least two independently recoverable key copies in separate failure
   domains. Test recovery from the escrow copy, not from the live SDK process.
3. Back up the client checkpoint key. It is a separate caller-supplied
   `SecretKey`; do not assume that the repository derives it from the RK.
4. Record whether the external-recovery signing key is distinct from each index
   owner signing key. Its public key id must resolve to identical Ed25519 public
   bytes in every bound HNSW/result provider registry.
5. Restrict signing to a policy that verifies the complete signing intent before
   using `package_private_oram_external_recovery_checkpoint`. That helper checks
   shape and signs canonical bytes; it does not decide whether a server-provided
   checkpoint is operationally authorized.
6. Log key ids and vault versions only. Never log private bytes, decrypted
   client state, token maps, roots, ciphertext bodies, or operation tokens.

## Generation and root pins

The backup catalog must retain these pins for every generation:

- external `backup_generation`;
- stable `collection_id`;
- source peer id and sorted source shard ids;
- layout generation, sorted owner peer ids, `layout_digest`, and
  `owner_snapshot_authority_digest`;
- immutable manifest digest and V2 state sequence;
- every index kind/name, epoch, root hash, logical/dummy counts, and last
  writeback digest;
- canonical `index_state_digest`;
- snapshot byte size and lowercase-hex SHA-256;
- complete encrypted client artifact byte size and base64url SHA-256;
- signed-state digest, owner/recovery signing key ids, and creation time;
- runtime verifier-registry revision, Qdrant binary revision, and peer identity.

Use `canonical_private_oram_recovery_index_state_digest` from
[`private_oram_recovery.rs`](../lib/crypto/src/private_oram_recovery.rs) to
independently recompute the index-state digest before signing. Do not compare
only the HNSW root when a result ORAM is also configured.

`backup_generation` is a rollback floor, not a timestamp. The operator chooses
a unique, monotonically increasing generation. `expected_committed_backup_generation`
is the generation already committed by the server's recovery state, which may
be lower than the latest generation merely exported to backup storage. After a
restore commits generation `N`, a checkpoint at generation `N` or lower is no
longer admissible. Maintain both values in the external catalog and never guess
or reset either value.

## Backup procedure

### 1. Preflight and quiesce

1. Confirm the collection is within the supported topology described above.
2. Confirm `storage.private_oram_external_recovery` has sufficient
   `max_snapshot_bytes`, `max_total_staged_bytes`, `max_unpacked_bytes`,
   `min_free_space_bytes`, and `max_concurrent_verify_prepare` capacity.
3. Stop admission of private searches and appends at the single-writer SDK
   coordinator.
4. Let any accepted operation finish, including its ORAM writeback and client
   state persistence. Close HNSW and result sessions.
5. Confirm there is no unresolved mutation lease, pending writeback, snapshot
   recovery, transfer, resharding, or external recovery.
6. Hold the application-side writer fence until the export response, snapshot
   download, and client artifact are durably cataloged. The Qdrant endpoint also
   rejects active sessions, but it cannot freeze a client that is outside the
   request path.

### 2. Freeze and verify client state

Copy the already committed encrypted client checkpoint and its immutable
manifest/signed-state bundles without resealing it. Resealing changes the
ciphertext and therefore the signed client-state digest.

The following is **SDK-reference pseudocode**, not a repository-provided CLI or
a directly compilable example:

```rust
// SDK-reference pseudocode.
validate_private_oram_immutable_manifest_v2_signature(
    &immutable_manifest_bundle.manifest,
    Some(&immutable_manifest_bundle.signature),
    verification,
)?;
validate_private_oram_signed_state_v2_signature(
    &signed_state_bundle.state,
    Some(&signed_state_bundle.signature),
    verification,
)?;

let checkpoint = open_private_oram_append_client_checkpoint_v2(
    &checkpoint_key,
    &encrypted_client_checkpoint,
    &immutable_manifest_bundle.manifest,
    &signed_state_bundle.state,
)?;
validate_private_oram_append_client_checkpoint_v2(
    &checkpoint,
    &immutable_manifest_bundle.manifest,
    &signed_state_bundle.state,
)?;

let exact_recovery_bytes = sdk_encode_complete_recovery_artifact(
    &encrypted_client_checkpoint,
    &immutable_manifest_bundle,
    &signed_state_bundle,
); // SDK-defined deterministic container; not a qdrant-sec API.
let client_recovery_state_digest = base64url_no_pad(sha256(&exact_recovery_bytes));
durably_store_exact_bytes(exact_recovery_bytes)?;
```

Before continuing, prove that:

- each client checkpoint index epoch/root equals the current signed state;
- HNSW and result index sets exactly match the immutable manifest;
- HNSW entry node, point ledger, position maps, and stashes validate;
- the `ids_visible` token map or private-result payload-token map is complete;
- opening the encrypted artifact succeeds using keys recovered through the
  documented escrow path.

### 3. Export the coordinated Qdrant snapshot

Choose a new monotonic `backup_generation`. Submit the digest of the exact
encrypted client artifact, not a component ciphertext hash.

```bash
export QDRANT_URL='https://qdrant.example'
export COLLECTION='docs'
export QDRANT_API_KEY='<global-manage-api-key>'

curl --fail-with-body --silent --show-error \
  -H "api-key: $QDRANT_API_KEY" \
  -H 'content-type: application/json' \
  --data-binary @export-request.json \
  "$QDRANT_URL/collections/$COLLECTION/private-oram/recovery/export-context" \
  > export-response.json
```

`export-request.json` has this exact request shape:

```json
{
  "expected_committed_backup_generation": 7,
  "backup_generation": 8,
  "client_recovery_state_digest": "<43-char-base64url-sha256>",
  "owner_signing_key_id": "tenant-a/private-oram-recovery-v2"
}
```

The endpoint prepares and publishes a collection snapshot and returns
`snapshot`, an unsigned `checkpoint`, and `index_states`. It revalidates the
collection and recovery authority after snapshot preparation. Do not create a
separate ordinary snapshot and substitute it into this checkpoint.

Compare every returned `index_states` entry to the frozen client signed state,
then independently recompute `index_state_digest`. Reject and delete the
candidate generation if kind/name, epoch, root, writeback digest, layout, peer,
shard, collection UUID, or client digest differs.

### 4. Sign and download

After the independent comparisons, sign the returned checkpoint with
`package_private_oram_external_recovery_checkpoint` or equivalent canonical
message/signature helpers. The signer must pin a predeclared intent containing
all checkpoint fields and the independently verified snapshot and index state.
Store the resulting `PrivateOramExternalRecoveryCheckpointBundle` as
`recovery-bundle.json`.

Download the exact snapshot named by the export response:

```bash
SNAPSHOT_NAME=$(jq -er '.result.snapshot.name' export-response.json)

curl --fail-with-body --silent --show-error \
  -H "api-key: $QDRANT_API_KEY" \
  -o qdrant.snapshot \
  "$QDRANT_URL/collections/$COLLECTION/snapshots/$SNAPSHOT_NAME"
```

Verify both properties returned by the checkpoint before accepting the file:

```bash
stat --format='%s' qdrant.snapshot
sha256sum qdrant.snapshot
```

The byte count must equal `checkpoint.snapshot_size_bytes`; the lowercase hash
must equal `checkpoint.snapshot_sha256`. Hash the file again after transfer to
each backup destination.

### 5. Publish the generation

Write the following to two independent, immutable backup destinations:

1. `qdrant.snapshot`;
2. `recovery-bundle.json`;
3. the exact encrypted client recovery artifact bytes;
4. the generation inventory and non-secret runtime/peer recovery metadata;
5. references to the separately escrowed RK, checkpoint key, and signing keys.

Publish the catalog record only after all destination writes and read-back hash
checks succeed. A Qdrant-local published snapshot is not one of the required
independent copies. Resume SDK traffic only after publication.

## Restore procedure

### 1. Select an admissible generation

Select the newest complete generation that matches the live recovery context.
Before touching Qdrant, require all of the following:

- its generation is greater than the server's committed recovery generation;
- collection UUID, source peer identity, source shard ids, layout generation,
  owner set, and authority mode match;
- the runtime has the same private provider policy, RK id/epoch pins, and every
  public verifier needed by the snapshot and recovery bundle;
- the running binary satisfies the persisted Private ORAM format/capability
  floor;
- snapshot size/hash and client artifact hash match the signed checkpoint;
- no active client session, mutation, transfer, reshard, snapshot recovery, or
  external recovery exists.

Do not edit checkpoint JSON, change a source peer id, lower a generation, copy
an old root into current metadata, or bypass signature verification to make a
backup fit. A mismatch means the generation is not admissible.

### 2. Verify client recovery offline

Recover keys through the real escrow process. In an isolated client process:

1. hash the exact encrypted client artifact and compare it to
   `checkpoint.client_recovery_state_digest`;
2. verify the immutable manifest, signed state, and external checkpoint
   signatures against archived and currently configured public keys;
3. call `open_private_oram_append_client_checkpoint_v2` with the recovered
   checkpoint key and validate the returned checkpoint;
4. reconstruct each HNSW state with
   `PrivateHnswOramClientState::from_snapshot` and each result state with
   `PrivateResultOramClientState::from_snapshot`;
5. validate the entry node, point/token ledger, stash bounds, generations, and
   every epoch/root against the signed state and recovery inventory;
6. keep the recovered plaintext state in memory or protected temporary storage
   only. Do not activate it against Qdrant yet.

Wrong RK/checkpoint keys, malformed state, missing token records, duplicate
positions, stale roots, or signature failures stop the restore.

### 3. Begin and retain the operation token

Send the signed bundle exactly as stored:

```bash
set +x
BEGIN_RESPONSE=$(
  curl --fail-with-body --silent --show-error \
    -H "api-key: $QDRANT_API_KEY" \
    -H 'content-type: application/json' \
    --data-binary @recovery-bundle.json \
    "$QDRANT_URL/collections/$COLLECTION/private-oram/recovery/begin"
)
OPERATION_TOKEN=$(printf '%s' "$BEGIN_RESPONSE" | jq -er '.result.operation_token')
```

Store `OPERATION_TOKEN` in protected volatile operator state immediately. Qdrant
stores only its hash. There is no API to recover a lost raw token, and status,
verify, commit, and abort all require it. Never place it in a URL query string
or shell trace.

Status accepts the token only in the dedicated header:

```bash
curl --fail-with-body --silent --show-error \
  -H "api-key: $QDRANT_API_KEY" \
  -H "x-qdrant-private-oram-recovery-token: $OPERATION_TOKEN" \
  "$QDRANT_URL/collections/$COLLECTION/private-oram/recovery/status"
```

### 4. Upload in fixed chunks

Read `result.status.chunk_size_bytes` from the begin response. It is currently
8 MiB. Upload chunks in order starting at zero; every non-final chunk must have
that exact size. `chunk_sha256` is lowercase hexadecimal SHA-256 of the raw
chunk. For example, after producing the exact first chunk as `chunk-000000`:

```bash
CHUNK_SHA256=$(sha256sum chunk-000000 | cut -d' ' -f1)

curl --fail-with-body --silent --show-error \
  -H "api-key: $QDRANT_API_KEY" \
  -F "operation_token=$OPERATION_TOKEN" \
  -F 'chunk_index=0' \
  -F "chunk_sha256=$CHUNK_SHA256" \
  -F 'chunk=@chunk-000000;type=application/octet-stream' \
  "$QDRANT_URL/collections/$COLLECTION/private-oram/recovery/upload"
```

After every response, require `next_chunk_index` to advance by one. An exact
duplicate chunk is idempotent only when its stored bytes hash identically. Use
status to resume after interruption; never skip or replace a chunk.

### 5. Verify and commit

Verification restores into an isolated pending directory and validates the
archive, collection config, peer/shard topology, and complete HNSW/result
epoch/root state. It does not change the live collection.

```bash
umask 077
OPERATION_FILE=$(mktemp "${XDG_RUNTIME_DIR:-/dev/shm}/private-oram-operation.XXXXXX")
printf '{"operation_token":"%s"}\n' "$OPERATION_TOKEN" > "$OPERATION_FILE"

curl --fail-with-body --silent --show-error \
  -H "api-key: $QDRANT_API_KEY" \
  -H 'content-type: application/json' \
  --data-binary @"$OPERATION_FILE" \
  "$QDRANT_URL/collections/$COLLECTION/private-oram/recovery/verify"
```

Require the returned phase to be `verified`. Then commit:

```bash
curl --fail-with-body --silent --show-error \
  -H "api-key: $QDRANT_API_KEY" \
  -H 'content-type: application/json' \
  --data-binary @"$OPERATION_FILE" \
  "$QDRANT_URL/collections/$COLLECTION/private-oram/recovery/commit"
```

`commit` is the only step that may replace the live collection and advance the
committed backup generation. The server continues the install future if the
HTTP client disconnects. On timeout or process restart, retry status/commit with
the same token; do not assume failure and do not start another restore.

Before commit, an operator may abort the exact operation:

```bash
curl --fail-with-body --silent --show-error \
  -H "api-key: $QDRANT_API_KEY" \
  -H 'content-type: application/json' \
  --data-binary @"$OPERATION_FILE" \
  "$QDRANT_URL/collections/$COLLECTION/private-oram/recovery/abort"
```

An expired operation remains fenced until explicitly aborted. Never delete
recovery staging files manually. Remove `OPERATION_FILE` after commit or abort;
do not retain the raw token in the backup catalog.

### 6. Activate client state and verify service

Only after commit succeeds or an idempotent retry proves it already committed:

1. atomically install the previously verified client artifact in the SDK state
   store;
2. pin its collection UUID, layout/state sequence, and every index epoch/root;
3. derive `PrivateHnswClientKeys` and `PrivateResultOramClientKeys` from the
   signed manifest context and recovered RK, never with the deprecated
   domain-only derivation;
4. open an HNSW session at the exact restored epoch with `fixed_budget: true`
   and the configured `result_privacy`;
5. if configured, open and close a result ORAM session at its exact epoch;
6. require each session response root to equal the client pin before reading a
   bucket;
7. run one fixed-budget SDK search using verified Merkle proofs and
   `validate_private_hnsw_strict_search_result`.

An HNSW session request has the repository-supported shape:

```json
{
  "client_id": "recovery-verifier-1",
  "desired_epoch": 42,
  "fixed_budget": true,
  "result_privacy": "ids_visible"
}
```

Send it to
`POST /collections/{collection}/private-hnsw/{vector}/session`. A private result
session uses
`POST /collections/{collection}/private-result-oram/session` and omits
`result_privacy`.

A real ORAM read remaps client state and normally requires signed writeback. If
the smoke search commits a writeback, persist the advanced client state
atomically and create a new coordinated backup before declaring the writer
available. Opening and closing a session without a read is suitable only for
epoch/root admission checking, not end-to-end recovery validation.

## Rotation

### External-recovery signer

1. Add the new Ed25519 public key id with identical public bytes to every bound
   private HNSW/result provider `signature_public_keys` registry.
2. Roll out and verify runtime parity before using the key.
3. Export a new backup generation and sign its checkpoint with the new key.
4. Complete a restore drill using that generation.
5. Keep the old public key configured while any retained checkpoint uses it.
   The old recovery private key may be retired only if it is not also an active
   index owner key and policy no longer requires producing signatures with it.

### Index owner signer

Private manifests, V2 immutable manifests, signed states, sessions, and commits
bind an exact `owner_signing_key_id`. Adding another public key to the registry
does not transfer ownership of an existing index. This repository does not
provide an in-place owner-key handoff for this contract. Rotate by building a
new index/collection lineage under the new signer, validating it, cutting over,
and retaining the old verifier and recovery material for the old backup
retention period.

### Resource key or RK epoch

The RK id/epoch is bound into manifests, bucket/client-state AEAD contexts, KDF
contexts, and runtime pins. Do not change `expected_rk_id`, `min_rk_epoch`, or
`max_rk_epoch` on an existing encrypted store and call that rotation. There is
no in-place private ORAM rekey in this contract. Build and seal a new index
lineage under the new RK epoch, verify recall and recovery, cut over, and retain
the old RK until every old snapshot and client artifact expires.

### Checkpoint encryption key

Prefer rotating the KEK that wraps the client checkpoint key, leaving the inner
checkpoint bytes unchanged. Resealing
`PrivateOramSealedAppendClientCheckpointV2` changes its digest, which is bound
by the signed state. Changing the inner key therefore requires a supported new
signed-state transition or a rebuilt lineage; it is not an out-of-band file
rewrite.

## Loss and rollback drills

Run drills on an isolated copy that cannot join or contact the production
cluster. A cloned peer identity must never run concurrently against shared
storage or the production network.

| Drill | Expected result |
| --- | --- |
| Lose the live RK handle | Recover through escrow, open the client checkpoint and one bucket locally, and record the recovery time. Without escrow, declare the data cryptographically lost. |
| Use the wrong RK/checkpoint key | Client checkpoint or bucket AEAD open fails before a session is activated. |
| Lose client position maps/stashes | Restore the exact encrypted client artifact. Do not reconstruct from Qdrant buckets or start with empty maps/stashes. |
| Lose the HNSW entry node | Restore it from the aggregate checkpoint. Component position-map backups alone are insufficient. |
| Lose the `ids_visible` token map | Restore the map from the aggregate checkpoint. Do not ask Qdrant to infer it. If no copy exists, rebuild the index from an independent authoritative dataset. |
| Corrupt one snapshot byte | Local SHA-256 check or server upload/verify rejects it; live collection remains unchanged. |
| Corrupt one client-artifact byte | External digest or local AEAD open rejects it before recovery begin. |
| Replace one epoch/root or writeback digest | Signed-state, canonical index-state digest, session pin, or server verification rejects it. |
| Replay an old backup generation | Monotonic generation and exact current context reject it. Do not lower the floor. |
| Interrupt upload | Status reports the next chunk; retry the exact chunk/token and complete or explicitly abort. |
| Interrupt commit or restart the peer | Retry the same token and let durable install reconciliation converge; do not start a competing operation. |
| Rotate the recovery signer | A backup signed by the new key restores while retained old backups still verify under the retained old public key. |

If RK, checkpoint key, client state, and authoritative source data are all lost,
there is no recovery procedure. If only Qdrant encrypted storage is lost, the
client artifact is useful only with a snapshot whose signed epoch/root set
exactly matches it.

## RPO and RTO drill

Private ORAM searches and appends can advance server buckets and client state.
The client state must be atomically durable after every successful writeback.
A coordinated external backup is valid only for its exact epoch/root set, so
the interval between complete coordinated generations is not automatically a
classic point-in-time RPO.

Define operational objectives as follows:

- **Client-state RPO:** zero committed writebacks. A commit is acknowledged to
  the application only after the matching encrypted client state is durable.
- **External-recovery RPO:** the newest complete, independently verified
  generation that remains admissible against the retained consensus context.
  If arbitrary rollback is required, record this as unsupported rather than
  assigning a misleading time value.
- **RTO start:** incident declaration or drill start.
- **RTO end:** server commit has converged, client state is activated, exact
  epoch/root admission passes, and one strict fixed-budget search returns the
  expected result mapping.

For every release and at least quarterly thereafter:

1. Select a production-sized encrypted generation without using live key
   handles or local snapshot files.
2. Recover all keys from escrow and all artifacts from independent backup
   storage.
3. Verify hashes, signatures, generation, topology, and client state offline.
4. Restore through `begin`, ordered `upload`, `verify`, and `commit` on an
   isolated same-identity environment.
5. Restart the peer once during an upload drill and once during a commit drill.
6. Open exact-root sessions and run fixed-budget known-query searches. For
   `ids_visible`, verify the token-to-visible-id mapping and ordinary retrieve
   behavior; for private result mode, verify result ORAM fetch and writeback.
7. Record snapshot size, upload throughput, verification time, commit/restart
   time, total RTO, observed client-state RPO, and every manual step.
8. Repeat one negative drill with a stale generation/root and one with a
   corrupted artifact. Both must fail closed without changing live state.

## `ids_visible` caveats

`ids_visible` protects vectors, query vectors, HNSW traversal, and ORAM node
accesses, but it does not provide result-id privacy after the SDK maps a
`point_token` to a Qdrant point id and performs ordinary retrieve. Qdrant can
observe the retrieved ids, request timing, request count, and ordinary payload
access policy. Repeated result fetches may therefore be linkable.

The token map is client-secret recovery state even though its mapped point ids
may be ordinary Qdrant identifiers. Keep it inside the encrypted client
artifact. Do not store it as Qdrant payload, in a snapshot side file, in the
recovery bundle, or in operator logs. If result-id privacy is required, use
`private_payload_oram_required` and back up the paired result token position map
and stash.

## Acceptance checklist

Production gate 5 is complete only when all applicable items are checked:

- [ ] The deployed topology is within the documented RF=1, automatic-sharding,
      same-peer, one/two-shard recovery scope.
- [ ] Every writeback durably persists the matching encrypted client state
      before application acknowledgement.
- [ ] RK, checkpoint key, index signer, and recovery signer escrow restores have
      been tested from an independent failure domain.
- [ ] The backup contains the HNSW position map, stash, entry node, point/token
      ledger, and generation records.
- [ ] Private result mode backups contain the result token position map, stash,
      and payload-token/point generation records.
- [ ] `ids_visible` backups contain the complete point-token-to-visible-id map
      and the leakage tradeoff is accepted by the data owner.
- [ ] The Qdrant snapshot contains no client keys, client state, entry node, or
      token map, encrypted or plaintext.
- [ ] The complete encrypted client artifact digest equals the signed external
      checkpoint field and is not confused with a component ciphertext hash.
- [ ] Snapshot size/hash, canonical index-state digest, all epochs/roots, layout,
      peer/shards, and stable collection UUID were independently checked before
      signing.
- [ ] Backup generation allocation is monotonic and the committed-generation
      floor is stored in an append-only catalog.
- [ ] Two immutable artifact copies and two independently recoverable key copies
      passed read-back verification.
- [ ] Recovery limits and free-space reservations are sized for the largest
      retained snapshot and unpacked collection.
- [ ] The operation-token custody and timeout/retry procedure has been drilled.
- [ ] Corruption, wrong-key, stale-root, stale-generation, interrupted-upload,
      and interrupted-commit drills fail closed or converge as documented.
- [ ] A production-sized restore met the declared RTO and completed a strict
      fixed-budget search at the exact restored root.
- [ ] A new coordinated backup was taken after any verification search that
      committed an ORAM writeback.
- [ ] Key rotation uses overlap or rebuild procedures; no operator plans an
      unsupported in-place RK or index-owner rekey.
- [ ] Operators understand that this protocol is exact-state recovery, not
      arbitrary point-in-time rollback.

## Monitoring during recovery

Monitor the unlabelled
`qdrant_private_oram_external_recovery_*` gauges, especially reserved bytes,
staging reservations, worker limit, and workers in use. Also monitor the
successful-preflight scanned-byte and scanned-entry counters. These metrics do
not replace status polling with the operation token.

Alert on an expired recovery that has not been explicitly aborted, a staging
reservation that remains after the change window, repeated verification
failure, free space approaching `min_free_space_bytes`, or an SDK root pin that
does not equal the session response. Keep the standalone metrics port behind a
trusted monitoring boundary when it is enabled; it is not protected by Qdrant
API keys.

The process-level reference flow and adversarial cases are exercised in
[`test_private_oram_sessions.py`](../tests/consensus_tests/test_private_oram_sessions.py).
That fixture is test infrastructure, not an operator signing tool or supported
production SDK.
