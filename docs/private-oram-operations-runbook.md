# qdrant-sec Operations Runbook: Backups, Restore Drills and Key Loss

This runbook covers the operational procedures that PLAN V2-E requires before a
private ORAM release: backup rotation, client recovery-state escrow, restore
drills and key loss. It links to the normative descriptions in `docs/ckks.md`
and `docs/private-oram-v2-owner-lifecycle.md` instead of repeating them. When
this runbook and those documents disagree, those documents win; please fix the
runbook.

Status: RF=1 external restore (`/private-oram/recovery/*`) is still an
**experimental same-peer recovery path**. The hard-crash/RF=1 process matrix is
an open release gate (`docs/ckks.md`, "Non-Redundant Owner External Restore").
Rehearse every procedure below on a staging cluster before relying on it.

## 1. What a complete backup is

A private HNSW/result ORAM collection cannot be rebuilt from the server alone.
The server stores encrypted buckets, manifests, Merkle data and the consensus
epoch/root. It never holds the position maps, stashes, HNSW entry node or point
token map. Those live only in client state.

A backup set is complete only when it contains all of the following:

| Part | Where it comes from | Who holds it |
| --- | --- | --- |
| Collection snapshot | `POST /collections/{c}/snapshots` (collection write access); refused unless `migration_state` is `active` and no ORAM session, upload window or lifecycle operation is open | Server operator |
| Signed external recovery checkpoint | Built and signed by the owner client (`PrivateOramExternalRecoveryCheckpoint`, signature domain `qdrant-sec/private-oram-external-recovery-checkpoint-signature/v1`) | Owner client |
| Encrypted client recovery state | `seal_private_hnsw_oram_client_state_snapshot` (and the result ORAM equivalent); bound to collection, vector, RK id/epoch, index epoch and root | Owner client, escrowed out of band |
| Client key material | Client RK and signing keys | Client key escrow (never sent to Qdrant) |
| Server key material | Wrapping keys (MK/KEK) and wrapped RK records from the runtime config, or references to the KMS/Vault keys | Server operator / secret backend |

The checkpoint ties these parts together. It signs the snapshot's byte size and
SHA-256, the layout and index-state digests, every shard id, a monotonic
`backup_generation` and the digest of the complete encrypted client
recovery-state set (`client_recovery_state_digest`). A snapshot and a client
state from different moments do not match, and restore rejects the pair.

Never upload client RK material, position maps, stashes, entry nodes, token
maps or client-state plaintext to Qdrant, and never put them in a server
snapshot.

## 2. Backup rotation

1. Quiesce writers for the collection. Snapshot creation is refused while a
   private ORAM session, upload window or lifecycle operation is open.
2. Create the collection snapshot. Download it with an account holding
   `snapshot_export`; encrypted markers are exported raw.
3. On the owner client, seal the client recovery state for the **same** epoch
   and root, and compute its digest.
4. Build and sign the checkpoint with a `backup_generation` strictly greater
   than the last committed generation. Generation 0 is rejected. An active
   recovery lease must use a generation above the committed one.
5. Store the snapshot, the checkpoint with its signature and the sealed client
   state as one unit, labelled with the generation. Verify the snapshot SHA-256
   against the checkpoint before you call the backup done.
6. Retention: keep at least the newest two complete sets. Delete a set only as
   a whole. A snapshot without its client state, or the reverse, is unusable.
   The server enforces only the strict increase of `backup_generation`, so
   the retention policy is the operator's to define and audit.

For V2 append collections, every append changes the signed state and its
client checkpoint set digest. Take a new set after each append batch you need
to be able to restore.

## 3. Client recovery-state escrow

- Escrow the sealed client state together with a backup of the client RK and
  signing keys, under a different trust domain from the Qdrant operator (for
  example, a tenant-controlled KMS or offline media).
- The sealed state is only as recoverable as the client RK that sealed it.
  Escrowing the state without the key that opens it is not a backup.
- Record, next to each escrowed set: collection UUID (the stable crypto id),
  `backup_generation`, index epoch and root, RK id and epoch, and the
  checkpoint digest.
- Test opening an escrowed state with `from_snapshot` during every restore
  drill (section 4), not only during an incident.

## 4. Restore drill

Run this drill regularly on a staging cluster built from the same version and
runtime crypto settings as production. External restore needs the same peer
as the signed source and the current collection UUID, crypto config, shard
set, layout and epoch/roots. It is not a cross-cluster migration tool.

All six recovery routes require global `manage`. The access check runs before
the multipart body is read.

1. **Preflight.** Confirm that no ORAM session lease and no pending generic
   snapshot recovery exist for the collection. Confirm that the runtime crypto
   settings match on every peer (see section 6).
2. **Begin.** `POST /collections/{c}/private-oram/recovery/begin` with
   `{"checkpoint": …, "signature": …}`. This stages the signed checkpoint and
   takes a sliding one-hour consensus lease. The response carries a 43-character
   operation token. Keep it secret and keep it until the drill ends.
3. **Upload.** `POST …/recovery/upload` as multipart with fields
   `operation_token`, `chunk_index`, `chunk_sha256` and `chunk`. Send the
   snapshot in ordered 8 MiB chunks.
4. **Status.** `GET …/recovery/status` with header
   `x-qdrant-private-oram-recovery-token: <token>`. Tokens in the query string
   are ignored.
5. **Verify.** `POST …/recovery/verify` with `{"operation_token": …}`. This
   restores into an isolated directory, validates it and promotes it to the
   verified collection. The live collection is untouched.
6. **Client check.** On the owner client, open the escrowed client state with
   `from_snapshot` against the checkpoint's epoch and root. Run a known-answer
   search and a paired result payload fetch.
7. **Commit or abort.**
   - `POST …/recovery/commit` is the only call that replaces the live
     collection and advances the committed `backup_generation`.
   - `POST …/recovery/abort` needs the same owner peer and token, and still
     works after the lease expires.
   - **Point of no return:** once the durable `Loaded` marker exists, Qdrant
     never rolls back automatically. An active Staging/Installing recovery
     also blocks startup snapshot restore.
8. Record the drill: generation restored, timings, any failures and the
   client known-answer results.

Collection-level `PUT /collections/{c}/snapshots/recover` (global `manage`)
also preflights private ORAM manifests, signatures, epoch/roots, buckets and
Merkle data, and the persisted UUID. It does not restore client state, so the
client still needs the escrowed state that matches the snapshot.

## 5. Key rotation and key loss

### Rotation (planned)

- **MK rotation:** load both the old and new wrapping keys, then call
  `POST /crypto/resource-keys/rewrap` with `old_wrapped_by` and
  `new_wrapped_by` (`dry_run: true` first). Apply the returned config patch to
  **every** node atomically. Payload and vector envelopes do not change.
  Resource keys re-wrapped through Vault Transit are recorded as
  `wrap_algorithm: vault-transit-bound`. Re-wrap legacy `vault-transit`
  materials so that they become scope-bound.
- **RK rotation:**
  1. `POST /crypto/resource-keys/generate` returns a new `active` wrapped RK
     patch.
  2. Apply the patch, point the provider's `materials.sym_key` at the new RK,
     and move the old RK into `options.retired_materials`.
  3. Run `POST /collections/{c}/crypto/migration/run-payloads` (collection
     `manage`; rerun it if interrupted).
  4. Only then call `POST /crypto/resource-keys/retire` with
     `target_state: disabled`. `destroyed` is rejected, because shredding
     wrapped RK material without a migration-completion proof can orphan old
     envelopes.
- Keep the old MK available until every node runs the rewrapped config.

### Key loss (unplanned)

| Lost item | Consequence | Response |
| --- | --- | --- |
| Server MK/KEK (wrapping key, KMS or Vault key) with no backup | Every RK wrapped only under it cannot be unwrapped, so server-encrypted payloads and vectors under those RKs are unrecoverable | Restore the MK from the secret backend's own backup. If it is truly gone, the affected collections must be re-ingested from source data. Disable the affected RK records so nodes stop retrying unwraps. |
| A wrapped RK record (config) | Same as above for that RK | Restore the record from config history or backups. The record is not secret without its MK. |
| Client RK or signing key | Client-side envelopes and the sealed client recovery state cannot be opened, and new mutations cannot be signed | Restore the key from client escrow. Without it the collection's private data is unrecoverable by design. |
| Client recovery state (no escrowed copy) | The server snapshot alone cannot rebuild position maps, stashes or the token map, so the ORAM index cannot be read | Restore the newest complete set (section 4). If none matches, rebuild the collection from source data. |
| Raft image **and** the V2 mutation authority floor on a node | Outside automatic recovery | Do not let the node serve mutations. Restore a newer floor or re-enroll the node (`docs/private-oram-v2-owner-lifecycle.md`). |

Compromise (as opposed to loss) of a server key: rotate the MK (rewrap), then
rotate the affected RKs and run the payload migration. Client-side zero-trust
data is not exposed by server key compromise, but rotate client signing keys
if the client environment is suspect.

## 6. Cluster parity settings to verify before any restore

- Every peer must have identical runtime crypto settings. Shard transfer,
  replication and restore fail closed on a mismatched or missing runtime
  capability fingerprint. Wrapped RK `state`, provider key versions and
  attestation ids are part of the fingerprint.
- In cluster mode, collections with server-side keyed providers require
  `QDRANT_CRYPTO_CLUSTER_ATTESTATION_B64` on every peer: exactly 43 base64url
  characters without padding, decoding to 32 bytes. The fingerprint uses it to
  compare non-reversible resource-key commitments. Use the same value on every
  peer and keep it secret.
- Strict zero-trust (`crypto.zero_trust_profile: strict`) rejects server
  materials and backends, so only client-held keys matter for those
  collections.

## 7. Open gaps (tracked in PLAN V2-E and the docs/ckks.md review passes)

- Multi-process crash matrix for RF=1 external restore, leader/supervisor
  change concurrency, disk-full/permission/fsync injection and end-to-end
  snapshot/WAL sentinel scans are not yet automated.
- There is no tooling in this repository that signs checkpoints or seals and
  escrows client state end to end. The SDK helpers exist
  (`lib/crypto/src/private_oram_recovery.rs`), and the orchestration is the
  client's.
- Legacy `vault-transit` wrapped RKs still open without scope binding, with a
  warning; re-wrap them.
