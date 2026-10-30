//! Client side of a private ORAM V2 paired append for multi-process tests.
//!
//! A long-lived process: every stdin line is one JSON command and every stdout line answers it
//! with `{"ok": true, "result": ...}` or `{"ok": false, "error": ...}`. The process keeps the
//! client state between commands (keys, plaintext buckets, position maps, the signed V2 state
//! and its sealed checkpoint), so a test can drive the real protocol against a live cluster:
//!
//! - `{"cmd": "build", "collection_id": ...}` seals a V1 HNSW index and a V1 result index from
//!   three points and returns them, with one signed V1 write-back per index, in the
//!   `private_oram_cluster_fixture` shape. Each write-back re-seals the root bucket under the
//!   next epoch, so every stored bucket stays readable by this client. An optional
//!   `"tree_height"` (2-16, default 2) sets both indexes' Path ORAM tree height.
//! - `{"cmd": "enroll", "template": ...}` (after both write-backs) signs the V2 immutable
//!   manifest of both indexes and a genesis state whose client state digest is that of the
//!   sealed append checkpoint built from the real position maps.
//! - `{"cmd": "open"}` returns a mutation `open` body for the enrolled state.
//! - `{"cmd": "begin", "session": <open response>}` starts the paired append of one new point
//!   (HNSW node and result payload) and returns the first `read` body; every
//!   `{"cmd": "read_response", "response": <read result>}` verifies a read window and returns the
//!   next `read` body, until it returns the `append` body (owner prepare of the finalized
//!   mutation).
//! - `{"cmd": "open_next"}` adopts the appended state and returns an `open` body for it.
//!
//! The `begin` answer also carries `plaintext_sentinels`: hex byte strings of the appended
//! point (node id, point and fetch tokens raw and base64url, vector bytes, payload raw and
//! base64url) and of the client keys, which must never reach server storage, snapshots or logs.
//! The `append` answer carries `written_ciphertext`, one bucket ciphertext the append writes, as
//! the positive control of such a scan.

use std::io::{BufRead as _, Write as _};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER, PRIVATE_HNSW_ORAM_V2_BINDING,
    PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_V2_VERSION, PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
    PRIVATE_ORAM_SIGNED_STATE_V2_VERSION, PRIVATE_RESULT_ORAM_BINDING,
    PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION, PRIVATE_RESULT_ORAM_V2_BINDING,
    PrivateHnswBucketAeadBaseContext, PrivateHnswBuildPoint, PrivateHnswClientKeys,
    PrivateHnswCommitSignatureContext, PrivateHnswEncryptedPathBatch,
    PrivateHnswManifestBuildContext, PrivateHnswOramClientConfig, PrivateHnswOramManifest,
    PrivateHnswParams, PrivateHnswPlaintextIndexBuild, PrivateHnswVectorEncoding,
    PrivateOramAppendClientCheckpointV2, PrivateOramAppendClientIndexCheckpointV2,
    PrivateOramAppendHnswRecordV2, PrivateOramAppendHnswTransactionOutputV2,
    PrivateOramAppendHnswTransactionPlanV2, PrivateOramAppendHnswTransactionV2,
    PrivateOramAppendLevel0PointV2, PrivateOramAppendPairedFinalizationContextV1,
    PrivateOramAppendPairedFinalizationInputV1, PrivateOramAppendPairedFinalizationV1,
    PrivateOramAppendPointRecordV2, PrivateOramAppendResultPointV2,
    PrivateOramAppendResultRecordV2, PrivateOramAppendResultTransactionOutputV2,
    PrivateOramAppendResultTransactionPlanV2, PrivateOramAppendResultTransactionV2,
    PrivateOramEncryptedAppendClientCheckpointV2, PrivateOramImmutableIndexParamsV2,
    PrivateOramImmutableIndexV2, PrivateOramImmutableManifestBundleV2,
    PrivateOramImmutableManifestV2, PrivateOramIndexCapacityV2, PrivateOramIndexKindV2,
    PrivateOramIndexStateV2, PrivateOramSignedStateBundleV2, PrivateOramSignedStateV2,
    PrivateResultOramBucketAeadBaseContext, PrivateResultOramClientCommitBucketRef,
    PrivateResultOramClientKeys, PrivateResultOramClientState, PrivateResultOramCommitPlan,
    PrivateResultOramCommitSignatureContext, PrivateResultOramEncryptedBucketBatch,
    PrivateResultOramManifest, PrivateResultOramPayloadBlockPlaintext,
    PrivateResultOramReadBucketsSignatureContext, ResultPrivacyMode, SecretKey,
    VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER, bind_private_oram_append_client_checkpoint_v2,
    build_private_hnsw_oram_manifest_from_encrypted_index,
    build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points,
    decode_private_result_oram_leaf_label, empty_private_result_oram_plaintext_bucket,
    encode_private_hnsw_oram_leaf_label, finalize_private_oram_append_paired_mutation_v1,
    plan_private_hnsw_oram_commit_for_manifest, private_oram_append_client_checkpoint_v2_digest,
    private_oram_immutable_manifest_v2_digest, private_result_oram_bucket_ids_for_leaf,
    private_result_oram_client_config_from_manifest,
    private_result_oram_merkle_root_for_commitments,
    project_private_oram_append_paired_owner_prepare_v1, reserve_private_hnsw_oram_physical_slots,
    seal_private_hnsw_oram_plaintext_bucket, seal_private_hnsw_oram_plaintext_index,
    seal_private_oram_append_client_checkpoint_v2, seal_private_result_oram_plaintext_bucket,
    sign_private_hnsw_oram_commit, sign_private_hnsw_oram_manifest,
    sign_private_hnsw_oram_read_paths_for_manifest_context,
    sign_private_oram_immutable_manifest_v2, sign_private_oram_signed_state_v2,
    sign_private_result_oram_commit, sign_private_result_oram_manifest,
    sign_private_result_oram_read_buckets,
};
use ring::rand::{SecureRandom as _, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;
use serde_json::{Value, json};

type BoxError = Box<dyn std::error::Error>;

const VECTOR_NAME: &str = "text";
/// The V2 name of the result index, which the client chooses at enrollment.
const RESULT_INDEX_NAME: &str = "payload";
const KEY_ID: &str = "tenant-a/vector-private-rk";
/// A paired V2 collection has one owner: both V1 manifests and the V2 manifest name this key.
const OWNER_SIGNING_KEY_ID: &str = "tenant-a/private-hnsw-signing-v1";
const CLIENT_ID: &str = "tenant-a/append-e2e-sdk";
const RK_EPOCH: u64 = 7;
const BASE_EPOCH: u64 = 42;
const NEXT_EPOCH: u64 = 43;
const DEFAULT_TREE_HEIGHT: u32 = 2;
const HNSW_BLOCK_SIZE_BYTES: usize = 4096;
const RESULT_BLOCK_SIZE_BYTES: u32 = 1024;
/// Dummy blocks each index declares. V2 requires every index to declare the same logical
/// capacity (points plus dummies), so the HNSW build reserves every other free slot.
const DUMMY_COUNT: u64 = 1;
const CREATED_AT_UNIX: u64 = 1_770_000_000;
const MAX_NEIGHBOR_REWRITES: u32 = 1;
const MAX_CLIENT_STASH_BLOCKS: u64 = 8;
const RESOURCE_KEY: [u8; 32] = [13; 32];
const CHECKPOINT_KEY: [u8; 32] = [44; 32];
const APPENDED_PAYLOAD: &[u8] = b"{\"body\":\"append-e2e-appended-payload\"}";
const APPENDED_VECTOR: [f32; 2] = [1.5, 0.5];

struct HnswIndex {
    keys: PrivateHnswClientKeys,
    build: PrivateHnswPlaintextIndexBuild,
    manifest: PrivateHnswOramManifest,
    epoch: u64,
    root_hash: String,
}

struct ResultIndex {
    keys: PrivateResultOramClientKeys,
    positions: PrivateResultOramClientState,
    blocks: Vec<PrivateResultOramPayloadBlockPlaintext>,
    manifest: PrivateResultOramManifest,
    epoch: u64,
    root_hash: String,
}

struct Enrolled {
    manifest_bundle: PrivateOramImmutableManifestBundleV2,
    state_bundle: PrivateOramSignedStateBundleV2,
    checkpoint: PrivateOramAppendClientCheckpointV2,
    encrypted_checkpoint: PrivateOramEncryptedAppendClientCheckpointV2,
}

/// The mutation session an append runs in, from the `open` response.
struct Session {
    session_id: String,
    mutation_id: String,
    manifest_digest: String,
    old_state_digest: String,
    writer_lease_digest: String,
    writer_fence: u64,
    issued_at_unix: u64,
    lease_expires_unix: u64,
    hnsw_epoch: u64,
    hnsw_root_hash: String,
    result_epoch: u64,
    result_root_hash: String,
}

struct Append {
    session: Session,
    hnsw: Option<PrivateOramAppendHnswTransactionV2>,
    result: Option<PrivateOramAppendResultTransactionV2>,
    hnsw_output: Option<PrivateOramAppendHnswTransactionOutputV2>,
    result_output: Option<PrivateOramAppendResultTransactionOutputV2>,
    /// The index kind and sequence of the read window the server is answering.
    pending: Option<(PrivateOramIndexKindV2, u32)>,
    finalized: Option<PrivateOramAppendPairedFinalizationV1>,
}

struct Client {
    collection_id: String,
    owner_key: Ed25519KeyPair,
    checkpoint_key: SecretKey,
    points: Vec<PrivateHnswBuildPoint>,
    tree_height: u32,
    hnsw: Option<HnswIndex>,
    result: Option<ResultIndex>,
    enrolled: Option<Enrolled>,
    append: Option<Append>,
}

#[derive(Deserialize)]
struct Template {
    collection_id: String,
    layout_generation: u64,
    layout_digest: String,
    indexes: Vec<TemplateIndex>,
}

#[derive(Deserialize)]
struct TemplateIndex {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    index_epoch: u64,
    root_hash: String,
    writeback_digest: Option<String>,
}

fn main() -> Result<(), BoxError> {
    let mut client = Client {
        collection_id: String::new(),
        owner_key: Ed25519KeyPair::from_seed_unchecked(&[7; 32])
            .map_err(|_| "failed to create the owner key")?,
        checkpoint_key: SecretKey::from_bytes(CHECKPOINT_KEY),
        points: fixture_points(),
        tree_height: DEFAULT_TREE_HEIGHT,
        hnsw: None,
        result: None,
        enrolled: None,
        append: None,
    };
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let answer = match serde_json::from_str::<Value>(&line)
            .map_err(BoxError::from)
            .and_then(|command| client.handle(&command))
        {
            Ok(result) => json!({"ok": true, "result": result}),
            Err(error) => json!({"ok": false, "error": error_chain(error.as_ref())}),
        };
        writeln!(stdout, "{}", serde_json::to_string(&answer)?)?;
        stdout.flush()?;
    }
    Ok(())
}

impl Client {
    fn handle(&mut self, command: &Value) -> Result<Value, BoxError> {
        match command["cmd"].as_str() {
            Some("build") => {
                let collection_id = command["collection_id"]
                    .as_str()
                    .ok_or("build needs a collection_id")?;
                if let Some(tree_height) = command.get("tree_height").and_then(Value::as_u64) {
                    self.tree_height = u32::try_from(tree_height)
                        .ok()
                        .filter(|height| (2..=16).contains(height))
                        .ok_or("tree_height must be between 2 and 16")?;
                }
                self.build(collection_id)
            }
            Some("enroll") => {
                let template = serde_json::from_value(command["template"].clone())?;
                self.enroll(template)
            }
            Some("open") => self.open(),
            Some("begin") => self.begin(&command["session"]),
            Some("read_response") => {
                self.accept_read(&command["response"])?;
                self.next_action()
            }
            Some("open_next") => self.open_next(),
            _ => Err("unknown command".into()),
        }
    }

    fn build(&mut self, collection_id: &str) -> Result<Value, BoxError> {
        self.collection_id = collection_id.to_string();
        let (hnsw, hnsw_output) = self.build_hnsw()?;
        let (result, result_output) = self.build_result()?;
        self.hnsw = Some(hnsw);
        self.result = Some(result);
        Ok(json!({
            "hnsw_public_key": BASE64URL_NOPAD.encode(self.owner_key.public_key().as_ref()),
            "result_public_key": BASE64URL_NOPAD.encode(self.owner_key.public_key().as_ref()),
            "hnsw": hnsw_output,
            "result": result_output,
        }))
    }

    fn hnsw_base_context(&self) -> PrivateHnswBucketAeadBaseContext<'_> {
        PrivateHnswBucketAeadBaseContext {
            collection_id: &self.collection_id,
            vector_name: VECTOR_NAME,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
        }
    }

    fn result_base_context(&self) -> PrivateResultOramBucketAeadBaseContext<'_> {
        PrivateResultOramBucketAeadBaseContext {
            collection_id: &self.collection_id,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
        }
    }

    fn build_hnsw(&self) -> Result<(HnswIndex, Value), BoxError> {
        let config = PrivateHnswOramClientConfig {
            tree_height: self.tree_height,
            bucket_size: 2,
            block_size_bytes: HNSW_BLOCK_SIZE_BYTES,
            fixed_neighbor_slots: 4,
        };
        let mut build = build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
            config,
            DistanceKind::Euclid,
            2,
            1,
            2,
            &self.points,
            &[0, 1, 2],
        )?;
        // An index that enrolls into mutation V2 keeps physical slots free for appends.
        let physical_slots = ((1_u64 << (self.tree_height + 1)) - 1) * config.bucket_size as u64;
        let reserved_slots = physical_slots
            .checked_sub(self.points.len() as u64 + DUMMY_COUNT)
            .ok_or("the HNSW tree is too small for the fixture points")?;
        reserve_private_hnsw_oram_physical_slots(&mut build, reserved_slots)?;
        let keys = PrivateHnswClientKeys::derive_from_resource_key_with_context(
            &SecretKey::from_bytes(RESOURCE_KEY),
            &self.collection_id,
            VECTOR_NAME,
            KEY_ID,
            RK_EPOCH,
        )?;
        let encrypted = seal_private_hnsw_oram_plaintext_index(
            &keys,
            self.hnsw_base_context(),
            BASE_EPOCH,
            &build,
            config,
        )?;
        let manifest = build_private_hnsw_oram_manifest_from_encrypted_index(
            PrivateHnswManifestBuildContext {
                collection_id: &self.collection_id,
                vector_name: VECTOR_NAME,
                key_id: KEY_ID,
                rk_id: KEY_ID,
                rk_epoch: RK_EPOCH,
                dim: 2,
                distance: DistanceKind::Euclid,
                hnsw: PrivateHnswParams {
                    m: 2,
                    ef_construction: 4,
                    max_layers: 3,
                    fixed_neighbor_slots: 4,
                },
                oram: OramParams {
                    kind: OramKind::PathOram,
                    bucket_size: 2,
                    block_size_bytes: HNSW_BLOCK_SIZE_BYTES as u32,
                    tree_height: self.tree_height,
                    path_batch_size: 1,
                },
                fixed_budget: FixedBudgetParams {
                    enabled: true,
                    upper_layer_steps: 1,
                    base_layer_steps: 3,
                    paths_per_round: 1,
                    fixed_result_k: 1,
                },
                result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
                owner_signing_key_id: OWNER_SIGNING_KEY_ID,
                created_at_unix: CREATED_AT_UNIX,
            },
            &encrypted,
        )?;
        let manifest_signature = sign_private_hnsw_oram_manifest(&self.owner_key, &manifest)?;

        // V1 write-back: read the path to leaf 0 and re-seal the root bucket under the next
        // epoch with unchanged plaintext.
        let read_paths = vec![encode_private_hnsw_oram_leaf_label(0, self.tree_height)?];
        let read_signature = sign_private_hnsw_oram_read_paths_for_manifest_context(
            &self.owner_key,
            &manifest,
            BASE_EPOCH,
            &manifest.root_hash,
            &read_paths,
        )?;
        let root_plaintext = build
            .buckets
            .iter()
            .find(|bucket| bucket.bucket_id == 0)
            .ok_or("the HNSW build has no root bucket")?;
        let updated_bucket = seal_private_hnsw_oram_plaintext_bucket(
            &keys,
            self.hnsw_base_context(),
            NEXT_EPOCH,
            root_plaintext,
            config,
        )?;
        let commitments = encrypted
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        let commit_plan = plan_private_hnsw_oram_commit_for_manifest(
            &manifest,
            NEXT_EPOCH,
            &commitments,
            std::slice::from_ref(&updated_bucket),
        )?;
        let commit_signature = sign_private_hnsw_oram_commit(
            &self.owner_key,
            PrivateHnswCommitSignatureContext {
                collection_id: &self.collection_id,
                vector_name: VECTOR_NAME,
                key_id: KEY_ID,
                rk_id: KEY_ID,
                rk_epoch: RK_EPOCH,
                signing_key_id: OWNER_SIGNING_KEY_ID,
            },
            &commit_plan,
        )?;
        let output = json!({
            "manifest": manifest,
            "manifest_signature": manifest_signature,
            "buckets": encrypted.buckets,
            "read": {"paths": read_paths, "signature": read_signature},
            "commit": {
                "old_epoch": commit_plan.old_epoch,
                "new_epoch": commit_plan.new_epoch,
                "old_root_hash": commit_plan.old_root_hash,
                "new_root_hash": commit_plan.new_root_hash,
                "updated_buckets": [updated_bucket],
                "signature": commit_signature,
            },
        });

        Ok((
            HnswIndex {
                keys,
                build,
                manifest,
                epoch: NEXT_EPOCH,
                root_hash: commit_plan.new_root_hash,
            },
            output,
        ))
    }

    fn build_result(&self) -> Result<(ResultIndex, Value), BoxError> {
        let oram = OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: RESULT_BLOCK_SIZE_BYTES,
            tree_height: self.tree_height,
            path_batch_size: 1,
        };
        let bucket_count = (1_u64 << (self.tree_height + 1)) - 1;
        let mut manifest = PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: self.collection_id.clone(),
            key_id: KEY_ID.to_string(),
            rk_id: KEY_ID.to_string(),
            rk_epoch: RK_EPOCH,
            oram,
            index_epoch: BASE_EPOCH,
            root_hash: BASE64URL_NOPAD.encode(&[0; 32]),
            bucket_count,
            logical_result_count: self.points.len() as u64,
            dummy_result_count: DUMMY_COUNT,
            owner_signing_key_id: OWNER_SIGNING_KEY_ID.to_string(),
            created_at_unix: CREATED_AT_UNIX,
        };
        let config = private_result_oram_client_config_from_manifest(&manifest)?;
        let keys = PrivateResultOramClientKeys::derive_from_resource_key_with_context(
            &SecretKey::from_bytes(RESOURCE_KEY),
            &self.collection_id,
            KEY_ID,
            RK_EPOCH,
        )?;

        // Point `i` lives in the leaf bucket of leaf `i`, which is on that leaf's path.
        let mut plaintext = (0..bucket_count)
            .map(|bucket_id| empty_private_result_oram_plaintext_bucket(bucket_id, config))
            .collect::<Result<Vec<_>, _>>()?;
        let mut positions = PrivateResultOramClientState::new();
        let mut blocks = Vec::with_capacity(self.points.len());
        for (leaf, point) in (0_u64..).zip(&self.points) {
            let payload_fetch_token = point
                .payload_fetch_token
                .ok_or("every fixture point has a payload fetch token")?;
            let block = PrivateResultOramPayloadBlockPlaintext {
                version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
                payload_fetch_token,
                point_token: point.point_token,
                payload: format!("{{\"body\":\"append-e2e-payload-{leaf}\"}}").into_bytes(),
                deleted: false,
                generation: 1,
            };
            let leaf_bucket = *private_result_oram_bucket_ids_for_leaf(leaf, self.tree_height)?
                .last()
                .ok_or("a leaf path is never empty")?;
            plaintext[usize::try_from(leaf_bucket)?].blocks[0] = Some(block.clone());
            positions.insert_position(payload_fetch_token, leaf, self.tree_height)?;
            blocks.push(block);
        }
        let buckets = plaintext
            .iter()
            .map(|bucket| {
                seal_private_result_oram_plaintext_bucket(
                    &keys,
                    self.result_base_context(),
                    BASE_EPOCH,
                    bucket,
                    config,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let commitments = buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        manifest.root_hash = private_result_oram_merkle_root_for_commitments(&commitments)?;
        let manifest_signature = sign_private_result_oram_manifest(&self.owner_key, &manifest)?;

        // V1 write-back: read the path to leaf 0 and re-seal the root bucket.
        let read_bucket_ids = private_result_oram_bucket_ids_for_leaf(0, self.tree_height)?;
        let read_signature = sign_private_result_oram_read_buckets(
            &self.owner_key,
            PrivateResultOramReadBucketsSignatureContext {
                collection_id: &self.collection_id,
                key_id: KEY_ID,
                rk_id: KEY_ID,
                rk_epoch: RK_EPOCH,
                signing_key_id: OWNER_SIGNING_KEY_ID,
            },
            BASE_EPOCH,
            &manifest.root_hash,
            manifest.bucket_count,
            &read_bucket_ids,
        )?;
        let updated_bucket = seal_private_result_oram_plaintext_bucket(
            &keys,
            self.result_base_context(),
            NEXT_EPOCH,
            &plaintext[0],
            config,
        )?;
        let mut next_commitments = commitments;
        next_commitments[0] = updated_bucket.bucket_commitment.clone();
        let new_root_hash = private_result_oram_merkle_root_for_commitments(&next_commitments)?;
        let commit_plan = PrivateResultOramCommitPlan {
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: manifest.root_hash.clone(),
            new_root_hash: new_root_hash.clone(),
            leaf_commitments: next_commitments,
            updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }],
        };
        let commit_signature = sign_private_result_oram_commit(
            &self.owner_key,
            PrivateResultOramCommitSignatureContext {
                collection_id: &self.collection_id,
                key_id: KEY_ID,
                rk_id: KEY_ID,
                rk_epoch: RK_EPOCH,
                signing_key_id: OWNER_SIGNING_KEY_ID,
            },
            &commit_plan,
        )?;
        let output = json!({
            "manifest": manifest,
            "manifest_signature": manifest_signature,
            "buckets": buckets,
            "read": {"bucket_ids": read_bucket_ids, "signature": read_signature},
            "commit": {
                "old_epoch": BASE_EPOCH,
                "new_epoch": NEXT_EPOCH,
                "old_root_hash": commit_plan.old_root_hash,
                "new_root_hash": new_root_hash,
                "updated_buckets": [updated_bucket],
                "signature": commit_signature,
            },
        });

        Ok((
            ResultIndex {
                keys,
                positions,
                blocks,
                manifest,
                epoch: NEXT_EPOCH,
                root_hash: new_root_hash,
            },
            output,
        ))
    }

    fn enroll(&mut self, template: Template) -> Result<Value, BoxError> {
        let hnsw = self.hnsw.as_ref().ok_or("build before enroll")?;
        let result = self.result.as_ref().ok_or("build before enroll")?;
        if template.collection_id != self.collection_id || template.indexes.len() != 2 {
            return Err("the template must list this collection's HNSW and result index".into());
        }
        let mut writeback_digests = Vec::with_capacity(2);
        for (kind, index_name, epoch, root_hash) in [
            (
                PrivateOramIndexKindV2::Hnsw,
                VECTOR_NAME,
                hnsw.epoch,
                &hnsw.root_hash,
            ),
            (
                PrivateOramIndexKindV2::Result,
                "",
                result.epoch,
                &result.root_hash,
            ),
        ] {
            let index = template
                .indexes
                .iter()
                .find(|index| index.kind == kind && index.index_name == index_name)
                .ok_or("the template is missing an index")?;
            if index.index_epoch != epoch || &index.root_hash != root_hash {
                return Err("the template index does not match this client's write-back".into());
            }
            writeback_digests.push(
                index
                    .writeback_digest
                    .clone()
                    .ok_or("each index needs one V1 write-back before enrollment")?,
            );
        }

        // One path per window. Linking the new node to a neighbor whose level-0 list is full
        // prunes that list, which needs every current neighbor's vector, so the candidate
        // phase reads every node: the rewrites, the insert and one candidate path per point.
        let fixed_append_read_path_count = MAX_NEIGHBOR_REWRITES + 1 + self.points.len() as u32;
        let fixed_append_write_bucket_count = fixed_append_read_path_count * (self.tree_height + 1);
        let capacity = |bucket_count: u64, bucket_size: u32, logical: u64, dummy: u64| {
            let physical_slots = bucket_count * u64::from(bucket_size);
            let occupancy = logical + dummy;
            physical_slots
                .checked_sub(occupancy)
                .filter(|reserved| *reserved > 0)
                .map(|reserved_physical_slots| PrivateOramIndexCapacityV2 {
                    bucket_count,
                    logical_capacity: occupancy,
                    reserved_physical_slots,
                    max_client_stash_blocks: MAX_CLIENT_STASH_BLOCKS.min(physical_slots) as u32,
                    fixed_append_read_path_count,
                    fixed_append_write_bucket_count,
                })
                .ok_or("an index leaves no reserved physical slot")
        };
        let manifest = PrivateOramImmutableManifestV2 {
            version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
            collection_id: self.collection_id.clone(),
            manifest_nonce: BASE64URL_NOPAD.encode(&[21; 32]),
            indexes: vec![
                PrivateOramImmutableIndexV2 {
                    index_name: VECTOR_NAME.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Hnsw {
                        provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                        key_id: KEY_ID.to_string(),
                        rk_id: KEY_ID.to_string(),
                        rk_epoch: RK_EPOCH,
                        dim: hnsw.manifest.dim,
                        vector_encoding: PrivateHnswVectorEncoding::F32Le,
                        distance: hnsw.manifest.distance,
                        hnsw: hnsw.manifest.hnsw.clone(),
                        oram: hnsw.manifest.oram.clone(),
                        fixed_search_budget: hnsw.manifest.fixed_budget.clone(),
                        max_neighbor_rewrites: MAX_NEIGHBOR_REWRITES,
                    },
                    capacity: capacity(
                        hnsw.manifest.bucket_count,
                        hnsw.manifest.oram.bucket_size,
                        hnsw.manifest.logical_node_count,
                        hnsw.manifest.dummy_node_count,
                    )?,
                },
                PrivateOramImmutableIndexV2 {
                    index_name: RESULT_INDEX_NAME.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Result {
                        provider: PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
                        key_id: KEY_ID.to_string(),
                        rk_id: KEY_ID.to_string(),
                        rk_epoch: RK_EPOCH,
                        oram: result.manifest.oram.clone(),
                    },
                    capacity: capacity(
                        result.manifest.bucket_count,
                        result.manifest.oram.bucket_size,
                        result.manifest.logical_result_count,
                        result.manifest.dummy_result_count,
                    )?,
                },
            ],
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: OWNER_SIGNING_KEY_ID.to_string(),
            created_at_unix: CREATED_AT_UNIX,
        };
        let manifest_digest = private_oram_immutable_manifest_v2_digest(&manifest)?;

        let checkpoint = PrivateOramAppendClientCheckpointV2 {
            version: PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_V2_VERSION,
            collection_id: self.collection_id.clone(),
            manifest_digest: manifest_digest.clone(),
            layout_generation: template.layout_generation,
            state_sequence: 0,
            points: self.point_records()?,
            indexes: vec![
                PrivateOramAppendClientIndexCheckpointV2::Hnsw {
                    index_name: VECTOR_NAME.to_string(),
                    index_epoch: hnsw.epoch,
                    root_hash: hnsw.root_hash.clone(),
                    entry_node_id: Some(BASE64URL_NOPAD.encode(&hnsw.build.entry_node_id)),
                    state: hnsw.build.state.to_snapshot(self.tree_height)?,
                    records: self.hnsw_records(hnsw)?,
                },
                PrivateOramAppendClientIndexCheckpointV2::Result {
                    index_name: RESULT_INDEX_NAME.to_string(),
                    index_epoch: result.epoch,
                    root_hash: result.root_hash.clone(),
                    state: result.positions.to_snapshot(self.tree_height)?,
                    records: result_records(&result.blocks),
                },
            ],
        };
        let sealed =
            seal_private_oram_append_client_checkpoint_v2(&self.checkpoint_key, &checkpoint)?;
        let state = PrivateOramSignedStateV2 {
            version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
            collection_id: self.collection_id.clone(),
            manifest_digest,
            layout_generation: template.layout_generation,
            layout_digest: template.layout_digest,
            state_sequence: 0,
            indexes: vec![
                PrivateOramIndexStateV2 {
                    kind: PrivateOramIndexKindV2::Hnsw,
                    index_name: VECTOR_NAME.to_string(),
                    index_epoch: hnsw.epoch,
                    root_hash: hnsw.root_hash.clone(),
                    logical_count: hnsw.manifest.logical_node_count,
                    dummy_count: hnsw.manifest.dummy_node_count,
                    last_writeback_digest: writeback_digests[0].clone(),
                },
                PrivateOramIndexStateV2 {
                    kind: PrivateOramIndexKindV2::Result,
                    index_name: RESULT_INDEX_NAME.to_string(),
                    index_epoch: result.epoch,
                    root_hash: result.root_hash.clone(),
                    logical_count: result.manifest.logical_result_count,
                    dummy_count: result.manifest.dummy_result_count,
                    last_writeback_digest: writeback_digests[1].clone(),
                },
            ],
            client_state_digest: private_oram_append_client_checkpoint_v2_digest(&sealed)?,
            last_mutation_id: None,
            owner_signing_key_id: OWNER_SIGNING_KEY_ID.to_string(),
            signed_at_unix: CREATED_AT_UNIX + 1,
        };
        let encrypted_checkpoint = bind_private_oram_append_client_checkpoint_v2(sealed, &state)?;
        let manifest_bundle = PrivateOramImmutableManifestBundleV2 {
            signature: sign_private_oram_immutable_manifest_v2(&self.owner_key, &manifest)?,
            manifest,
        };
        let state_bundle = PrivateOramSignedStateBundleV2 {
            signature: sign_private_oram_signed_state_v2(&self.owner_key, &state)?,
            state,
        };
        let output = json!({
            "immutable_manifest": manifest_bundle,
            "genesis_state": state_bundle,
        });
        self.enrolled = Some(Enrolled {
            manifest_bundle,
            state_bundle,
            checkpoint,
            encrypted_checkpoint,
        });
        Ok(output)
    }

    fn open(&self) -> Result<Value, BoxError> {
        let enrolled = self.enrolled.as_ref().ok_or("enroll before open")?;
        Ok(json!({
            "client_id": CLIENT_ID,
            "vector_name": VECTOR_NAME,
            "mutation_id": random_base64url_32()?,
            "immutable_manifest": enrolled.manifest_bundle,
            "old_state": enrolled.state_bundle,
        }))
    }

    fn begin(&mut self, session: &Value) -> Result<Value, BoxError> {
        let enrolled = self.enrolled.as_ref().ok_or("enroll before begin")?;
        self.hnsw.as_ref().ok_or("build before begin")?;
        let session = Session::parse(session)?;
        let manifest = &enrolled.manifest_bundle.manifest;
        let fixed_read_path_count = manifest
            .indexes
            .first()
            .ok_or("the manifest has no index")?
            .capacity
            .fixed_append_read_path_count;

        // One new point: an HNSW node at level 0 and its payload in the result index.
        let node_id = random_bytes_32()?;
        let point_token = random_bytes_32()?;
        let payload_fetch_token = random_bytes_32()?;
        let hnsw_point = PrivateOramAppendLevel0PointV2 {
            node_id,
            point_token,
            visible_point_id: None,
            payload_fetch_token: Some(payload_fetch_token),
            vector: APPENDED_VECTOR.to_vec(),
            initial_leaf: random_leaf(self.tree_height)?,
        };
        // Every node is a candidate (see the read schedule chosen at enrollment).
        let hnsw_plan = PrivateOramAppendHnswTransactionPlanV2 {
            index_name: VECTOR_NAME.to_string(),
            mutation_id: session.mutation_id.clone(),
            writer_lease_digest: session.writer_lease_digest.clone(),
            writer_fence: session.writer_fence,
            paths_per_window: 1,
            candidate_node_ids: self.points.iter().map(|point| point.node_id).collect(),
            candidate_remap_leaves: random_leaves(self.points.len() as u32, self.tree_height)?,
            rewrite_remap_leaves: random_leaves(MAX_NEIGHBOR_REWRITES, self.tree_height)?,
            padding_leaves: random_leaves(fixed_read_path_count, self.tree_height)?,
        };
        let result_initial_leaf = random_leaf(self.tree_height)?;
        let result_point = PrivateOramAppendResultPointV2 {
            payload_fetch_token,
            point_token,
            payload: APPENDED_PAYLOAD.to_vec(),
            initial_leaf: result_initial_leaf,
        };
        let result_plan = PrivateOramAppendResultTransactionPlanV2 {
            index_name: RESULT_INDEX_NAME.to_string(),
            mutation_id: session.mutation_id.clone(),
            writer_lease_digest: session.writer_lease_digest.clone(),
            writer_fence: session.writer_fence,
            paths_per_window: 1,
            insert_eviction_leaf: (result_initial_leaf + 1) % (1 << self.tree_height),
            padding_leaves: random_leaves(fixed_read_path_count - 1, self.tree_height)?,
        };
        let hnsw_transaction = PrivateOramAppendHnswTransactionV2::begin(
            manifest,
            &enrolled.state_bundle.state,
            &enrolled.checkpoint,
            hnsw_point,
            hnsw_plan,
        )?;
        let result_transaction = PrivateOramAppendResultTransactionV2::begin(
            manifest,
            &enrolled.state_bundle.state,
            &enrolled.checkpoint,
            result_point,
            result_plan,
        )?;
        self.append = Some(Append {
            session,
            hnsw: Some(hnsw_transaction),
            result: Some(result_transaction),
            hnsw_output: None,
            result_output: None,
            pending: None,
            finalized: None,
        });
        let mut action = self.next_action()?;
        let mut sentinels = vec![RESOURCE_KEY.to_vec(), CHECKPOINT_KEY.to_vec()];
        for token in [node_id, point_token, payload_fetch_token] {
            sentinels.push(token.to_vec());
            sentinels.push(BASE64URL_NOPAD.encode(&token).into_bytes());
        }
        sentinels.push(
            APPENDED_VECTOR
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect(),
        );
        sentinels.push(APPENDED_PAYLOAD.to_vec());
        sentinels.push(BASE64URL_NOPAD.encode(APPENDED_PAYLOAD).into_bytes());
        action["plaintext_sentinels"] = json!(
            sentinels
                .iter()
                .map(|bytes| data_encoding::HEXLOWER.encode(bytes))
                .collect::<Vec<_>>()
        );
        Ok(action)
    }

    /// The next read window (HNSW windows first, then result windows) as a `read` body, or,
    /// once every window is verified, the finalized mutation as an `append` body.
    fn next_action(&mut self) -> Result<Value, BoxError> {
        let append = self.append.as_mut().ok_or("begin before reading")?;
        if let Some(transaction) = append.hnsw.as_mut() {
            if let Some(marker) = transaction.prepare_next_read_window()? {
                let window = transaction.next_read_window(&marker)?.window;
                append.pending = Some((PrivateOramIndexKindV2::Hnsw, window.sequence));
                return self.hnsw_read_body(window.paths);
            }
            let transaction = append.hnsw.take().ok_or("the HNSW transaction is gone")?;
            append.hnsw_output = Some(transaction.finalize()?);
        }
        if let Some(transaction) = append.result.as_mut() {
            if let Some(marker) = transaction.prepare_next_read_window()? {
                let window = transaction.next_read_window(&marker)?.window;
                append.pending = Some((PrivateOramIndexKindV2::Result, window.sequence));
                return self.result_read_body(&window.paths);
            }
            let transaction = append
                .result
                .take()
                .ok_or("the result transaction is gone")?;
            append.result_output = Some(transaction.finalize()?);
        }
        self.finalize_append()
    }

    fn hnsw_read_body(&self, paths: Vec<String>) -> Result<Value, BoxError> {
        let hnsw = self.hnsw.as_ref().ok_or("build before reading")?;
        let session = &self.append.as_ref().ok_or("begin before reading")?.session;
        let signature = sign_private_hnsw_oram_read_paths_for_manifest_context(
            &self.owner_key,
            &hnsw.manifest,
            session.hnsw_epoch,
            &session.hnsw_root_hash,
            &paths,
        )?;
        Ok(json!({"read": {
            "kind": "hnsw",
            "session_id": session.session_id,
            "padding": {"requested_paths": paths.len(), "dummy_paths_included": true},
            "paths": paths,
            "client_signature": signature,
        }}))
    }

    fn result_read_body(&self, paths: &[String]) -> Result<Value, BoxError> {
        let result = self.result.as_ref().ok_or("build before reading")?;
        let session = &self.append.as_ref().ok_or("begin before reading")?.session;
        let mut bucket_ids = Vec::new();
        for path in paths {
            let leaf = decode_private_result_oram_leaf_label(path, self.tree_height)?;
            bucket_ids.extend(private_result_oram_bucket_ids_for_leaf(
                leaf,
                self.tree_height,
            )?);
        }
        let signature = sign_private_result_oram_read_buckets(
            &self.owner_key,
            PrivateResultOramReadBucketsSignatureContext {
                collection_id: &self.collection_id,
                key_id: KEY_ID,
                rk_id: KEY_ID,
                rk_epoch: RK_EPOCH,
                signing_key_id: OWNER_SIGNING_KEY_ID,
            },
            session.result_epoch,
            &session.result_root_hash,
            result.manifest.bucket_count,
            &bucket_ids,
        )?;
        Ok(json!({"read": {
            "kind": "result",
            "session_id": session.session_id,
            "bucket_ids": bucket_ids,
            "read_signature": signature,
        }}))
    }

    /// Verifies the server's answer to the pending read window (Merkle proof against the
    /// session root, AEAD open of every bucket) and feeds it to that index's transaction.
    fn accept_read(&mut self, response: &Value) -> Result<(), BoxError> {
        let append = self.append.as_mut().ok_or("begin before reading")?;
        let (kind, sequence) = append.pending.take().ok_or("no read window is pending")?;
        // The mutation route wraps the index's read answer as `{"kind", "response"}`.
        let response = &response["response"];
        let index_epoch = u64_field(response, "index_epoch")?;
        let root_hash = str_field(response, "root_hash")?;
        let proof_value = str_field(&response["proof"], "value")?;
        match kind {
            PrivateOramIndexKindV2::Hnsw => {
                let hnsw = self.hnsw.as_ref().ok_or("build before reading")?;
                let batch = PrivateHnswEncryptedPathBatch {
                    index_epoch,
                    root_hash,
                    bucket_count: hnsw.manifest.bucket_count,
                    proof_value,
                    buckets: serde_json::from_value(response["buckets"].clone())?,
                };
                append
                    .hnsw
                    .as_mut()
                    .ok_or("the HNSW transaction is gone")?
                    .accept_verified_window(sequence, &hnsw.keys, &batch)?;
            }
            PrivateOramIndexKindV2::Result => {
                let result = self.result.as_ref().ok_or("build before reading")?;
                let batch = PrivateResultOramEncryptedBucketBatch {
                    index_epoch,
                    root_hash,
                    bucket_count: result.manifest.bucket_count,
                    proof_value,
                    buckets: serde_json::from_value(response["buckets"].clone())?,
                };
                append
                    .result
                    .as_mut()
                    .ok_or("the result transaction is gone")?
                    .accept_verified_window(sequence, &result.keys, &batch)?;
            }
        }
        Ok(())
    }

    fn finalize_append(&mut self) -> Result<Value, BoxError> {
        let enrolled = self.enrolled.as_ref().ok_or("enroll before appending")?;
        let append = self.append.as_mut().ok_or("begin before appending")?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let hnsw_output = append
            .hnsw_output
            .take()
            .ok_or("the HNSW reads are unfinished")?;
        let result_output = append
            .result_output
            .take()
            .ok_or("the result reads are unfinished")?;
        let session = &append.session;
        let finalized = finalize_private_oram_append_paired_mutation_v1(
            &self.checkpoint_key,
            &self.owner_key,
            PrivateOramAppendPairedFinalizationInputV1 {
                manifest_bundle: &enrolled.manifest_bundle,
                old_state_bundle: &enrolled.state_bundle,
                old_encrypted_checkpoint: &enrolled.encrypted_checkpoint,
                hnsw_output,
                result_output,
                // The mutation's validity window is exactly the session lease.
                issued_at_unix: session.issued_at_unix,
                expires_at_unix: session.lease_expires_unix,
                new_state_signed_at_unix: now_unix,
                validation: PrivateOramAppendPairedFinalizationContextV1 {
                    expected_collection_id: &self.collection_id,
                    expected_manifest_digest: &session.manifest_digest,
                    expected_owner_signing_key_id: OWNER_SIGNING_KEY_ID,
                    expected_layout_generation: enrolled.state_bundle.state.layout_generation,
                    expected_layout_digest: &enrolled.state_bundle.state.layout_digest,
                    expected_writer_lease_digest: &session.writer_lease_digest,
                    expected_writer_fence: session.writer_fence,
                    expected_state_sequence: enrolled.state_bundle.state.state_sequence,
                    expected_old_state_digest: &session.old_state_digest,
                    now_unix,
                    max_mutation_ttl_secs: session
                        .lease_expires_unix
                        .checked_sub(session.issued_at_unix)
                        .ok_or("the session lease ends before it starts")?,
                    public_key: self.owner_key.public_key().as_ref(),
                },
            },
        )?;
        let owner_prepare = project_private_oram_append_paired_owner_prepare_v1(&finalized)?;
        let written_ciphertext = finalized
            .hnsw_output
            .final_encrypted_buckets
            .first()
            .map(|bucket| bucket.ciphertext.clone())
            .ok_or("the append writes no HNSW bucket")?;
        let body = json!({
            "append": {
                "session_id": session.session_id,
                "owner_prepare": owner_prepare,
                "staged_insert_frame_b64": null,
            },
            "written_ciphertext": written_ciphertext,
        });
        append.finalized = Some(finalized);
        Ok(body)
    }

    /// Adopts the appended state and checkpoint as the client's current ones.
    fn open_next(&mut self) -> Result<Value, BoxError> {
        let finalized = self
            .append
            .take()
            .and_then(|append| append.finalized)
            .ok_or("append before open_next")?;
        let enrolled = self.enrolled.as_mut().ok_or("enroll before open_next")?;
        enrolled.state_bundle = finalized.mutation_bundle.mutation.new_state;
        enrolled.checkpoint = finalized.checkpoint;
        enrolled.encrypted_checkpoint = finalized.encrypted_checkpoint;
        self.open()
    }

    /// One point record per fixture point, ordered by point token bytes.
    fn point_records(&self) -> Result<Vec<PrivateOramAppendPointRecordV2>, BoxError> {
        let mut points = self.points.iter().collect::<Vec<_>>();
        points.sort_by_key(|point| point.point_token);
        points
            .into_iter()
            .map(|point| {
                let payload_fetch_token = point
                    .payload_fetch_token
                    .ok_or("every fixture point has a payload fetch token")?;
                Ok(PrivateOramAppendPointRecordV2 {
                    point_token: BASE64URL_NOPAD.encode(&point.point_token),
                    visible_point_id: None,
                    payload_fetch_token: Some(BASE64URL_NOPAD.encode(&payload_fetch_token)),
                })
            })
            .collect()
    }

    /// One HNSW record per fixture point, ordered by node id bytes, with the level mask and
    /// generation of the node's block in the plaintext build.
    fn hnsw_records(
        &self,
        hnsw: &HnswIndex,
    ) -> Result<Vec<PrivateOramAppendHnswRecordV2>, BoxError> {
        let blocks = hnsw
            .build
            .buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .chain(hnsw.build.state.to_snapshot(self.tree_height)?.stash.iter())
            .map(|block| (block.node_id, (block.level_mask, block.generation)))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut points = self.points.iter().collect::<Vec<_>>();
        points.sort_by_key(|point| point.node_id);
        points
            .into_iter()
            .map(|point| {
                let (level_mask, generation) = blocks
                    .get(&point.node_id)
                    .copied()
                    .ok_or("a fixture point has no HNSW block")?;
                Ok(PrivateOramAppendHnswRecordV2 {
                    node_id: BASE64URL_NOPAD.encode(&point.node_id),
                    point_token: BASE64URL_NOPAD.encode(&point.point_token),
                    level_mask,
                    generation,
                })
            })
            .collect()
    }
}

/// One result record per payload block, ordered by payload fetch token bytes.
fn result_records(
    blocks: &[PrivateResultOramPayloadBlockPlaintext],
) -> Vec<PrivateOramAppendResultRecordV2> {
    let mut blocks = blocks.iter().collect::<Vec<_>>();
    blocks.sort_by_key(|block| block.payload_fetch_token);
    blocks
        .into_iter()
        .map(|block| PrivateOramAppendResultRecordV2 {
            payload_fetch_token: BASE64URL_NOPAD.encode(&block.payload_fetch_token),
            point_token: BASE64URL_NOPAD.encode(&block.point_token),
            generation: block.generation,
        })
        .collect()
}

fn fixture_points() -> Vec<PrivateHnswBuildPoint> {
    vec![
        PrivateHnswBuildPoint {
            node_id: [1; 32],
            point_token: [11; 32],
            vector: vec![1.0, 0.0],
            payload_fetch_token: Some([101; 32]),
        },
        PrivateHnswBuildPoint {
            node_id: [2; 32],
            point_token: [22; 32],
            vector: vec![2.0, 0.0],
            payload_fetch_token: Some([102; 32]),
        },
        PrivateHnswBuildPoint {
            node_id: [3; 32],
            point_token: [33; 32],
            vector: vec![0.0, 1.0],
            payload_fetch_token: Some([103; 32]),
        },
    ]
}

impl Session {
    fn parse(value: &Value) -> Result<Self, BoxError> {
        let index = |kind: &str| {
            value["indexes"]
                .as_array()
                .and_then(|indexes| indexes.iter().find(|index| index["kind"] == kind))
                .ok_or("the session has no index of that kind")
        };
        let hnsw = index("hnsw")?;
        let result = index("result")?;
        Ok(Self {
            session_id: str_field(value, "session_id")?,
            mutation_id: str_field(value, "mutation_id")?,
            manifest_digest: str_field(value, "manifest_digest")?,
            old_state_digest: str_field(value, "old_state_digest")?,
            writer_lease_digest: str_field(value, "writer_lease_digest")?,
            writer_fence: u64_field(value, "writer_fence")?,
            issued_at_unix: u64_field(value, "issued_at_unix")?,
            lease_expires_unix: u64_field(value, "lease_expires_unix")?,
            hnsw_epoch: u64_field(hnsw, "index_epoch")?,
            hnsw_root_hash: str_field(hnsw, "root_hash")?,
            result_epoch: u64_field(result, "index_epoch")?,
            result_root_hash: str_field(result, "root_hash")?,
        })
    }
}

/// The error and every source under it, since the library errors redact their details.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

fn str_field(value: &Value, name: &str) -> Result<String, BoxError> {
    Ok(value[name]
        .as_str()
        .ok_or_else(|| format!("missing string field {name}"))?
        .to_string())
}

/// The V2 wire carries u64 values as decimal strings; plain numbers are accepted too.
fn u64_field(value: &Value, name: &str) -> Result<u64, BoxError> {
    match &value[name] {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
    .ok_or_else(|| format!("missing u64 field {name}").into())
}

fn random_bytes_32() -> Result<[u8; 32], BoxError> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "random generation failed")?;
    Ok(bytes)
}

fn random_base64url_32() -> Result<String, BoxError> {
    Ok(BASE64URL_NOPAD.encode(&random_bytes_32()?))
}

fn random_leaf(tree_height: u32) -> Result<u64, BoxError> {
    let mut bytes = [0_u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "random generation failed")?;
    Ok(u64::from_le_bytes(bytes) % (1 << tree_height))
}

fn random_leaves(count: u32, tree_height: u32) -> Result<Vec<u64>, BoxError> {
    (0..count).map(|_| random_leaf(tree_height)).collect()
}
