use std::collections::BTreeMap;
use std::env;
use std::io::{self, Read};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER,
    PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND, PRIVATE_HNSW_ORAM_V2_BINDING,
    PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AEAD_DOMAIN,
    PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_V2_VERSION, PRIVATE_ORAM_APPEND_MAX_MUTATION_TTL_SECS,
    PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION, PRIVATE_ORAM_APPEND_OWNER_PREPARE_V1_VERSION,
    PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION, PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
    PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PRIVATE_RESULT_ORAM_V2_BINDING,
    PrivateHnswBucketAeadBaseContext, PrivateHnswBucketAeadContext, PrivateHnswBuildPoint,
    PrivateHnswClientKeys, PrivateHnswCommitSignatureContext, PrivateHnswEncryptedPathBatch,
    PrivateHnswManifestBuildContext, PrivateHnswManifestValidationContext, PrivateHnswOramBucket,
    PrivateHnswOramClientConfig, PrivateHnswOramClientState, PrivateHnswOramClientStateSnapshot,
    PrivateHnswOramManifest, PrivateHnswOramReadPathsSignatureInput, PrivateHnswOramSignature,
    PrivateHnswParams, PrivateHnswSignatureVerification, PrivateHnswVectorEncoding,
    PrivateOramAppendBucketRefV1, PrivateOramAppendClientCheckpointV2,
    PrivateOramAppendClientIndexCheckpointV2, PrivateOramAppendHnswPreparedCommitDigestInputV4,
    PrivateOramAppendHnswRecordV2, PrivateOramAppendHnswTransactionOutputV2,
    PrivateOramAppendHnswTransactionPlanV2, PrivateOramAppendHnswTransactionV2,
    PrivateOramAppendLevel0PointV2, PrivateOramAppendMutationV1,
    PrivateOramAppendOwnerBucketBatchV1, PrivateOramAppendOwnerIndexPrepareV1,
    PrivateOramAppendOwnerPrepareV1, PrivateOramAppendOwnerPrepareValidationContextV1,
    PrivateOramAppendPointRecordV2, PrivateOramAppendReadTranscriptDigestInput,
    PrivateOramAppendReadWindowV1, PrivateOramAppendResultPointV2,
    PrivateOramAppendResultPreparedCommitDigestInputV4, PrivateOramAppendResultRecordV2,
    PrivateOramAppendResultTransactionOutputV2, PrivateOramAppendResultTransactionPlanV2,
    PrivateOramAppendResultTransactionV2, PrivateOramAppendTransactionError,
    PrivateOramAppendValidationContext, PrivateOramAppendWritebackDigestInput,
    PrivateOramEncryptedAppendClientCheckpointV2, PrivateOramExternalRecoveryCheckpoint,
    PrivateOramImmutableIndexParamsV2, PrivateOramImmutableIndexV2,
    PrivateOramImmutableManifestBundleV2, PrivateOramImmutableManifestV2,
    PrivateOramIndexCapacityV2, PrivateOramIndexKindV2, PrivateOramIndexStateV2,
    PrivateOramObservedReadTranscriptV1, PrivateOramPointOperationKindV1,
    PrivateOramRecoveryIndexKind, PrivateOramRecoveryIndexStateRef,
    PrivateOramSealedAppendClientCheckpointV2, PrivateOramServerReadEvidenceRecorderV1,
    PrivateOramSignatureVerification, PrivateOramSignedStateBundleV2, PrivateOramSignedStateV2,
    PrivateResultOramBucket, PrivateResultOramBucketAeadBaseContext,
    PrivateResultOramBucketAeadContext, PrivateResultOramBucketCommitmentContext,
    PrivateResultOramClientCommitBucketRef, PrivateResultOramClientConfig,
    PrivateResultOramClientKeys, PrivateResultOramClientState,
    PrivateResultOramClientStateAeadContext, PrivateResultOramClientStateSnapshot,
    PrivateResultOramClientStateSnapshotPadding, PrivateResultOramCommitPlan,
    PrivateResultOramCommitSignatureContext, PrivateResultOramEncryptedBucketBatch,
    PrivateResultOramManifest, PrivateResultOramManifestValidationContext,
    PrivateResultOramPayloadBlockPlaintext, PrivateResultOramReadBucketsSignatureContext,
    PrivateResultOramReadBucketsSignatureInput, PrivateResultOramSignature,
    PrivateResultOramSignatureVerification, ResultPrivacyMode, SecretKey,
    VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER, access_private_hnsw_oram_path,
    apply_private_oram_append_sparse_merkle_patch_v1,
    bind_private_oram_append_client_checkpoint_v2,
    build_private_hnsw_oram_manifest_from_encrypted_index,
    build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points,
    canonical_private_oram_recovery_index_state_digest, empty_private_result_oram_plaintext_bucket,
    encode_private_hnsw_oram_leaf_label, encode_private_result_oram_leaf_label,
    open_private_hnsw_oram_bucket, open_private_hnsw_oram_plaintext_bucket,
    open_private_hnsw_oram_verified_path_batch, open_private_oram_append_client_checkpoint_v2,
    open_private_result_oram_bucket, open_private_result_oram_plaintext_bucket,
    package_private_oram_append_mutation_v1, package_private_oram_external_recovery_checkpoint,
    package_private_oram_immutable_manifest_v2, package_private_oram_signed_state_v2,
    plan_private_hnsw_oram_commit_for_manifest, plan_private_hnsw_oram_commit_for_manifest_context,
    plan_private_oram_append_paired_checkpoint_delta_v2, private_hnsw_bucket_commitment,
    private_hnsw_oram_bucket_ids_for_leaf_labels, private_oram_append_client_checkpoint_v2_digest,
    private_oram_append_hnsw_prepared_commit_v4_digest, private_oram_append_mutation_v1_digest,
    private_oram_append_result_prepared_commit_v4_digest, private_oram_append_writeback_v1_digest,
    private_oram_immutable_manifest_v2_digest, private_oram_no_server_point_record_v1_digest,
    private_oram_signed_state_v2_digest, private_result_oram_bucket_commitment,
    private_result_oram_bucket_ids_for_leaf, private_result_oram_merkle_root_for_commitments,
    seal_private_hnsw_oram_plaintext_bucket, seal_private_hnsw_oram_plaintext_index,
    seal_private_result_oram_client_state_snapshot, seal_private_result_oram_plaintext_bucket,
    sign_private_hnsw_oram_commit, sign_private_hnsw_oram_manifest,
    sign_private_hnsw_oram_manifest_refresh,
    sign_private_hnsw_oram_read_paths_for_manifest_context, sign_private_result_oram_commit,
    sign_private_result_oram_manifest, sign_private_result_oram_manifest_refresh,
    sign_private_result_oram_read_buckets, validate_private_hnsw_oram_manifest,
    validate_private_hnsw_oram_read_paths_signature,
    validate_private_oram_append_client_checkpoint_v2,
    validate_private_oram_append_hnsw_transaction_output_v2,
    validate_private_oram_append_mutation_v1, validate_private_oram_append_owner_prepare_v1,
    validate_private_oram_append_result_transaction_output_v2,
    validate_private_oram_immutable_manifest_v2_signature,
    validate_private_oram_signed_state_v2_signature, validate_private_result_oram_manifest,
    validate_private_result_oram_read_buckets_signature,
    verify_private_result_oram_merkle_proof_json,
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VECTOR_NAME: &str = "text";
const KEY_ID: &str = "tenant-a/vector-private-rk";
const HNSW_SIGNING_KEY_ID: &str = "tenant-a/private-hnsw-signing-v1";
const RESULT_SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v1";
const RECOVERY_SIGNING_KEY_ID: &str = "tenant-a/private-oram-recovery-v1";
const MUTATION_V2_OWNER_SIGNING_KEY_ID: &str = "tenant-a/private-oram-owner-v2";
const MUTATION_V2_RESULT_INDEX_NAME: &str = "private-payload";
const MUTATION_V2_STDIN_MAX_BYTES: u64 = 4 * 1024 * 1024;
const MUTATION_V2_MANIFEST_NONCE_DOMAIN: &str =
    "qdrant-sec/private-oram-cluster-fixture-manifest-nonce/v2";
const MUTATION_V2_GENESIS_WRITEBACK_DOMAIN: &str =
    "qdrant-sec/private-oram-cluster-fixture-genesis-writeback/v2";
const MUTATION_V2_APPEND_NONCE_DOMAIN: &str =
    "qdrant-sec/private-oram-cluster-fixture-append-nonce/v2";
const MUTATION_V2_APPEND_CHECKPOINT_NONCE_DOMAIN: &str =
    "qdrant-sec/private-oram-cluster-fixture-append-checkpoint-nonce/v2";
const MUTATION_V2_APPEND_POINT_NODE_ID: [u8; 32] = [0xa1; 32];
const MUTATION_V2_APPEND_POINT_TOKEN: [u8; 32] = [0xa2; 32];
const MUTATION_V2_APPEND_FETCH_TOKEN: [u8; 32] = [0xa3; 32];
const MUTATION_V2_APPEND_PAYLOAD: &[u8] =
    br#"{"body":"qsec-v2-deterministic-private-oram-append"}"#;
const MUTATION_V2_APPEND_HNSW_BUCKET_AAD_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-bucket-aead/v1";
const MUTATION_V2_APPEND_RESULT_BUCKET_AAD_DOMAIN: &str =
    "qdrant-sec/private-result-oram-bucket-aead-context/v1";
const MUTATION_V2_APPEND_CHECKPOINT_KDF_CONTEXT_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-append-client-checkpoint-kdf-context/v2";
const MUTATION_V2_APPEND_CHECKPOINT_AAD_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-append-client-checkpoint-aad/v2";
const RK_EPOCH: u64 = 7;
const BASE_EPOCH: u64 = 42;
const NEXT_EPOCH: u64 = 43;
const SECOND_EPOCH: u64 = 44;
const PLAINTEXT_VECTOR_SENTINEL: [f32; 2] = [12345.125, -23456.25];
const PLAINTEXT_NODE_ID_SENTINEL: [u8; 32] = *b"qsec-v2-node-plaintext-7f3a9c1de";
const PLAINTEXT_POINT_TOKEN_SENTINEL: [u8; 32] = *b"qsec-v2-token-plaintext-82b4e6d9";
const PLAINTEXT_FETCH_TOKEN_SENTINEL: [u8; 32] = *b"qsec-v2-fetch-plaintext-19c5a7e2";
const CLIENT_RESOURCE_KEY_SENTINEL: [u8; 32] = *b"qsec-v2-client-rk-secret-4d8f2a6";
const PLAINTEXT_RESULT_PAYLOAD_SENTINEL: &[u8] =
    br#"{"body":"qsec-v2-private-result-payload-3f7a9c"}"#;
const CLIENT_RECOVERY_FETCH_TOKEN_SENTINEL: [u8; 32] = [0xd7; 32];
const CLIENT_RECOVERY_POINT_TOKEN_SENTINEL: [u8; 32] = [0xe3; 32];
const CLIENT_RECOVERY_PAYLOAD_SENTINEL: &[u8] = b"qsec-v2-client-recovery-state-payload-8d4c1a";

#[derive(Deserialize)]
struct HnswReadProofVerification {
    manifest: PrivateHnswOramManifest,
    expected_index_epoch: u64,
    expected_root_hash: String,
    response_index_epoch: u64,
    response_root_hash: String,
    leaf_labels: Vec<String>,
    bucket_count: u64,
    proof_value: String,
    buckets: Vec<PrivateHnswOramBucket>,
}

#[derive(Deserialize)]
struct ResultReadProofVerification {
    expected_index_epoch: u64,
    expected_root_hash: String,
    response_index_epoch: u64,
    response_root_hash: String,
    bucket_ids: Vec<u64>,
    bucket_count: u64,
    proof_value: String,
    buckets: Vec<PrivateResultOramBucket>,
}

#[derive(Deserialize)]
struct ReadProofVerificationRequest {
    hnsw: HnswReadProofVerification,
    result: ResultReadProofVerification,
}

#[derive(Deserialize)]
struct RecoveryCheckpointIndexKey {
    collection_id: String,
    index_kind: String,
    index_name: String,
}

#[derive(Deserialize)]
struct RecoveryCheckpointIndexState {
    index_epoch: u64,
    root_hash: String,
    writeback_digest: Option<String>,
}

#[derive(Deserialize)]
struct RecoveryCheckpointIndexBinding {
    key: RecoveryCheckpointIndexKey,
    state: RecoveryCheckpointIndexState,
}

#[derive(Deserialize)]
struct ExpectedRecoveryCheckpointIndex {
    index_kind: String,
    index_name: String,
    index_epoch: u64,
    root_hash: String,
    writeback_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryCheckpointSigningIntent {
    expected_collection_id: String,
    expected_committed_backup_generation: u64,
    requested_backup_generation: u64,
    expected_source_peer_id: u64,
    expected_source_shard_ids: Vec<u32>,
    expected_layout_generation: u64,
    expected_layout_digest: String,
    expected_owner_snapshot_authority_digest: String,
    expected_snapshot_size_bytes: u64,
    expected_snapshot_sha256: String,
    expected_client_recovery_state_digest: String,
    expected_owner_signing_key_id: String,
}

#[derive(Deserialize)]
struct RecoveryCheckpointSigningRequest {
    checkpoint: PrivateOramExternalRecoveryCheckpoint,
    index_states: Vec<RecoveryCheckpointIndexBinding>,
    expected_indexes: Vec<ExpectedRecoveryCheckpointIndex>,
    intent: RecoveryCheckpointSigningIntent,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2GenesisSigningRequest {
    collection_id: String,
    layout_generation: u64,
    layout_digest: String,
    client_state_digest: String,
    hnsw_manifest: PrivateHnswOramManifest,
    #[serde(default)]
    hnsw_manifest_signature: Option<PrivateHnswOramSignature>,
    result_manifest: PrivateResultOramManifest,
    #[serde(default)]
    result_manifest_signature: Option<PrivateResultOramSignature>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MutationV2HnswClientStateFixture {
    entry_node_id: String,
    snapshot: PrivateHnswOramClientStateSnapshot,
    records: Vec<PrivateOramAppendHnswRecordV2>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MutationV2ResultClientStateFixture {
    snapshot: PrivateResultOramClientStateSnapshot,
    records: Vec<PrivateOramAppendResultRecordV2>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2AppendFixtureContext {
    collection_id: String,
    hnsw_manifest: PrivateHnswOramManifest,
    hnsw_manifest_signature: PrivateHnswOramSignature,
    result_manifest: PrivateResultOramManifest,
    result_manifest_signature: PrivateResultOramSignature,
    hnsw_client_state: MutationV2HnswClientStateFixture,
    result_client_state: MutationV2ResultClientStateFixture,
    #[serde(default)]
    encrypted_client_checkpoint: Option<PrivateOramEncryptedAppendClientCheckpointV2>,
    immutable_manifest: PrivateOramImmutableManifestBundleV2,
    old_state: PrivateOramSignedStateBundleV2,
    open_response: MutationV2MutationOpenResponse,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2MutationOpenResponse {
    session_id: String,
    collection_id: String,
    vector_name: String,
    mutation_id: String,
    manifest_digest: String,
    old_state_digest: String,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    mutation_lease_generation: u64,
    writer_lease_digest: String,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    writer_fence: u64,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    issued_at_unix: u64,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    lease_expires_unix: u64,
    indexes: Vec<MutationV2MutationOpenIndex>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2MutationOpenIndex {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    read_session_id: String,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    index_epoch: u64,
    root_hash: String,
    paths_per_window: u32,
    tree_height: u32,
    fixed_append_read_path_count: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2AppendReadPlanRequest {
    context: MutationV2AppendFixtureContext,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2AppendFinalizeRequest {
    context: MutationV2AppendFixtureContext,
    read_responses: Vec<MutationV2AppendReadResponse>,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum MutationV2AppendReadResponse {
    Hnsw {
        sequence: u32,
        response: MutationV2HnswReadResponse,
    },
    Result {
        sequence: u32,
        response: MutationV2ResultReadResponse,
    },
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2HnswReadResponse {
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    index_epoch: u64,
    root_hash: String,
    buckets: Vec<MutationV2WireHnswBucket>,
    proof: MutationV2ReadProof,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2ResultReadResponse {
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    index_epoch: u64,
    root_hash: String,
    buckets: Vec<MutationV2WireResultBucket>,
    proof: MutationV2ReadProof,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2ReadProof {
    kind: String,
    value: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2WireHnswBucket {
    version: u16,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    bucket_id: u64,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    index_epoch: u64,
    ciphertext: String,
    ciphertext_sha256: String,
    bucket_commitment: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationV2WireResultBucket {
    version: u16,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    bucket_id: u64,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    index_epoch: u64,
    ciphertext: String,
    ciphertext_sha256: String,
    bucket_commitment: String,
}

impl From<MutationV2WireHnswBucket> for PrivateHnswOramBucket {
    fn from(bucket: MutationV2WireHnswBucket) -> Self {
        Self {
            version: bucket.version,
            bucket_id: bucket.bucket_id,
            index_epoch: bucket.index_epoch,
            ciphertext: bucket.ciphertext,
            ciphertext_sha256: bucket.ciphertext_sha256,
            bucket_commitment: bucket.bucket_commitment,
        }
    }
}

impl From<MutationV2WireResultBucket> for PrivateResultOramBucket {
    fn from(bucket: MutationV2WireResultBucket) -> Self {
        Self {
            version: bucket.version,
            bucket_id: bucket.bucket_id,
            index_epoch: bucket.index_epoch,
            ciphertext: bucket.ciphertext,
            ciphertext_sha256: bucket.ciphertext_sha256,
            bucket_commitment: bucket.bucket_commitment,
        }
    }
}

struct MutationV2AppendMaterials {
    checkpoint: PrivateOramAppendClientCheckpointV2,
    hnsw_point: PrivateOramAppendLevel0PointV2,
    result_point: PrivateOramAppendResultPointV2,
    hnsw_plan: PrivateOramAppendHnswTransactionPlanV2,
    result_plan: PrivateOramAppendResultTransactionPlanV2,
    hnsw_windows: Vec<PrivateOramAppendReadWindowV1>,
    result_windows: Vec<PrivateOramAppendReadWindowV1>,
    hnsw_open_index: MutationV2MutationOpenIndex,
    result_open_index: MutationV2MutationOpenIndex,
}

#[derive(Clone, Copy)]
struct HnswFixtureOptions<'a> {
    owner_signing_key_id: &'a str,
    logical_node_count: usize,
    dummy_node_count: Option<u64>,
    include_client_state: bool,
}

#[derive(Clone, Copy)]
struct ResultFixtureOptions<'a> {
    owner_signing_key_id: &'a str,
    logical_result_count: usize,
    dummy_result_count: u64,
    include_client_state: bool,
    include_recovery_stash: bool,
}

#[derive(Clone, Copy)]
struct FixtureProfile {
    tree_height: u32,
    hnsw_block_size_bytes: usize,
    result_block_size_bytes: u32,
}

impl FixtureProfile {
    const DEFAULT: Self = Self {
        tree_height: 2,
        hnsw_block_size_bytes: 4096,
        result_block_size_bytes: 1024,
    };

    const LARGE: Self = Self {
        tree_height: 5,
        hnsw_block_size_bytes: 65536,
        result_block_size_bytes: 32768,
    };
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let first_arg = args.next().ok_or(
        "usage: private_oram_cluster_fixture <stable-collection-uuid> \
             [default|large] [private_payload_oram_required|ids_visible] | verify-read-proofs | \
             sign-recovery-checkpoint | build-mutation-v2 <stable-collection-uuid> \
             [default|large] [logical-capacity] | sign-mutation-v2-genesis | plan-mutation-v2-append | \
             finalize-mutation-v2-append",
    )?;
    if first_arg == "verify-read-proofs" {
        if args.next().is_some() {
            return Err("verify-read-proofs received unexpected arguments".into());
        }
        return verify_read_proofs_from_stdin();
    }
    if first_arg == "sign-recovery-checkpoint" {
        if args.next().is_some() {
            return Err("sign-recovery-checkpoint received unexpected arguments".into());
        }
        return sign_recovery_checkpoint_from_stdin();
    }
    if first_arg == "build-mutation-v2" {
        let collection_id = args
            .next()
            .ok_or("build-mutation-v2 requires a stable collection UUID")?;
        let profile = match args.next().as_deref() {
            None | Some("default") => FixtureProfile::DEFAULT,
            Some("large") => FixtureProfile::LARGE,
            Some(_) => return Err("fixture profile must be default or large".into()),
        };
        let logical_capacity = match args.next() {
            None => 2,
            Some(value) => value
                .parse::<u64>()
                .ok()
                .filter(|capacity| (2..=8).contains(capacity))
                .ok_or("mutation V2 fixture logical capacity must be between 2 and 8")?,
        };
        if args.next().is_some() {
            return Err("build-mutation-v2 received unexpected arguments".into());
        }
        return build_mutation_v2_fixture(&collection_id, profile, logical_capacity);
    }
    if first_arg == "sign-mutation-v2-genesis" {
        if args.next().is_some() {
            return Err("sign-mutation-v2-genesis received unexpected arguments".into());
        }
        return sign_mutation_v2_genesis_from_stdin();
    }
    if first_arg == "plan-mutation-v2-append" {
        if args.next().is_some() {
            return Err("plan-mutation-v2-append received unexpected arguments".into());
        }
        return plan_mutation_v2_append_from_stdin();
    }
    if first_arg == "finalize-mutation-v2-append" {
        if args.next().is_some() {
            return Err("finalize-mutation-v2-append received unexpected arguments".into());
        }
        return finalize_mutation_v2_append_from_stdin();
    }
    let collection_id = first_arg;
    if collection_id.is_empty() {
        return Err("stable collection UUID must be non-empty".into());
    }
    let profile = match args.next().as_deref() {
        None | Some("default") => FixtureProfile::DEFAULT,
        Some("large") => FixtureProfile::LARGE,
        Some(_) => return Err("fixture profile must be default or large".into()),
    };
    let result_privacy = match args.next().as_deref() {
        None | Some("private_payload_oram_required") => {
            ResultPrivacyMode::PrivatePayloadOramRequired
        }
        Some("ids_visible") => ResultPrivacyMode::IdsVisible,
        Some(_) => {
            return Err(
                "fixture result privacy must be private_payload_oram_required or ids_visible"
                    .into(),
            );
        }
    };
    if args.next().is_some() {
        return Err("private ORAM fixture received unexpected arguments".into());
    }

    let hnsw_signing_key = Ed25519KeyPair::from_seed_unchecked(&[7; 32])
        .map_err(|_| std::io::Error::other("failed to create HNSW fixture signing key"))?;
    let result_signing_key = Ed25519KeyPair::from_seed_unchecked(&[9; 32])
        .map_err(|_| std::io::Error::other("failed to create result fixture signing key"))?;
    let recovery_signing_key = Ed25519KeyPair::from_seed_unchecked(&[11; 32])
        .map_err(|_| std::io::Error::other("failed to create recovery fixture signing key"))?;
    let hnsw = hnsw_fixture(
        &collection_id,
        &hnsw_signing_key,
        profile,
        result_privacy,
        HnswFixtureOptions {
            owner_signing_key_id: HNSW_SIGNING_KEY_ID,
            logical_node_count: 3,
            dummy_node_count: None,
            include_client_state: false,
        },
    )?;
    let result = result_fixture(
        &collection_id,
        &result_signing_key,
        profile,
        ResultFixtureOptions {
            owner_signing_key_id: RESULT_SIGNING_KEY_ID,
            logical_result_count: 3,
            dummy_result_count: 1,
            include_client_state: false,
            include_recovery_stash: true,
        },
    )?;
    let client_recovery_state_base64url = result["client_recovery_state_base64url"]
        .as_str()
        .ok_or("fixture result client recovery state is missing")?;
    let encrypted_client_state_ciphertext = result["encrypted_client_state"]["ciphertext"]
        .as_str()
        .ok_or("fixture encrypted client-state ciphertext is missing")?;
    let encrypted_client_state_ciphertext_sha256 =
        result["encrypted_client_state"]["ciphertext_sha256"]
            .as_str()
            .ok_or("fixture encrypted client-state ciphertext hash is missing")?;

    let output = json!({
        "hnsw_public_key": BASE64URL_NOPAD.encode(hnsw_signing_key.public_key().as_ref()),
        "result_public_key": BASE64URL_NOPAD.encode(result_signing_key.public_key().as_ref()),
        "recovery_public_key": BASE64URL_NOPAD.encode(recovery_signing_key.public_key().as_ref()),
        "plaintext_leakage_sentinels": plaintext_leakage_sentinels(
            client_recovery_state_base64url,
            encrypted_client_state_ciphertext,
            encrypted_client_state_ciphertext_sha256,
        ),
        "hnsw": hnsw,
        "result": result,
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn build_mutation_v2_fixture(
    collection_id: &str,
    profile: FixtureProfile,
    logical_capacity: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if collection_id.is_empty() {
        return Err("stable collection UUID must be non-empty".into());
    }
    let owner_key = mutation_v2_owner_key()?;
    let recovery_signing_key = Ed25519KeyPair::from_seed_unchecked(&[11; 32])
        .map_err(|_| "failed to initialize recovery signing key")?;
    let hnsw = hnsw_fixture(
        collection_id,
        &owner_key,
        profile,
        ResultPrivacyMode::PrivatePayloadOramRequired,
        HnswFixtureOptions {
            owner_signing_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
            logical_node_count: 1,
            dummy_node_count: Some(logical_capacity - 1),
            include_client_state: true,
        },
    )?;
    let result = result_fixture(
        collection_id,
        &owner_key,
        profile,
        ResultFixtureOptions {
            owner_signing_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
            logical_result_count: 1,
            dummy_result_count: logical_capacity - 1,
            include_client_state: true,
            include_recovery_stash: false,
        },
    )?;
    let hnsw_manifest: PrivateHnswOramManifest = serde_json::from_value(hnsw["manifest"].clone())?;
    let hnsw_manifest_signature: PrivateHnswOramSignature =
        serde_json::from_value(hnsw["manifest_signature"].clone())?;
    let result_manifest: PrivateResultOramManifest =
        serde_json::from_value(result["manifest"].clone())?;
    let result_manifest_signature: PrivateResultOramSignature =
        serde_json::from_value(result["manifest_signature"].clone())?;
    validate_mutation_v2_physical_pair(
        collection_id,
        &hnsw_manifest,
        &hnsw_manifest_signature,
        &result_manifest,
        &result_manifest_signature,
        owner_key.public_key().as_ref(),
    )?;

    let profile_name = if profile.tree_height == FixtureProfile::LARGE.tree_height {
        "large"
    } else {
        "default"
    };
    let fixture_contract_digest = deterministic_fixture_digest(
        MUTATION_V2_MANIFEST_NONCE_DOMAIN,
        &[
            b"build-mutation-v2",
            collection_id.as_bytes(),
            profile_name.as_bytes(),
            MUTATION_V2_OWNER_SIGNING_KEY_ID.as_bytes(),
            &logical_capacity.to_be_bytes(),
        ],
    )?;
    let owner_public_key = BASE64URL_NOPAD.encode(owner_key.public_key().as_ref());
    let output = json!({
        "mode": "mutation_v2",
        "collection_id": collection_id,
        "vector_name": VECTOR_NAME,
        "profile": profile_name,
        "logical_capacity": logical_capacity,
        "owner_signing_key_id": MUTATION_V2_OWNER_SIGNING_KEY_ID,
        "owner_public_key": owner_public_key,
        "hnsw_public_key": owner_public_key,
        "result_public_key": owner_public_key,
        "recovery_public_key": BASE64URL_NOPAD.encode(recovery_signing_key.public_key().as_ref()),
        "client_resource_key_base64url": BASE64URL_NOPAD.encode(&CLIENT_RESOURCE_KEY_SENTINEL),
        "fixture_contract_digest": fixture_contract_digest,
        "hnsw": hnsw,
        "result": result,
        "self_check": {
            "physical_pair_valid": true,
            "shared_owner_key": true,
            "shared_owner_signing_key_id": true,
        },
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn sign_mutation_v2_genesis_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = Vec::new();
    io::stdin()
        .take(MUTATION_V2_STDIN_MAX_BYTES + 1)
        .read_to_end(&mut encoded)?;
    if u64::try_from(encoded.len())? > MUTATION_V2_STDIN_MAX_BYTES {
        return Err("sign-mutation-v2-genesis input exceeds 4 MiB".into());
    }
    let request: MutationV2GenesisSigningRequest = serde_json::from_slice(&encoded)?;
    if request.layout_generation != 1 {
        return Err("mutation V2 genesis layout_generation must be 1".into());
    }
    for (field, value) in [
        ("layout_digest", request.layout_digest.as_str()),
        ("client_state_digest", request.client_state_digest.as_str()),
    ] {
        let decoded = BASE64URL_NOPAD
            .decode(value.as_bytes())
            .map_err(|_| format!("mutation V2 genesis {field} is not canonical base64url"))?;
        if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != value {
            return Err(format!("mutation V2 genesis {field} must encode exactly 32 bytes").into());
        }
    }

    let owner_key = mutation_v2_owner_key()?;
    let hnsw_manifest_signature = match &request.hnsw_manifest_signature {
        Some(signature) => signature.clone(),
        None => sign_private_hnsw_oram_manifest(&owner_key, &request.hnsw_manifest)?,
    };
    let result_manifest_signature = match &request.result_manifest_signature {
        Some(signature) => signature.clone(),
        None => sign_private_result_oram_manifest(&owner_key, &request.result_manifest)?,
    };
    validate_mutation_v2_physical_pair(
        &request.collection_id,
        &request.hnsw_manifest,
        &hnsw_manifest_signature,
        &request.result_manifest,
        &result_manifest_signature,
        owner_key.public_key().as_ref(),
    )?;

    let capacity_for = |oram: &OramParams,
                        bucket_count: u64,
                        logical_count: u64,
                        dummy_count: u64|
     -> Result<PrivateOramIndexCapacityV2, Box<dyn std::error::Error>> {
        let logical_capacity = logical_count
            .checked_add(dummy_count)
            .ok_or("mutation V2 logical capacity overflow")?;
        let physical_slots = bucket_count
            .checked_mul(u64::from(oram.bucket_size))
            .ok_or("mutation V2 physical capacity overflow")?;
        let reserved_physical_slots = physical_slots
            .checked_sub(logical_capacity)
            .filter(|reserved| *reserved > 0)
            .ok_or("mutation V2 fixture requires reserved physical slots")?;
        let minimum_read_paths = u32::try_from(logical_capacity)?
            .checked_add(1)
            .ok_or("mutation V2 read path budget overflow")?;
        let read_batches = minimum_read_paths.div_ceil(oram.path_batch_size);
        let fixed_append_read_path_count = read_batches
            .checked_mul(oram.path_batch_size)
            .ok_or("mutation V2 read path budget overflow")?;
        let fixed_append_write_bucket_count = fixed_append_read_path_count
            .checked_mul(
                oram.tree_height
                    .checked_add(1)
                    .ok_or("mutation V2 tree height overflow")?,
            )
            .ok_or("mutation V2 write bucket budget overflow")?;
        Ok(PrivateOramIndexCapacityV2 {
            bucket_count,
            logical_capacity,
            reserved_physical_slots,
            max_client_stash_blocks: u32::try_from(reserved_physical_slots)?,
            fixed_append_read_path_count,
            fixed_append_write_bucket_count,
        })
    };
    let hnsw_capacity = capacity_for(
        &request.hnsw_manifest.oram,
        request.hnsw_manifest.bucket_count,
        request.hnsw_manifest.logical_node_count,
        request.hnsw_manifest.dummy_node_count,
    )?;
    let result_capacity = capacity_for(
        &request.result_manifest.oram,
        request.result_manifest.bucket_count,
        request.result_manifest.logical_result_count,
        request.result_manifest.dummy_result_count,
    )?;

    let hnsw_manifest_json = serde_json::to_vec(&request.hnsw_manifest)?;
    let result_manifest_json = serde_json::to_vec(&request.result_manifest)?;
    let manifest_nonce = deterministic_fixture_digest(
        MUTATION_V2_MANIFEST_NONCE_DOMAIN,
        &[
            request.collection_id.as_bytes(),
            &hnsw_manifest_json,
            &result_manifest_json,
        ],
    )?;
    let immutable_manifest = PrivateOramImmutableManifestV2 {
        version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
        collection_id: request.collection_id.clone(),
        manifest_nonce,
        indexes: vec![
            PrivateOramImmutableIndexV2 {
                index_name: request.hnsw_manifest.vector_name.clone(),
                params: PrivateOramImmutableIndexParamsV2::Hnsw {
                    provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                    binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                    key_id: request.hnsw_manifest.key_id.clone(),
                    rk_id: request.hnsw_manifest.rk_id.clone(),
                    rk_epoch: request.hnsw_manifest.rk_epoch,
                    dim: request.hnsw_manifest.dim,
                    vector_encoding: PrivateHnswVectorEncoding::F32Le,
                    distance: request.hnsw_manifest.distance,
                    hnsw: request.hnsw_manifest.hnsw.clone(),
                    oram: request.hnsw_manifest.oram.clone(),
                    fixed_search_budget: request.hnsw_manifest.fixed_budget.clone(),
                    max_neighbor_rewrites: 1,
                },
                capacity: hnsw_capacity,
            },
            PrivateOramImmutableIndexV2 {
                index_name: MUTATION_V2_RESULT_INDEX_NAME.to_string(),
                params: PrivateOramImmutableIndexParamsV2::Result {
                    provider: PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
                    binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
                    key_id: request.result_manifest.key_id.clone(),
                    rk_id: request.result_manifest.rk_id.clone(),
                    rk_epoch: request.result_manifest.rk_epoch,
                    oram: request.result_manifest.oram.clone(),
                },
                capacity: result_capacity,
            },
        ],
        result_privacy: request.hnsw_manifest.result_privacy,
        owner_signing_key_id: request.hnsw_manifest.owner_signing_key_id.clone(),
        created_at_unix: request.hnsw_manifest.created_at_unix,
    };
    let immutable_manifest =
        package_private_oram_immutable_manifest_v2(&owner_key, immutable_manifest)?;
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&immutable_manifest.manifest)?;

    let hnsw_writeback_context = serde_json::to_vec(&json!({
        "kind": "hnsw",
        "index_name": request.hnsw_manifest.vector_name,
        "index_epoch": request.hnsw_manifest.index_epoch,
        "root_hash": request.hnsw_manifest.root_hash,
        "logical_count": request.hnsw_manifest.logical_node_count,
        "dummy_count": request.hnsw_manifest.dummy_node_count,
    }))?;
    let result_writeback_context = serde_json::to_vec(&json!({
        "kind": "result",
        "index_name": MUTATION_V2_RESULT_INDEX_NAME,
        "index_epoch": request.result_manifest.index_epoch,
        "root_hash": request.result_manifest.root_hash,
        "logical_count": request.result_manifest.logical_result_count,
        "dummy_count": request.result_manifest.dummy_result_count,
    }))?;
    let hnsw_writeback_digest = deterministic_fixture_digest(
        MUTATION_V2_GENESIS_WRITEBACK_DOMAIN,
        &[request.collection_id.as_bytes(), &hnsw_writeback_context],
    )?;
    let result_writeback_digest = deterministic_fixture_digest(
        MUTATION_V2_GENESIS_WRITEBACK_DOMAIN,
        &[request.collection_id.as_bytes(), &result_writeback_context],
    )?;
    let genesis_state = PrivateOramSignedStateV2 {
        version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        collection_id: request.collection_id.clone(),
        manifest_digest: manifest_digest.clone(),
        layout_generation: request.layout_generation,
        layout_digest: request.layout_digest.clone(),
        state_sequence: 0,
        indexes: vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: request.hnsw_manifest.vector_name.clone(),
                index_epoch: request.hnsw_manifest.index_epoch,
                root_hash: request.hnsw_manifest.root_hash.clone(),
                logical_count: request.hnsw_manifest.logical_node_count,
                dummy_count: request.hnsw_manifest.dummy_node_count,
                last_writeback_digest: hnsw_writeback_digest.clone(),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: MUTATION_V2_RESULT_INDEX_NAME.to_string(),
                index_epoch: request.result_manifest.index_epoch,
                root_hash: request.result_manifest.root_hash.clone(),
                logical_count: request.result_manifest.logical_result_count,
                dummy_count: request.result_manifest.dummy_result_count,
                last_writeback_digest: result_writeback_digest.clone(),
            },
        ],
        client_state_digest: request.client_state_digest.clone(),
        last_mutation_id: None,
        owner_signing_key_id: request.hnsw_manifest.owner_signing_key_id.clone(),
        signed_at_unix: request.hnsw_manifest.created_at_unix,
    };
    let genesis_state = package_private_oram_signed_state_v2(&owner_key, genesis_state)?;
    let genesis_state_digest = private_oram_signed_state_v2_digest(&genesis_state.state)?;

    let verification = PrivateOramSignatureVerification {
        expected_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
        public_key: owner_key.public_key().as_ref(),
    };
    validate_private_oram_immutable_manifest_v2_signature(
        &immutable_manifest.manifest,
        Some(&immutable_manifest.signature),
        verification,
    )?;
    validate_private_oram_signed_state_v2_signature(
        &genesis_state.state,
        Some(&genesis_state.signature),
        verification,
    )?;

    let rest_enroll_body = json!({
        "vector_name": request.hnsw_manifest.vector_name,
        "immutable_manifest": immutable_manifest,
        "genesis_state": genesis_state,
    });
    let output = json!({
        "owner_signing_key_id": MUTATION_V2_OWNER_SIGNING_KEY_ID,
        "owner_public_key": BASE64URL_NOPAD.encode(owner_key.public_key().as_ref()),
        "manifest_digest": manifest_digest,
        "immutable_manifest_digest": manifest_digest,
        "genesis_state_digest": genesis_state_digest,
        "signed_state_digest": genesis_state_digest,
        "layout_digest": request.layout_digest,
        "client_state_digest": request.client_state_digest,
        "genesis_writeback_digests": {
            "hnsw": hnsw_writeback_digest,
            "result": result_writeback_digest,
        },
        "rest_enroll_body": rest_enroll_body,
        "self_check": {
            "physical_pair_valid": true,
            "immutable_manifest_signature_valid": true,
            "genesis_state_signature_valid": true,
            "state_sequence": 0,
        },
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn plan_mutation_v2_append_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let request: MutationV2AppendReadPlanRequest =
        read_mutation_v2_stdin("plan-mutation-v2-append")?;
    let materials = validate_mutation_v2_append_context(&request.context)?;
    let owner_key = mutation_v2_owner_key()?;
    let owner_public_key = owner_key.public_key().as_ref();
    let mut rest_read_requests = Vec::with_capacity(6);

    for window in &materials.hnsw_windows {
        let signature = sign_private_hnsw_oram_read_paths_for_manifest_context(
            &owner_key,
            &request.context.hnsw_manifest,
            materials.hnsw_open_index.index_epoch,
            &materials.hnsw_open_index.root_hash,
            &window.paths,
        )?;
        let path_refs = window.paths.iter().map(String::as_str).collect::<Vec<_>>();
        validate_private_hnsw_oram_read_paths_signature(
            PrivateHnswOramReadPathsSignatureInput {
                collection_id: &request.context.hnsw_manifest.collection_id,
                vector_name: &request.context.hnsw_manifest.vector_name,
                key_id: &request.context.hnsw_manifest.key_id,
                rk_id: &request.context.hnsw_manifest.rk_id,
                rk_epoch: request.context.hnsw_manifest.rk_epoch,
                index_epoch: materials.hnsw_open_index.index_epoch,
                root_hash: &materials.hnsw_open_index.root_hash,
                paths: &path_refs,
                requested_paths: materials.hnsw_open_index.paths_per_window,
                dummy_paths_included: true,
                signature_alg: &signature.alg,
                signature_key_id: &signature.key_id,
            },
            &signature.sig,
            PrivateHnswSignatureVerification {
                expected_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
                public_key: owner_public_key,
            },
        )?;
        rest_read_requests.push(json!({
            "kind": "hnsw",
            "sequence": window.sequence,
            "read_session_id": materials.hnsw_open_index.read_session_id,
            "rest_read_body": {
                "kind": "hnsw",
                "session_id": request.context.open_response.session_id,
                "paths": window.paths,
                "padding": {
                    "requested_paths": materials.hnsw_open_index.paths_per_window,
                    "dummy_paths_included": true,
                },
                "client_signature": signature,
            },
        }));
    }

    for window in &materials.result_windows {
        let leaf = decode_fixture_leaf_label(&window.paths[0])?;
        let bucket_ids = private_result_oram_bucket_ids_for_leaf(
            leaf,
            request.context.result_manifest.oram.tree_height,
        )?;
        let signature = sign_private_result_oram_read_buckets(
            &owner_key,
            PrivateResultOramReadBucketsSignatureContext {
                collection_id: &request.context.result_manifest.collection_id,
                key_id: &request.context.result_manifest.key_id,
                rk_id: &request.context.result_manifest.rk_id,
                rk_epoch: request.context.result_manifest.rk_epoch,
                signing_key_id: &request.context.result_manifest.owner_signing_key_id,
            },
            materials.result_open_index.index_epoch,
            &materials.result_open_index.root_hash,
            request.context.result_manifest.bucket_count,
            &bucket_ids,
        )?;
        validate_private_result_oram_read_buckets_signature(
            PrivateResultOramReadBucketsSignatureInput {
                collection_id: &request.context.result_manifest.collection_id,
                key_id: &request.context.result_manifest.key_id,
                rk_id: &request.context.result_manifest.rk_id,
                rk_epoch: request.context.result_manifest.rk_epoch,
                index_epoch: materials.result_open_index.index_epoch,
                root_hash: &materials.result_open_index.root_hash,
                bucket_count: request.context.result_manifest.bucket_count,
                bucket_ids: &bucket_ids,
                signature_alg: &signature.alg,
                signature_key_id: &signature.key_id,
            },
            &signature.sig,
            PrivateResultOramSignatureVerification {
                expected_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
                public_key: owner_public_key,
            },
        )?;
        rest_read_requests.push(json!({
            "kind": "result",
            "sequence": window.sequence,
            "read_session_id": materials.result_open_index.read_session_id,
            "rest_read_body": {
                "kind": "result",
                "session_id": request.context.open_response.session_id,
                "bucket_ids": bucket_ids.iter().map(u64::to_string).collect::<Vec<_>>(),
                "read_signature": signature,
            },
        }));
    }

    let encoded_requests = serde_json::to_vec(&rest_read_requests)?;
    let read_plan_digest = deterministic_fixture_digest(
        MUTATION_V2_APPEND_NONCE_DOMAIN,
        &[
            b"read-plan",
            request.context.open_response.mutation_id.as_bytes(),
            &encoded_requests,
        ],
    )?;
    let output = json!({
        "collection_id": request.context.collection_id,
        "vector_name": VECTOR_NAME,
        "session_id": request.context.open_response.session_id,
        "mutation_id": request.context.open_response.mutation_id,
        "read_plan_digest": read_plan_digest,
        "fixed_read_budget": {
            "hnsw_paths": materials.hnsw_windows.len(),
            "result_paths": materials.result_windows.len(),
            "paths_per_window": 1,
        },
        "rest_read_requests": rest_read_requests,
        "self_check": {
            "physical_manifest_signatures_valid": true,
            "v2_manifest_and_state_signatures_valid": true,
            "client_state_digest_valid": true,
            "read_signatures_valid": true,
        },
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn finalize_mutation_v2_append_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let request: MutationV2AppendFinalizeRequest =
        read_mutation_v2_stdin("finalize-mutation-v2-append")?;
    let materials = validate_mutation_v2_append_context(&request.context)?;
    if request.read_responses.len() != materials.hnsw_windows.len() + materials.result_windows.len()
    {
        return Err("mutation V2 append read response count mismatch".into());
    }

    let immutable = &request.context.immutable_manifest.manifest;
    let old_state = &request.context.old_state.state;
    let hnsw_keys = PrivateHnswClientKeys::derive_from_resource_key_with_context(
        &SecretKey::from_bytes(CLIENT_RESOURCE_KEY_SENTINEL),
        &request.context.collection_id,
        &request.context.hnsw_manifest.vector_name,
        &request.context.hnsw_manifest.key_id,
        request.context.hnsw_manifest.rk_epoch,
    )?;
    let result_keys = PrivateResultOramClientKeys::derive_from_resource_key_with_context(
        &SecretKey::from_bytes(CLIENT_RESOURCE_KEY_SENTINEL),
        &request.context.collection_id,
        &request.context.result_manifest.rk_id,
        request.context.result_manifest.rk_epoch,
    )?;
    let mut hnsw_transaction = PrivateOramAppendHnswTransactionV2::begin(
        immutable,
        old_state,
        &materials.checkpoint,
        materials.hnsw_point.clone(),
        materials.hnsw_plan.clone(),
    )
    .map_err(|_| "mutation V2 append HNSW transaction begin failed")?;
    let mut result_transaction = PrivateOramAppendResultTransactionV2::begin(
        immutable,
        old_state,
        &materials.checkpoint,
        materials.result_point.clone(),
        materials.result_plan.clone(),
    )
    .map_err(|_| "mutation V2 append result transaction begin failed")?;
    let mut responses = request.read_responses.iter();

    for expected in &materials.hnsw_windows {
        let marker = hnsw_transaction
            .prepare_next_read_window()
            .map_err(|_| "mutation V2 append HNSW read preparation failed")?
            .ok_or("mutation V2 append HNSW transaction ended before its fixed budget")?;
        let read = hnsw_transaction
            .next_read_window(&marker)
            .map_err(|_| "mutation V2 append HNSW read projection failed")?;
        if read.window != *expected {
            return Err("mutation V2 append HNSW transaction read schedule mismatch".into());
        }
        let Some(MutationV2AppendReadResponse::Hnsw { sequence, response }) = responses.next()
        else {
            return Err("mutation V2 append HNSW read response order mismatch".into());
        };
        if *sequence != expected.sequence
            || response.proof.kind != PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND
        {
            return Err("mutation V2 append HNSW read response context mismatch".into());
        }
        let batch = PrivateHnswEncryptedPathBatch {
            index_epoch: response.index_epoch,
            root_hash: response.root_hash.clone(),
            bucket_count: request.context.hnsw_manifest.bucket_count,
            proof_value: response.proof.value.clone(),
            buckets: response
                .buckets
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
        };
        if old_state.state_sequence != 0 && expected.sequence == 0 {
            let config = PrivateHnswOramClientConfig {
                tree_height: request.context.hnsw_manifest.oram.tree_height,
                bucket_size: usize::try_from(request.context.hnsw_manifest.oram.bucket_size)?,
                block_size_bytes: usize::try_from(
                    request.context.hnsw_manifest.oram.block_size_bytes,
                )?,
                fixed_neighbor_slots: usize::try_from(
                    request.context.hnsw_manifest.hnsw.fixed_neighbor_slots,
                )?,
            };
            let base_context = PrivateHnswBucketAeadBaseContext {
                collection_id: &request.context.collection_id,
                vector_name: &request.context.hnsw_manifest.vector_name,
                key_id: &request.context.hnsw_manifest.key_id,
                rk_id: &request.context.hnsw_manifest.rk_id,
                rk_epoch: request.context.hnsw_manifest.rk_epoch,
            };
            let opened = open_private_hnsw_oram_verified_path_batch(
                &hnsw_keys,
                base_context,
                config,
                batch.index_epoch,
                &batch.root_hash,
                batch.bucket_count,
                &batch.proof_value,
                &batch.buckets,
            )?;
            let mut state = PrivateHnswOramClientState::from_snapshot(
                &request.context.hnsw_client_state.snapshot,
            )?;
            let candidate_id = materials.hnsw_plan.candidate_node_ids[0];
            let access = access_private_hnsw_oram_path(
                &mut state,
                config,
                candidate_id,
                &opened,
                materials.hnsw_plan.candidate_remap_leaves[0],
            )?;
            let record = request
                .context
                .hnsw_client_state
                .records
                .iter()
                .find(|record| {
                    decode_base64url_32_fixture(&record.node_id, "node_id")
                        .is_ok_and(|node_id| node_id == candidate_id)
                })
                .ok_or("mutation V2 append diagnostic candidate record is missing")?;
            let point = materials
                .checkpoint
                .points
                .iter()
                .find(|point| point.point_token == record.point_token)
                .ok_or("mutation V2 append diagnostic point record is missing")?;
            if access.block.deleted {
                return Err("mutation V2 append diagnostic candidate is deleted".into());
            }
            if record.point_token != BASE64URL_NOPAD.encode(&access.block.point_token) {
                return Err("mutation V2 append diagnostic candidate point token mismatch".into());
            }
            if record.level_mask != access.block.level_mask {
                return Err("mutation V2 append diagnostic candidate level mask mismatch".into());
            }
            if record.generation != access.block.generation {
                return Err("mutation V2 append diagnostic candidate generation mismatch".into());
            }
            if point.payload_fetch_token
                != access
                    .block
                    .payload_fetch_token
                    .map(|token| BASE64URL_NOPAD.encode(&token))
            {
                return Err(
                    "mutation V2 append diagnostic candidate payload token mismatch".into(),
                );
            }
            if access.block.neighbors.iter().any(|neighbor| {
                !request
                    .context
                    .hnsw_client_state
                    .records
                    .iter()
                    .any(|record| {
                        decode_base64url_32_fixture(&record.node_id, "node_id")
                            .is_ok_and(|node_id| node_id == *neighbor)
                    })
            }) {
                return Err("mutation V2 append diagnostic candidate neighbor mismatch".into());
            }
        }
        hnsw_transaction
            .accept_verified_window(*sequence, &hnsw_keys, &batch)
            .map_err(|error| match error {
                PrivateOramAppendTransactionError::Client(error) => {
                    format!("mutation V2 append HNSW verified read acceptance failed: {error:?}")
                }
                error => {
                    format!("mutation V2 append HNSW verified read acceptance failed: {error:?}")
                }
            })?;
    }
    if hnsw_transaction
        .prepare_next_read_window()
        .map_err(|_| "mutation V2 append HNSW fixed-budget completion failed")?
        .is_some()
    {
        return Err("mutation V2 append HNSW transaction exceeded its fixed budget".into());
    }

    for expected in &materials.result_windows {
        let marker = result_transaction
            .prepare_next_read_window()
            .map_err(|_| "mutation V2 append result read preparation failed")?
            .ok_or("mutation V2 append result transaction ended before its fixed budget")?;
        let read = result_transaction
            .next_read_window(&marker)
            .map_err(|_| "mutation V2 append result read projection failed")?;
        if read.window != *expected {
            return Err("mutation V2 append result transaction read schedule mismatch".into());
        }
        let Some(MutationV2AppendReadResponse::Result { sequence, response }) = responses.next()
        else {
            return Err("mutation V2 append result read response order mismatch".into());
        };
        if *sequence != expected.sequence
            || response.proof.kind != PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND
        {
            return Err("mutation V2 append result read response context mismatch".into());
        }
        let batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: response.index_epoch,
            root_hash: response.root_hash.clone(),
            bucket_count: request.context.result_manifest.bucket_count,
            proof_value: response.proof.value.clone(),
            buckets: response
                .buckets
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
        };
        result_transaction
            .accept_verified_window(*sequence, &result_keys, &batch)
            .map_err(|error| match error {
                PrivateOramAppendTransactionError::Result(error) => {
                    format!(
                        "mutation V2 append result verified read acceptance failed at sequence {sequence}: {error:?}"
                    )
                }
                error => {
                    format!(
                        "mutation V2 append result verified read acceptance failed at sequence {sequence}: {error:?}"
                    )
                }
            })?;
    }
    if responses.next().is_some()
        || result_transaction
            .prepare_next_read_window()
            .map_err(|_| "mutation V2 append result fixed-budget completion failed")?
            .is_some()
    {
        return Err("mutation V2 append result transaction exceeded its fixed budget".into());
    }

    let mut hnsw_output = hnsw_transaction
        .finalize()
        .map_err(|_| "mutation V2 append HNSW transaction finalization failed")?;
    let mut result_output = result_transaction
        .finalize()
        .map_err(|_| "mutation V2 append result transaction finalization failed")?;
    normalize_hnsw_append_output(
        immutable,
        &hnsw_keys,
        &request.context.open_response.mutation_id,
        &mut hnsw_output,
    )?;
    normalize_result_append_output(
        immutable,
        &result_keys,
        &request.context.open_response.mutation_id,
        &mut result_output,
    )?;
    let delta = plan_private_oram_append_paired_checkpoint_delta_v2(
        immutable,
        old_state,
        &materials.checkpoint,
        &hnsw_output,
        &result_output,
    )
    .map_err(|_| "mutation V2 append paired checkpoint transition failed")?;
    let owner_key = mutation_v2_owner_key()?;
    let mut refreshed_hnsw_manifest = request.context.hnsw_manifest.clone();
    refreshed_hnsw_manifest.index_epoch = hnsw_output.new_epoch;
    refreshed_hnsw_manifest.root_hash = hnsw_output.new_root_hash.clone();
    refreshed_hnsw_manifest.logical_node_count = refreshed_hnsw_manifest
        .logical_node_count
        .checked_add(1)
        .ok_or("mutation V2 append HNSW logical count overflow")?;
    refreshed_hnsw_manifest.dummy_node_count = refreshed_hnsw_manifest
        .dummy_node_count
        .checked_sub(1)
        .ok_or("mutation V2 append HNSW dummy capacity exhausted")?;
    let refreshed_hnsw_manifest_signature =
        sign_private_hnsw_oram_manifest(&owner_key, &refreshed_hnsw_manifest)?;
    let mut refreshed_result_manifest = request.context.result_manifest.clone();
    refreshed_result_manifest.index_epoch = result_output.new_epoch;
    refreshed_result_manifest.root_hash = result_output.new_root_hash.clone();
    refreshed_result_manifest.logical_result_count = refreshed_result_manifest
        .logical_result_count
        .checked_add(1)
        .ok_or("mutation V2 append result logical count overflow")?;
    refreshed_result_manifest.dummy_result_count = refreshed_result_manifest
        .dummy_result_count
        .checked_sub(1)
        .ok_or("mutation V2 append result dummy capacity exhausted")?;
    let refreshed_result_manifest_signature =
        sign_private_result_oram_manifest(&owner_key, &refreshed_result_manifest)?;
    let checkpoint_key = SecretKey::from_bytes(CLIENT_RESOURCE_KEY_SENTINEL);
    let sealed_checkpoint = seal_deterministic_append_checkpoint(
        &checkpoint_key,
        delta.checkpoint(),
        &request.context.open_response.mutation_id,
    )?;
    let client_state_digest = private_oram_append_client_checkpoint_v2_digest(&sealed_checkpoint)?;
    if client_state_digest == old_state.client_state_digest {
        return Err("mutation V2 append client state did not advance".into());
    }
    let new_state = PrivateOramSignedStateV2 {
        version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        collection_id: old_state.collection_id.clone(),
        manifest_digest: old_state.manifest_digest.clone(),
        layout_generation: old_state.layout_generation,
        layout_digest: old_state.layout_digest.clone(),
        state_sequence: old_state
            .state_sequence
            .checked_add(1)
            .ok_or("mutation V2 append state sequence overflow")?,
        indexes: delta.next_indexes().to_vec(),
        client_state_digest,
        last_mutation_id: Some(delta.mutation_id().to_string()),
        owner_signing_key_id: old_state.owner_signing_key_id.clone(),
        signed_at_unix: request
            .context
            .open_response
            .issued_at_unix
            .max(old_state.signed_at_unix),
    };
    validate_private_oram_append_client_checkpoint_v2(delta.checkpoint(), immutable, &new_state)?;
    let new_state_bundle = package_private_oram_signed_state_v2(&owner_key, new_state)?;
    let next_signed_state = new_state_bundle.clone();
    let encrypted_checkpoint =
        bind_private_oram_append_client_checkpoint_v2(sealed_checkpoint, &new_state_bundle.state)?;
    let reopened = open_private_oram_append_client_checkpoint_v2(
        &checkpoint_key,
        &encrypted_checkpoint,
        immutable,
        &new_state_bundle.state,
    )?;
    if reopened != *delta.checkpoint() {
        return Err("mutation V2 append checkpoint round-trip mismatch".into());
    }

    let manifest_digest = private_oram_immutable_manifest_v2_digest(immutable)?;
    let old_state_digest = private_oram_signed_state_v2_digest(old_state)?;
    let issued_at_unix = request.context.open_response.issued_at_unix;
    let expires_at_unix = request.context.open_response.lease_expires_unix.min(
        issued_at_unix
            .checked_add(PRIVATE_ORAM_APPEND_MAX_MUTATION_TTL_SECS)
            .ok_or("mutation V2 append expiry overflow")?,
    );
    if expires_at_unix <= issued_at_unix {
        return Err("mutation V2 append lease is too short".into());
    }
    let observed_read_transcripts = vec![
        hnsw_output.read_transcript.clone(),
        result_output.read_transcript.clone(),
    ];
    let mutation = PrivateOramAppendMutationV1 {
        version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
        mutation_id: request.context.open_response.mutation_id.clone(),
        collection_id: request.context.collection_id.clone(),
        manifest_digest: manifest_digest.clone(),
        layout_generation: old_state.layout_generation,
        writer_lease_digest: request.context.open_response.writer_lease_digest.clone(),
        writer_fence: request.context.open_response.writer_fence,
        issued_at_unix,
        expires_at_unix,
        old_state: request.context.old_state.clone(),
        new_state: new_state_bundle,
        point_operation_kind: PrivateOramPointOperationKindV1::NoServerPointRecord,
        point_operation_digest: private_oram_no_server_point_record_v1_digest(
            &request.context.collection_id,
            &manifest_digest,
            &request.context.open_response.mutation_id,
        )?,
        writebacks: vec![
            hnsw_output.writeback.clone(),
            result_output.writeback.clone(),
        ],
        owner_signing_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID.to_string(),
    };
    let mutation_bundle = package_private_oram_append_mutation_v1(&owner_key, mutation)?;
    let validation = PrivateOramAppendValidationContext {
        expected_collection_id: &request.context.collection_id,
        expected_manifest_digest: &manifest_digest,
        expected_owner_signing_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
        expected_layout_generation: old_state.layout_generation,
        expected_layout_digest: &old_state.layout_digest,
        expected_writer_lease_digest: &request.context.open_response.writer_lease_digest,
        expected_writer_fence: request.context.open_response.writer_fence,
        expected_state_sequence: old_state.state_sequence,
        expected_old_state_digest: &old_state_digest,
        expected_visible_point_record: None,
        observed_read_transcripts: &observed_read_transcripts,
        now_unix: issued_at_unix,
        max_mutation_ttl_secs: PRIVATE_ORAM_APPEND_MAX_MUTATION_TTL_SECS,
        public_key: owner_key.public_key().as_ref(),
    };
    validate_private_oram_append_mutation_v1(
        &request.context.immutable_manifest,
        &mutation_bundle,
        validation,
    )?;
    let owner_prepare = PrivateOramAppendOwnerPrepareV1 {
        version: PRIVATE_ORAM_APPEND_OWNER_PREPARE_V1_VERSION,
        mutation_bundle,
        indexes: vec![
            PrivateOramAppendOwnerIndexPrepareV1 {
                index_name: hnsw_output.writeback.index_name.clone(),
                ordered_encrypted_buckets: PrivateOramAppendOwnerBucketBatchV1::Hnsw(
                    hnsw_output.ordered_encrypted_buckets.clone(),
                ),
                merkle_patch_proof: hnsw_output.merkle_patch_proof.clone(),
            },
            PrivateOramAppendOwnerIndexPrepareV1 {
                index_name: result_output.writeback.index_name.clone(),
                ordered_encrypted_buckets: PrivateOramAppendOwnerBucketBatchV1::Result(
                    result_output.ordered_encrypted_buckets.clone(),
                ),
                merkle_patch_proof: result_output.merkle_patch_proof.clone(),
            },
        ],
    };
    validate_fixture_owner_prepare(
        &request.context,
        &owner_prepare,
        &observed_read_transcripts,
        &manifest_digest,
        &old_state_digest,
        issued_at_unix,
        owner_key.public_key().as_ref(),
    )?;

    let mutation_digest =
        private_oram_append_mutation_v1_digest(&owner_prepare.mutation_bundle.mutation)?;
    let mut rest_append_body = json!({
        "session_id": request.context.open_response.session_id,
        "owner_prepare": owner_prepare,
        "staged_insert_frame_b64": null,
    });
    encode_mutation_v2_wire_u64_fields(&mut rest_append_body)?;
    let append_body_bytes = serde_json::to_vec(&rest_append_body)?;
    let append_body_digest = BASE64URL_NOPAD.encode(Sha256::digest(&append_body_bytes).as_ref());
    let output = json!({
        "collection_id": request.context.collection_id,
        "vector_name": VECTOR_NAME,
        "session_id": request.context.open_response.session_id,
        "mutation_id": request.context.open_response.mutation_id,
        "mutation_digest": mutation_digest,
        "append_body_digest": append_body_digest,
        "new_state_digest": private_oram_signed_state_v2_digest(
            &owner_prepare.mutation_bundle.mutation.new_state.state,
        )?,
        "next_signed_state": next_signed_state,
        "next_client_checkpoint": delta.checkpoint(),
        "encrypted_client_checkpoint": encrypted_checkpoint,
        "manifest_refresh": {
            "hnsw": {
                "manifest": refreshed_hnsw_manifest,
                "signature": refreshed_hnsw_manifest_signature,
            },
            "result": {
                "manifest": refreshed_result_manifest,
                "signature": refreshed_result_manifest_signature,
            },
        },
        "rest_append_body": rest_append_body,
        "self_check": {
            "fixed_hnsw_read_budget": materials.hnsw_windows.len(),
            "fixed_result_read_budget": materials.result_windows.len(),
            "read_proofs_and_ciphertexts_valid": true,
            "transaction_outputs_valid": true,
            "new_state_signature_valid": true,
            "manifest_refresh_signatures_valid": true,
            "mutation_signature_valid": true,
            "owner_prepare_valid": true,
            "checkpoint_round_trip_valid": true,
            "deterministic_fixture_writeback": true,
        },
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn validate_mutation_v2_append_context(
    context: &MutationV2AppendFixtureContext,
) -> Result<MutationV2AppendMaterials, Box<dyn std::error::Error>> {
    let owner_key = mutation_v2_owner_key()?;
    let owner_public_key = owner_key.public_key().as_ref();
    validate_mutation_v2_physical_pair(
        &context.collection_id,
        &context.hnsw_manifest,
        &context.hnsw_manifest_signature,
        &context.result_manifest,
        &context.result_manifest_signature,
        owner_public_key,
    )?;
    let signature_verification = PrivateOramSignatureVerification {
        expected_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
        public_key: owner_public_key,
    };
    validate_private_oram_immutable_manifest_v2_signature(
        &context.immutable_manifest.manifest,
        Some(&context.immutable_manifest.signature),
        signature_verification,
    )?;
    validate_private_oram_signed_state_v2_signature(
        &context.old_state.state,
        Some(&context.old_state.signature),
        signature_verification,
    )?;

    let immutable = &context.immutable_manifest.manifest;
    let old_state = &context.old_state.state;
    let manifest_digest = private_oram_immutable_manifest_v2_digest(immutable)?;
    let old_state_digest = private_oram_signed_state_v2_digest(old_state)?;
    if immutable.collection_id != context.collection_id
        || immutable.owner_signing_key_id != MUTATION_V2_OWNER_SIGNING_KEY_ID
        || immutable.result_privacy != ResultPrivacyMode::PrivatePayloadOramRequired
        || immutable.created_at_unix != context.hnsw_manifest.created_at_unix
        || old_state.collection_id != context.collection_id
        || old_state.manifest_digest != manifest_digest
        || old_state.owner_signing_key_id != MUTATION_V2_OWNER_SIGNING_KEY_ID
        || (old_state.state_sequence == 0) != old_state.last_mutation_id.is_none()
    {
        return Err("mutation V2 append immutable manifest or old state mismatch".into());
    }
    validate_mutation_v2_append_index_mapping(context)?;

    let mut hnsw_records = context
        .hnsw_client_state
        .records
        .iter()
        .cloned()
        .map(|record| {
            Ok((
                decode_base64url_32_fixture(&record.node_id, "hnsw_record.node_id")?,
                record,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    hnsw_records.sort_by_key(|(node_id, _)| *node_id);
    let hnsw_records = hnsw_records
        .into_iter()
        .map(|(_, record)| record)
        .collect::<Vec<_>>();
    let mut result_records = context
        .result_client_state
        .records
        .iter()
        .cloned()
        .map(|record| {
            Ok((
                decode_base64url_32_fixture(
                    &record.payload_fetch_token,
                    "result_record.payload_fetch_token",
                )?,
                record,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    result_records.sort_by_key(|(payload_fetch_token, _)| *payload_fetch_token);
    let result_records = result_records
        .into_iter()
        .map(|(_, record)| record)
        .collect::<Vec<_>>();
    let result_by_point = result_records
        .iter()
        .map(|record| {
            (
                record.point_token.clone(),
                record.payload_fetch_token.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if result_by_point.len() != result_records.len() || hnsw_records.len() != result_records.len() {
        return Err("mutation V2 append client records are duplicated or incomplete".into());
    }
    let points = hnsw_records
        .iter()
        .map(|record| {
            let payload_fetch_token = result_by_point
                .get(&record.point_token)
                .ok_or("mutation V2 append client record point-token mismatch")?;
            Ok(PrivateOramAppendPointRecordV2 {
                point_token: record.point_token.clone(),
                visible_point_id: None,
                payload_fetch_token: Some(payload_fetch_token.clone()),
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let mut points = points
        .into_iter()
        .map(|record| {
            Ok((
                decode_base64url_32_fixture(&record.point_token, "point.point_token")?,
                record,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    points.sort_by_key(|(point_token, _)| *point_token);
    let points = points
        .into_iter()
        .map(|(_, record)| record)
        .collect::<Vec<_>>();
    let checkpoint = PrivateOramAppendClientCheckpointV2 {
        version: PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_V2_VERSION,
        collection_id: context.collection_id.clone(),
        manifest_digest: manifest_digest.clone(),
        layout_generation: old_state.layout_generation,
        state_sequence: old_state.state_sequence,
        points,
        indexes: vec![
            PrivateOramAppendClientIndexCheckpointV2::Hnsw {
                index_name: context.hnsw_manifest.vector_name.clone(),
                index_epoch: old_state.indexes[0].index_epoch,
                root_hash: old_state.indexes[0].root_hash.clone(),
                entry_node_id: Some(context.hnsw_client_state.entry_node_id.clone()),
                state: context.hnsw_client_state.snapshot.clone(),
                records: hnsw_records.clone(),
            },
            PrivateOramAppendClientIndexCheckpointV2::Result {
                index_name: MUTATION_V2_RESULT_INDEX_NAME.to_string(),
                index_epoch: old_state.indexes[1].index_epoch,
                root_hash: old_state.indexes[1].root_hash.clone(),
                state: context.result_client_state.snapshot.clone(),
                records: result_records,
            },
        ],
    };
    validate_private_oram_append_client_checkpoint_v2(&checkpoint, immutable, old_state)?;
    match (
        old_state.state_sequence,
        context.encrypted_client_checkpoint.as_ref(),
    ) {
        (0, None) => {
            let expected_client_state_digest = mutation_v2_client_fixture_digest(
                &context.hnsw_client_state,
                &context.result_client_state,
            )?;
            if old_state.client_state_digest != expected_client_state_digest {
                return Err("mutation V2 append genesis client state digest mismatch".into());
            }
        }
        (0, Some(_)) | (_, None) => {
            return Err("mutation V2 append client checkpoint generation mismatch".into());
        }
        (_, Some(encrypted_checkpoint)) => {
            let expected_state_digest = private_oram_signed_state_v2_digest(old_state)?;
            let expected_client_state_digest =
                private_oram_append_client_checkpoint_v2_digest(&encrypted_checkpoint.sealed)?;
            if encrypted_checkpoint.state_digest != expected_state_digest {
                return Err("mutation V2 append encrypted checkpoint state digest mismatch".into());
            }
            if encrypted_checkpoint.sealed.collection_id != old_state.collection_id
                || encrypted_checkpoint.sealed.manifest_digest != old_state.manifest_digest
                || encrypted_checkpoint.sealed.layout_generation != old_state.layout_generation
                || encrypted_checkpoint.sealed.state_sequence != old_state.state_sequence
                || expected_client_state_digest != old_state.client_state_digest
            {
                return Err(
                    "mutation V2 append encrypted checkpoint state binding mismatch".into(),
                );
            }
            let checkpoint_key = SecretKey::from_bytes(CLIENT_RESOURCE_KEY_SENTINEL);
            let opened_checkpoint = open_private_oram_append_client_checkpoint_v2(
                &checkpoint_key,
                encrypted_checkpoint,
                immutable,
                old_state,
            )?;
            if opened_checkpoint != checkpoint {
                return Err("mutation V2 append encrypted client checkpoint mismatch".into());
            }
        }
    }

    validate_base64url_32_fixture(&context.open_response.mutation_id, "mutation_id")?;
    validate_base64url_32_fixture(
        &context.open_response.writer_lease_digest,
        "writer_lease_digest",
    )?;
    if context.open_response.collection_id != context.collection_id
        || context.open_response.vector_name != VECTOR_NAME
        || context.open_response.manifest_digest != manifest_digest
        || context.open_response.old_state_digest != old_state_digest
        || context.open_response.session_id.is_empty()
        || context.open_response.mutation_lease_generation == 0
        || context.open_response.writer_fence == 0
        || context.open_response.issued_at_unix >= context.open_response.lease_expires_unix
        || context.open_response.indexes.len() != 2
    {
        return Err("mutation V2 append open response mismatch".into());
    }
    let hnsw_open_index = context
        .open_response
        .indexes
        .iter()
        .find(|index| index.kind == PrivateOramIndexKindV2::Hnsw)
        .cloned()
        .ok_or("mutation V2 append open response has no HNSW index")?;
    let result_open_index = context
        .open_response
        .indexes
        .iter()
        .find(|index| index.kind == PrivateOramIndexKindV2::Result)
        .cloned()
        .ok_or("mutation V2 append open response has no result index")?;
    for (open, state, immutable_index, tree_height) in [
        (
            &hnsw_open_index,
            &old_state.indexes[0],
            &immutable.indexes[0],
            context.hnsw_manifest.oram.tree_height,
        ),
        (
            &result_open_index,
            &old_state.indexes[1],
            &immutable.indexes[1],
            context.result_manifest.oram.tree_height,
        ),
    ] {
        if open.index_name != state.index_name
            || open.index_epoch != state.index_epoch
            || open.root_hash != state.root_hash
            || open.paths_per_window != 1
            || open.tree_height != tree_height
            || open.fixed_append_read_path_count
                != immutable_index.capacity.fixed_append_read_path_count
            || open.read_session_id.is_empty()
        {
            return Err("mutation V2 append open index contract mismatch".into());
        }
    }

    if hnsw_records.is_empty() {
        return Err("mutation V2 append requires an existing HNSW candidate".into());
    }
    let candidate_node_ids = hnsw_records
        .iter()
        .map(|candidate| decode_base64url_32_fixture(&candidate.node_id, "candidate_node_id"))
        .collect::<Result<Vec<_>, _>>()?;
    let candidate_leaf_labels = hnsw_records
        .iter()
        .map(|candidate| {
            context
                .hnsw_client_state
                .snapshot
                .positions
                .iter()
                .find(|position| position.node_id == candidate.node_id)
                .map(|position| position.leaf_label.clone())
                .ok_or("mutation V2 append candidate is missing from the position map")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let candidate_remap_leaves = [2, 1, 0, 3]
        .into_iter()
        .cycle()
        .take(candidate_node_ids.len())
        .collect::<Vec<_>>();
    let sequence_byte = u8::try_from(old_state.state_sequence)
        .map_err(|_| "mutation V2 append fixture state sequence is too large")?;
    let node_id = [MUTATION_V2_APPEND_POINT_NODE_ID[0]
        .checked_add(sequence_byte)
        .ok_or("mutation V2 append node id overflow")?; 32];
    let point_token = [MUTATION_V2_APPEND_POINT_TOKEN[0]
        .checked_add(sequence_byte)
        .ok_or("mutation V2 append point token overflow")?; 32];
    let payload_fetch_token = [MUTATION_V2_APPEND_FETCH_TOKEN[0]
        .checked_add(sequence_byte)
        .ok_or("mutation V2 append payload token overflow")?; 32];
    let mut payload = MUTATION_V2_APPEND_PAYLOAD.to_vec();
    if old_state.state_sequence != 0 {
        payload.extend_from_slice(&old_state.state_sequence.to_be_bytes());
    }
    let hnsw_point = PrivateOramAppendLevel0PointV2 {
        node_id,
        point_token,
        visible_point_id: None,
        payload_fetch_token: Some(payload_fetch_token),
        vector: vec![0.5, 0.5],
        initial_leaf: 3,
    };
    let result_point = PrivateOramAppendResultPointV2 {
        payload_fetch_token,
        point_token,
        payload,
        initial_leaf: 3,
    };
    let hnsw_plan = PrivateOramAppendHnswTransactionPlanV2 {
        index_name: VECTOR_NAME.to_string(),
        mutation_id: context.open_response.mutation_id.clone(),
        writer_lease_digest: context.open_response.writer_lease_digest.clone(),
        writer_fence: context.open_response.writer_fence,
        paths_per_window: 1,
        candidate_node_ids,
        candidate_remap_leaves: candidate_remap_leaves.clone(),
        rewrite_remap_leaves: vec![0],
        padding_leaves: [0, 1, 2, 3]
            .into_iter()
            .cycle()
            .take(usize::try_from(
                immutable.indexes[0].capacity.fixed_append_read_path_count,
            )?)
            .collect(),
    };
    let result_plan = PrivateOramAppendResultTransactionPlanV2 {
        index_name: MUTATION_V2_RESULT_INDEX_NAME.to_string(),
        mutation_id: context.open_response.mutation_id.clone(),
        writer_lease_digest: context.open_response.writer_lease_digest.clone(),
        writer_fence: context.open_response.writer_fence,
        paths_per_window: 1,
        insert_eviction_leaf: 0,
        padding_leaves: [1, 2, 0, 3]
            .into_iter()
            .cycle()
            .take(usize::try_from(
                immutable.indexes[1].capacity.fixed_append_read_path_count - 1,
            )?)
            .collect(),
    };
    let mut hnsw_window_leaves = candidate_leaf_labels;
    let rewrite_candidate_id = if old_state.state_sequence == 0 {
        *hnsw_plan
            .candidate_node_ids
            .first()
            .ok_or("mutation V2 append candidate schedule is empty")?
    } else {
        MUTATION_V2_APPEND_POINT_NODE_ID
    };
    let rewrite_candidate_offset = hnsw_plan
        .candidate_node_ids
        .iter()
        .position(|candidate_id| *candidate_id == rewrite_candidate_id)
        .ok_or("mutation V2 append rewrite candidate is missing")?;
    let rewrite_leaf = *candidate_remap_leaves
        .get(rewrite_candidate_offset)
        .ok_or("mutation V2 append candidate remap schedule is incomplete")?;
    hnsw_window_leaves.push(encode_private_hnsw_oram_leaf_label(
        rewrite_leaf,
        context.hnsw_manifest.oram.tree_height,
    )?);
    let fixed_hnsw_read_count =
        usize::try_from(immutable.indexes[0].capacity.fixed_append_read_path_count)?;
    // The insert evicts along the first padding leaf; the point's position stays private.
    for padding_leaf in hnsw_plan.padding_leaves.iter().copied() {
        if hnsw_window_leaves.len() == fixed_hnsw_read_count {
            break;
        }
        hnsw_window_leaves.push(encode_private_hnsw_oram_leaf_label(
            padding_leaf,
            context.hnsw_manifest.oram.tree_height,
        )?);
    }
    if hnsw_window_leaves.len() != fixed_hnsw_read_count {
        return Err("mutation V2 append HNSW fixture schedule is incomplete".into());
    }
    let hnsw_windows = hnsw_window_leaves
        .into_iter()
        .enumerate()
        .map(|(sequence, leaf)| {
            Ok(PrivateOramAppendReadWindowV1 {
                sequence: u32::try_from(sequence)?,
                paths: vec![leaf],
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let result_window_leaves = std::iter::once(result_plan.insert_eviction_leaf)
        .chain(result_plan.padding_leaves.iter().copied())
        .collect::<Vec<_>>();
    let result_windows = result_window_leaves
        .into_iter()
        .enumerate()
        .map(|(sequence, leaf)| {
            Ok(PrivateOramAppendReadWindowV1 {
                sequence: u32::try_from(sequence)?,
                paths: vec![encode_private_result_oram_leaf_label(
                    leaf,
                    context.result_manifest.oram.tree_height,
                )?],
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

    let mut hnsw_transaction = PrivateOramAppendHnswTransactionV2::begin(
        immutable,
        old_state,
        &checkpoint,
        hnsw_point.clone(),
        hnsw_plan.clone(),
    )?;
    let hnsw_marker = hnsw_transaction
        .prepare_next_read_window()?
        .ok_or("mutation V2 append HNSW transaction produced no read window")?;
    if hnsw_transaction.next_read_window(&hnsw_marker)?.window != hnsw_windows[0] {
        return Err("mutation V2 append HNSW read plan mismatch".into());
    }
    let mut result_transaction = PrivateOramAppendResultTransactionV2::begin(
        immutable,
        old_state,
        &checkpoint,
        result_point.clone(),
        result_plan.clone(),
    )?;
    let result_marker = result_transaction
        .prepare_next_read_window()?
        .ok_or("mutation V2 append result transaction produced no read window")?;
    if result_transaction.next_read_window(&result_marker)?.window != result_windows[0] {
        return Err("mutation V2 append result read plan mismatch".into());
    }

    Ok(MutationV2AppendMaterials {
        checkpoint,
        hnsw_point,
        result_point,
        hnsw_plan,
        result_plan,
        hnsw_windows,
        result_windows,
        hnsw_open_index,
        result_open_index,
    })
}

fn validate_mutation_v2_append_index_mapping(
    context: &MutationV2AppendFixtureContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let immutable = &context.immutable_manifest.manifest;
    let state = &context.old_state.state;
    if immutable.indexes.len() != 2 || state.indexes.len() != 2 {
        return Err("mutation V2 append index topology mismatch".into());
    }
    let hnsw = &immutable.indexes[0];
    let result = &immutable.indexes[1];
    let expected_hnsw_read_count = u32::try_from(hnsw.capacity.logical_capacity)?
        .checked_add(1)
        .ok_or("mutation V2 append read budget overflow")?;
    let expected_result_read_count = u32::try_from(result.capacity.logical_capacity)?
        .checked_add(1)
        .ok_or("mutation V2 append read budget overflow")?;
    if expected_hnsw_read_count != expected_result_read_count {
        return Err("mutation V2 append paired read budget mismatch".into());
    }
    let expected_write_count = expected_hnsw_read_count
        .checked_mul(context.hnsw_manifest.oram.tree_height + 1)
        .ok_or("mutation V2 append write budget overflow")?;
    let expected_capacity = |bucket_count: u64,
                             bucket_size: u32,
                             logical_count: u64,
                             dummy_count: u64|
     -> Result<(u64, u64), Box<dyn std::error::Error>> {
        let logical_capacity = logical_count
            .checked_add(dummy_count)
            .ok_or("invalid capacity")?;
        let physical = bucket_count
            .checked_mul(u64::from(bucket_size))
            .ok_or("mutation V2 append physical capacity overflow")?;
        Ok((
            logical_capacity,
            physical
                .checked_sub(logical_capacity)
                .ok_or("invalid capacity")?,
        ))
    };
    let (hnsw_logical_capacity, hnsw_reserved) = expected_capacity(
        context.hnsw_manifest.bucket_count,
        context.hnsw_manifest.oram.bucket_size,
        context.hnsw_manifest.logical_node_count,
        context.hnsw_manifest.dummy_node_count,
    )?;
    let (result_logical_capacity, result_reserved) = expected_capacity(
        context.result_manifest.bucket_count,
        context.result_manifest.oram.bucket_size,
        context.result_manifest.logical_result_count,
        context.result_manifest.dummy_result_count,
    )?;
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        provider,
        binding,
        key_id,
        rk_id,
        rk_epoch,
        dim,
        vector_encoding,
        distance,
        hnsw: hnsw_params,
        oram,
        fixed_search_budget,
        max_neighbor_rewrites,
    } = &hnsw.params
    else {
        return Err("mutation V2 append HNSW immutable params mismatch".into());
    };
    if hnsw.index_name != context.hnsw_manifest.vector_name
        || provider != VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER
        || binding != PRIVATE_HNSW_ORAM_V2_BINDING
        || key_id != &context.hnsw_manifest.key_id
        || rk_id != &context.hnsw_manifest.rk_id
        || *rk_epoch != context.hnsw_manifest.rk_epoch
        || *dim != context.hnsw_manifest.dim
        || *vector_encoding != PrivateHnswVectorEncoding::F32Le
        || *distance != context.hnsw_manifest.distance
        || hnsw_params != &context.hnsw_manifest.hnsw
        || oram != &context.hnsw_manifest.oram
        || fixed_search_budget != &context.hnsw_manifest.fixed_budget
        || *max_neighbor_rewrites != 1
        || hnsw.capacity.bucket_count != context.hnsw_manifest.bucket_count
        || hnsw.capacity.logical_capacity != hnsw_logical_capacity
        || hnsw.capacity.reserved_physical_slots != hnsw_reserved
        || u64::from(hnsw.capacity.max_client_stash_blocks) != hnsw_reserved
        || hnsw.capacity.fixed_append_read_path_count != expected_hnsw_read_count
        || hnsw.capacity.fixed_append_write_bucket_count != expected_write_count
    {
        return Err("mutation V2 append HNSW immutable mapping mismatch".into());
    }
    let PrivateOramImmutableIndexParamsV2::Result {
        provider,
        binding,
        key_id,
        rk_id,
        rk_epoch,
        oram,
    } = &result.params
    else {
        return Err("mutation V2 append result immutable params mismatch".into());
    };
    if result.index_name != MUTATION_V2_RESULT_INDEX_NAME
        || provider != PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER
        || binding != PRIVATE_RESULT_ORAM_V2_BINDING
        || key_id != &context.result_manifest.key_id
        || rk_id != &context.result_manifest.rk_id
        || *rk_epoch != context.result_manifest.rk_epoch
        || oram != &context.result_manifest.oram
        || result.capacity.bucket_count != context.result_manifest.bucket_count
        || result.capacity.logical_capacity != result_logical_capacity
        || result.capacity.reserved_physical_slots != result_reserved
        || u64::from(result.capacity.max_client_stash_blocks) != result_reserved
        || result.capacity.fixed_append_read_path_count != expected_result_read_count
        || result.capacity.fixed_append_write_bucket_count != expected_write_count
    {
        return Err("mutation V2 append result immutable mapping mismatch".into());
    }
    let expected_states = [
        (
            &state.indexes[0],
            PrivateOramIndexKindV2::Hnsw,
            context.hnsw_manifest.vector_name.as_str(),
            context.hnsw_manifest.index_epoch,
            context.hnsw_manifest.root_hash.as_str(),
            context.hnsw_manifest.logical_node_count,
            context.hnsw_manifest.dummy_node_count,
        ),
        (
            &state.indexes[1],
            PrivateOramIndexKindV2::Result,
            MUTATION_V2_RESULT_INDEX_NAME,
            context.result_manifest.index_epoch,
            context.result_manifest.root_hash.as_str(),
            context.result_manifest.logical_result_count,
            context.result_manifest.dummy_result_count,
        ),
    ];
    let state_sequence = state.state_sequence;
    if expected_states.iter().any(
        |(observed, kind, name, epoch, root_hash, logical_count, dummy_count)| {
            let Some(expected_epoch) = epoch.checked_add(state_sequence) else {
                return true;
            };
            let Some(expected_logical_count) = logical_count.checked_add(state_sequence) else {
                return true;
            };
            let Some(expected_dummy_count) = dummy_count.checked_sub(state_sequence) else {
                return true;
            };
            observed.kind != *kind
                || observed.index_name != *name
                || observed.index_epoch != expected_epoch
                || (state_sequence == 0 && observed.root_hash != *root_hash)
                || observed.logical_count != expected_logical_count
                || observed.dummy_count != expected_dummy_count
        },
    ) {
        return Err("mutation V2 append signed index state mismatch".into());
    }
    Ok(())
}

fn normalize_hnsw_append_output(
    manifest: &PrivateOramImmutableManifestV2,
    keys: &PrivateHnswClientKeys,
    mutation_id: &str,
    output: &mut PrivateOramAppendHnswTransactionOutputV2,
) -> Result<(), Box<dyn std::error::Error>> {
    let index = manifest
        .indexes
        .iter()
        .find(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
        .ok_or("mutation V2 append immutable manifest has no HNSW index")?;
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        key_id,
        rk_id,
        rk_epoch,
        ..
    } = &index.params
    else {
        return Err("mutation V2 append immutable HNSW params mismatch".into());
    };
    let mut deterministic_buckets = Vec::with_capacity(output.ordered_encrypted_buckets.len());
    for (sequence, bucket) in output.ordered_encrypted_buckets.iter().enumerate() {
        let context = PrivateHnswBucketAeadContext {
            collection_id: &manifest.collection_id,
            vector_name: &index.index_name,
            key_id,
            rk_id,
            rk_epoch: *rk_epoch,
            bucket_id: bucket.bucket_id,
            index_epoch: output.new_epoch,
        };
        let plaintext = open_private_hnsw_oram_bucket(keys, context, bucket)?;
        let sequence = u64::try_from(sequence)?.to_be_bytes();
        let bucket_id = bucket.bucket_id.to_be_bytes();
        let new_epoch = output.new_epoch.to_be_bytes();
        let nonce = deterministic_append_nonce(
            MUTATION_V2_APPEND_NONCE_DOMAIN,
            &[
                mutation_id.as_bytes(),
                b"hnsw",
                &sequence,
                &bucket_id,
                &new_epoch,
            ],
        )?;
        let aad = mutation_v2_hnsw_bucket_aad(context)?;
        let raw =
            seal_deterministic_aead(keys.bucket_aead_key().as_bytes(), nonce, &aad, &plaintext)?;
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&raw).as_ref());
        let bucket_commitment = private_hnsw_bucket_commitment(context, &ciphertext_sha256)?;
        deterministic_buckets.push(PrivateHnswOramBucket {
            version: 1,
            bucket_id: bucket.bucket_id,
            index_epoch: output.new_epoch,
            ciphertext: BASE64URL_NOPAD.encode(&raw),
            ciphertext_sha256,
            bucket_commitment,
        });
    }

    let ordered_refs = deterministic_buckets
        .iter()
        .map(|bucket| PrivateOramAppendBucketRefV1 {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
            bucket_commitment: bucket.bucket_commitment.clone(),
        })
        .collect::<Vec<_>>();
    let final_buckets = deterministic_buckets
        .iter()
        .cloned()
        .map(|bucket| (bucket.bucket_id, bucket))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();
    let final_refs = final_buckets
        .iter()
        .map(|bucket| PrivateOramAppendBucketRefV1 {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
            bucket_commitment: bucket.bucket_commitment.clone(),
        })
        .collect::<Vec<_>>();
    let patch = apply_private_oram_append_sparse_merkle_patch_v1(
        output.old_epoch,
        &output.old_root_hash,
        index.capacity.bucket_count,
        &output.merkle_patch_proof,
        &ordered_refs,
    )?;
    if patch.final_buckets != final_refs {
        return Err("mutation V2 deterministic HNSW bucket patch mismatch".into());
    }

    output.new_root_hash = patch.new_root_hash;
    output.ordered_encrypted_buckets = deterministic_buckets;
    output.final_encrypted_buckets = final_buckets;
    output.writeback.updated_buckets = ordered_refs;
    let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
    let writeback_digest =
        private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
            collection_id: &manifest.collection_id,
            manifest_digest: &manifest_digest,
            kind: output.writeback.kind,
            index_name: &output.writeback.index_name,
            old_epoch: output.old_epoch,
            new_epoch: output.new_epoch,
            old_root_hash: &output.old_root_hash,
            new_root_hash: &output.new_root_hash,
            read_path_count: output.writeback.read_path_count,
            read_transcript_digest: &output.writeback.read_transcript_digest,
            updated_buckets: &output.writeback.updated_buckets,
        })?;
    output.recovery_marker.prepared_commit_digest =
        Some(private_oram_append_hnsw_prepared_commit_v4_digest(
            PrivateOramAppendHnswPreparedCommitDigestInputV4 {
                attempt_digest: &output.recovery_marker.attempt_digest,
                source_checkpoint_digest: &output.source_checkpoint_digest,
                graph_delta: &output.graph_delta,
                old_epoch: output.old_epoch,
                new_epoch: output.new_epoch,
                old_root_hash: &output.old_root_hash,
                new_root_hash: &output.new_root_hash,
                read_transcript_digest: &output.read_transcript.transcript_digest,
                writeback_digest: &writeback_digest,
                next_client_state: &output.next_client_state,
            },
        )?);
    validate_private_oram_append_hnsw_transaction_output_v2(manifest, output)?;
    Ok(())
}

fn normalize_result_append_output(
    manifest: &PrivateOramImmutableManifestV2,
    keys: &PrivateResultOramClientKeys,
    mutation_id: &str,
    output: &mut PrivateOramAppendResultTransactionOutputV2,
) -> Result<(), Box<dyn std::error::Error>> {
    let index = manifest
        .indexes
        .iter()
        .find(|index| index.kind() == PrivateOramIndexKindV2::Result)
        .ok_or("mutation V2 append immutable manifest has no result index")?;
    let PrivateOramImmutableIndexParamsV2::Result {
        key_id,
        rk_id,
        rk_epoch,
        ..
    } = &index.params
    else {
        return Err("mutation V2 append immutable result params mismatch".into());
    };
    let mut deterministic_buckets = Vec::with_capacity(output.ordered_encrypted_buckets.len());
    for (sequence, bucket) in output.ordered_encrypted_buckets.iter().enumerate() {
        let context = PrivateResultOramBucketAeadContext {
            collection_id: &manifest.collection_id,
            key_id,
            rk_id,
            rk_epoch: *rk_epoch,
            bucket_id: bucket.bucket_id,
            index_epoch: output.new_epoch,
        };
        let plaintext = open_private_result_oram_bucket(keys, context, bucket)?;
        let sequence = u64::try_from(sequence)?.to_be_bytes();
        let bucket_id = bucket.bucket_id.to_be_bytes();
        let new_epoch = output.new_epoch.to_be_bytes();
        let nonce = deterministic_append_nonce(
            MUTATION_V2_APPEND_NONCE_DOMAIN,
            &[
                mutation_id.as_bytes(),
                b"result",
                &sequence,
                &bucket_id,
                &new_epoch,
            ],
        )?;
        let aad = mutation_v2_result_bucket_aad(context)?;
        let raw =
            seal_deterministic_aead(keys.bucket_aead_key().as_bytes(), nonce, &aad, &plaintext)?;
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&raw).as_ref());
        let bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: context.collection_id,
                key_id: context.key_id,
                rk_id: context.rk_id,
                rk_epoch: context.rk_epoch,
                bucket_id: context.bucket_id,
                index_epoch: context.index_epoch,
            },
            &ciphertext_sha256,
        )?;
        deterministic_buckets.push(PrivateResultOramBucket {
            version: 1,
            bucket_id: bucket.bucket_id,
            index_epoch: output.new_epoch,
            ciphertext: BASE64URL_NOPAD.encode(&raw),
            ciphertext_sha256,
            bucket_commitment,
        });
    }

    let ordered_refs = deterministic_buckets
        .iter()
        .map(|bucket| PrivateOramAppendBucketRefV1 {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
            bucket_commitment: bucket.bucket_commitment.clone(),
        })
        .collect::<Vec<_>>();
    let final_buckets = deterministic_buckets
        .iter()
        .cloned()
        .map(|bucket| (bucket.bucket_id, bucket))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();
    let final_refs = final_buckets
        .iter()
        .map(|bucket| PrivateOramAppendBucketRefV1 {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
            bucket_commitment: bucket.bucket_commitment.clone(),
        })
        .collect::<Vec<_>>();
    let patch = apply_private_oram_append_sparse_merkle_patch_v1(
        output.old_epoch,
        &output.old_root_hash,
        index.capacity.bucket_count,
        &output.merkle_patch_proof,
        &ordered_refs,
    )?;
    if patch.final_buckets != final_refs {
        return Err("mutation V2 deterministic result bucket patch mismatch".into());
    }

    output.new_root_hash = patch.new_root_hash;
    output.ordered_encrypted_buckets = deterministic_buckets;
    output.final_encrypted_buckets = final_buckets;
    output.writeback.updated_buckets = ordered_refs;
    let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
    let writeback_digest =
        private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
            collection_id: &manifest.collection_id,
            manifest_digest: &manifest_digest,
            kind: output.writeback.kind,
            index_name: &output.writeback.index_name,
            old_epoch: output.old_epoch,
            new_epoch: output.new_epoch,
            old_root_hash: &output.old_root_hash,
            new_root_hash: &output.new_root_hash,
            read_path_count: output.writeback.read_path_count,
            read_transcript_digest: &output.writeback.read_transcript_digest,
            updated_buckets: &output.writeback.updated_buckets,
        })?;
    output.recovery_marker.prepared_commit_digest =
        Some(private_oram_append_result_prepared_commit_v4_digest(
            PrivateOramAppendResultPreparedCommitDigestInputV4 {
                attempt_digest: &output.recovery_marker.attempt_digest,
                source_checkpoint_digest: &output.source_checkpoint_digest,
                result_record: &output.result_record,
                old_epoch: output.old_epoch,
                new_epoch: output.new_epoch,
                old_root_hash: &output.old_root_hash,
                new_root_hash: &output.new_root_hash,
                read_transcript_digest: &output.read_transcript.transcript_digest,
                writeback_digest: &writeback_digest,
                next_client_state: &output.next_client_state,
            },
        )?);
    validate_private_oram_append_result_transaction_output_v2(manifest, output)?;
    Ok(())
}

fn mutation_v2_hnsw_bucket_aad(
    context: PrivateHnswBucketAeadContext<'_>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut aad = Vec::new();
    for field in [
        MUTATION_V2_APPEND_HNSW_BUCKET_AAD_DOMAIN.as_bytes(),
        context.collection_id.as_bytes(),
        context.vector_name.as_bytes(),
        context.key_id.as_bytes(),
        context.rk_id.as_bytes(),
    ] {
        aad.extend_from_slice(&u32::try_from(field.len())?.to_be_bytes());
        aad.extend_from_slice(field);
    }
    aad.extend_from_slice(&context.rk_epoch.to_be_bytes());
    aad.extend_from_slice(&context.bucket_id.to_be_bytes());
    aad.extend_from_slice(&context.index_epoch.to_be_bytes());
    Ok(aad)
}

fn mutation_v2_result_bucket_aad(
    context: PrivateResultOramBucketAeadContext<'_>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut aad = Vec::new();
    let domain = MUTATION_V2_APPEND_RESULT_BUCKET_AAD_DOMAIN.as_bytes();
    aad.extend_from_slice(&u32::try_from(domain.len())?.to_be_bytes());
    aad.extend_from_slice(domain);
    for field in [context.collection_id, context.key_id, context.rk_id] {
        aad.extend_from_slice(&u64::try_from(field.len())?.to_be_bytes());
        aad.extend_from_slice(field.as_bytes());
    }
    aad.extend_from_slice(&context.rk_epoch.to_be_bytes());
    aad.extend_from_slice(&context.bucket_id.to_be_bytes());
    aad.extend_from_slice(&context.index_epoch.to_be_bytes());
    Ok(aad)
}

fn deterministic_append_nonce(
    domain: &str,
    fields: &[&[u8]],
) -> Result<[u8; 12], Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    for field in std::iter::once(domain.as_bytes()).chain(fields.iter().copied()) {
        hasher.update(u64::try_from(field.len())?.to_be_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize()[..12].try_into()?)
}

fn seal_deterministic_aead(
    key_bytes: &[u8],
    nonce_bytes: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
        .map_err(|_| "mutation V2 deterministic AEAD key is invalid")?;
    let key = LessSafeKey::new(unbound_key);
    let mut ciphertext = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| "mutation V2 deterministic AEAD seal failed")?;
    let mut encoded =
        Vec::with_capacity(1 + nonce_bytes.len() + ciphertext.len() + tag.as_ref().len());
    encoded.push(1);
    encoded.extend_from_slice(&nonce_bytes);
    encoded.extend_from_slice(&ciphertext);
    encoded.extend_from_slice(tag.as_ref());
    Ok(encoded)
}

fn seal_deterministic_append_checkpoint(
    checkpoint_key: &SecretKey,
    checkpoint: &PrivateOramAppendClientCheckpointV2,
    mutation_id: &str,
) -> Result<PrivateOramSealedAppendClientCheckpointV2, Box<dyn std::error::Error>> {
    let plaintext = serde_json::to_vec(checkpoint)?;
    let derived_key = checkpoint_key.derive_subkey_with_context(
        PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AEAD_DOMAIN,
        MUTATION_V2_APPEND_CHECKPOINT_KDF_CONTEXT_DOMAIN,
        &[
            checkpoint.collection_id.as_bytes(),
            checkpoint.manifest_digest.as_bytes(),
        ],
    )?;
    let mut aad = Vec::new();
    aad.extend_from_slice(
        &u32::try_from(MUTATION_V2_APPEND_CHECKPOINT_AAD_DOMAIN.len())?.to_be_bytes(),
    );
    aad.extend_from_slice(MUTATION_V2_APPEND_CHECKPOINT_AAD_DOMAIN);
    aad.extend_from_slice(&checkpoint.version.to_be_bytes());
    for field in [&checkpoint.collection_id, &checkpoint.manifest_digest] {
        aad.extend_from_slice(&u64::try_from(field.len())?.to_be_bytes());
        aad.extend_from_slice(field.as_bytes());
    }
    aad.extend_from_slice(&checkpoint.layout_generation.to_be_bytes());
    aad.extend_from_slice(&checkpoint.state_sequence.to_be_bytes());
    let layout_generation = checkpoint.layout_generation.to_be_bytes();
    let state_sequence = checkpoint.state_sequence.to_be_bytes();
    let nonce = deterministic_append_nonce(
        MUTATION_V2_APPEND_CHECKPOINT_NONCE_DOMAIN,
        &[
            mutation_id.as_bytes(),
            checkpoint.collection_id.as_bytes(),
            checkpoint.manifest_digest.as_bytes(),
            &layout_generation,
            &state_sequence,
        ],
    )?;
    let raw = seal_deterministic_aead(derived_key.as_bytes(), nonce, &aad, &plaintext)?;
    Ok(PrivateOramSealedAppendClientCheckpointV2 {
        version: checkpoint.version,
        collection_id: checkpoint.collection_id.clone(),
        manifest_digest: checkpoint.manifest_digest.clone(),
        layout_generation: checkpoint.layout_generation,
        state_sequence: checkpoint.state_sequence,
        ciphertext: BASE64URL_NOPAD.encode(&raw),
        ciphertext_sha256: BASE64URL_NOPAD.encode(Sha256::digest(&raw).as_ref()),
    })
}

fn validate_fixture_owner_prepare(
    context: &MutationV2AppendFixtureContext,
    owner_prepare: &PrivateOramAppendOwnerPrepareV1,
    observed_read_transcripts: &[PrivateOramObservedReadTranscriptV1],
    manifest_digest: &str,
    old_state_digest: &str,
    now_unix: u64,
    owner_public_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let recorder = PrivateOramServerReadEvidenceRecorderV1::new();
    let mut evidence = Vec::with_capacity(observed_read_transcripts.len());
    for transcript in observed_read_transcripts {
        let paths_per_window = usize::try_from(transcript.paths_per_window)?;
        if paths_per_window == 0 || transcript.ordered_leaf_labels.len() % paths_per_window != 0 {
            return Err("mutation V2 append read transcript window shape mismatch".into());
        }
        let windows = transcript
            .ordered_leaf_labels
            .chunks(paths_per_window)
            .enumerate()
            .map(|(sequence, paths)| {
                Ok(PrivateOramAppendReadWindowV1 {
                    sequence: u32::try_from(sequence)?,
                    paths: paths.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let observed = recorder.record(PrivateOramAppendReadTranscriptDigestInput {
            collection_id: &transcript.collection_id,
            manifest_digest: &transcript.manifest_digest,
            mutation_id: &transcript.mutation_id,
            old_state_digest: &transcript.old_state_digest,
            writer_lease_digest: &transcript.writer_lease_digest,
            writer_fence: transcript.writer_fence,
            paths_per_window: transcript.paths_per_window,
            tree_height: transcript.tree_height,
            kind: transcript.kind,
            index_name: &transcript.index_name,
            windows: &windows,
        })?;
        if observed.transcript() != transcript {
            return Err("mutation V2 append read transcript self-check mismatch".into());
        }
        evidence.push(observed);
    }
    validate_private_oram_append_owner_prepare_v1(
        &context.immutable_manifest,
        owner_prepare,
        PrivateOramAppendOwnerPrepareValidationContextV1 {
            expected_collection_id: &context.collection_id,
            expected_manifest_digest: manifest_digest,
            expected_owner_signing_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
            expected_layout_generation: context.old_state.state.layout_generation,
            expected_layout_digest: &context.old_state.state.layout_digest,
            expected_writer_lease_digest: &context.open_response.writer_lease_digest,
            expected_writer_fence: context.open_response.writer_fence,
            expected_state_sequence: context.old_state.state.state_sequence,
            expected_old_state_digest: old_state_digest,
            expected_visible_point_record: None,
            server_read_evidence_recorder: &recorder,
            server_read_evidence: &evidence,
            now_unix,
            max_mutation_ttl_secs: PRIVATE_ORAM_APPEND_MAX_MUTATION_TTL_SECS,
            public_key: owner_public_key,
        },
    )?;
    Ok(())
}

fn encode_mutation_v2_wire_u64_fields(value: &mut Value) -> Result<(), Box<dyn std::error::Error>> {
    const U64_FIELDS: &[&str] = &[
        "bucket_count",
        "bucket_id",
        "created_at_unix",
        "dummy_count",
        "dummy_node_count",
        "dummy_result_count",
        "expires_at_unix",
        "generation",
        "index_epoch",
        "initial_leaf",
        "issued_at_unix",
        "layout_generation",
        "lease_expires_unix",
        "level_mask",
        "logical_capacity",
        "logical_count",
        "logical_node_count",
        "logical_result_count",
        "mutation_lease_generation",
        "new_epoch",
        "new_leaf",
        "old_epoch",
        "old_leaf",
        "owner_peer_id",
        "reserved_physical_slots",
        "rk_epoch",
        "signed_at_unix",
        "state_sequence",
        "writer_fence",
    ];
    const U64_ARRAY_FIELDS: &[&str] = &["bucket_ids", "owner_peer_ids"];

    fn encode(
        value: &mut Value,
        field_name: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if field_name.is_some_and(|name| U64_FIELDS.contains(&name)) {
            let encoded = match value {
                Value::Number(number) => number
                    .as_u64()
                    .ok_or("mutation V2 REST u64 field is not unsigned")?
                    .to_string(),
                Value::String(encoded) => {
                    let parsed = encoded.parse::<u64>()?;
                    if parsed.to_string() != *encoded {
                        return Err("mutation V2 REST u64 field is not canonical".into());
                    }
                    return Ok(());
                }
                _ => return Err("mutation V2 REST u64 field has the wrong type".into()),
            };
            *value = Value::String(encoded);
            return Ok(());
        }
        if field_name.is_some_and(|name| U64_ARRAY_FIELDS.contains(&name)) {
            let Value::Array(entries) = value else {
                return Err("mutation V2 REST u64 array has the wrong type".into());
            };
            for entry in entries {
                encode(entry, Some("bucket_id"))?;
            }
            return Ok(());
        }
        match value {
            Value::Object(fields) => {
                for (name, value) in fields {
                    encode(value, Some(name))?;
                }
            }
            Value::Array(entries) => {
                for entry in entries {
                    encode(entry, None)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    encode(value, None)
}

fn mutation_v2_owner_key() -> Result<Ed25519KeyPair, Box<dyn std::error::Error>> {
    Ed25519KeyPair::from_seed_unchecked(&[13; 32])
        .map_err(|_| std::io::Error::other("failed to create mutation V2 fixture owner key").into())
}

fn validate_mutation_v2_physical_pair(
    collection_id: &str,
    hnsw: &PrivateHnswOramManifest,
    hnsw_signature: &PrivateHnswOramSignature,
    result: &PrivateResultOramManifest,
    result_signature: &PrivateResultOramSignature,
    owner_public_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if collection_id.is_empty()
        || hnsw.collection_id != collection_id
        || result.collection_id != collection_id
        || hnsw.vector_name != VECTOR_NAME
        || hnsw.key_id != KEY_ID
        || hnsw.rk_id != KEY_ID
        || result.key_id != KEY_ID
        || result.rk_id != KEY_ID
        || hnsw.rk_epoch != RK_EPOCH
        || result.rk_epoch != RK_EPOCH
        || hnsw.owner_signing_key_id != MUTATION_V2_OWNER_SIGNING_KEY_ID
        || result.owner_signing_key_id != MUTATION_V2_OWNER_SIGNING_KEY_ID
        || hnsw.owner_signing_key_id != result.owner_signing_key_id
        || hnsw.created_at_unix != result.created_at_unix
        || hnsw.result_privacy != ResultPrivacyMode::PrivatePayloadOramRequired
        || hnsw.logical_node_count != result.logical_result_count
        || hnsw.dummy_node_count != result.dummy_result_count
        || hnsw.logical_node_count != 1
        || !(1..=7).contains(&hnsw.dummy_node_count)
        || hnsw.oram.kind != OramKind::PathOram
        || result.oram.kind != OramKind::PathOram
        || hnsw.oram.bucket_size != 2
        || result.oram.bucket_size != 2
        || hnsw.oram.tree_height != result.oram.tree_height
        || hnsw.oram.path_batch_size != 1
        || result.oram.path_batch_size != 1
        || hnsw.bucket_count != result.bucket_count
        || hnsw.dim != 2
        || hnsw.distance != DistanceKind::Euclid
        || hnsw.hnsw
            != (PrivateHnswParams {
                m: 2,
                ef_construction: 4,
                max_layers: 3,
                fixed_neighbor_slots: 4,
            })
        || hnsw.fixed_budget
            != (FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 1,
                base_layer_steps: 3,
                paths_per_round: 1,
                fixed_result_k: 1,
            })
    {
        return Err(
            "mutation V2 physical manifest pair does not match the fixture contract".into(),
        );
    }
    let profile_matches = (hnsw.oram.tree_height == FixtureProfile::DEFAULT.tree_height
        && hnsw.oram.block_size_bytes
            == u32::try_from(FixtureProfile::DEFAULT.hnsw_block_size_bytes)?
        && result.oram.block_size_bytes == FixtureProfile::DEFAULT.result_block_size_bytes)
        || (hnsw.oram.tree_height == FixtureProfile::LARGE.tree_height
            && hnsw.oram.block_size_bytes
                == u32::try_from(FixtureProfile::LARGE.hnsw_block_size_bytes)?
            && result.oram.block_size_bytes == FixtureProfile::LARGE.result_block_size_bytes);
    let expected_bucket_count = hnsw
        .oram
        .tree_height
        .checked_add(1)
        .and_then(|height| 1u64.checked_shl(height))
        .and_then(|count| count.checked_sub(1));
    let hnsw_physical_slots = hnsw
        .bucket_count
        .checked_mul(u64::from(hnsw.oram.bucket_size));
    let result_physical_slots = result
        .bucket_count
        .checked_mul(u64::from(result.oram.bucket_size));
    if !profile_matches
        || expected_bucket_count != Some(hnsw.bucket_count)
        || hnsw
            .logical_node_count
            .checked_add(hnsw.dummy_node_count)
            .zip(hnsw_physical_slots)
            .is_none_or(|(capacity, physical_slots)| capacity >= physical_slots)
        || result
            .logical_result_count
            .checked_add(result.dummy_result_count)
            .zip(result_physical_slots)
            .is_none_or(|(capacity, physical_slots)| capacity >= physical_slots)
    {
        return Err("mutation V2 physical manifest capacity is invalid".into());
    }

    validate_private_hnsw_oram_manifest(
        hnsw,
        Some(hnsw_signature),
        PrivateHnswManifestValidationContext {
            expected_collection_id: collection_id,
            expected_vector_name: VECTOR_NAME,
            expected_key_id: KEY_ID,
            expected_rk_id: KEY_ID,
            min_rk_epoch: RK_EPOCH,
            max_rk_epoch: RK_EPOCH,
            expected_dim: 2,
            expected_distance: DistanceKind::Euclid,
            signature_verification: PrivateHnswSignatureVerification {
                expected_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
                public_key: owner_public_key,
            },
        },
    )?;
    validate_private_result_oram_manifest(
        result,
        Some(result_signature),
        PrivateResultOramManifestValidationContext {
            expected_collection_id: collection_id,
            expected_key_id: KEY_ID,
            expected_rk_id: KEY_ID,
            min_rk_epoch: RK_EPOCH,
            max_rk_epoch: RK_EPOCH,
            signature_verification: PrivateResultOramSignatureVerification {
                expected_key_id: MUTATION_V2_OWNER_SIGNING_KEY_ID,
                public_key: owner_public_key,
            },
        },
    )?;
    Ok(())
}

fn deterministic_fixture_digest(
    domain: &str,
    fields: &[&[u8]],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    for field in std::iter::once(domain.as_bytes()).chain(fields.iter().copied()) {
        hasher.update(u64::try_from(field.len())?.to_be_bytes());
        hasher.update(field);
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn read_mutation_v2_stdin<T: for<'de> Deserialize<'de>>(
    command: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut encoded = Vec::new();
    io::stdin()
        .take(MUTATION_V2_STDIN_MAX_BYTES + 1)
        .read_to_end(&mut encoded)?;
    if u64::try_from(encoded.len())? > MUTATION_V2_STDIN_MAX_BYTES {
        return Err(format!("{command} input exceeds 4 MiB").into());
    }
    Ok(serde_json::from_slice(&encoded)?)
}

fn deserialize_canonical_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let parsed = encoded.parse::<u64>().map_err(serde::de::Error::custom)?;
    if parsed.to_string() != encoded {
        return Err(serde::de::Error::custom(
            "private ORAM V2 u64 field is not canonical",
        ));
    }
    Ok(parsed)
}

fn decode_base64url_32_fixture(
    encoded: &str,
    field: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let decoded = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| format!("mutation V2 append {field} is not canonical base64url"))?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != encoded {
        return Err(format!("mutation V2 append {field} must encode exactly 32 bytes").into());
    }
    decoded
        .try_into()
        .map_err(|_| format!("mutation V2 append {field} must encode exactly 32 bytes").into())
}

fn validate_base64url_32_fixture(
    encoded: &str,
    field: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    decode_base64url_32_fixture(encoded, field).map(|_| ())
}

fn decode_fixture_leaf_label(encoded: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let decoded = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| "mutation V2 append leaf label is not canonical base64url")?;
    if decoded.len() != 8 || BASE64URL_NOPAD.encode(&decoded) != encoded {
        return Err("mutation V2 append leaf label must encode exactly 8 bytes".into());
    }
    let decoded: [u8; 8] = decoded
        .try_into()
        .map_err(|_| "mutation V2 append leaf label must encode exactly 8 bytes")?;
    Ok(u64::from_be_bytes(decoded))
}

fn mutation_v2_client_fixture_digest(
    hnsw: &MutationV2HnswClientStateFixture,
    result: &MutationV2ResultClientStateFixture,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = json!({"hnsw": hnsw, "result": result});
    let mut canonical = String::new();
    write_canonical_json(&value, &mut canonical)?;
    Ok(BASE64URL_NOPAD.encode(Sha256::digest(canonical.as_bytes()).as_ref()))
}

fn write_canonical_json(
    value: &Value,
    output: &mut String,
) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            output.push_str(&serde_json::to_string(value)?);
        }
        Value::Array(values) => {
            output.push('[');
            for (offset, value) in values.iter().enumerate() {
                if offset != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(fields) => {
            output.push('{');
            let mut ordered = fields.iter().collect::<Vec<_>>();
            ordered.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (offset, (name, value)) in ordered.into_iter().enumerate() {
                if offset != 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(name)?);
                output.push(':');
                write_canonical_json(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn sign_recovery_checkpoint_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = String::new();
    io::stdin().read_to_string(&mut encoded)?;
    let mut request: RecoveryCheckpointSigningRequest = serde_json::from_str(&encoded)?;
    let intent = &request.intent;
    if intent.expected_committed_backup_generation.checked_add(1)
        != Some(intent.requested_backup_generation)
        || request.checkpoint.collection_id != intent.expected_collection_id
        || request.checkpoint.backup_generation != intent.requested_backup_generation
        || request.checkpoint.source_peer_id != intent.expected_source_peer_id
        || request.checkpoint.source_shard_ids != intent.expected_source_shard_ids
        || request.checkpoint.owner_peer_ids != [intent.expected_source_peer_id]
        || request.checkpoint.layout_generation != intent.expected_layout_generation
        || request.checkpoint.layout_digest != intent.expected_layout_digest
        || request.checkpoint.owner_snapshot_authority_digest
            != intent.expected_owner_snapshot_authority_digest
        || request.checkpoint.snapshot_size_bytes != intent.expected_snapshot_size_bytes
        || request.checkpoint.snapshot_sha256 != intent.expected_snapshot_sha256
        || request.checkpoint.client_recovery_state_digest
            != intent.expected_client_recovery_state_digest
        || request.checkpoint.owner_signing_key_id != intent.expected_owner_signing_key_id
        || intent.expected_owner_signing_key_id != RECOVERY_SIGNING_KEY_ID
    {
        return Err("private ORAM recovery checkpoint signing key mismatch".into());
    }
    request.index_states.sort_by(|left, right| {
        left.key
            .index_kind
            .cmp(&right.key.index_kind)
            .then_with(|| left.key.index_name.cmp(&right.key.index_name))
    });
    request.expected_indexes.sort_by(|left, right| {
        left.index_kind
            .cmp(&right.index_kind)
            .then_with(|| left.index_name.cmp(&right.index_name))
    });
    if request.index_states.len() != request.expected_indexes.len() {
        return Err("private ORAM recovery checkpoint index set mismatch".into());
    }
    for (observed, expected) in request.index_states.iter().zip(&request.expected_indexes) {
        if observed.key.collection_id != intent.expected_collection_id
            || observed.key.index_kind != expected.index_kind
            || observed.key.index_name != expected.index_name
            || observed.state.index_epoch != expected.index_epoch
            || observed.state.root_hash != expected.root_hash
            || observed.state.writeback_digest != expected.writeback_digest
        {
            return Err("private ORAM recovery checkpoint index state mismatch".into());
        }
    }
    if request.index_states.windows(2).any(|states| {
        states[0].key.index_kind == states[1].key.index_kind
            && states[0].key.index_name == states[1].key.index_name
    }) {
        return Err("private ORAM recovery checkpoint index set is duplicated".into());
    }

    let expected_states = request
        .expected_indexes
        .iter()
        .map(|expected| {
            let index_kind = match expected.index_kind.as_str() {
                "hnsw" => PrivateOramRecoveryIndexKind::Hnsw,
                "result_payload" => PrivateOramRecoveryIndexKind::ResultPayload,
                _ => return Err("private ORAM recovery checkpoint index kind mismatch"),
            };
            Ok(PrivateOramRecoveryIndexStateRef {
                collection_id: &intent.expected_collection_id,
                index_kind,
                index_name: &expected.index_name,
                index_epoch: expected.index_epoch,
                root_hash: &expected.root_hash,
                writeback_digest: expected.writeback_digest.as_deref(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_index_state_digest = canonical_private_oram_recovery_index_state_digest(
        &intent.expected_collection_id,
        &expected_states,
    )?;
    if request.checkpoint.index_state_digest != expected_index_state_digest {
        return Err("private ORAM recovery checkpoint index digest mismatch".into());
    }

    let signing_key = Ed25519KeyPair::from_seed_unchecked(&[11; 32])
        .map_err(|_| std::io::Error::other("failed to create recovery fixture signing key"))?;
    let bundle =
        package_private_oram_external_recovery_checkpoint(&signing_key, request.checkpoint)?;
    println!("{}", serde_json::to_string(&bundle)?);
    Ok(())
}

fn verify_read_proofs_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = String::new();
    io::stdin().read_to_string(&mut encoded)?;
    let request: ReadProofVerificationRequest = serde_json::from_str(&encoded)?;
    let manifest = &request.hnsw.manifest;
    let keys = PrivateHnswClientKeys::derive_from_resource_key_with_context(
        &SecretKey::from_bytes(CLIENT_RESOURCE_KEY_SENTINEL),
        &manifest.collection_id,
        &manifest.vector_name,
        &manifest.key_id,
        manifest.rk_epoch,
    )?;
    let config = PrivateHnswOramClientConfig {
        tree_height: manifest.oram.tree_height,
        bucket_size: usize::try_from(manifest.oram.bucket_size)?,
        block_size_bytes: usize::try_from(manifest.oram.block_size_bytes)?,
        fixed_neighbor_slots: usize::try_from(manifest.hnsw.fixed_neighbor_slots)?,
    };
    if request.hnsw.response_index_epoch != request.hnsw.expected_index_epoch
        || request.hnsw.response_root_hash != request.hnsw.expected_root_hash
    {
        return Err("private HNSW ORAM response context mismatch".into());
    }
    let expected_hnsw_bucket_ids = private_hnsw_oram_bucket_ids_for_leaf_labels(
        request.hnsw.leaf_labels.iter().map(String::as_str),
        manifest.oram.tree_height,
        request.hnsw.bucket_count,
    )?;
    let response_hnsw_bucket_ids = request
        .hnsw
        .buckets
        .iter()
        .map(|bucket| bucket.bucket_id)
        .collect::<Vec<_>>();
    if response_hnsw_bucket_ids != expected_hnsw_bucket_ids {
        return Err("private HNSW ORAM response bucket set mismatch".into());
    }
    open_private_hnsw_oram_verified_path_batch(
        &keys,
        PrivateHnswBucketAeadBaseContext {
            collection_id: &manifest.collection_id,
            vector_name: &manifest.vector_name,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
        },
        config,
        request.hnsw.expected_index_epoch,
        &request.hnsw.expected_root_hash,
        request.hnsw.bucket_count,
        &request.hnsw.proof_value,
        &request.hnsw.buckets,
    )?;
    if request.result.response_index_epoch != request.result.expected_index_epoch
        || request.result.response_root_hash != request.result.expected_root_hash
    {
        return Err("private result ORAM response context mismatch".into());
    }
    let response_result_bucket_ids = request
        .result
        .buckets
        .iter()
        .map(|bucket| bucket.bucket_id)
        .collect::<Vec<_>>();
    if response_result_bucket_ids != request.result.bucket_ids {
        return Err("private result ORAM response bucket set mismatch".into());
    }
    verify_private_result_oram_merkle_proof_json(
        &request.result.proof_value,
        request.result.expected_index_epoch,
        &request.result.expected_root_hash,
        request.result.bucket_count,
        &request.result.buckets,
    )?;
    println!("{{\"verified\":true}}");
    Ok(())
}

/// `QDRANT_PRIVATE_ORAM_FIXTURE_LEAK_SCAN=1` swaps in points whose ids, tokens and vectors are
/// distinctive byte strings, so a cluster leakage scan can search storage and logs for them.
fn fixture_points() -> Vec<PrivateHnswBuildPoint> {
    if env::var("QDRANT_PRIVATE_ORAM_FIXTURE_LEAK_SCAN").as_deref() == Ok("1") {
        return (1_u8..=3)
            .map(|index| PrivateHnswBuildPoint {
                node_id: leak_scan_bytes(b"leak-scan-node-id", index),
                point_token: leak_scan_bytes(b"leak-scan-point-token", index),
                vector: vec![1234.5678 * f32::from(index), -8_765.432 + f32::from(index)],
                payload_fetch_token: Some(leak_scan_bytes(b"leak-scan-fetch-token", index)),
            })
            .collect();
    }
    vec![
        PrivateHnswBuildPoint {
            node_id: PLAINTEXT_NODE_ID_SENTINEL,
            point_token: PLAINTEXT_POINT_TOKEN_SENTINEL,
            vector: PLAINTEXT_VECTOR_SENTINEL.to_vec(),
            payload_fetch_token: Some(PLAINTEXT_FETCH_TOKEN_SENTINEL),
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

fn leak_scan_bytes(label: &[u8], index: u8) -> [u8; 32] {
    let mut bytes = [b'#'; 32];
    bytes[..label.len()].copy_from_slice(label);
    bytes[31] = b'0' + index;
    bytes
}

/// Hex-encoded byte strings that must never appear in server storage, snapshots or logs:
/// node ids, point and fetch tokens (raw and base64url), vectors (f32, f64, decimal text) and
/// the client resource key.
fn plaintext_sentinels(points: &[PrivateHnswBuildPoint]) -> Vec<String> {
    let mut sentinels = vec![CLIENT_RESOURCE_KEY_SENTINEL.to_vec()];
    for point in points {
        for token in [
            Some(point.node_id),
            Some(point.point_token),
            point.payload_fetch_token,
        ]
        .into_iter()
        .flatten()
        {
            sentinels.push(token.to_vec());
            sentinels.push(BASE64URL_NOPAD.encode(&token).into_bytes());
        }
        sentinels.push(
            point
                .vector
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect(),
        );
        sentinels.push(
            point
                .vector
                .iter()
                .flat_map(|value| f64::from(*value).to_le_bytes())
                .collect(),
        );
        for value in &point.vector {
            let text = format!("{value}");
            if text.len() >= 8 {
                sentinels.push(text.into_bytes());
            }
        }
    }
    sentinels
        .into_iter()
        .map(|bytes| data_encoding::HEXLOWER.encode(&bytes))
        .collect()
}

fn hnsw_fixture(
    collection_id: &str,
    signing_key: &Ed25519KeyPair,
    profile: FixtureProfile,
    result_privacy: ResultPrivacyMode,
    options: HnswFixtureOptions<'_>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let config = PrivateHnswOramClientConfig {
        tree_height: profile.tree_height,
        bucket_size: 2,
        block_size_bytes: profile.hnsw_block_size_bytes,
        fixed_neighbor_slots: 4,
    };
    let points = fixture_points();
    if options.logical_node_count == 0 || options.logical_node_count > points.len() {
        return Err("HNSW fixture logical node count is invalid".into());
    }
    let point_leaves = [0, 1, 2];
    let mut plaintext = build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
        config,
        DistanceKind::Euclid,
        2,
        1,
        2,
        &points[..options.logical_node_count],
        &point_leaves[..options.logical_node_count],
    )?;
    // `QDRANT_PRIVATE_ORAM_FIXTURE_RESERVED_SLOTS=<n>` keeps n physical slots free, as an index
    // that will enroll into private ORAM mutation V2 must.
    if let Ok(reserved) = env::var("QDRANT_PRIVATE_ORAM_FIXTURE_RESERVED_SLOTS") {
        reserve_private_hnsw_oram_physical_slots(&mut plaintext, reserved.parse()?)?;
    }
    let keys = PrivateHnswClientKeys::derive_from_resource_key_with_context(
        &SecretKey::from_bytes(CLIENT_RESOURCE_KEY_SENTINEL),
        collection_id,
        VECTOR_NAME,
        KEY_ID,
        RK_EPOCH,
    )?;
    let base_context = PrivateHnswBucketAeadBaseContext {
        collection_id,
        vector_name: VECTOR_NAME,
        key_id: KEY_ID,
        rk_id: KEY_ID,
        rk_epoch: RK_EPOCH,
    };
    let client_state = if options.include_client_state {
        let mut records = plaintext
            .buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .map(|block| {
                json!({
                    "node_id": BASE64URL_NOPAD.encode(&block.node_id),
                    "point_token": BASE64URL_NOPAD.encode(&block.point_token),
                    "level_mask": block.level_mask,
                    "generation": block.generation,
                })
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left["node_id"].as_str().cmp(&right["node_id"].as_str()));
        Some(json!({
            "entry_node_id": BASE64URL_NOPAD.encode(&plaintext.entry_node_id),
            "snapshot": plaintext.state.to_snapshot(config.tree_height)?,
            "records": records,
        }))
    } else {
        None
    };
    let encrypted = seal_private_hnsw_oram_plaintext_index(
        &keys,
        base_context,
        BASE_EPOCH,
        &plaintext,
        config,
    )?;
    let mut manifest = build_private_hnsw_oram_manifest_from_encrypted_index(
        PrivateHnswManifestBuildContext {
            collection_id,
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
                block_size_bytes: profile.hnsw_block_size_bytes as u32,
                tree_height: profile.tree_height,
                path_batch_size: 1,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 1,
                base_layer_steps: 3,
                paths_per_round: 1,
                fixed_result_k: 1,
            },
            result_privacy,
            owner_signing_key_id: options.owner_signing_key_id,
            created_at_unix: 1_770_000_000,
        },
        &encrypted,
    )?;
    if let Some(dummy_node_count) = options.dummy_node_count {
        if dummy_node_count == 0 || dummy_node_count > manifest.dummy_node_count {
            return Err("mutation V2 HNSW dummy capacity is invalid".into());
        }
        manifest.dummy_node_count = dummy_node_count;
    }
    let manifest_signature = sign_private_hnsw_oram_manifest(signing_key, &manifest)?;
    let path = encode_private_hnsw_oram_leaf_label(0, manifest.oram.tree_height)?;
    let read_paths = vec![path];
    let read_signature = sign_private_hnsw_oram_read_paths_for_manifest_context(
        signing_key,
        &manifest,
        BASE_EPOCH,
        &manifest.root_hash,
        &read_paths,
    )?;

    let updated_plaintext = open_private_hnsw_oram_plaintext_bucket(
        &keys,
        base_context,
        &encrypted.buckets[0],
        config,
    )?;
    let updated_bucket = seal_private_hnsw_oram_plaintext_bucket(
        &keys,
        base_context,
        NEXT_EPOCH,
        &updated_plaintext,
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
        signing_key,
        PrivateHnswCommitSignatureContext {
            collection_id,
            vector_name: VECTOR_NAME,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
            signing_key_id: options.owner_signing_key_id,
        },
        &commit_plan,
    )?;
    let (refreshed_manifest, refreshed_manifest_signature) =
        sign_private_hnsw_oram_manifest_refresh(signing_key, &manifest, &commit_plan)?;
    let restart_read_signature = sign_private_hnsw_oram_read_paths_for_manifest_context(
        signing_key,
        &manifest,
        NEXT_EPOCH,
        &commit_plan.new_root_hash,
        &read_paths,
    )?;

    let restart_plaintext =
        open_private_hnsw_oram_plaintext_bucket(&keys, base_context, &updated_bucket, config)?;
    let restart_updated_bucket = seal_private_hnsw_oram_plaintext_bucket(
        &keys,
        base_context,
        SECOND_EPOCH,
        &restart_plaintext,
        config,
    )?;
    let restart_commit_plan = plan_private_hnsw_oram_commit_for_manifest_context(
        &manifest,
        NEXT_EPOCH,
        SECOND_EPOCH,
        &commit_plan.new_root_hash,
        &commit_plan.leaf_commitments,
        std::slice::from_ref(&restart_updated_bucket),
    )?;
    let restart_commit_signature = sign_private_hnsw_oram_commit(
        signing_key,
        PrivateHnswCommitSignatureContext {
            collection_id,
            vector_name: VECTOR_NAME,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
            signing_key_id: options.owner_signing_key_id,
        },
        &restart_commit_plan,
    )?;

    let mut output = json!({
        "plaintext_sentinels": plaintext_sentinels(&points[..options.logical_node_count]),
        "manifest": manifest,
        "manifest_signature": manifest_signature,
        "buckets": encrypted.buckets,
        "read": {
            "paths": read_paths,
            "signature": read_signature,
        },
        "commit": {
            "old_epoch": commit_plan.old_epoch,
            "new_epoch": commit_plan.new_epoch,
            "old_root_hash": commit_plan.old_root_hash,
            "new_root_hash": commit_plan.new_root_hash,
            "updated_buckets": [updated_bucket],
            "signature": commit_signature,
        },
        "manifest_refresh": {
            "manifest": refreshed_manifest,
            "signature": refreshed_manifest_signature,
        },
        "restart_read": {
            "paths": read_paths,
            "signature": restart_read_signature,
        },
        "restart_commit": {
            "old_epoch": restart_commit_plan.old_epoch,
            "new_epoch": restart_commit_plan.new_epoch,
            "old_root_hash": restart_commit_plan.old_root_hash,
            "new_root_hash": restart_commit_plan.new_root_hash,
            "updated_buckets": [restart_updated_bucket],
            "signature": restart_commit_signature,
        },
    });
    if let Some(client_state) = client_state {
        output["client_state"] = client_state;
    }
    Ok(output)
}

fn plaintext_leakage_sentinels(
    client_recovery_state_base64url: &str,
    encrypted_client_state_ciphertext: &str,
    encrypted_client_state_ciphertext_sha256: &str,
) -> serde_json::Value {
    let vector_f32_le = PLAINTEXT_VECTOR_SENTINEL
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    json!([
        {
            "name": "vector-f32-le",
            "base64url": BASE64URL_NOPAD.encode(&vector_f32_le),
        },
        {
            "name": "vector-json",
            "base64url": BASE64URL_NOPAD.encode(b"12345.125,-23456.25"),
        },
        {
            "name": "vector-debug",
            "base64url": BASE64URL_NOPAD.encode(b"[12345.125, -23456.25]"),
        },
        {
            "name": "node-id",
            "base64url": BASE64URL_NOPAD.encode(&PLAINTEXT_NODE_ID_SENTINEL),
        },
        {
            "name": "point-token",
            "base64url": BASE64URL_NOPAD.encode(&PLAINTEXT_POINT_TOKEN_SENTINEL),
        },
        {
            "name": "payload-fetch-token",
            "base64url": BASE64URL_NOPAD.encode(&PLAINTEXT_FETCH_TOKEN_SENTINEL),
        },
        {
            "name": "client-resource-key",
            "base64url": BASE64URL_NOPAD.encode(&CLIENT_RESOURCE_KEY_SENTINEL),
        },
        {
            "name": "result-payload",
            "base64url": BASE64URL_NOPAD.encode(PLAINTEXT_RESULT_PAYLOAD_SENTINEL),
        },
        {
            "name": "client-recovery-fetch-token",
            "base64url": BASE64URL_NOPAD.encode(&CLIENT_RECOVERY_FETCH_TOKEN_SENTINEL),
        },
        {
            "name": "client-recovery-point-token",
            "base64url": BASE64URL_NOPAD.encode(&CLIENT_RECOVERY_POINT_TOKEN_SENTINEL),
        },
        {
            "name": "client-recovery-payload",
            "base64url": BASE64URL_NOPAD.encode(CLIENT_RECOVERY_PAYLOAD_SENTINEL),
        },
        {
            "name": "forbidden-complete-encrypted-client-recovery-state",
            "base64url": client_recovery_state_base64url,
        },
        {
            "name": "forbidden-component-client-state-ciphertext",
            "base64url": encrypted_client_state_ciphertext,
        },
        {
            "name": "forbidden-component-client-state-ciphertext-sha256",
            "base64url": encrypted_client_state_ciphertext_sha256,
        },
    ])
}

fn result_fixture(
    collection_id: &str,
    signing_key: &Ed25519KeyPair,
    profile: FixtureProfile,
    options: ResultFixtureOptions<'_>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let oram = OramParams {
        kind: OramKind::PathOram,
        bucket_size: 2,
        block_size_bytes: profile.result_block_size_bytes,
        tree_height: profile.tree_height,
        path_batch_size: 1,
    };
    let config = PrivateResultOramClientConfig {
        tree_height: oram.tree_height,
        bucket_size: oram.bucket_size as usize,
        block_size_bytes: oram.block_size_bytes as usize,
    };
    let bucket_count = (1_u64 << (oram.tree_height + 1)) - 1;
    let mut manifest = PrivateResultOramManifest {
        version: 1,
        provider: qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
        binding: qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string(),
        collection_id: collection_id.to_string(),
        key_id: KEY_ID.to_string(),
        rk_id: KEY_ID.to_string(),
        rk_epoch: RK_EPOCH,
        oram,
        index_epoch: BASE_EPOCH,
        root_hash: BASE64URL_NOPAD.encode(&[0; 32]),
        bucket_count,
        logical_result_count: u64::try_from(options.logical_result_count)?,
        dummy_result_count: options.dummy_result_count,
        owner_signing_key_id: options.owner_signing_key_id.to_string(),
        created_at_unix: 1_770_000_000,
    };
    let keys = PrivateResultOramClientKeys::derive_from_resource_key_with_context(
        &SecretKey::from_bytes(CLIENT_RESOURCE_KEY_SENTINEL),
        collection_id,
        KEY_ID,
        RK_EPOCH,
    )?;
    let base_context = PrivateResultOramBucketAeadBaseContext {
        collection_id,
        key_id: KEY_ID,
        rk_id: KEY_ID,
        rk_epoch: RK_EPOCH,
    };
    let mut payload_blocks = [
        (
            0,
            PrivateResultOramPayloadBlockPlaintext {
                version: 1,
                payload_fetch_token: PLAINTEXT_FETCH_TOKEN_SENTINEL,
                point_token: PLAINTEXT_POINT_TOKEN_SENTINEL,
                payload: PLAINTEXT_RESULT_PAYLOAD_SENTINEL.to_vec(),
                deleted: false,
                generation: 7,
            },
        ),
        (
            1,
            PrivateResultOramPayloadBlockPlaintext {
                version: 1,
                payload_fetch_token: [102; 32],
                point_token: [22; 32],
                payload: br#"{"body":"second private result"}"#.to_vec(),
                deleted: false,
                generation: 7,
            },
        ),
        (
            2,
            PrivateResultOramPayloadBlockPlaintext {
                version: 1,
                payload_fetch_token: [103; 32],
                point_token: [33; 32],
                payload: br#"{"body":"third private result"}"#.to_vec(),
                deleted: false,
                generation: 7,
            },
        ),
    ];
    let leak_scan = env::var("QDRANT_PRIVATE_ORAM_FIXTURE_LEAK_SCAN").as_deref() == Ok("1");
    if leak_scan {
        for (index, (_, block)) in payload_blocks.iter_mut().enumerate() {
            let index = u8::try_from(index + 1)?;
            block.payload_fetch_token = leak_scan_bytes(b"leak-scan-fetch-token", index);
            block.point_token = leak_scan_bytes(b"leak-scan-point-token", index);
            block.payload =
                format!("{{\"body\":\"leak-scan-result-payload-{index}\"}}").into_bytes();
            block.generation = 1;
        }
    }
    if options.logical_result_count == 0 || options.logical_result_count > payload_blocks.len() {
        return Err("result fixture logical result count is invalid".into());
    }
    let payload_blocks = &payload_blocks[..options.logical_result_count];
    let mut plaintext_buckets = (0..bucket_count)
        .map(|bucket_id| empty_private_result_oram_plaintext_bucket(bucket_id, config))
        .collect::<Result<Vec<_>, _>>()?;
    for (leaf, block) in payload_blocks {
        let leaf_bucket_id = *private_result_oram_bucket_ids_for_leaf(*leaf, config.tree_height)?
            .last()
            .ok_or("private result ORAM path must contain a leaf bucket")?;
        let leaf_bucket = plaintext_buckets
            .get_mut(usize::try_from(leaf_bucket_id)?)
            .ok_or("private result ORAM leaf bucket is missing")?;
        let slot = leaf_bucket
            .blocks
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or("private result ORAM leaf bucket is full")?;
        *slot = Some(block.clone());
    }
    let buckets = plaintext_buckets
        .iter()
        .map(|bucket| {
            seal_private_result_oram_plaintext_bucket(
                &keys,
                base_context,
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
    let sentinel_leaf_bucket_id = *private_result_oram_bucket_ids_for_leaf(0, config.tree_height)?
        .last()
        .ok_or("private result ORAM path must contain a leaf bucket")?;
    let reopened_sentinel_bucket = open_private_result_oram_plaintext_bucket(
        &keys,
        base_context,
        buckets
            .get(usize::try_from(sentinel_leaf_bucket_id)?)
            .ok_or("private result ORAM sentinel bucket is missing")?,
        config,
    )?;
    if reopened_sentinel_bucket.blocks[0].as_ref() != Some(&payload_blocks[0].1) {
        return Err("private result ORAM sentinel payload did not round-trip".into());
    }

    let mut client_state = PrivateResultOramClientState::with_position_map(
        payload_blocks
            .iter()
            .map(|(leaf, block)| (block.payload_fetch_token, *leaf)),
        config.tree_height,
    )?;
    if options.include_recovery_stash {
        client_state.insert_new_stash_block(
            PrivateResultOramPayloadBlockPlaintext {
                version: 1,
                payload_fetch_token: CLIENT_RECOVERY_FETCH_TOKEN_SENTINEL,
                point_token: CLIENT_RECOVERY_POINT_TOKEN_SENTINEL,
                payload: CLIENT_RECOVERY_PAYLOAD_SENTINEL.to_vec(),
                deleted: false,
                generation: 7,
            },
            3,
            config,
        )?;
    }
    let client_state_snapshot = client_state.to_snapshot(config.tree_height)?;
    let encrypted_client_state = seal_private_result_oram_client_state_snapshot(
        &keys,
        PrivateResultOramClientStateAeadContext {
            collection_id,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
            index_epoch: BASE_EPOCH,
            root_hash: &manifest.root_hash,
        },
        &client_state_snapshot,
        PrivateResultOramClientStateSnapshotPadding {
            block_size_bytes: config.block_size_bytes,
            stash_capacity: config.bucket_size * (usize::try_from(config.tree_height)? + 1),
        },
    )?;
    let client_recovery_state = serde_json::to_vec(&encrypted_client_state)?;
    let manifest_signature = sign_private_result_oram_manifest(signing_key, &manifest)?;
    let read_bucket_ids = (0..=manifest.oram.tree_height)
        .map(|level| (1_u64 << level) - 1)
        .collect::<Vec<_>>();
    let read_signature = sign_private_result_oram_read_buckets(
        signing_key,
        PrivateResultOramReadBucketsSignatureContext {
            collection_id,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
            signing_key_id: options.owner_signing_key_id,
        },
        BASE_EPOCH,
        &manifest.root_hash,
        manifest.bucket_count,
        &read_bucket_ids,
    )?;

    let updated_plaintext =
        open_private_result_oram_plaintext_bucket(&keys, base_context, &buckets[0], config)?;
    let updated_bucket = seal_private_result_oram_plaintext_bucket(
        &keys,
        base_context,
        NEXT_EPOCH,
        &updated_plaintext,
        config,
    )?;
    let mut next_commitments = buckets
        .iter()
        .map(|bucket| bucket.bucket_commitment.clone())
        .collect::<Vec<_>>();
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
        signing_key,
        PrivateResultOramCommitSignatureContext {
            collection_id,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
            signing_key_id: options.owner_signing_key_id,
        },
        &commit_plan,
    )?;
    let (refreshed_manifest, refreshed_manifest_signature) =
        sign_private_result_oram_manifest_refresh(signing_key, &manifest, &commit_plan)?;
    let restart_read_signature = sign_private_result_oram_read_buckets(
        signing_key,
        PrivateResultOramReadBucketsSignatureContext {
            collection_id,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
            signing_key_id: options.owner_signing_key_id,
        },
        NEXT_EPOCH,
        &commit_plan.new_root_hash,
        manifest.bucket_count,
        &read_bucket_ids,
    )?;

    let restart_plaintext =
        open_private_result_oram_plaintext_bucket(&keys, base_context, &updated_bucket, config)?;
    let restart_updated_bucket = seal_private_result_oram_plaintext_bucket(
        &keys,
        base_context,
        SECOND_EPOCH,
        &restart_plaintext,
        config,
    )?;
    let mut restart_commitments = commit_plan.leaf_commitments.clone();
    restart_commitments[0] = restart_updated_bucket.bucket_commitment.clone();
    let restart_root_hash = private_result_oram_merkle_root_for_commitments(&restart_commitments)?;
    let restart_commit_plan = PrivateResultOramCommitPlan {
        old_epoch: NEXT_EPOCH,
        new_epoch: SECOND_EPOCH,
        old_root_hash: commit_plan.new_root_hash.clone(),
        new_root_hash: restart_root_hash.clone(),
        leaf_commitments: restart_commitments,
        updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
            bucket_id: restart_updated_bucket.bucket_id,
            ciphertext_sha256: restart_updated_bucket.ciphertext_sha256.clone(),
        }],
    };
    let restart_commit_signature = sign_private_result_oram_commit(
        signing_key,
        PrivateResultOramCommitSignatureContext {
            collection_id,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
            signing_key_id: options.owner_signing_key_id,
        },
        &restart_commit_plan,
    )?;

    let plaintext_sentinels = if leak_scan {
        let mut sentinels = vec![
            b"leak-scan-result-payload".to_vec(),
            keys.bucket_aead_key().as_bytes().to_vec(),
        ];
        for (_, block) in payload_blocks {
            sentinels.push(block.payload.clone());
            sentinels.push(BASE64URL_NOPAD.encode(&block.payload).into_bytes());
        }
        sentinels
            .into_iter()
            .map(|bytes| data_encoding::HEXLOWER.encode(&bytes))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut output = json!({
        "plaintext_sentinels": plaintext_sentinels,
        "manifest": manifest,
        "manifest_signature": manifest_signature,
        "buckets": buckets,
        "encrypted_client_state": encrypted_client_state,
        "client_recovery_state_base64url": BASE64URL_NOPAD.encode(&client_recovery_state),
        "read": {
            "bucket_ids": read_bucket_ids,
            "signature": read_signature,
        },
        "commit": {
            "old_epoch": BASE_EPOCH,
            "new_epoch": NEXT_EPOCH,
            "old_root_hash": commit_plan.old_root_hash,
            "new_root_hash": new_root_hash,
            "updated_buckets": [updated_bucket],
            "signature": commit_signature,
        },
        "manifest_refresh": {
            "manifest": refreshed_manifest,
            "signature": refreshed_manifest_signature,
        },
        "restart_read": {
            "bucket_ids": read_bucket_ids,
            "signature": restart_read_signature,
        },
        "restart_commit": {
            "old_epoch": restart_commit_plan.old_epoch,
            "new_epoch": restart_commit_plan.new_epoch,
            "old_root_hash": restart_commit_plan.old_root_hash,
            "new_root_hash": restart_root_hash,
            "updated_buckets": [restart_updated_bucket],
            "signature": restart_commit_signature,
        },
    });
    if options.include_client_state {
        output["client_state"] = json!({
            "snapshot": client_state_snapshot,
            "records": payload_blocks.iter().map(|(_, block)| json!({
                "payload_fetch_token": BASE64URL_NOPAD.encode(&block.payload_fetch_token),
                "point_token": BASE64URL_NOPAD.encode(&block.point_token),
                "generation": block.generation,
            })).collect::<Vec<_>>(),
        });
    }
    Ok(output)
}
