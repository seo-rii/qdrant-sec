//! Client-side cost of one private ORAM V2 append (docs/ckks.md, V2-E benchmarks): latency
//! of the HNSW and result append transactions, and the bucket bytes read and written per
//! appended point. The fixtures are copied from `tests/private_oram_append_client.rs`.

#![allow(dead_code)]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

fn digest(byte: u8) -> String {
    BASE64URL_NOPAD.encode(&[byte; 32])
}

fn deterministic_owner_key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap()
}

fn refresh_hnsw_prepared_commit_digest(
    manifest: &PrivateOramImmutableManifestV2,
    output: &mut PrivateOramAppendHnswTransactionOutputV2,
) {
    let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest).unwrap();
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
        })
        .unwrap();
    output.recovery_marker.prepared_commit_digest = Some(
        private_oram_append_hnsw_prepared_commit_v4_digest(
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
        )
        .unwrap(),
    );
}

fn merkle_levels(commitments: &[String]) -> Vec<Vec<[u8; 32]>> {
    let mut leaves = commitments
        .iter()
        .map(|commitment| {
            BASE64URL_NOPAD
                .decode(commitment.as_bytes())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<_>>();
    leaves.resize(leaves.len().next_power_of_two(), [0; 32]);
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let next = levels
            .last()
            .unwrap()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update([1]);
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                hasher.finalize().into()
            })
            .collect();
        levels.push(next);
    }
    levels
}

fn hnsw_merkle_proof(
    index_epoch: u64,
    commitments: &[String],
    bucket_ids: &[u64],
) -> PrivateHnswOramMerkleProof {
    let levels = merkle_levels(commitments);
    PrivateHnswOramMerkleProof {
        kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
        index_epoch,
        root_hash: BASE64URL_NOPAD.encode(&levels.last().unwrap()[0]),
        bucket_count: commitments.len().try_into().unwrap(),
        leaves: bucket_ids
            .iter()
            .map(|bucket_id| {
                let mut index = usize::try_from(*bucket_id).unwrap();
                let siblings = levels[..levels.len() - 1]
                    .iter()
                    .enumerate()
                    .map(|(level, hashes)| {
                        let sibling_index = index ^ 1;
                        let sibling = PrivateHnswOramMerkleSibling {
                            level: level.try_into().unwrap(),
                            position: if index % 2 == 0 {
                                PrivateHnswMerkleSiblingPosition::Right
                            } else {
                                PrivateHnswMerkleSiblingPosition::Left
                            },
                            hash: BASE64URL_NOPAD.encode(&hashes[sibling_index]),
                        };
                        index /= 2;
                        sibling
                    })
                    .collect();
                PrivateHnswOramMerkleProofLeaf {
                    bucket_id: *bucket_id,
                    leaf_hash: commitments[usize::try_from(*bucket_id).unwrap()].clone(),
                    siblings,
                }
            })
            .collect(),
    }
}

fn result_merkle_proof(
    index_epoch: u64,
    commitments: &[String],
    bucket_ids: &[u64],
) -> PrivateResultOramMerkleProof {
    let levels = merkle_levels(commitments);
    PrivateResultOramMerkleProof {
        kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
        index_epoch,
        root_hash: BASE64URL_NOPAD.encode(&levels.last().unwrap()[0]),
        bucket_count: commitments.len().try_into().unwrap(),
        leaves: bucket_ids
            .iter()
            .map(|bucket_id| {
                let mut index = usize::try_from(*bucket_id).unwrap();
                let siblings = levels[..levels.len() - 1]
                    .iter()
                    .enumerate()
                    .map(|(level, hashes)| {
                        let sibling_index = index ^ 1;
                        let sibling = PrivateResultOramMerkleSibling {
                            level: level.try_into().unwrap(),
                            position: if index % 2 == 0 {
                                PrivateResultOramMerkleSiblingPosition::Right
                            } else {
                                PrivateResultOramMerkleSiblingPosition::Left
                            },
                            hash: BASE64URL_NOPAD.encode(&hashes[sibling_index]),
                        };
                        index /= 2;
                        sibling
                    })
                    .collect();
                PrivateResultOramMerkleProofLeaf {
                    bucket_id: *bucket_id,
                    leaf_hash: commitments[usize::try_from(*bucket_id).unwrap()].clone(),
                    siblings,
                }
            })
            .collect(),
    }
}

fn append_bucket(bucket_id: u64, byte: u8) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id,
        ciphertext_sha256: digest(byte.wrapping_add(64)),
        bucket_commitment: digest(byte),
    }
}

fn checkpoint_candidate_block() -> PrivateHnswNodeBlockPlaintext {
    PrivateHnswNodeBlockPlaintext {
        version: 1,
        node_id: [2; 32],
        point_token: [3; 32],
        level_mask: 1,
        vector_encoding: PrivateHnswVectorEncoding::F32Le,
        vector: [1.0f32, 0.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect(),
        neighbors: vec![],
        neighbor_levels: vec![],
        deleted: false,
        generation: 0,
        payload_fetch_token: Some([4; 32]),
    }
}

fn oram() -> OramParams {
    OramParams {
        kind: OramKind::PathOram,
        bucket_size: 2,
        block_size_bytes: 512,
        tree_height: 2,
        path_batch_size: 1,
    }
}

fn capacity() -> PrivateOramIndexCapacityV2 {
    PrivateOramIndexCapacityV2 {
        bucket_count: 7,
        logical_capacity: 4,
        reserved_physical_slots: 4,
        max_client_stash_blocks: 4,
        fixed_append_read_path_count: 4,
        fixed_append_write_bucket_count: 12,
    }
}

fn manifest() -> PrivateOramImmutableManifestV2 {
    PrivateOramImmutableManifestV2 {
        version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
        collection_id: "collection-uuid-1".to_string(),
        manifest_nonce: digest(1),
        indexes: vec![
            PrivateOramImmutableIndexV2 {
                index_name: "text".to_string(),
                params: PrivateOramImmutableIndexParamsV2::Hnsw {
                    provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                    binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                    key_id: "tenant-a/vector-rk".to_string(),
                    rk_id: "tenant-a/vector-rk".to_string(),
                    rk_epoch: 7,
                    dim: 2,
                    vector_encoding: PrivateHnswVectorEncoding::F32Le,
                    distance: DistanceKind::Cosine,
                    hnsw: PrivateHnswParams {
                        m: 2,
                        ef_construction: 8,
                        max_layers: 4,
                        fixed_neighbor_slots: 2,
                    },
                    oram: oram(),
                    fixed_search_budget: FixedBudgetParams {
                        enabled: true,
                        upper_layer_steps: 2,
                        base_layer_steps: 4,
                        paths_per_round: 1,
                        fixed_result_k: 1,
                    },
                    max_neighbor_rewrites: 1,
                },
                capacity: capacity(),
            },
            PrivateOramImmutableIndexV2 {
                index_name: "private-payload".to_string(),
                params: PrivateOramImmutableIndexParamsV2::Result {
                    provider: PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
                    binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
                    key_id: "tenant-a/result-rk".to_string(),
                    rk_id: "tenant-a/result-rk".to_string(),
                    rk_epoch: 7,
                    oram: oram(),
                },
                capacity: capacity(),
            },
        ],
        result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
        owner_signing_key_id: "tenant-a/private-oram-owner-v2".to_string(),
        created_at_unix: 1_770_000_000,
    }
}

fn checkpoint(manifest: &PrivateOramImmutableManifestV2) -> PrivateOramAppendClientCheckpointV2 {
    let node_id = [2; 32];
    let point_token = [3; 32];
    let payload_fetch_token = [4; 32];
    PrivateOramAppendClientCheckpointV2 {
        version: PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_V2_VERSION,
        collection_id: manifest.collection_id.clone(),
        manifest_digest: private_oram_immutable_manifest_v2_digest(manifest).unwrap(),
        layout_generation: 5,
        state_sequence: 7,
        points: vec![PrivateOramAppendPointRecordV2 {
            point_token: BASE64URL_NOPAD.encode(&point_token),
            visible_point_id: None,
            payload_fetch_token: Some(BASE64URL_NOPAD.encode(&payload_fetch_token)),
        }],
        indexes: vec![
            PrivateOramAppendClientIndexCheckpointV2::Hnsw {
                index_name: "text".to_string(),
                index_epoch: 11,
                root_hash: digest(5),
                entry_node_id: Some(BASE64URL_NOPAD.encode(&node_id)),
                state: PrivateHnswOramClientStateSnapshot {
                    version: 1,
                    tree_height: 2,
                    positions: vec![PrivateHnswPositionMapSnapshotEntry {
                        node_id: BASE64URL_NOPAD.encode(&node_id),
                        leaf_label: encode_private_hnsw_oram_leaf_label(1, 2).unwrap(),
                    }],
                    stash: vec![],
                },
                records: vec![PrivateOramAppendHnswRecordV2 {
                    node_id: BASE64URL_NOPAD.encode(&node_id),
                    point_token: BASE64URL_NOPAD.encode(&point_token),
                    level_mask: 1,
                    generation: 0,
                }],
            },
            PrivateOramAppendClientIndexCheckpointV2::Result {
                index_name: "private-payload".to_string(),
                index_epoch: 11,
                root_hash: digest(6),
                state: PrivateResultOramClientStateSnapshot {
                    version: 1,
                    tree_height: 2,
                    positions: vec![PrivateResultOramPositionMapSnapshotEntry {
                        payload_fetch_token: BASE64URL_NOPAD.encode(&payload_fetch_token),
                        leaf_label: encode_private_result_oram_leaf_label(1, 2).unwrap(),
                    }],
                    stash: vec![],
                },
                records: vec![PrivateOramAppendResultRecordV2 {
                    payload_fetch_token: BASE64URL_NOPAD.encode(&payload_fetch_token),
                    point_token: BASE64URL_NOPAD.encode(&point_token),
                    generation: 0,
                }],
            },
        ],
    }
}

fn state(
    manifest: &PrivateOramImmutableManifestV2,
    client_state_digest: String,
) -> PrivateOramSignedStateV2 {
    PrivateOramSignedStateV2 {
        version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        collection_id: manifest.collection_id.clone(),
        manifest_digest: private_oram_immutable_manifest_v2_digest(manifest).unwrap(),
        layout_generation: 5,
        layout_digest: digest(7),
        state_sequence: 7,
        indexes: vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: "text".to_string(),
                index_epoch: 11,
                root_hash: digest(5),
                logical_count: 1,
                dummy_count: 3,
                last_writeback_digest: digest(8),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: "private-payload".to_string(),
                index_epoch: 11,
                root_hash: digest(6),
                logical_count: 1,
                dummy_count: 3,
                last_writeback_digest: digest(9),
            },
        ],
        client_state_digest,
        last_mutation_id: Some(digest(10)),
        owner_signing_key_id: manifest.owner_signing_key_id.clone(),
        signed_at_unix: 1_770_000_100,
    }
}

fn sealed_checkpoint_fixture() -> (
    SecretKey,
    PrivateOramImmutableManifestV2,
    PrivateOramSignedStateV2,
    PrivateOramEncryptedAppendClientCheckpointV2,
) {
    let key = SecretKey::from_bytes([11; 32]);
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let sealed = seal_private_oram_append_client_checkpoint_v2(&key, &checkpoint).unwrap();
    let state = state(
        &manifest,
        private_oram_append_client_checkpoint_v2_digest(&sealed).unwrap(),
    );
    let encrypted = bind_private_oram_append_client_checkpoint_v2(sealed, &state).unwrap();
    (key, manifest, state, encrypted)
}

struct HnswAppendTransactionFixture {
    manifest: PrivateOramImmutableManifestV2,
    state: PrivateOramSignedStateV2,
    checkpoint: PrivateOramAppendClientCheckpointV2,
    keys: PrivateHnswClientKeys,
    buckets: Vec<PrivateHnswOramBucket>,
}

fn hnsw_append_transaction_fixture() -> HnswAppendTransactionFixture {
    hnsw_append_transaction_fixture_with_path_batch_size(1)
}

fn hnsw_append_transaction_fixture_with_path_batch_size(
    path_batch_size: u32,
) -> HnswAppendTransactionFixture {
    hnsw_append_transaction_fixture_with_candidate_generation(path_batch_size, None)
}

fn hnsw_append_transaction_fixture_with_candidate_generation(
    path_batch_size: u32,
    candidate_generation: Option<u64>,
) -> HnswAppendTransactionFixture {
    let mut manifest = manifest();
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        oram,
        fixed_search_budget,
        ..
    } = &mut manifest.indexes[0].params
    else {
        panic!("fixture HNSW manifest is missing");
    };
    oram.path_batch_size = path_batch_size;
    fixed_search_budget.paths_per_round = path_batch_size;
    let mut checkpoint = checkpoint(&manifest);
    let config = PrivateHnswOramClientConfig {
        tree_height: 2,
        bucket_size: 2,
        block_size_bytes: 512,
        fixed_neighbor_slots: 2,
    };
    let mut plaintext_buckets = (0..capacity().bucket_count)
        .map(|bucket_id| empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    let mut candidate = checkpoint_candidate_block();
    if let Some(generation) = candidate_generation {
        candidate.generation = generation;
    }
    let candidate_leaf_bucket = *private_hnsw_oram_bucket_ids_for_leaf(1, 2)
        .unwrap()
        .last()
        .unwrap();
    plaintext_buckets[usize::try_from(candidate_leaf_bucket).unwrap()].blocks[0] = Some(candidate);

    let resource_key = SecretKey::from_bytes([31; 32]);
    let keys = PrivateHnswClientKeys::derive_from_resource_key_with_context(
        &resource_key,
        &manifest.collection_id,
        "text",
        "tenant-a/vector-rk",
        7,
    )
    .unwrap();
    let base_context = PrivateHnswBucketAeadBaseContext {
        collection_id: &manifest.collection_id,
        vector_name: "text",
        key_id: "tenant-a/vector-rk",
        rk_id: "tenant-a/vector-rk",
        rk_epoch: 7,
    };
    let buckets = plaintext_buckets
        .iter()
        .map(|bucket| {
            seal_private_hnsw_oram_plaintext_bucket(&keys, base_context, 11, bucket, config)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let root_hash = private_hnsw_oram_merkle_root_for_commitments(
        &buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        root_hash: checkpoint_root,
        ..
    } = &mut checkpoint.indexes[0]
    else {
        panic!("fixture HNSW checkpoint is missing");
    };
    *checkpoint_root = root_hash.clone();
    let mut state = state(&manifest, digest(30));
    state.indexes[0].root_hash = root_hash;

    HnswAppendTransactionFixture {
        manifest,
        state,
        checkpoint,
        keys,
        buckets,
    }
}

fn hnsw_append_transaction_plan() -> PrivateOramAppendHnswTransactionPlanV2 {
    PrivateOramAppendHnswTransactionPlanV2 {
        index_name: "text".to_string(),
        mutation_id: digest(20),
        writer_lease_digest: digest(21),
        writer_fence: 3,
        paths_per_window: 1,
        candidate_node_ids: vec![[2; 32]],
        candidate_remap_leaves: vec![2],
        rewrite_remap_leaves: vec![0],
        padding_leaves: vec![3, 1, 2, 0],
    }
}

fn hnsw_append_transaction_point() -> PrivateOramAppendLevel0PointV2 {
    PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![0.0, 1.0],
        initial_leaf: 3,
    }
}

fn encrypted_hnsw_window_batch(
    window: &PrivateOramAppendReadWindowV1,
    buckets: &[PrivateHnswOramBucket],
) -> PrivateHnswEncryptedPathBatch {
    let bucket_ids = window
        .paths
        .iter()
        .map(|leaf_label| decode_private_hnsw_oram_leaf_label(leaf_label, 2).unwrap())
        .flat_map(|leaf| private_hnsw_oram_bucket_ids_for_leaf(leaf, 2).unwrap())
        .collect::<Vec<_>>();
    let commitments = buckets
        .iter()
        .map(|bucket| bucket.bucket_commitment.clone())
        .collect::<Vec<_>>();
    let proof = hnsw_merkle_proof(11, &commitments, &bucket_ids);
    PrivateHnswEncryptedPathBatch {
        index_epoch: 11,
        root_hash: proof.root_hash.clone(),
        bucket_count: buckets.len().try_into().unwrap(),
        proof_value: serde_json::to_string(&proof).unwrap(),
        buckets: bucket_ids
            .iter()
            .map(|bucket_id| buckets[usize::try_from(*bucket_id).unwrap()].clone())
            .collect(),
    }
}

fn hnsw_leaf_label(leaf: u64) -> String {
    encode_private_hnsw_oram_leaf_label(leaf, 2).unwrap()
}

/// Drives an HNSW append transaction to completion and returns the path labels of every
/// window the server was asked to read, in order.
fn hnsw_append_transaction_window_paths(
    fixture: &HnswAppendTransactionFixture,
    plan: PrivateOramAppendHnswTransactionPlanV2,
    point: PrivateOramAppendLevel0PointV2,
) -> (PrivateOramAppendHnswTransactionOutputV2, Vec<Vec<String>>) {
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        point,
        plan,
    )
    .unwrap();
    let mut windows = Vec::new();
    while let Some(marker) = transaction.prepare_next_read_window().unwrap() {
        let request = transaction.next_read_window(&marker).unwrap();
        let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
        transaction
            .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
            .unwrap();
        windows.push(request.window.paths);
    }
    (transaction.finalize().unwrap(), windows)
}

fn complete_hnsw_append_transaction(
    fixture: &HnswAppendTransactionFixture,
    plan: PrivateOramAppendHnswTransactionPlanV2,
) -> (PrivateOramAppendHnswTransactionOutputV2, u32) {
    complete_hnsw_append_transaction_with_point(fixture, plan, hnsw_append_transaction_point())
}

fn complete_hnsw_append_transaction_with_point(
    fixture: &HnswAppendTransactionFixture,
    plan: PrivateOramAppendHnswTransactionPlanV2,
    point: PrivateOramAppendLevel0PointV2,
) -> (PrivateOramAppendHnswTransactionOutputV2, u32) {
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        point,
        plan,
    )
    .unwrap();
    assert!(!transaction.requires_recovery());

    let mut accepted_windows = 0;
    while let Some(marker) = transaction.prepare_next_read_window().unwrap() {
        assert_eq!(transaction.requires_recovery(), accepted_windows != 0);
        assert_eq!(marker.phase, PrivateOramAppendRecoveryPhaseV2::WindowIssued);
        assert_eq!(marker.attempt_digest.len(), 43);
        assert_eq!(marker.prepared_commit_digest, None);
        let request = transaction.next_read_window(&marker).unwrap();
        assert_eq!(request.window.sequence, accepted_windows);
        assert_eq!(
            request.recovery_marker.requested_window_count,
            accepted_windows + 1
        );
        let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
        transaction
            .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
            .unwrap();
        accepted_windows += 1;
    }
    (transaction.finalize().unwrap(), accepted_windows)
}

struct ResultAppendTransactionFixture {
    manifest: PrivateOramImmutableManifestV2,
    state: PrivateOramSignedStateV2,
    checkpoint: PrivateOramAppendClientCheckpointV2,
    keys: PrivateResultOramClientKeys,
    buckets: Vec<PrivateResultOramBucket>,
}

fn result_append_transaction_fixture_with_path_batch_size(
    path_batch_size: u32,
) -> ResultAppendTransactionFixture {
    let mut manifest = manifest();
    let PrivateOramImmutableIndexParamsV2::Result { oram, .. } = &mut manifest.indexes[1].params
    else {
        panic!("fixture result manifest is missing");
    };
    oram.path_batch_size = path_batch_size;
    let mut checkpoint = checkpoint(&manifest);
    let config = PrivateResultOramClientConfig {
        tree_height: 2,
        bucket_size: 2,
        block_size_bytes: 512,
    };
    let mut plaintext_buckets = (0..capacity().bucket_count)
        .map(|bucket_id| empty_private_result_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    let existing_block = PrivateResultOramPayloadBlockPlaintext {
        version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
        payload_fetch_token: [4; 32],
        point_token: [3; 32],
        payload: b"existing payload".to_vec(),
        deleted: false,
        generation: 0,
    };
    plaintext_buckets[0].blocks[0] = Some(existing_block);

    let resource_key = SecretKey::from_bytes([32; 32]);
    let keys = PrivateResultOramClientKeys::derive_from_resource_key_with_context(
        &resource_key,
        &manifest.collection_id,
        "tenant-a/result-rk",
        7,
    )
    .unwrap();
    let base_context = PrivateResultOramBucketAeadBaseContext {
        collection_id: &manifest.collection_id,
        key_id: "tenant-a/result-rk",
        rk_id: "tenant-a/result-rk",
        rk_epoch: 7,
    };
    let buckets = plaintext_buckets
        .iter()
        .map(|bucket| {
            seal_private_result_oram_plaintext_bucket(&keys, base_context, 11, bucket, config)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let root_hash = private_result_oram_merkle_root_for_commitments(
        &buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        root_hash: checkpoint_root,
        state: checkpoint_state,
        ..
    } = &mut checkpoint.indexes[1]
    else {
        panic!("fixture result checkpoint is missing");
    };
    *checkpoint_root = root_hash.clone();
    checkpoint_state.positions[0].leaf_label = encode_private_result_oram_leaf_label(3, 2).unwrap();
    let mut state = state(&manifest, digest(30));
    state.indexes[1].root_hash = root_hash;

    ResultAppendTransactionFixture {
        manifest,
        state,
        checkpoint,
        keys,
        buckets,
    }
}

fn result_append_transaction_plan(
    paths_per_window: u32,
) -> PrivateOramAppendResultTransactionPlanV2 {
    PrivateOramAppendResultTransactionPlanV2 {
        index_name: "private-payload".to_string(),
        mutation_id: digest(20),
        writer_lease_digest: digest(21),
        writer_fence: 3,
        paths_per_window,
        insert_eviction_leaf: 0,
        padding_leaves: vec![1, 2, 1],
    }
}

fn result_append_transaction_point() -> PrivateOramAppendResultPointV2 {
    PrivateOramAppendResultPointV2 {
        payload_fetch_token: [7; 32],
        point_token: [6; 32],
        payload: b"new private payload".to_vec(),
        initial_leaf: 3,
    }
}

fn encrypted_result_window_batch(
    window: &PrivateOramAppendReadWindowV1,
    buckets: &[PrivateResultOramBucket],
) -> PrivateResultOramEncryptedBucketBatch {
    let bucket_ids = window
        .paths
        .iter()
        .map(|leaf_label| decode_private_result_oram_leaf_label(leaf_label, 2).unwrap())
        .flat_map(|leaf| private_result_oram_bucket_ids_for_leaf(leaf, 2).unwrap())
        .collect::<Vec<_>>();
    let commitments = buckets
        .iter()
        .map(|bucket| bucket.bucket_commitment.clone())
        .collect::<Vec<_>>();
    let proof = result_merkle_proof(11, &commitments, &bucket_ids);
    PrivateResultOramEncryptedBucketBatch {
        index_epoch: 11,
        root_hash: proof.root_hash.clone(),
        bucket_count: buckets.len().try_into().unwrap(),
        proof_value: serde_json::to_string(&proof).unwrap(),
        buckets: bucket_ids
            .iter()
            .map(|bucket_id| buckets[usize::try_from(*bucket_id).unwrap()].clone())
            .collect(),
    }
}

fn complete_result_append_transaction(
    fixture: &ResultAppendTransactionFixture,
    plan: PrivateOramAppendResultTransactionPlanV2,
) -> (PrivateOramAppendResultTransactionOutputV2, u32) {
    complete_result_append_transaction_with_point(fixture, plan, result_append_transaction_point())
}

fn complete_result_append_transaction_with_point(
    fixture: &ResultAppendTransactionFixture,
    plan: PrivateOramAppendResultTransactionPlanV2,
    point: PrivateOramAppendResultPointV2,
) -> (PrivateOramAppendResultTransactionOutputV2, u32) {
    let mut transaction = PrivateOramAppendResultTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        point,
        plan,
    )
    .unwrap();
    assert!(!transaction.requires_recovery());

    let mut accepted_windows = 0;
    while let Some(marker) = transaction.prepare_next_read_window().unwrap() {
        assert_eq!(marker.index_kind, PrivateOramIndexKindV2::Result);
        assert_eq!(marker.index_name, "private-payload");
        let request = transaction.next_read_window(&marker).unwrap();
        let batch = encrypted_result_window_batch(&request.window, &fixture.buckets);
        transaction
            .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
            .unwrap();
        accepted_windows += 1;
    }
    (transaction.finalize().unwrap(), accepted_windows)
}

/// Bucket wire bytes (base64url ciphertext text) and counts of one append on one index.
struct AppendCost {
    read_paths: u64,
    read_buckets: u64,
    read_bytes: u64,
    written_frames: u64,
    written_distinct_buckets: u64,
    written_bytes: u64,
}

impl AppendCost {
    fn new(
        read_paths: u32,
        bucket_text_len: usize,
        ordered_lens: impl Iterator<Item = usize>,
        distinct_buckets: usize,
    ) -> Self {
        // Every read path returns tree_height + 1 buckets; shared ancestors are sent again.
        let read_buckets = u64::from(read_paths) * (u64::from(oram().tree_height) + 1);
        let mut written_frames = 0;
        let mut written_bytes = 0;
        for len in ordered_lens {
            written_frames += 1;
            written_bytes += len as u64;
        }
        Self {
            read_paths: u64::from(read_paths),
            read_buckets,
            read_bytes: read_buckets * bucket_text_len as u64,
            written_frames,
            written_distinct_buckets: distinct_buckets as u64,
            written_bytes,
        }
    }

    fn report(&self, label: &str) {
        eprintln!(
            "{label}: read {} paths / {} buckets / {} B, wrote {} frames ({} distinct buckets) / {} B, write amplification {} buckets per appended point",
            self.read_paths,
            self.read_buckets,
            self.read_bytes,
            self.written_frames,
            self.written_distinct_buckets,
            self.written_bytes,
            self.written_frames,
        );
    }
}

fn report_append_costs() {
    let hnsw = hnsw_append_transaction_fixture();
    let (output, _) = complete_hnsw_append_transaction(&hnsw, hnsw_append_transaction_plan());
    AppendCost::new(
        output.writeback.read_path_count,
        hnsw.buckets[0].ciphertext.len(),
        output
            .ordered_encrypted_buckets
            .iter()
            .map(|bucket| bucket.ciphertext.len()),
        output.final_encrypted_buckets.len(),
    )
    .report("private ORAM V2 append, HNSW index");

    let result = result_append_transaction_fixture_with_path_batch_size(1);
    let (output, _) =
        complete_result_append_transaction(&result, result_append_transaction_plan(1));
    AppendCost::new(
        output.writeback.read_path_count,
        result.buckets[0].ciphertext.len(),
        output
            .ordered_encrypted_buckets
            .iter()
            .map(|bucket| bucket.ciphertext.len()),
        output.final_encrypted_buckets.len(),
    )
    .report("private ORAM V2 append, result index");
}

fn bench_private_oram_append(c: &mut Criterion) {
    report_append_costs();

    let hnsw = hnsw_append_transaction_fixture();
    c.bench_function("private_oram_v2_append/hnsw_transaction", |b| {
        b.iter_batched(
            || {
                (
                    hnsw_append_transaction_plan(),
                    hnsw_append_transaction_point(),
                )
            },
            |(plan, point)| {
                black_box(complete_hnsw_append_transaction_with_point(
                    &hnsw, plan, point,
                ))
            },
            BatchSize::SmallInput,
        )
    });

    let result = result_append_transaction_fixture_with_path_batch_size(1);
    c.bench_function("private_oram_v2_append/result_transaction", |b| {
        b.iter_batched(
            || {
                (
                    result_append_transaction_plan(1),
                    result_append_transaction_point(),
                )
            },
            |(plan, point)| {
                black_box(complete_result_append_transaction_with_point(
                    &result, plan, point,
                ))
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_private_oram_append);
criterion_main!(benches);
