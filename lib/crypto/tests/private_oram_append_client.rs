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

/// Two live candidates that both sit at leaf 1, so a candidate window reading both collides.
fn hnsw_append_transaction_fixture_with_colliding_candidates() -> HnswAppendTransactionFixture {
    let mut manifest = manifest();
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        oram,
        fixed_search_budget,
        ..
    } = &mut manifest.indexes[0].params
    else {
        panic!("fixture HNSW manifest is missing");
    };
    oram.path_batch_size = 2;
    fixed_search_budget.paths_per_round = 2;
    let second_candidate = PrivateHnswNodeBlockPlaintext {
        version: 1,
        node_id: [12; 32],
        point_token: [13; 32],
        level_mask: 1,
        vector_encoding: PrivateHnswVectorEncoding::F32Le,
        vector: [0.0f32, 1.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect(),
        neighbors: vec![],
        neighbor_levels: vec![],
        deleted: false,
        generation: 0,
        payload_fetch_token: Some([14; 32]),
    };
    let mut checkpoint = checkpoint(&manifest);
    checkpoint.points.push(PrivateOramAppendPointRecordV2 {
        point_token: BASE64URL_NOPAD.encode(&second_candidate.point_token),
        visible_point_id: None,
        payload_fetch_token: Some(BASE64URL_NOPAD.encode(&[14; 32])),
    });
    {
        let PrivateOramAppendClientIndexCheckpointV2::Hnsw { state, records, .. } =
            &mut checkpoint.indexes[0]
        else {
            panic!("fixture HNSW checkpoint is missing");
        };
        state.positions.push(PrivateHnswPositionMapSnapshotEntry {
            node_id: BASE64URL_NOPAD.encode(&second_candidate.node_id),
            leaf_label: encode_private_hnsw_oram_leaf_label(1, 2).unwrap(),
        });
        records.push(PrivateOramAppendHnswRecordV2 {
            node_id: BASE64URL_NOPAD.encode(&second_candidate.node_id),
            point_token: BASE64URL_NOPAD.encode(&second_candidate.point_token),
            level_mask: 1,
            generation: 0,
        });
        let PrivateOramAppendClientIndexCheckpointV2::Result { state, records, .. } =
            &mut checkpoint.indexes[1]
        else {
            panic!("fixture result checkpoint is missing");
        };
        state
            .positions
            .push(PrivateResultOramPositionMapSnapshotEntry {
                payload_fetch_token: BASE64URL_NOPAD.encode(&[14; 32]),
                leaf_label: encode_private_result_oram_leaf_label(2, 2).unwrap(),
            });
        records.push(PrivateOramAppendResultRecordV2 {
            payload_fetch_token: BASE64URL_NOPAD.encode(&[14; 32]),
            point_token: BASE64URL_NOPAD.encode(&second_candidate.point_token),
            generation: 0,
        });
    }
    let config = PrivateHnswOramClientConfig {
        tree_height: 2,
        bucket_size: 2,
        block_size_bytes: 512,
        fixed_neighbor_slots: 2,
    };
    let mut plaintext_buckets = (0..capacity().bucket_count)
        .map(|bucket_id| empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    let candidate_leaf_bucket = usize::try_from(
        *private_hnsw_oram_bucket_ids_for_leaf(1, 2)
            .unwrap()
            .last()
            .unwrap(),
    )
    .unwrap();
    plaintext_buckets[candidate_leaf_bucket].blocks[0] = Some(checkpoint_candidate_block());
    plaintext_buckets[candidate_leaf_bucket].blocks[1] = Some(second_candidate);

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
    for index in &mut state.indexes {
        index.logical_count = 2;
        index.dummy_count = 2;
    }

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

struct PairedAppendTransactionFixture {
    manifest: PrivateOramImmutableManifestV2,
    state: PrivateOramSignedStateV2,
    checkpoint: PrivateOramAppendClientCheckpointV2,
    old_encrypted_checkpoint: PrivateOramEncryptedAppendClientCheckpointV2,
    hnsw_output: PrivateOramAppendHnswTransactionOutputV2,
    result_output: PrivateOramAppendResultTransactionOutputV2,
}

fn paired_append_transaction_fixture() -> PairedAppendTransactionFixture {
    paired_append_transaction_fixture_with_inputs(
        hnsw_append_transaction_point(),
        result_append_transaction_point(),
        hnsw_append_transaction_plan(),
        result_append_transaction_plan(1),
    )
}

fn paired_append_transaction_fixture_with_inputs(
    hnsw_point: PrivateOramAppendLevel0PointV2,
    result_point: PrivateOramAppendResultPointV2,
    hnsw_plan: PrivateOramAppendHnswTransactionPlanV2,
    result_plan: PrivateOramAppendResultTransactionPlanV2,
) -> PairedAppendTransactionFixture {
    paired_append_transaction_fixture_with_inputs_and_last_mutation(
        hnsw_point,
        result_point,
        hnsw_plan,
        result_plan,
        None,
    )
}

fn paired_append_transaction_fixture_with_inputs_and_last_mutation(
    hnsw_point: PrivateOramAppendLevel0PointV2,
    result_point: PrivateOramAppendResultPointV2,
    hnsw_plan: PrivateOramAppendHnswTransactionPlanV2,
    result_plan: PrivateOramAppendResultTransactionPlanV2,
    last_mutation_id: Option<String>,
) -> PairedAppendTransactionFixture {
    let mut hnsw_fixture = hnsw_append_transaction_fixture();
    let mut result_fixture = result_append_transaction_fixture_with_path_batch_size(1);

    hnsw_fixture.checkpoint.indexes[1] = result_fixture.checkpoint.indexes[1].clone();
    hnsw_fixture.state.indexes[1] = result_fixture.state.indexes[1].clone();
    result_fixture.checkpoint.indexes[0] = hnsw_fixture.checkpoint.indexes[0].clone();
    result_fixture.state.indexes[0] = hnsw_fixture.state.indexes[0].clone();
    let checkpoint_key = SecretKey::from_bytes([44; 32]);
    let sealed =
        seal_private_oram_append_client_checkpoint_v2(&checkpoint_key, &hnsw_fixture.checkpoint)
            .unwrap();
    let client_state_digest = private_oram_append_client_checkpoint_v2_digest(&sealed).unwrap();
    hnsw_fixture.state.client_state_digest = client_state_digest.clone();
    result_fixture.state.client_state_digest = client_state_digest;
    if let Some(last_mutation_id) = last_mutation_id {
        hnsw_fixture.state.last_mutation_id = Some(last_mutation_id.clone());
        result_fixture.state.last_mutation_id = Some(last_mutation_id);
    }
    let old_encrypted_checkpoint =
        bind_private_oram_append_client_checkpoint_v2(sealed, &hnsw_fixture.state).unwrap();

    let (hnsw_output, _) =
        complete_hnsw_append_transaction_with_point(&hnsw_fixture, hnsw_plan, hnsw_point);
    let (result_output, _) =
        complete_result_append_transaction_with_point(&result_fixture, result_plan, result_point);

    PairedAppendTransactionFixture {
        manifest: hnsw_fixture.manifest,
        state: hnsw_fixture.state,
        checkpoint: hnsw_fixture.checkpoint,
        old_encrypted_checkpoint,
        hnsw_output,
        result_output,
    }
}

fn paired_finalization_validation<'a>(
    manifest_bundle: &'a PrivateOramImmutableManifestBundleV2,
    old_state_bundle: &'a PrivateOramSignedStateBundleV2,
    manifest_digest: &'a str,
    old_state_digest: &'a str,
    writer_lease_digest: &'a str,
    key_pair: &'a Ed25519KeyPair,
) -> PrivateOramAppendPairedFinalizationContextV1<'a> {
    PrivateOramAppendPairedFinalizationContextV1 {
        expected_collection_id: &manifest_bundle.manifest.collection_id,
        expected_manifest_digest: manifest_digest,
        expected_owner_signing_key_id: &manifest_bundle.manifest.owner_signing_key_id,
        expected_layout_generation: old_state_bundle.state.layout_generation,
        expected_layout_digest: &old_state_bundle.state.layout_digest,
        expected_writer_lease_digest: writer_lease_digest,
        expected_writer_fence: 3,
        expected_state_sequence: old_state_bundle.state.state_sequence,
        expected_old_state_digest: old_state_digest,
        now_unix: 1_770_000_130,
        max_mutation_ttl_secs: 300,
        public_key: key_pair.public_key().as_ref(),
    }
}

fn server_read_evidence(
    recorder: &PrivateOramServerReadEvidenceRecorderV1,
    transcript: &PrivateOramObservedReadTranscriptV1,
) -> PrivateOramServerReadEvidenceV1 {
    let paths_per_window = usize::try_from(transcript.paths_per_window).unwrap();
    let windows = transcript
        .ordered_leaf_labels
        .chunks(paths_per_window)
        .enumerate()
        .map(|(sequence, paths)| PrivateOramAppendReadWindowV1 {
            sequence: u32::try_from(sequence).unwrap(),
            paths: paths.to_vec(),
        })
        .collect::<Vec<_>>();
    recorder
        .record(PrivateOramAppendReadTranscriptDigestInput {
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
        })
        .unwrap()
}

#[test]
fn hnsw_append_transaction_accepts_fixed_size_read_sequence_with_shared_ancestors() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        plan,
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
    let bucket_ids = batch
        .buckets
        .iter()
        .map(|bucket| bucket.bucket_id)
        .collect::<Vec<_>>();

    assert_eq!(bucket_ids.len(), 6);
    assert_eq!(bucket_ids[0], bucket_ids[3]);
    transaction
        .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
        .unwrap();
}

#[test]
fn hnsw_append_transaction_rejects_reordered_fixed_size_read_sequence() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        plan,
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let mut batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
    batch.buckets.swap(1, 2);

    assert_eq!(
        transaction.accept_verified_window(request.window.sequence, &fixture.keys, &batch),
        Err(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch)
    );
    assert!(transaction.requires_recovery());
}

#[test]
fn paired_checkpoint_seals_binds_and_opens_against_signed_state() {
    let (key, manifest, state, encrypted) = sealed_checkpoint_fixture();
    let opened =
        open_private_oram_append_client_checkpoint_v2(&key, &encrypted, &manifest, &state).unwrap();
    assert_eq!(opened, checkpoint(&manifest));
    validate_private_oram_append_client_checkpoint_v2(&opened, &manifest, &state).unwrap();
}

#[test]
fn checkpoint_digest_known_answer_is_stable() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/qdrant-sec-private-oram-append-checkpoint-test-vector.json"
    ))
    .unwrap();
    let input = &vector["input"];
    let sealed = PrivateOramSealedAppendClientCheckpointV2 {
        version: input["version"].as_u64().unwrap().try_into().unwrap(),
        collection_id: input["collection_id"].as_str().unwrap().to_string(),
        manifest_digest: input["manifest_digest"].as_str().unwrap().to_string(),
        layout_generation: input["layout_generation"].as_u64().unwrap(),
        state_sequence: input["state_sequence"].as_u64().unwrap(),
        ciphertext: input["ciphertext"].as_str().unwrap().to_string(),
        ciphertext_sha256: input["ciphertext_sha256"].as_str().unwrap().to_string(),
    };
    let message = try_private_oram_append_client_checkpoint_v2_digest_message(&sealed).unwrap();
    assert_eq!(
        vector["domain"],
        serde_json::json!(PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_DIGEST_DOMAIN)
    );
    assert_eq!(
        vector["digest_message_len"],
        serde_json::json!(message.len())
    );
    assert_eq!(
        vector["digest_message_b64"],
        serde_json::json!(BASE64URL_NOPAD.encode(&message))
    );
    assert_eq!(
        vector["digest_b64"],
        serde_json::json!(private_oram_append_client_checkpoint_v2_digest(&sealed).unwrap())
    );
}

#[test]
fn hnsw_append_recovery_digest_known_answers_are_stable() {
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let state = state(&manifest, digest(30));
    let point = hnsw_append_transaction_point();
    let plan = hnsw_append_transaction_plan();
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&state).unwrap();
    let source_checkpoint_digest =
        private_oram_append_client_checkpoint_plaintext_v3_digest(&checkpoint).unwrap();
    let attempt =
        private_oram_append_hnsw_attempt_v2_digest(PrivateOramAppendHnswAttemptDigestInput {
            manifest_digest: &manifest_digest,
            old_state_digest: &old_state_digest,
            checkpoint: &checkpoint,
            point: &point,
            plan: &plan,
        })
        .unwrap();
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        state: next_client_state,
        ..
    } = &checkpoint.indexes[0]
    else {
        panic!("fixture HNSW checkpoint is missing");
    };
    let graph_delta = plan_private_oram_level0_hnsw_graph_delta_v2(
        &manifest,
        &state,
        &checkpoint,
        "text",
        &point,
        &[checkpoint_candidate_block()],
        1,
    )
    .unwrap();
    let legacy_prepared = private_oram_append_hnsw_prepared_commit_v2_digest(
        PrivateOramAppendHnswPreparedCommitDigestInput {
            attempt_digest: &attempt,
            old_epoch: 11,
            new_epoch: 12,
            old_root_hash: &digest(5),
            new_root_hash: &digest(6),
            read_transcript_digest: &digest(40),
            writeback_digest: &digest(41),
            next_client_state,
        },
    )
    .unwrap();

    assert_eq!(attempt, "k6aBmpM33qQZMHZUlLm8zjcuFuNJIxs_kmRYFFOH_9M");
    assert_eq!(
        legacy_prepared,
        "ftlODQe353ZRs3E7s_ZUGCJrY16zvRysuW3-SR4iRQQ"
    );
    let attempt_v3 =
        private_oram_append_hnsw_attempt_v3_digest(PrivateOramAppendHnswAttemptDigestInputV3 {
            manifest_digest: &manifest_digest,
            old_state_digest: &old_state_digest,
            checkpoint: &checkpoint,
            point: &point,
            plan: &plan,
        })
        .unwrap();
    let prepared_v3 = private_oram_append_hnsw_prepared_commit_v3_digest(
        PrivateOramAppendHnswPreparedCommitDigestInputV3 {
            attempt_digest: &attempt_v3,
            graph_delta: &graph_delta,
            old_epoch: 11,
            new_epoch: 12,
            old_root_hash: &digest(5),
            new_root_hash: &digest(6),
            read_transcript_digest: &digest(40),
            writeback_digest: &digest(41),
            next_client_state,
        },
    )
    .unwrap();
    assert_eq!(attempt_v3, "w44sXNVM2ZJY7URs6zazcFtJFMlk0uNrtuIB2E_-G48");
    assert_eq!(prepared_v3, "Zq9VGumZ46WjHl1pDbuZOlbnmwdty6HcBTA2YDehafo");
    let prepared_v4 = private_oram_append_hnsw_prepared_commit_v4_digest(
        PrivateOramAppendHnswPreparedCommitDigestInputV4 {
            attempt_digest: &attempt_v3,
            source_checkpoint_digest: &source_checkpoint_digest,
            graph_delta: &graph_delta,
            old_epoch: 11,
            new_epoch: 12,
            old_root_hash: &digest(5),
            new_root_hash: &digest(6),
            read_transcript_digest: &digest(40),
            writeback_digest: &digest(41),
            next_client_state,
        },
    )
    .unwrap();
    assert_eq!(prepared_v4, "yzTgS8CIoXDT177h0jmp8ueqFYbS9YOHoYZ3BKB4XfM");
    assert_ne!(prepared_v4, prepared_v3);
    assert_ne!(
        private_oram_append_hnsw_prepared_commit_v4_digest(
            PrivateOramAppendHnswPreparedCommitDigestInputV4 {
                attempt_digest: &attempt_v3,
                source_checkpoint_digest: &digest(42),
                graph_delta: &graph_delta,
                old_epoch: 11,
                new_epoch: 12,
                old_root_hash: &digest(5),
                new_root_hash: &digest(6),
                read_transcript_digest: &digest(40),
                writeback_digest: &digest(41),
                next_client_state,
            },
        )
        .unwrap(),
        prepared_v4
    );
    let mut changed_graph_delta = graph_delta.clone();
    changed_graph_delta.hnsw_record.generation += 1;
    assert_ne!(
        private_oram_append_hnsw_prepared_commit_v3_digest(
            PrivateOramAppendHnswPreparedCommitDigestInputV3 {
                attempt_digest: &attempt_v3,
                graph_delta: &changed_graph_delta,
                old_epoch: 11,
                new_epoch: 12,
                old_root_hash: &digest(5),
                new_root_hash: &digest(6),
                read_transcript_digest: &digest(40),
                writeback_digest: &digest(41),
                next_client_state,
            },
        )
        .unwrap(),
        prepared_v3
    );
}

#[test]
fn result_append_recovery_digest_known_answers_are_stable() {
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let state = state(&manifest, digest(30));
    let point = result_append_transaction_point();
    let plan = result_append_transaction_plan(1);
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&state).unwrap();
    let source_checkpoint_digest =
        private_oram_append_client_checkpoint_plaintext_v3_digest(&checkpoint).unwrap();
    let attempt =
        private_oram_append_result_attempt_v3_digest(PrivateOramAppendResultAttemptDigestInputV3 {
            manifest_digest: &manifest_digest,
            old_state_digest: &old_state_digest,
            checkpoint: &checkpoint,
            point: &point,
            plan: &plan,
        })
        .unwrap();
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        state: next_client_state,
        ..
    } = &checkpoint.indexes[1]
    else {
        panic!("fixture result checkpoint is missing");
    };
    let result_record = PrivateOramAppendResultRecordV2 {
        payload_fetch_token: BASE64URL_NOPAD.encode(&point.payload_fetch_token),
        point_token: BASE64URL_NOPAD.encode(&point.point_token),
        generation: 1,
    };
    let prepared = private_oram_append_result_prepared_commit_v3_digest(
        PrivateOramAppendResultPreparedCommitDigestInputV3 {
            attempt_digest: &attempt,
            result_record: &result_record,
            old_epoch: 11,
            new_epoch: 12,
            old_root_hash: &digest(5),
            new_root_hash: &digest(6),
            read_transcript_digest: &digest(40),
            writeback_digest: &digest(41),
            next_client_state,
        },
    )
    .unwrap();

    assert_eq!(attempt, "LeNkoXW2iV10zksXqwhadqFueao5_6twh91Wuu4lmPg");
    assert_eq!(prepared, "pNrVNtaqYbpC6yC4OAIJn5y3GwSKULc8jM_RkfK0pPM");
    let prepared_v4 = private_oram_append_result_prepared_commit_v4_digest(
        PrivateOramAppendResultPreparedCommitDigestInputV4 {
            attempt_digest: &attempt,
            source_checkpoint_digest: &source_checkpoint_digest,
            result_record: &result_record,
            old_epoch: 11,
            new_epoch: 12,
            old_root_hash: &digest(5),
            new_root_hash: &digest(6),
            read_transcript_digest: &digest(40),
            writeback_digest: &digest(41),
            next_client_state,
        },
    )
    .unwrap();
    assert_eq!(prepared_v4, "04hHfpLL0CwzoWSpoSNLK-VOklkdHsrkkaX04xcdVYM");
    assert_ne!(prepared_v4, prepared);
    assert_ne!(
        private_oram_append_result_prepared_commit_v4_digest(
            PrivateOramAppendResultPreparedCommitDigestInputV4 {
                attempt_digest: &attempt,
                source_checkpoint_digest: &digest(42),
                result_record: &result_record,
                old_epoch: 11,
                new_epoch: 12,
                old_root_hash: &digest(5),
                new_root_hash: &digest(6),
                read_transcript_digest: &digest(40),
                writeback_digest: &digest(41),
                next_client_state,
            },
        )
        .unwrap(),
        prepared_v4
    );
    let mut changed_result_record = result_record;
    changed_result_record.generation += 1;
    assert_ne!(
        private_oram_append_result_prepared_commit_v3_digest(
            PrivateOramAppendResultPreparedCommitDigestInputV3 {
                attempt_digest: &attempt,
                result_record: &changed_result_record,
                old_epoch: 11,
                new_epoch: 12,
                old_root_hash: &digest(5),
                new_root_hash: &digest(6),
                read_transcript_digest: &digest(40),
                writeback_digest: &digest(41),
                next_client_state,
            },
        )
        .unwrap(),
        prepared
    );
}

#[test]
fn v3_checkpoint_and_client_state_digests_use_u32_domain_framing() {
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        state: hnsw_state, ..
    } = &checkpoint.indexes[0]
    else {
        panic!("fixture HNSW checkpoint is missing");
    };
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        state: result_state,
        ..
    } = &checkpoint.indexes[1]
    else {
        panic!("fixture result checkpoint is missing");
    };
    let cases = [
        (
            try_private_oram_append_client_checkpoint_plaintext_v3_digest_message(&checkpoint)
                .unwrap(),
            PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_PLAINTEXT_V3_DIGEST_DOMAIN,
        ),
        (
            try_private_oram_append_hnsw_client_state_v3_digest_message(hnsw_state).unwrap(),
            PRIVATE_ORAM_APPEND_HNSW_CLIENT_STATE_V3_DIGEST_DOMAIN,
        ),
        (
            try_private_oram_append_result_client_state_v3_digest_message(result_state).unwrap(),
            PRIVATE_ORAM_APPEND_RESULT_CLIENT_STATE_V3_DIGEST_DOMAIN,
        ),
    ];

    for (message, domain) in cases {
        let domain_len = u32::try_from(domain.len()).unwrap().to_be_bytes();
        assert_eq!(&message[..4], &domain_len);
        assert_eq!(&message[4..4 + domain.len()], domain.as_bytes());
    }
}

#[test]
fn v3_client_state_digests_canonicalize_snapshot_map_order() {
    let mut first_hnsw_block = checkpoint_candidate_block();
    first_hnsw_block.node_id = [1; 32];
    first_hnsw_block.point_token = [10; 32];
    first_hnsw_block.payload_fetch_token = Some([11; 32]);
    let mut second_hnsw_block = checkpoint_candidate_block();
    second_hnsw_block.node_id = [2; 32];
    second_hnsw_block.point_token = [12; 32];
    second_hnsw_block.payload_fetch_token = Some([13; 32]);
    let mut hnsw = PrivateHnswOramClientStateSnapshot {
        version: 1,
        tree_height: 2,
        positions: vec![
            PrivateHnswPositionMapSnapshotEntry {
                node_id: BASE64URL_NOPAD.encode(&[1; 32]),
                leaf_label: encode_private_hnsw_oram_leaf_label(1, 2).unwrap(),
            },
            PrivateHnswPositionMapSnapshotEntry {
                node_id: BASE64URL_NOPAD.encode(&[2; 32]),
                leaf_label: encode_private_hnsw_oram_leaf_label(2, 2).unwrap(),
            },
        ],
        stash: vec![first_hnsw_block, second_hnsw_block],
    };
    let hnsw_digest = private_oram_append_hnsw_client_state_v3_digest(&hnsw).unwrap();
    hnsw.positions.reverse();
    hnsw.stash.reverse();
    assert_eq!(
        private_oram_append_hnsw_client_state_v3_digest(&hnsw).unwrap(),
        hnsw_digest
    );

    let mut result = PrivateResultOramClientStateSnapshot {
        version: 1,
        tree_height: 2,
        positions: vec![
            PrivateResultOramPositionMapSnapshotEntry {
                payload_fetch_token: BASE64URL_NOPAD.encode(&[3; 32]),
                leaf_label: encode_private_result_oram_leaf_label(1, 2).unwrap(),
            },
            PrivateResultOramPositionMapSnapshotEntry {
                payload_fetch_token: BASE64URL_NOPAD.encode(&[4; 32]),
                leaf_label: encode_private_result_oram_leaf_label(2, 2).unwrap(),
            },
        ],
        stash: vec![
            PrivateResultOramPayloadBlockPlaintext {
                version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
                payload_fetch_token: [3; 32],
                point_token: [5; 32],
                payload: b"first".to_vec(),
                deleted: false,
                generation: 1,
            },
            PrivateResultOramPayloadBlockPlaintext {
                version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
                payload_fetch_token: [4; 32],
                point_token: [6; 32],
                payload: b"second".to_vec(),
                deleted: false,
                generation: 1,
            },
        ],
    };
    let result_digest = private_oram_append_result_client_state_v3_digest(&result).unwrap();
    result.positions.reverse();
    result.stash.reverse();
    assert_eq!(
        private_oram_append_result_client_state_v3_digest(&result).unwrap(),
        result_digest
    );
}

#[test]
fn legacy_v2_recovery_marker_round_trips_without_v3_index_fields() {
    let encoded = serde_json::json!({
        "version": PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V2_VERSION,
        "collection_id": "collection",
        "manifest_digest": digest(1),
        "mutation_id": "mutation",
        "old_state_digest": digest(2),
        "attempt_digest": digest(3),
        "writer_lease_digest": digest(4),
        "writer_fence": 7,
        "requested_window_count": 3,
        "accepted_window_count": 2,
        "observed_read_path_count": 4,
        "phase": "window_issued",
        "prepared_commit_digest": null
    });
    let marker: PrivateOramAppendRecoveryMarkerV2 =
        serde_json::from_value(encoded.clone()).unwrap();

    assert_eq!(
        marker.version,
        PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V2_VERSION
    );
    assert_eq!(serde_json::to_value(marker).unwrap(), encoded);
}

#[test]
fn checkpoint_rejects_duplicate_and_cross_index_token_records() {
    let manifest = manifest();
    let mut malformed_checkpoint = checkpoint(&manifest);
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        state: hnsw_state,
        records,
        ..
    } = &mut malformed_checkpoint.indexes[0]
    else {
        unreachable!();
    };
    hnsw_state
        .positions
        .push(PrivateHnswPositionMapSnapshotEntry {
            node_id: digest(12),
            leaf_label: encode_private_hnsw_oram_leaf_label(2, 2).unwrap(),
        });
    let mut duplicate = records[0].clone();
    duplicate.node_id = digest(12);
    records.push(duplicate);
    assert_eq!(
        validate_private_oram_append_client_checkpoint_v2_shape(&malformed_checkpoint),
        Err(PrivateOramAppendClientError::DuplicateCheckpointRecord)
    );

    let mut mismatched_checkpoint = checkpoint(&manifest);
    let PrivateOramAppendClientIndexCheckpointV2::Result { records, .. } =
        &mut mismatched_checkpoint.indexes[1]
    else {
        unreachable!();
    };
    records[0].point_token = digest(13);
    let signed_state = state(&manifest, digest(14));
    assert_eq!(
        validate_private_oram_append_client_checkpoint_v2(
            &mismatched_checkpoint,
            &manifest,
            &signed_state,
        ),
        Err(PrivateOramAppendClientError::CheckpointStateMismatch)
    );

    let mut visible_duplicate = checkpoint(&manifest);
    visible_duplicate.points[0].visible_point_id = Some("42".to_string());
    visible_duplicate
        .points
        .push(PrivateOramAppendPointRecordV2 {
            point_token: digest(15),
            visible_point_id: Some("42".to_string()),
            payload_fetch_token: None,
        });
    assert_eq!(
        validate_private_oram_append_client_checkpoint_v2_shape(&visible_duplicate),
        Err(PrivateOramAppendClientError::DuplicateCheckpointRecord)
    );
}

#[test]
fn checkpoint_rejects_state_binding_and_ciphertext_tampering() {
    let (key, manifest, state, encrypted) = sealed_checkpoint_fixture();

    let mut wrong_state = state.clone();
    wrong_state.state_sequence += 1;
    assert_eq!(
        open_private_oram_append_client_checkpoint_v2(&key, &encrypted, &manifest, &wrong_state,),
        Err(PrivateOramAppendClientError::CheckpointStateMismatch)
    );

    let mut tampered = encrypted.clone();
    let mut raw_ciphertext = BASE64URL_NOPAD
        .decode(tampered.sealed.ciphertext.as_bytes())
        .unwrap();
    *raw_ciphertext.last_mut().unwrap() ^= 1;
    tampered.sealed.ciphertext = BASE64URL_NOPAD.encode(&raw_ciphertext);
    assert_eq!(
        open_private_oram_append_client_checkpoint_v2(&key, &tampered, &manifest, &state,),
        Err(PrivateOramAppendClientError::InvalidCheckpointCiphertextHash)
    );

    assert_eq!(
        open_private_oram_append_client_checkpoint_v2(
            &SecretKey::from_bytes([12; 32]),
            &encrypted,
            &manifest,
            &state,
        ),
        Err(PrivateOramAppendClientError::CheckpointOpenFailed)
    );
}

#[test]
fn checkpoint_supports_empty_paired_state_and_ids_visible_point_mapping() {
    let paired_manifest = manifest();
    let mut empty_checkpoint = checkpoint(&paired_manifest);
    empty_checkpoint.points.clear();
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        entry_node_id,
        state: hnsw_state,
        records: hnsw_records,
        ..
    } = &mut empty_checkpoint.indexes[0]
    else {
        unreachable!();
    };
    *entry_node_id = None;
    hnsw_state.positions.clear();
    hnsw_records.clear();
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        state: result_state,
        records: result_records,
        ..
    } = &mut empty_checkpoint.indexes[1]
    else {
        unreachable!();
    };
    result_state.positions.clear();
    result_records.clear();
    let mut empty_state = state(&paired_manifest, digest(16));
    for index in &mut empty_state.indexes {
        index.logical_count = 0;
        index.dummy_count = 4;
    }
    validate_private_oram_append_client_checkpoint_v2(
        &empty_checkpoint,
        &paired_manifest,
        &empty_state,
    )
    .unwrap();

    let mut visible_manifest = paired_manifest;
    visible_manifest.indexes.pop();
    visible_manifest.result_privacy = ResultPrivacyMode::IdsVisible;
    let mut visible_checkpoint = checkpoint(&manifest());
    visible_checkpoint.manifest_digest =
        private_oram_immutable_manifest_v2_digest(&visible_manifest).unwrap();
    visible_checkpoint.indexes.pop();
    visible_checkpoint.points[0].visible_point_id = Some("42".to_string());
    visible_checkpoint.points[0].payload_fetch_token = None;

    let mut visible_state = state(&manifest(), digest(17));
    visible_state.manifest_digest = visible_checkpoint.manifest_digest.clone();
    visible_state.indexes.pop();
    validate_private_oram_append_client_checkpoint_v2(
        &visible_checkpoint,
        &visible_manifest,
        &visible_state,
    )
    .unwrap();
}

#[test]
fn append_only_position_and_stash_apis_do_not_overwrite_existing_records() {
    let node_id = [2; 32];
    let point_token = [3; 32];
    let payload_fetch_token = [4; 32];
    let mut hnsw = PrivateHnswOramClientState::with_position_map([(node_id, 1)], 2).unwrap();
    let before = hnsw.clone();
    assert_eq!(
        hnsw.insert_position_if_absent(node_id, 2, 2),
        Err(PrivateHnswClientError::DuplicateBlock)
    );
    assert_eq!(hnsw, before);
    assert_eq!(
        hnsw.insert_new_stash_block(
            PrivateHnswNodeBlockPlaintext {
                version: 1,
                node_id,
                point_token,
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
                payload_fetch_token: Some(payload_fetch_token),
            },
            1,
            PrivateHnswOramClientConfig {
                tree_height: 2,
                bucket_size: 2,
                block_size_bytes: 512,
                fixed_neighbor_slots: 2,
            },
        ),
        Err(PrivateHnswClientError::DuplicateBlock)
    );
    assert_eq!(hnsw, before);

    let mut result =
        PrivateResultOramClientState::with_position_map([(payload_fetch_token, 1)], 2).unwrap();
    let before = result.clone();
    assert_eq!(
        result.insert_position_if_absent(payload_fetch_token, 2, 2),
        Err(PrivateResultOramError::DuplicatePayloadFetchToken)
    );
    assert_eq!(result, before);
}

#[test]
fn checkpoint_debug_output_redacts_client_owned_identifiers_and_ciphertext() {
    let (_key, manifest, _state, encrypted) = sealed_checkpoint_fixture();
    let checkpoint = checkpoint(&manifest);
    let checkpoint_debug = format!("{checkpoint:?}");
    let encrypted_debug = format!("{encrypted:?}");
    for sentinel in [
        checkpoint.collection_id.as_str(),
        checkpoint.manifest_digest.as_str(),
        encrypted.sealed.ciphertext.as_str(),
        encrypted.sealed.ciphertext_sha256.as_str(),
        encrypted.state_digest.as_str(),
    ] {
        assert!(!checkpoint_debug.contains(sentinel));
        assert!(!encrypted_debug.contains(sentinel));
    }
}

#[test]
fn sparse_merkle_patch_matches_full_recompute_and_uses_last_occurrence() {
    let commitments = (1..=7).map(digest).collect::<Vec<_>>();
    let old_root = private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap();
    let hnsw_proof = hnsw_merkle_proof(11, &commitments, &[0, 1, 3]);
    let proof = PrivateOramAppendMerklePatchProofV1::from(&hnsw_proof);
    let ordered_updates = vec![
        append_bucket(0, 20),
        append_bucket(1, 21),
        append_bucket(0, 22),
        append_bucket(3, 23),
    ];

    let patch = apply_private_oram_append_sparse_merkle_patch_v1(
        11,
        &old_root,
        commitments.len().try_into().unwrap(),
        &proof,
        &ordered_updates,
    )
    .unwrap();
    let mut expected_commitments = commitments;
    expected_commitments[0] = digest(22);
    expected_commitments[1] = digest(21);
    expected_commitments[3] = digest(23);
    assert_eq!(
        patch.new_root_hash,
        private_hnsw_oram_merkle_root_for_commitments(&expected_commitments).unwrap()
    );
    assert_eq!(
        patch
            .final_buckets
            .iter()
            .map(|bucket| bucket.bucket_id)
            .collect::<Vec<_>>(),
        vec![0, 1, 3]
    );
    assert_eq!(patch.final_buckets[0], append_bucket(0, 22));

    let result_proof = PrivateResultOramMerkleProof {
        kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
        index_epoch: hnsw_proof.index_epoch,
        root_hash: hnsw_proof.root_hash.clone(),
        bucket_count: hnsw_proof.bucket_count,
        leaves: hnsw_proof
            .leaves
            .iter()
            .map(|leaf| PrivateResultOramMerkleProofLeaf {
                bucket_id: leaf.bucket_id,
                leaf_hash: leaf.leaf_hash.clone(),
                siblings: leaf
                    .siblings
                    .iter()
                    .map(|sibling| PrivateResultOramMerkleSibling {
                        level: sibling.level,
                        position: match sibling.position {
                            PrivateHnswMerkleSiblingPosition::Left => {
                                PrivateResultOramMerkleSiblingPosition::Left
                            }
                            PrivateHnswMerkleSiblingPosition::Right => {
                                PrivateResultOramMerkleSiblingPosition::Right
                            }
                        },
                        hash: sibling.hash.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };
    assert_eq!(
        PrivateOramAppendMerklePatchProofV1::from(&result_proof),
        proof
    );
}

#[test]
fn sparse_merkle_patch_rejects_unproven_updates_and_conflicting_proofs() {
    let commitments = (1..=7).map(digest).collect::<Vec<_>>();
    let old_root = private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap();
    let proof =
        PrivateOramAppendMerklePatchProofV1::from(&hnsw_merkle_proof(11, &commitments, &[0]));

    assert_eq!(
        apply_private_oram_append_sparse_merkle_patch_v1(
            11,
            &old_root,
            commitments.len().try_into().unwrap(),
            &proof,
            &[append_bucket(1, 20)],
        ),
        Err(PrivateOramAppendClientError::MerklePatchMismatch)
    );
    assert_eq!(
        apply_private_oram_append_sparse_merkle_patch_v1(
            12,
            &old_root,
            commitments.len().try_into().unwrap(),
            &proof,
            &[append_bucket(0, 20)],
        ),
        Err(PrivateOramAppendClientError::InvalidMerklePatch)
    );

    let mut conflicting = proof;
    let mut duplicate = conflicting.leaves[0].clone();
    duplicate.old_commitment = digest(31);
    conflicting.leaves.push(duplicate);
    assert_eq!(
        apply_private_oram_append_sparse_merkle_patch_v1(
            11,
            &old_root,
            commitments.len().try_into().unwrap(),
            &conflicting,
            &[append_bucket(0, 20)],
        ),
        Err(PrivateOramAppendClientError::MerklePatchMismatch)
    );
}

#[test]
fn sparse_merkle_patch_handles_a_single_bucket_tree() {
    let commitments = vec![digest(1)];
    let old_root = commitments[0].clone();
    let proof =
        PrivateOramAppendMerklePatchProofV1::from(&hnsw_merkle_proof(3, &commitments, &[0]));
    let patch = apply_private_oram_append_sparse_merkle_patch_v1(
        3,
        &old_root,
        1,
        &proof,
        &[append_bucket(0, 9)],
    )
    .unwrap();
    assert_eq!(patch.new_root_hash, digest(9));
}

#[test]
fn level0_append_plan_is_bounded_and_rewrites_a_visited_neighbor() {
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let state = state(&manifest, digest(40));
    let checkpoint_before = checkpoint.clone();
    let point = PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![0.9, 0.1],
        initial_leaf: 2,
    };
    let candidate = checkpoint_candidate_block();

    let plan = plan_private_oram_level0_hnsw_graph_delta_v2(
        &manifest,
        &state,
        &checkpoint,
        "text",
        &point,
        std::slice::from_ref(&candidate),
        1,
    )
    .unwrap();

    assert_eq!(checkpoint, checkpoint_before);
    assert_eq!(plan.new_block.node_id, point.node_id);
    assert_eq!(plan.new_block.generation, 1);
    assert_eq!(plan.new_block.level_mask, 1);
    assert_eq!(plan.selected_neighbor_ids, vec![candidate.node_id]);
    assert_eq!(plan.neighbor_rewrites.len(), 1);
    let rewrite = &plan.neighbor_rewrites[0];
    assert_eq!(rewrite.previous, candidate);
    assert_eq!(rewrite.replacement.generation, 1);
    assert_eq!(rewrite.replacement.point_token, candidate.point_token);
    assert_eq!(rewrite.replacement.vector, candidate.vector);
    assert_eq!(rewrite.replacement.neighbors, vec![point.node_id]);
    assert_eq!(rewrite.replacement.neighbor_levels, vec![0]);
    assert_eq!(plan.next_entry_node_id, candidate.node_id);
    assert_eq!(plan.fixed_read_path_count, 4);
    assert_eq!(plan.candidate_read_path_budget, 2);
    assert_eq!(plan.candidate_read_path_count, 1);
    assert_eq!(plan.rewrite_read_path_budget, 1);
    assert_eq!(plan.rewrite_read_path_count, 1);
    assert_eq!(plan.real_read_path_count, 3);
    assert_eq!(plan.padding_read_path_count, 1);
}

#[test]
fn level0_append_plan_rejects_duplicate_stale_and_over_budget_inputs() {
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let state = state(&manifest, digest(41));
    let mut point = PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![0.9, 0.1],
        initial_leaf: 2,
    };
    let candidate = checkpoint_candidate_block();

    point.node_id = candidate.node_id;
    assert_eq!(
        plan_private_oram_level0_hnsw_graph_delta_v2(
            &manifest,
            &state,
            &checkpoint,
            "text",
            &point,
            std::slice::from_ref(&candidate),
            1,
        ),
        Err(PrivateOramAppendClientError::DuplicateCheckpointRecord)
    );
    point.node_id = [5; 32];
    assert_eq!(
        plan_private_oram_level0_hnsw_graph_delta_v2(
            &manifest,
            &state,
            &checkpoint,
            "text",
            &point,
            std::slice::from_ref(&candidate),
            3,
        ),
        Err(PrivateOramAppendClientError::AppendBudgetExceeded)
    );

    let mut stale_candidate = candidate;
    stale_candidate.generation = 1;
    assert_eq!(
        plan_private_oram_level0_hnsw_graph_delta_v2(
            &manifest,
            &state,
            &checkpoint,
            "text",
            &point,
            &[stale_candidate],
            1,
        ),
        Err(PrivateOramAppendClientError::AppendCandidateMismatch)
    );
}

#[test]
fn level0_append_plan_initializes_an_empty_index_with_padding() {
    let manifest = manifest();
    let mut checkpoint = checkpoint(&manifest);
    checkpoint.points.clear();
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        entry_node_id,
        state: hnsw_state,
        records,
        ..
    } = &mut checkpoint.indexes[0]
    else {
        unreachable!();
    };
    *entry_node_id = None;
    hnsw_state.positions.clear();
    records.clear();
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        state: result_state,
        records,
        ..
    } = &mut checkpoint.indexes[1]
    else {
        unreachable!();
    };
    result_state.positions.clear();
    records.clear();
    let mut state = state(&manifest, digest(42));
    for index in &mut state.indexes {
        index.logical_count = 0;
        index.dummy_count = 4;
    }
    let point = PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![1.0, 0.0],
        initial_leaf: 1,
    };

    let plan = plan_private_oram_level0_hnsw_graph_delta_v2(
        &manifest,
        &state,
        &checkpoint,
        "text",
        &point,
        &[],
        0,
    )
    .unwrap();
    assert!(plan.selected_neighbor_ids.is_empty());
    assert!(plan.neighbor_rewrites.is_empty());
    assert_eq!(plan.next_entry_node_id, point.node_id);
    assert_eq!(plan.real_read_path_count, 1);
    assert_eq!(plan.padding_read_path_count, 3);
}

#[test]
fn level0_graph_delta_promotes_new_entry_when_reverse_edge_is_pruned() {
    let mut manifest = manifest();
    let PrivateOramImmutableIndexParamsV2::Hnsw { distance, hnsw, .. } =
        &mut manifest.indexes[0].params
    else {
        unreachable!();
    };
    *distance = DistanceKind::Euclid;
    hnsw.m = 1;
    hnsw.fixed_neighbor_slots = 1;

    let mut checkpoint = checkpoint(&manifest);
    checkpoint.points.push(PrivateOramAppendPointRecordV2 {
        point_token: BASE64URL_NOPAD.encode(&[9; 32]),
        visible_point_id: None,
        payload_fetch_token: Some(BASE64URL_NOPAD.encode(&[10; 32])),
    });
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        state: hnsw_state,
        records: hnsw_records,
        ..
    } = &mut checkpoint.indexes[0]
    else {
        unreachable!();
    };
    hnsw_state
        .positions
        .push(PrivateHnswPositionMapSnapshotEntry {
            node_id: BASE64URL_NOPAD.encode(&[8; 32]),
            leaf_label: encode_private_hnsw_oram_leaf_label(2, 2).unwrap(),
        });
    hnsw_records.push(PrivateOramAppendHnswRecordV2 {
        node_id: BASE64URL_NOPAD.encode(&[8; 32]),
        point_token: BASE64URL_NOPAD.encode(&[9; 32]),
        level_mask: 1,
        generation: 0,
    });
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        state: result_state,
        records: result_records,
        ..
    } = &mut checkpoint.indexes[1]
    else {
        unreachable!();
    };
    result_state
        .positions
        .push(PrivateResultOramPositionMapSnapshotEntry {
            payload_fetch_token: BASE64URL_NOPAD.encode(&[10; 32]),
            leaf_label: encode_private_result_oram_leaf_label(2, 2).unwrap(),
        });
    result_records.push(PrivateOramAppendResultRecordV2 {
        payload_fetch_token: BASE64URL_NOPAD.encode(&[10; 32]),
        point_token: BASE64URL_NOPAD.encode(&[9; 32]),
        generation: 0,
    });

    let mut state = state(&manifest, digest(43));
    for index in &mut state.indexes {
        index.logical_count = 2;
        index.dummy_count = 2;
    }
    let mut entry = checkpoint_candidate_block();
    entry.vector = [0.0f32, 0.0]
        .into_iter()
        .flat_map(f32::to_le_bytes)
        .collect();
    entry.neighbors = vec![[8; 32]];
    entry.neighbor_levels = vec![0];
    let second = PrivateHnswNodeBlockPlaintext {
        version: PRIVATE_HNSW_NODE_BLOCK_VERSION,
        node_id: [8; 32],
        point_token: [9; 32],
        level_mask: 1,
        vector_encoding: PrivateHnswVectorEncoding::F32Le,
        vector: [1.0f32, 0.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect(),
        neighbors: vec![entry.node_id],
        neighbor_levels: vec![0],
        deleted: false,
        generation: 0,
        payload_fetch_token: Some([10; 32]),
    };
    let point = PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![2.0, 0.0],
        initial_leaf: 3,
    };

    let delta = plan_private_oram_level0_hnsw_graph_delta_v2(
        &manifest,
        &state,
        &checkpoint,
        "text",
        &point,
        &[entry.clone(), second],
        2,
    )
    .unwrap();
    assert!(delta.neighbor_rewrites.is_empty());
    assert_eq!(delta.next_entry_node_id, point.node_id);
    assert_eq!(delta.new_block.neighbors, vec![entry.node_id]);
    assert_eq!(delta.rewrite_read_path_count, 0);
    assert_eq!(delta.real_read_path_count, 3);
    assert_eq!(delta.padding_read_path_count, 1);
}

#[test]
fn append_rewrite_and_targetless_hnsw_eviction_are_atomic() {
    let config = PrivateHnswOramClientConfig {
        tree_height: 2,
        bucket_size: 2,
        block_size_bytes: 512,
        fixed_neighbor_slots: 2,
    };
    let block = checkpoint_candidate_block();
    let mut state = PrivateHnswOramClientState::with_position_map([(block.node_id, 1)], 2).unwrap();
    let mut path = private_hnsw_oram_bucket_ids_for_leaf(1, 2)
        .unwrap()
        .into_iter()
        .map(|bucket_id| empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    path.last_mut().unwrap().blocks[0] = Some(block.clone());

    let access = access_private_hnsw_oram_path_with_append_rewrite(
        &mut state,
        config,
        block.node_id,
        &path,
        2,
        |previous| {
            let mut replacement = previous.clone();
            replacement.neighbors.push([5; 32]);
            replacement.neighbor_levels.push(0);
            replacement.generation += 1;
            Ok(replacement)
        },
    )
    .unwrap();
    assert_eq!(state.position(&block.node_id), Some(2));
    assert_eq!(access.block.neighbors, vec![[5; 32]]);
    assert!(
        access
            .writeback_buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .any(|written| written == &access.block)
    );

    let mut rejected_state =
        PrivateHnswOramClientState::with_position_map([(block.node_id, 1)], 2).unwrap();
    let before = rejected_state.clone();
    assert_eq!(
        access_private_hnsw_oram_path_with_append_rewrite(
            &mut rejected_state,
            config,
            block.node_id,
            &path,
            2,
            |previous| {
                let mut replacement = previous.clone();
                replacement.vector[0] ^= 1;
                replacement.generation += 1;
                Ok(replacement)
            },
        ),
        Err(PrivateHnswClientError::InvalidAppendRewrite)
    );
    assert_eq!(rejected_state, before);

    let new_block = PrivateHnswNodeBlockPlaintext {
        node_id: [11; 32],
        point_token: [12; 32],
        payload_fetch_token: Some([13; 32]),
        vector: [0.0f32, 1.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect(),
        ..checkpoint_candidate_block()
    };
    let mut insertion_state = PrivateHnswOramClientState::new();
    insertion_state
        .insert_new_stash_block(new_block.clone(), 3, config)
        .unwrap();
    let empty_path = private_hnsw_oram_bucket_ids_for_leaf(3, 2)
        .unwrap()
        .into_iter()
        .map(|bucket_id| empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    let eviction =
        evict_private_hnsw_oram_path(&mut insertion_state, config, 3, &empty_path).unwrap();
    assert_eq!(insertion_state.stash_len(), 0);
    assert!(
        eviction
            .writeback_buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .any(|written| written == &new_block)
    );
}

#[test]
fn targetless_result_eviction_places_a_new_private_payload_block() {
    let config = PrivateResultOramClientConfig {
        tree_height: 2,
        bucket_size: 2,
        block_size_bytes: 512,
    };
    let block = PrivateResultOramPayloadBlockPlaintext {
        version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
        payload_fetch_token: [7; 32],
        point_token: [6; 32],
        payload: b"encrypted-client-payload-plaintext".to_vec(),
        deleted: false,
        generation: 1,
    };
    let mut state = PrivateResultOramClientState::new();
    state
        .insert_new_stash_block(block.clone(), 2, config)
        .unwrap();
    let path = private_result_oram_bucket_ids_for_leaf(2, 2)
        .unwrap()
        .into_iter()
        .map(|bucket_id| empty_private_result_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    let eviction = evict_private_result_oram_path(&mut state, config, 2, &path).unwrap();
    assert_eq!(state.stash_len(), 0);
    assert!(
        eviction
            .writeback_buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .any(|written| written == &block)
    );

    let mut rejected_state = PrivateResultOramClientState::new();
    rejected_state
        .insert_new_stash_block(block, 2, config)
        .unwrap();
    let before = rejected_state.clone();
    assert_eq!(
        evict_private_result_oram_path(&mut rejected_state, config, 2, &path[..2]),
        Err(PrivateResultOramError::PathBucketMismatch)
    );
    assert_eq!(rejected_state, before);
}

#[test]
fn verified_result_append_transaction_preserves_fixed_ordered_frames_and_overlay() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(2);
    let (output, accepted_windows) =
        complete_result_append_transaction(&fixture, result_append_transaction_plan(2));
    assert_eq!(accepted_windows, 2);

    assert_eq!(output.old_epoch, 11);
    assert_eq!(output.new_epoch, 12);
    assert_eq!(output.read_transcript.read_path_count, 4);
    assert_eq!(output.read_transcript.ordered_leaf_labels.len(), 4);
    assert_eq!(
        output.read_transcript.ordered_leaf_labels[1],
        output.read_transcript.ordered_leaf_labels[3]
    );
    assert_eq!(output.writeback.kind, PrivateOramIndexKindV2::Result);
    assert_eq!(output.writeback.updated_buckets.len(), 12);
    assert_eq!(output.ordered_encrypted_buckets.len(), 12);
    assert_eq!(
        output
            .writeback
            .updated_buckets
            .iter()
            .filter(|bucket| bucket.bucket_id == 0)
            .count(),
        4
    );
    assert_eq!(
        output.result_record.payload_fetch_token,
        BASE64URL_NOPAD.encode(&[7; 32])
    );
    assert_eq!(
        output.result_record.point_token,
        BASE64URL_NOPAD.encode(&[6; 32])
    );
    assert_eq!(
        output.recovery_marker.phase,
        PrivateOramAppendRecoveryPhaseV2::PreparedCommit
    );
    assert_eq!(
        output.recovery_marker.version,
        PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION
    );
    assert_eq!(
        output.recovery_marker.index_kind,
        PrivateOramIndexKindV2::Result
    );
    assert_eq!(output.recovery_marker.index_name, "private-payload");
    assert_eq!(output.recovery_marker.attempt_digest.len(), 43);
    assert_eq!(
        output
            .recovery_marker
            .prepared_commit_digest
            .as_ref()
            .map(String::len),
        Some(43)
    );
    assert!(
        output
            .next_client_state
            .positions
            .iter()
            .any(|entry| entry.payload_fetch_token == BASE64URL_NOPAD.encode(&[7; 32]))
    );

    let mut next_commitments = fixture
        .buckets
        .iter()
        .map(|bucket| bucket.bucket_commitment.clone())
        .collect::<Vec<_>>();
    for bucket in &output.final_encrypted_buckets {
        next_commitments[usize::try_from(bucket.bucket_id).unwrap()] =
            bucket.bucket_commitment.clone();
    }
    assert_eq!(
        private_result_oram_merkle_root_for_commitments(&next_commitments).unwrap(),
        output.new_root_hash
    );

    let base_context = PrivateResultOramBucketAeadBaseContext {
        collection_id: &fixture.manifest.collection_id,
        key_id: "tenant-a/result-rk",
        rk_id: "tenant-a/result-rk",
        rk_epoch: 7,
    };
    let config = PrivateResultOramClientConfig {
        tree_height: 2,
        bucket_size: 2,
        block_size_bytes: 512,
    };
    let mut stored_tokens = output
        .final_encrypted_buckets
        .iter()
        .flat_map(|bucket| {
            open_private_result_oram_plaintext_bucket(&fixture.keys, base_context, bucket, config)
                .unwrap()
                .blocks
                .into_iter()
                .flatten()
                .map(|block| block.payload_fetch_token)
        })
        .collect::<Vec<_>>();
    stored_tokens.extend(
        output
            .next_client_state
            .stash
            .iter()
            .map(|block| block.payload_fetch_token),
    );
    assert_eq!(
        stored_tokens
            .iter()
            .filter(|token| **token == [4; 32])
            .count(),
        1
    );
    assert_eq!(
        stored_tokens
            .iter()
            .filter(|token| **token == [7; 32])
            .count(),
        1
    );
    validate_private_oram_append_result_transaction_output_v2(&fixture.manifest, &output).unwrap();
}

#[test]
fn result_prepared_output_validator_rejects_body_frame_and_transcript_tampering() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(2);
    let (output, _) =
        complete_result_append_transaction(&fixture, result_append_transaction_plan(2));

    let mut tampered_body = output.clone();
    let replacement = if tampered_body.ordered_encrypted_buckets[0]
        .ciphertext
        .starts_with('A')
    {
        "B"
    } else {
        "A"
    };
    tampered_body.ordered_encrypted_buckets[0]
        .ciphertext
        .replace_range(..1, replacement);
    assert!(
        validate_private_oram_append_result_transaction_output_v2(
            &fixture.manifest,
            &tampered_body,
        )
        .is_err()
    );

    let mut missing_final_bucket = output.clone();
    missing_final_bucket.final_encrypted_buckets.pop();
    assert_eq!(
        validate_private_oram_append_result_transaction_output_v2(
            &fixture.manifest,
            &missing_final_bucket,
        ),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "final_encrypted_buckets",
        ))
    );

    let mut tampered_frame = output.clone();
    tampered_frame.ordered_encrypted_buckets.swap(1, 2);
    tampered_frame.writeback.updated_buckets.swap(1, 2);
    assert_eq!(
        validate_private_oram_append_result_transaction_output_v2(
            &fixture.manifest,
            &tampered_frame,
        ),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "ordered_bucket_frames",
        ))
    );

    let mut tampered_proof = output.clone();
    tampered_proof.merkle_patch_proof.leaves[0].old_commitment = digest(99);
    assert!(
        validate_private_oram_append_result_transaction_output_v2(
            &fixture.manifest,
            &tampered_proof,
        )
        .is_err()
    );

    let mut tampered_root = output.clone();
    tampered_root.new_root_hash = digest(99);
    assert_eq!(
        validate_private_oram_append_result_transaction_output_v2(
            &fixture.manifest,
            &tampered_root,
        ),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "merkle_patch_proof",
        ))
    );

    let mut tampered_transcript = output;
    tampered_transcript
        .read_transcript
        .ordered_leaf_labels
        .swap(0, 1);
    assert_eq!(
        validate_private_oram_append_result_transaction_output_v2(
            &fixture.manifest,
            &tampered_transcript,
        ),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "read_transcript",
        ))
    );
}

#[test]
fn result_append_transaction_rejects_reordered_read_sequence_and_rolls_back() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(2);
    let mut transaction = PrivateOramAppendResultTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        result_append_transaction_point(),
        result_append_transaction_plan(2),
    )
    .unwrap();
    let before = transaction.progress();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let mut batch = encrypted_result_window_batch(&request.window, &fixture.buckets);
    batch.buckets.swap(1, 2);

    assert_eq!(
        transaction.accept_verified_window(request.window.sequence, &fixture.keys, &batch),
        Err(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch)
    );
    assert!(transaction.is_poisoned());
    assert_eq!(transaction.progress(), before);
    let recovery = transaction.recovery_marker().unwrap();
    assert_eq!(recovery.accepted_window_count, 0);
    assert_eq!(recovery.observed_read_path_count, 2);
    assert_eq!(recovery.phase, PrivateOramAppendRecoveryPhaseV2::Poisoned);
}

#[test]
fn result_append_transaction_rolls_back_after_a_later_path_operation_fails() {
    let mut manifest = manifest();
    let PrivateOramImmutableIndexParamsV2::Result { oram, .. } = &mut manifest.indexes[1].params
    else {
        panic!("fixture result manifest is missing");
    };
    oram.bucket_size = 2;
    oram.tree_height = 1;
    oram.path_batch_size = 2;
    manifest.indexes[1].capacity.bucket_count = 3;
    manifest.indexes[1].capacity.reserved_physical_slots = 2;
    manifest.indexes[1].capacity.fixed_append_write_bucket_count = 8;

    let mut checkpoint = checkpoint(&manifest);
    checkpoint.points.push(PrivateOramAppendPointRecordV2 {
        point_token: BASE64URL_NOPAD.encode(&[10; 32]),
        visible_point_id: None,
        payload_fetch_token: Some(BASE64URL_NOPAD.encode(&[5; 32])),
    });
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        state: hnsw_state,
        records: hnsw_records,
        ..
    } = &mut checkpoint.indexes[0]
    else {
        panic!("fixture HNSW checkpoint is missing");
    };
    hnsw_state
        .positions
        .push(PrivateHnswPositionMapSnapshotEntry {
            node_id: BASE64URL_NOPAD.encode(&[9; 32]),
            leaf_label: encode_private_hnsw_oram_leaf_label(2, 2).unwrap(),
        });
    hnsw_records.push(PrivateOramAppendHnswRecordV2 {
        node_id: BASE64URL_NOPAD.encode(&[9; 32]),
        point_token: BASE64URL_NOPAD.encode(&[10; 32]),
        level_mask: 1,
        generation: 0,
    });
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        root_hash: checkpoint_root,
        state: result_state,
        records: result_records,
        ..
    } = &mut checkpoint.indexes[1]
    else {
        panic!("fixture result checkpoint is missing");
    };
    result_state.tree_height = 1;
    result_state.positions[0].leaf_label = encode_private_result_oram_leaf_label(1, 1).unwrap();
    result_state
        .positions
        .push(PrivateResultOramPositionMapSnapshotEntry {
            payload_fetch_token: BASE64URL_NOPAD.encode(&[5; 32]),
            leaf_label: encode_private_result_oram_leaf_label(1, 1).unwrap(),
        });
    result_records.push(PrivateOramAppendResultRecordV2 {
        payload_fetch_token: BASE64URL_NOPAD.encode(&[5; 32]),
        point_token: BASE64URL_NOPAD.encode(&[10; 32]),
        generation: 0,
    });

    let config = PrivateResultOramClientConfig {
        tree_height: 1,
        bucket_size: 2,
        block_size_bytes: 512,
    };
    let mut plaintext_buckets = (0..3)
        .map(|bucket_id| empty_private_result_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    plaintext_buckets[2].blocks = vec![
        Some(PrivateResultOramPayloadBlockPlaintext {
            version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
            payload_fetch_token: [4; 32],
            point_token: [3; 32],
            payload: b"first existing payload".to_vec(),
            deleted: false,
            generation: 0,
        }),
        Some(PrivateResultOramPayloadBlockPlaintext {
            version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
            payload_fetch_token: [5; 32],
            point_token: [10; 32],
            payload: b"second existing payload".to_vec(),
            deleted: false,
            generation: 0,
        }),
    ];
    plaintext_buckets[1].blocks[0] = Some(PrivateResultOramPayloadBlockPlaintext {
        version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
        payload_fetch_token: [8; 32],
        point_token: [6; 32],
        payload: b"conflicting authenticated payload".to_vec(),
        deleted: false,
        generation: 0,
    });
    let resource_key = SecretKey::from_bytes([33; 32]);
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
    let commitments = buckets
        .iter()
        .map(|bucket| bucket.bucket_commitment.clone())
        .collect::<Vec<_>>();
    let root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
    *checkpoint_root = root_hash.clone();
    let mut state = state(&manifest, digest(30));
    for index in &mut state.indexes {
        index.logical_count = 2;
        index.dummy_count = 2;
    }
    state.indexes[1].root_hash = root_hash;

    // The position (leaf 0) differs from the insert eviction path (leaf 1), as `begin` requires;
    // the conflicting block sits on the padding path read second, so the first path operation
    // succeeds and the second fails.
    let point = PrivateOramAppendResultPointV2 {
        payload_fetch_token: [7; 32],
        point_token: [6; 32],
        payload: b"new private payload".to_vec(),
        initial_leaf: 0,
    };
    let plan = PrivateOramAppendResultTransactionPlanV2 {
        index_name: "private-payload".to_string(),
        mutation_id: digest(20),
        writer_lease_digest: digest(21),
        writer_fence: 3,
        paths_per_window: 2,
        insert_eviction_leaf: 1,
        padding_leaves: vec![0, 1, 0],
    };
    let mut transaction =
        PrivateOramAppendResultTransactionV2::begin(&manifest, &state, &checkpoint, point, plan)
            .unwrap();
    let before = transaction.progress();
    let before_client_state = transaction.working_client_state_digest().unwrap();
    let before_artifacts = transaction.working_artifact_digest().unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let bucket_ids = request
        .window
        .paths
        .iter()
        .map(|leaf_label| decode_private_result_oram_leaf_label(leaf_label, 1).unwrap())
        .flat_map(|leaf| private_result_oram_bucket_ids_for_leaf(leaf, 1).unwrap())
        .collect::<Vec<_>>();
    let proof = result_merkle_proof(11, &commitments, &bucket_ids);
    let batch = PrivateResultOramEncryptedBucketBatch {
        index_epoch: 11,
        root_hash: proof.root_hash.clone(),
        bucket_count: 3,
        proof_value: serde_json::to_string(&proof).unwrap(),
        buckets: bucket_ids
            .iter()
            .map(|bucket_id| buckets[usize::try_from(*bucket_id).unwrap()].clone())
            .collect(),
    };

    assert_eq!(
        transaction.accept_verified_window(request.window.sequence, &keys, &batch),
        Err(PrivateOramAppendTransactionError::Result(
            PrivateResultOramError::DuplicatePointToken
        ))
    );
    assert!(transaction.is_poisoned());
    assert_eq!(transaction.progress(), before);
    assert_eq!(
        transaction.working_client_state_digest().unwrap(),
        before_client_state
    );
    assert_eq!(
        transaction.working_artifact_digest().unwrap(),
        before_artifacts
    );
}

#[test]
fn result_append_recovery_marker_binds_plan_point_and_randomized_artifact() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(1);
    let point = result_append_transaction_point();
    let plan = result_append_transaction_plan(1);
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&fixture.manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&fixture.state).unwrap();
    let expected_attempt =
        private_oram_append_result_attempt_v3_digest(PrivateOramAppendResultAttemptDigestInputV3 {
            manifest_digest: &manifest_digest,
            old_state_digest: &old_state_digest,
            checkpoint: &fixture.checkpoint,
            point: &point,
            plan: &plan,
        })
        .unwrap();
    let mut transaction = PrivateOramAppendResultTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        point,
        plan,
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    assert_eq!(marker.attempt_digest, expected_attempt);

    let mut changed_plan = result_append_transaction_plan(1);
    changed_plan.padding_leaves[2] = 0;
    let mut changed = PrivateOramAppendResultTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        result_append_transaction_point(),
        changed_plan,
    )
    .unwrap();
    let changed_marker = changed.prepare_next_read_window().unwrap().unwrap();
    assert_ne!(marker.attempt_digest, changed_marker.attempt_digest);
    assert_eq!(
        changed.next_read_window(&marker),
        Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch)
    );

    let (first, _) =
        complete_result_append_transaction(&fixture, result_append_transaction_plan(1));
    let (second, _) =
        complete_result_append_transaction(&fixture, result_append_transaction_plan(1));
    assert_eq!(
        first.recovery_marker.attempt_digest,
        second.recovery_marker.attempt_digest
    );
    assert_ne!(first.new_root_hash, second.new_root_hash);
    assert_ne!(
        first.recovery_marker.prepared_commit_digest,
        second.recovery_marker.prepared_commit_digest
    );
    let writeback_digest =
        private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
            collection_id: &fixture.manifest.collection_id,
            manifest_digest: &manifest_digest,
            kind: first.writeback.kind,
            index_name: &first.writeback.index_name,
            old_epoch: first.old_epoch,
            new_epoch: first.new_epoch,
            old_root_hash: &first.old_root_hash,
            new_root_hash: &first.new_root_hash,
            read_path_count: first.writeback.read_path_count,
            read_transcript_digest: &first.writeback.read_transcript_digest,
            updated_buckets: &first.writeback.updated_buckets,
        })
        .unwrap();
    let expected_prepared = private_oram_append_result_prepared_commit_v4_digest(
        PrivateOramAppendResultPreparedCommitDigestInputV4 {
            attempt_digest: &first.recovery_marker.attempt_digest,
            source_checkpoint_digest: &first.source_checkpoint_digest,
            result_record: &first.result_record,
            old_epoch: first.old_epoch,
            new_epoch: first.new_epoch,
            old_root_hash: &first.old_root_hash,
            new_root_hash: &first.new_root_hash,
            read_transcript_digest: &first.read_transcript.transcript_digest,
            writeback_digest: &writeback_digest,
            next_client_state: &first.next_client_state,
        },
    )
    .unwrap();
    assert_eq!(
        first.recovery_marker.prepared_commit_digest.as_deref(),
        Some(expected_prepared.as_str())
    );
}

#[test]
fn result_append_transaction_rejects_duplicates_and_oversized_payload_before_read() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(1);
    let mut duplicate = result_append_transaction_point();
    duplicate.payload_fetch_token = [4; 32];
    assert_eq!(
        PrivateOramAppendResultTransactionV2::begin(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            duplicate,
            result_append_transaction_plan(1),
        )
        .unwrap_err(),
        PrivateOramAppendTransactionError::Client(
            PrivateOramAppendClientError::DuplicateCheckpointRecord,
        )
    );

    let mut oversized = result_append_transaction_point();
    oversized.payload = vec![0; 512];
    assert_eq!(
        PrivateOramAppendResultTransactionV2::begin(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            oversized,
            result_append_transaction_plan(1),
        )
        .unwrap_err(),
        PrivateOramAppendTransactionError::Result(PrivateResultOramError::PayloadBlockOversized)
    );
}

#[test]
fn result_append_transaction_rejects_oversized_read_body_before_decode() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(1);
    let mut transaction = PrivateOramAppendResultTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        result_append_transaction_point(),
        result_append_transaction_plan(1),
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let mut batch = encrypted_result_window_batch(&request.window, &fixture.buckets);
    let oversized_encoded_len = batch.buckets[0].ciphertext.len() + 1;
    batch.buckets[0].ciphertext = "A".repeat(oversized_encoded_len);

    assert_eq!(
        transaction.accept_verified_window(request.window.sequence, &fixture.keys, &batch),
        Err(PrivateOramAppendTransactionError::Result(
            PrivateResultOramError::BucketOversized,
        ))
    );
    assert!(transaction.is_poisoned());
}

#[test]
fn result_append_transaction_accepts_authenticated_buckets_from_an_older_epoch() {
    let mut fixture = result_append_transaction_fixture_with_path_batch_size(1);
    let PrivateOramAppendClientIndexCheckpointV2::Result { index_epoch, .. } =
        &mut fixture.checkpoint.indexes[1]
    else {
        panic!("fixture result checkpoint is missing");
    };
    *index_epoch = 12;
    fixture.state.indexes[1].index_epoch = 12;

    let mut transaction = PrivateOramAppendResultTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        result_append_transaction_point(),
        result_append_transaction_plan(1),
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let mut batch = encrypted_result_window_batch(&request.window, &fixture.buckets);
    batch.index_epoch = 12;
    let mut proof: PrivateResultOramMerkleProof = serde_json::from_str(&batch.proof_value).unwrap();
    proof.index_epoch = 12;
    batch.proof_value = serde_json::to_string(&proof).unwrap();

    assert!(batch.buckets.iter().all(|bucket| bucket.index_epoch == 11));
    transaction
        .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
        .unwrap();
    assert_eq!(transaction.progress().accepted_read_path_count, 1);
}

#[test]
fn result_append_transaction_rejects_duplicate_paths_only_within_a_window() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = result_append_transaction_plan(2);
    plan.insert_eviction_leaf = plan.padding_leaves[0];
    assert_eq!(
        PrivateOramAppendResultTransactionV2::begin(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            result_append_transaction_point(),
            plan,
        )
        .unwrap_err(),
        PrivateOramAppendTransactionError::InvalidInput("duplicate_window_path")
    );

    let (output, accepted_windows) =
        complete_result_append_transaction(&fixture, result_append_transaction_plan(2));
    assert_eq!(accepted_windows, 2);
    assert_eq!(
        output.read_transcript.ordered_leaf_labels[1],
        output.read_transcript.ordered_leaf_labels[3]
    );
}

#[test]
fn result_append_transaction_preflights_a_later_window_before_any_read() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = result_append_transaction_plan(2);
    plan.padding_leaves[2] = 2;
    assert_eq!(
        PrivateOramAppendResultTransactionV2::begin(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            result_append_transaction_point(),
            plan,
        )
        .unwrap_err(),
        PrivateOramAppendTransactionError::InvalidInput("duplicate_window_path",)
    );
}

#[test]
fn verified_hnsw_append_transaction_preserves_fixed_ordered_frames() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let (output, accepted_windows) = complete_hnsw_append_transaction(&fixture, plan);
    assert_eq!(accepted_windows, 2);

    assert_eq!(output.old_epoch, 11);
    assert_eq!(output.new_epoch, 12);
    assert_eq!(output.read_transcript.read_path_count, 4);
    assert_eq!(output.read_transcript.ordered_leaf_labels.len(), 4);
    // candidate (leaf 1), padding 3, rewrite of the remapped candidate (leaf 2), then the insert
    // evicting the next padding leaf (1) instead of the new node's own position (3).
    let expected_leaves =
        [1u64, 3, 2, 1].map(|leaf| encode_private_hnsw_oram_leaf_label(leaf, 2).unwrap());
    assert_eq!(output.read_transcript.ordered_leaf_labels, expected_leaves);
    assert_eq!(output.writeback.updated_buckets.len(), 12);
    assert_eq!(output.ordered_encrypted_buckets.len(), 12);
    assert_eq!(
        output
            .writeback
            .updated_buckets
            .iter()
            .filter(|bucket| bucket.bucket_id == 0)
            .count(),
        4
    );
    assert_eq!(output.graph_delta.neighbor_rewrites.len(), 1);
    assert_eq!(output.graph_delta.new_block.node_id, [5; 32]);
    assert_eq!(
        output.recovery_marker.phase,
        PrivateOramAppendRecoveryPhaseV2::PreparedCommit
    );
    assert_eq!(output.recovery_marker.attempt_digest.len(), 43);
    assert_eq!(
        output
            .recovery_marker
            .prepared_commit_digest
            .as_ref()
            .map(String::len),
        Some(43)
    );
    assert!(
        output
            .next_client_state
            .positions
            .iter()
            .any(|entry| entry.node_id == BASE64URL_NOPAD.encode(&[5; 32]))
    );

    let mut next_commitments = fixture
        .buckets
        .iter()
        .map(|bucket| bucket.bucket_commitment.clone())
        .collect::<Vec<_>>();
    for bucket in &output.final_encrypted_buckets {
        next_commitments[usize::try_from(bucket.bucket_id).unwrap()] =
            bucket.bucket_commitment.clone();
    }
    assert_eq!(
        private_hnsw_oram_merkle_root_for_commitments(&next_commitments).unwrap(),
        output.new_root_hash
    );
    validate_private_oram_append_hnsw_transaction_output_v2(&fixture.manifest, &output).unwrap();
}

#[test]
fn hnsw_prepared_output_validator_rejects_body_frame_proof_and_state_tampering() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let (output, _) = complete_hnsw_append_transaction(&fixture, plan);

    let mut tampered_body = output.clone();
    let replacement = if tampered_body.ordered_encrypted_buckets[0]
        .ciphertext
        .starts_with('A')
    {
        "B"
    } else {
        "A"
    };
    tampered_body.ordered_encrypted_buckets[0]
        .ciphertext
        .replace_range(..1, replacement);
    assert!(
        validate_private_oram_append_hnsw_transaction_output_v2(&fixture.manifest, &tampered_body,)
            .is_err()
    );

    let mut oversized_body = output.clone();
    oversized_body.ordered_encrypted_buckets[0].ciphertext = "A".repeat(100_000);
    assert!(
        validate_private_oram_append_hnsw_transaction_output_v2(
            &fixture.manifest,
            &oversized_body,
        )
        .is_err()
    );

    let mut invalid_aead_version = output.clone();
    let mut ciphertext = BASE64URL_NOPAD
        .decode(
            invalid_aead_version.ordered_encrypted_buckets[0]
                .ciphertext
                .as_bytes(),
        )
        .unwrap();
    ciphertext[0] = 99;
    invalid_aead_version.ordered_encrypted_buckets[0].ciphertext =
        BASE64URL_NOPAD.encode(&ciphertext);
    assert!(matches!(
        validate_private_oram_append_hnsw_transaction_output_v2(
            &fixture.manifest,
            &invalid_aead_version,
        ),
        Err(PrivateOramAppendTransactionError::Hnsw(
            PrivateHnswClientError::UnsupportedBucketCiphertextVersion(99)
        ))
    ));

    let mut missing_final_bucket = output.clone();
    missing_final_bucket.final_encrypted_buckets.pop();
    assert_eq!(
        validate_private_oram_append_hnsw_transaction_output_v2(
            &fixture.manifest,
            &missing_final_bucket,
        ),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "final_encrypted_buckets",
        ))
    );

    let mut tampered_frame = output.clone();
    tampered_frame.ordered_encrypted_buckets.swap(1, 2);
    tampered_frame.writeback.updated_buckets.swap(1, 2);
    assert_eq!(
        validate_private_oram_append_hnsw_transaction_output_v2(&fixture.manifest, &tampered_frame,),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "ordered_bucket_frames",
        ))
    );

    let mut tampered_proof = output.clone();
    tampered_proof.merkle_patch_proof.leaves[0].old_commitment = digest(99);
    assert!(
        validate_private_oram_append_hnsw_transaction_output_v2(
            &fixture.manifest,
            &tampered_proof,
        )
        .is_err()
    );

    let mut tampered_root = output.clone();
    tampered_root.new_root_hash = digest(99);
    assert_eq!(
        validate_private_oram_append_hnsw_transaction_output_v2(&fixture.manifest, &tampered_root,),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "merkle_patch_proof",
        ))
    );

    let mut tampered_state = output;
    tampered_state.next_client_state.positions[0].leaf_label =
        encode_private_hnsw_oram_leaf_label(3, 2).unwrap();
    assert!(
        validate_private_oram_append_hnsw_transaction_output_v2(
            &fixture.manifest,
            &tampered_state,
        )
        .is_err()
    );
}

#[test]
fn hnsw_prepared_output_validator_rejects_graph_and_state_tampering_after_v4_recompute() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let (output, _) = complete_hnsw_append_transaction(&fixture, plan);

    let mut invalid_generation = output.clone();
    invalid_generation.graph_delta.new_block.generation = 2;
    invalid_generation.graph_delta.hnsw_record.generation = 2;
    refresh_hnsw_prepared_commit_digest(&fixture.manifest, &mut invalid_generation);
    assert_eq!(
        validate_private_oram_append_hnsw_transaction_output_v2(
            &fixture.manifest,
            &invalid_generation,
        ),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "graph_delta",
        ))
    );

    let mut invalid_budget = output.clone();
    invalid_budget.graph_delta.padding_read_path_count += 1;
    refresh_hnsw_prepared_commit_digest(&fixture.manifest, &mut invalid_budget);
    assert_eq!(
        validate_private_oram_append_hnsw_transaction_output_v2(&fixture.manifest, &invalid_budget,),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "graph_delta",
        ))
    );

    let mut unrelated_rewrite_neighbor = output.clone();
    unrelated_rewrite_neighbor.graph_delta.neighbor_rewrites[0]
        .replacement
        .neighbors
        .push([99; 32]);
    unrelated_rewrite_neighbor.graph_delta.neighbor_rewrites[0]
        .replacement
        .neighbor_levels
        .push(0);
    let mut unrelated_position = unrelated_rewrite_neighbor.next_client_state.positions[0].clone();
    unrelated_position.node_id = BASE64URL_NOPAD.encode(&[99; 32]);
    unrelated_rewrite_neighbor
        .next_client_state
        .positions
        .push(unrelated_position);
    refresh_hnsw_prepared_commit_digest(&fixture.manifest, &mut unrelated_rewrite_neighbor);
    assert_eq!(
        validate_private_oram_append_hnsw_transaction_output_v2(
            &fixture.manifest,
            &unrelated_rewrite_neighbor,
        ),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "graph_delta",
        ))
    );

    let mut missing_position = output;
    missing_position
        .next_client_state
        .positions
        .retain(|position| position.node_id != BASE64URL_NOPAD.encode(&[5; 32]));
    refresh_hnsw_prepared_commit_digest(&fixture.manifest, &mut missing_position);
    assert!(
        validate_private_oram_append_hnsw_transaction_output_v2(
            &fixture.manifest,
            &missing_position,
        )
        .is_err()
    );
}

#[test]
fn prepared_commit_marker_binds_randomized_ciphertext_artifact() {
    let fixture = hnsw_append_transaction_fixture();
    let (first, _) = complete_hnsw_append_transaction(&fixture, hnsw_append_transaction_plan());
    let (second, _) = complete_hnsw_append_transaction(&fixture, hnsw_append_transaction_plan());

    assert_eq!(
        first.recovery_marker.attempt_digest,
        second.recovery_marker.attempt_digest
    );
    assert_ne!(first.new_root_hash, second.new_root_hash);
    assert_ne!(
        first.recovery_marker.prepared_commit_digest,
        second.recovery_marker.prepared_commit_digest
    );
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&fixture.manifest).unwrap();
    let writeback_digest =
        private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
            collection_id: &fixture.manifest.collection_id,
            manifest_digest: &manifest_digest,
            kind: first.writeback.kind,
            index_name: &first.writeback.index_name,
            old_epoch: first.old_epoch,
            new_epoch: first.new_epoch,
            old_root_hash: &first.old_root_hash,
            new_root_hash: &first.new_root_hash,
            read_path_count: first.writeback.read_path_count,
            read_transcript_digest: &first.writeback.read_transcript_digest,
            updated_buckets: &first.writeback.updated_buckets,
        })
        .unwrap();
    let expected = private_oram_append_hnsw_prepared_commit_v4_digest(
        PrivateOramAppendHnswPreparedCommitDigestInputV4 {
            attempt_digest: &first.recovery_marker.attempt_digest,
            source_checkpoint_digest: &first.source_checkpoint_digest,
            graph_delta: &first.graph_delta,
            old_epoch: first.old_epoch,
            new_epoch: first.new_epoch,
            old_root_hash: &first.old_root_hash,
            new_root_hash: &first.new_root_hash,
            read_transcript_digest: &first.read_transcript.transcript_digest,
            writeback_digest: &writeback_digest,
            next_client_state: &first.next_client_state,
        },
    )
    .unwrap();
    assert_eq!(
        first.recovery_marker.prepared_commit_digest.as_deref(),
        Some(expected.as_str())
    );
}

#[test]
fn hnsw_append_recovery_marker_binds_the_exact_attempt_plan() {
    let fixture = hnsw_append_transaction_fixture();
    let point = hnsw_append_transaction_point();
    let plan = hnsw_append_transaction_plan();
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&fixture.manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&fixture.state).unwrap();
    let expected_attempt =
        private_oram_append_hnsw_attempt_v3_digest(PrivateOramAppendHnswAttemptDigestInputV3 {
            manifest_digest: &manifest_digest,
            old_state_digest: &old_state_digest,
            checkpoint: &fixture.checkpoint,
            point: &point,
            plan: &plan,
        })
        .unwrap();
    let mut first = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        point,
        plan,
    )
    .unwrap();
    let first_marker = first.prepare_next_read_window().unwrap().unwrap();
    assert_eq!(
        first_marker.version,
        PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION
    );
    assert_eq!(first_marker.index_kind, PrivateOramIndexKindV2::Hnsw);
    assert_eq!(first_marker.index_name, "text");
    assert_eq!(first_marker.attempt_digest, expected_attempt);

    let mut changed_plan = hnsw_append_transaction_plan();
    changed_plan.padding_leaves[3] = 3;
    let mut changed = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        changed_plan,
    )
    .unwrap();
    let changed_marker = changed.prepare_next_read_window().unwrap().unwrap();

    assert_ne!(first_marker.attempt_digest, changed_marker.attempt_digest);
    assert_eq!(
        changed.next_read_window(&first_marker),
        Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch)
    );
}

#[test]
fn hnsw_append_transaction_migrates_a_persisted_v2_window_marker_to_v3() {
    let fixture = hnsw_append_transaction_fixture();
    let point = hnsw_append_transaction_point();
    let plan = hnsw_append_transaction_plan();
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&fixture.manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&fixture.state).unwrap();
    let legacy_attempt =
        private_oram_append_hnsw_attempt_v2_digest(PrivateOramAppendHnswAttemptDigestInput {
            manifest_digest: &manifest_digest,
            old_state_digest: &old_state_digest,
            checkpoint: &fixture.checkpoint,
            point: &point,
            plan: &plan,
        })
        .unwrap();
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        point,
        plan,
    )
    .unwrap();
    let v3_marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let legacy_marker = PrivateOramAppendRecoveryMarkerV2 {
        version: PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V2_VERSION,
        collection_id: v3_marker.collection_id.clone(),
        manifest_digest: v3_marker.manifest_digest.clone(),
        mutation_id: v3_marker.mutation_id.clone(),
        old_state_digest: v3_marker.old_state_digest.clone(),
        attempt_digest: legacy_attempt,
        writer_lease_digest: v3_marker.writer_lease_digest.clone(),
        writer_fence: v3_marker.writer_fence,
        requested_window_count: v3_marker.requested_window_count,
        accepted_window_count: v3_marker.accepted_window_count,
        observed_read_path_count: v3_marker.observed_read_path_count,
        phase: v3_marker.phase,
        prepared_commit_digest: None,
    };
    let mut wrong_marker = legacy_marker.clone();
    wrong_marker.attempt_digest = digest(99);
    assert_eq!(
        transaction.next_read_window_v2(&wrong_marker),
        Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch)
    );

    let request = transaction.next_read_window_v2(&legacy_marker).unwrap();
    assert_eq!(request.recovery_marker, v3_marker);
    assert_eq!(
        request.recovery_marker.version,
        PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION
    );
}

#[test]
fn hnsw_append_transaction_rejects_duplicate_point_before_first_read() {
    let fixture = hnsw_append_transaction_fixture();
    let mut duplicate = hnsw_append_transaction_point();
    duplicate.node_id = [2; 32];
    assert_eq!(
        PrivateOramAppendHnswTransactionV2::begin(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            duplicate,
            hnsw_append_transaction_plan(),
        )
        .unwrap_err(),
        PrivateOramAppendTransactionError::Client(
            PrivateOramAppendClientError::DuplicateCheckpointRecord,
        )
    );
}

#[test]
fn hnsw_append_transaction_reads_a_substitute_path_when_a_padding_leaf_collides() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    // The candidate sits at leaf 1. The padding leaf that shares its window collides with it,
    // and so does the first spare padding leaf, so the substitute search has to skip one.
    plan.padding_leaves = vec![1, 1, 2, 0];
    let (output, windows) =
        hnsw_append_transaction_window_paths(&fixture, plan, hnsw_append_transaction_point());
    assert_eq!(
        windows,
        vec![
            vec![hnsw_leaf_label(1), hnsw_leaf_label(2)],
            vec![hnsw_leaf_label(2), hnsw_leaf_label(0)],
        ]
    );
    assert_eq!(output.read_transcript.read_path_count, 4);
}

#[test]
fn hnsw_append_transaction_merges_colliding_candidates_into_one_path_read() {
    let fixture = hnsw_append_transaction_fixture_with_colliding_candidates();
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    plan.candidate_node_ids = vec![[2; 32], [12; 32]];
    plan.candidate_remap_leaves = vec![2, 3];
    let (output, windows) =
        hnsw_append_transaction_window_paths(&fixture, plan, hnsw_append_transaction_point());
    // Both candidates share leaf 1: one read serves both and the freed slot reads the first
    // spare padding leaf, so the server still sees two distinct paths per window and cannot
    // tell that the secret positions collided.
    assert_eq!(windows.len(), 2);
    assert_eq!(windows[0], vec![hnsw_leaf_label(1), hnsw_leaf_label(3)]);
    assert_eq!(windows[1].len(), 2);
    assert_ne!(windows[1][0], windows[1][1]);
    assert_eq!(output.read_transcript.read_path_count, 4);
    // Both candidates were found on the shared path and became neighbors of the new block.
    let mut neighbors = output.graph_delta.new_block.neighbors.clone();
    neighbors.sort_unstable();
    assert_eq!(neighbors, vec![[2; 32], [12; 32]]);
}

#[test]
fn hnsw_append_transaction_merges_the_insert_eviction_into_a_colliding_rewrite_path() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    // Candidate window: leaf 1 plus padding leaf 0. Rewrite window: the rewrite path (the
    // candidate's remap leaf 2) collides with the insert eviction leaf 2, and the next spare
    // padding leaf collides as well, so the substitute is leaf 0.
    plan.padding_leaves = vec![0, 2, 2, 0];
    let mut point = hnsw_append_transaction_point();
    point.initial_leaf = 2;
    let (output, windows) = hnsw_append_transaction_window_paths(&fixture, plan, point);
    assert_eq!(
        windows,
        vec![
            vec![hnsw_leaf_label(1), hnsw_leaf_label(0)],
            vec![hnsw_leaf_label(2), hnsw_leaf_label(0)],
        ]
    );
    assert_eq!(output.read_transcript.read_path_count, 4);
}

#[test]
fn hnsw_append_transaction_poisoned_when_substitute_padding_leaves_run_out() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    // Every spare padding leaf equals the rewrite path, so the second window cannot be shaped
    // after the first one has already been disclosed.
    plan.padding_leaves = vec![0, 2, 2, 2];
    let mut point = hnsw_append_transaction_point();
    point.initial_leaf = 2;
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        point,
        plan,
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
    transaction
        .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
        .unwrap();

    assert_eq!(
        transaction.prepare_next_read_window(),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "padding_leaves",
        ))
    );
    assert!(transaction.is_poisoned());
    assert_eq!(
        transaction.recovery_marker().unwrap().phase,
        PrivateOramAppendRecoveryPhaseV2::Poisoned
    );
}

#[test]
fn hnsw_append_transaction_keeps_waiting_after_a_window_sequence_mismatch() {
    let fixture = hnsw_append_transaction_fixture();
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        hnsw_append_transaction_plan(),
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
    let before = transaction.progress();

    // A response for the wrong window consumes nothing, so the attempt stays retryable.
    assert_eq!(
        transaction.accept_verified_window(request.window.sequence + 1, &fixture.keys, &batch),
        Err(PrivateOramAppendTransactionError::WindowSequenceMismatch)
    );
    assert!(!transaction.is_poisoned());
    assert_eq!(transaction.progress(), before);
    transaction
        .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
        .unwrap();
}

#[test]
fn result_append_transaction_keeps_waiting_after_a_window_sequence_mismatch() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(2);
    let mut transaction = PrivateOramAppendResultTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        result_append_transaction_point(),
        result_append_transaction_plan(2),
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let batch = encrypted_result_window_batch(&request.window, &fixture.buckets);
    let before = transaction.progress();

    assert_eq!(
        transaction.accept_verified_window(request.window.sequence + 1, &fixture.keys, &batch),
        Err(PrivateOramAppendTransactionError::WindowSequenceMismatch)
    );
    assert!(!transaction.is_poisoned());
    assert_eq!(transaction.progress(), before);
    transaction
        .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
        .unwrap();
}

#[test]
fn hnsw_append_transaction_rolls_back_a_fully_applied_window_when_planning_fails() {
    let fixture = hnsw_append_transaction_fixture_with_candidate_generation(2, Some(99));
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        plan,
    )
    .unwrap();
    let before = transaction.progress();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);

    assert_eq!(
        transaction.accept_verified_window(request.window.sequence, &fixture.keys, &batch),
        Err(PrivateOramAppendTransactionError::Client(
            PrivateOramAppendClientError::AppendCandidateMismatch
        ))
    );
    assert!(transaction.is_poisoned());
    assert_eq!(transaction.progress(), before);
    let recovery = transaction.recovery_marker().unwrap();
    assert_eq!(recovery.accepted_window_count, 0);
    assert_eq!(recovery.observed_read_path_count, 2);
    assert_eq!(recovery.phase, PrivateOramAppendRecoveryPhaseV2::Poisoned);
}

#[test]
fn hnsw_append_transaction_poisoning_requires_recovery_after_first_read() {
    let fixture = hnsw_append_transaction_fixture();
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        hnsw_append_transaction_plan(),
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    assert!(!transaction.requires_recovery());
    let mut wrong_marker = marker.clone();
    wrong_marker.writer_fence += 1;
    assert_eq!(
        transaction.next_read_window(&wrong_marker),
        Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch)
    );
    assert!(!transaction.requires_recovery());
    let request = transaction.next_read_window(&marker).unwrap();
    assert!(transaction.requires_recovery());
    assert_eq!(
        transaction.next_read_window(&marker),
        Err(PrivateOramAppendTransactionError::WindowPending)
    );

    let mut incomplete_batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
    incomplete_batch.buckets.pop();
    assert_eq!(
        transaction.accept_verified_window(
            request.window.sequence,
            &fixture.keys,
            &incomplete_batch,
        ),
        Err(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch)
    );
    assert!(transaction.is_poisoned());
    let marker = transaction.recovery_marker().unwrap();
    assert_eq!(marker.phase, PrivateOramAppendRecoveryPhaseV2::Poisoned);
    assert_eq!(marker.requested_window_count, 1);
    assert_eq!(marker.accepted_window_count, 0);
    assert_eq!(marker.observed_read_path_count, 1);
    assert_eq!(
        transaction.prepare_next_read_window(),
        Err(PrivateOramAppendTransactionError::RecoveryRequired)
    );
    assert_eq!(
        transaction.finalize(),
        Err(PrivateOramAppendTransactionError::RecoveryRequired)
    );
}

#[test]
fn paired_checkpoint_delta_advances_both_ledgers_and_index_states() {
    let fixture = paired_append_transaction_fixture();
    let delta = plan_private_oram_append_paired_checkpoint_delta_v2(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        &fixture.hnsw_output,
        &fixture.result_output,
    )
    .unwrap();
    let checkpoint = delta.checkpoint();
    let source_checkpoint_digest =
        private_oram_append_client_checkpoint_plaintext_v3_digest(&fixture.checkpoint).unwrap();

    assert_eq!(delta.mutation_id(), digest(20));
    assert_eq!(
        fixture.hnsw_output.source_checkpoint_digest,
        source_checkpoint_digest
    );
    assert_eq!(
        fixture.result_output.source_checkpoint_digest,
        source_checkpoint_digest
    );
    assert_eq!(checkpoint.state_sequence, fixture.state.state_sequence + 1);
    assert_eq!(checkpoint.points.len(), 2);
    assert_eq!(
        checkpoint.points[0].point_token,
        BASE64URL_NOPAD.encode(&[3; 32])
    );
    assert_eq!(
        checkpoint.points[1].point_token,
        BASE64URL_NOPAD.encode(&[6; 32])
    );
    assert_eq!(delta.next_indexes().len(), 2);
    assert!(
        delta
            .next_indexes()
            .iter()
            .all(|index| index.logical_count == 2 && index.dummy_count == 2)
    );

    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        index_epoch,
        root_hash,
        entry_node_id,
        state,
        records,
        ..
    } = &checkpoint.indexes[0]
    else {
        panic!("paired checkpoint HNSW index is missing");
    };
    assert_eq!(*index_epoch, fixture.hnsw_output.new_epoch);
    assert_eq!(root_hash, &fixture.hnsw_output.new_root_hash);
    assert_eq!(
        entry_node_id.as_deref(),
        Some(
            BASE64URL_NOPAD
                .encode(&fixture.hnsw_output.graph_delta.next_entry_node_id)
                .as_str()
        )
    );
    assert_eq!(state, &fixture.hnsw_output.next_client_state);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].node_id, BASE64URL_NOPAD.encode(&[2; 32]));
    assert_eq!(records[0].generation, 1);
    assert_eq!(records[1].node_id, BASE64URL_NOPAD.encode(&[5; 32]));
    assert_eq!(records[1].generation, 1);

    let PrivateOramAppendClientIndexCheckpointV2::Result {
        index_epoch,
        root_hash,
        state,
        records,
        ..
    } = &checkpoint.indexes[1]
    else {
        panic!("paired checkpoint result index is missing");
    };
    assert_eq!(*index_epoch, fixture.result_output.new_epoch);
    assert_eq!(root_hash, &fixture.result_output.new_root_hash);
    assert_eq!(state, &fixture.result_output.next_client_state);
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0].payload_fetch_token,
        BASE64URL_NOPAD.encode(&[4; 32])
    );
    assert_eq!(records[0].generation, 0);
    assert_eq!(
        records[1].payload_fetch_token,
        BASE64URL_NOPAD.encode(&[7; 32])
    );
    assert_eq!(records[1].generation, 1);
}

#[test]
fn paired_checkpoint_delta_canonicalizes_new_records_before_existing_records() {
    let hnsw_point = PrivateOramAppendLevel0PointV2 {
        node_id: [1; 32],
        point_token: [1; 32],
        visible_point_id: None,
        payload_fetch_token: Some([1; 32]),
        vector: vec![0.0, 1.0],
        initial_leaf: 3,
    };
    let result_point = PrivateOramAppendResultPointV2 {
        payload_fetch_token: [1; 32],
        point_token: [1; 32],
        payload: b"canonical private payload".to_vec(),
        initial_leaf: 3,
    };
    let fixture = paired_append_transaction_fixture_with_inputs(
        hnsw_point,
        result_point,
        hnsw_append_transaction_plan(),
        result_append_transaction_plan(1),
    );
    let delta = plan_private_oram_append_paired_checkpoint_delta_v2(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        &fixture.hnsw_output,
        &fixture.result_output,
    )
    .unwrap();

    assert_eq!(
        delta.checkpoint().points[0].point_token,
        BASE64URL_NOPAD.encode(&[1; 32])
    );
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw { records, .. } =
        &delta.checkpoint().indexes[0]
    else {
        panic!("paired checkpoint HNSW index is missing");
    };
    assert_eq!(records[0].node_id, BASE64URL_NOPAD.encode(&[1; 32]));
    let PrivateOramAppendClientIndexCheckpointV2::Result { records, .. } =
        &delta.checkpoint().indexes[1]
    else {
        panic!("paired checkpoint result index is missing");
    };
    assert_eq!(
        records[0].payload_fetch_token,
        BASE64URL_NOPAD.encode(&[1; 32])
    );
}

#[test]
fn paired_checkpoint_delta_rejects_cross_index_point_and_payload_mismatches() {
    let mismatched_point_fixture = paired_append_transaction_fixture_with_inputs(
        hnsw_append_transaction_point(),
        PrivateOramAppendResultPointV2 {
            point_token: [8; 32],
            ..result_append_transaction_point()
        },
        hnsw_append_transaction_plan(),
        result_append_transaction_plan(1),
    );
    assert_eq!(
        plan_private_oram_append_paired_checkpoint_delta_v2(
            &mismatched_point_fixture.manifest,
            &mismatched_point_fixture.state,
            &mismatched_point_fixture.checkpoint,
            &mismatched_point_fixture.hnsw_output,
            &mismatched_point_fixture.result_output,
        ),
        Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "point_ledger"
        ))
    );

    let mismatched_payload_fixture = paired_append_transaction_fixture_with_inputs(
        hnsw_append_transaction_point(),
        PrivateOramAppendResultPointV2 {
            payload_fetch_token: [8; 32],
            ..result_append_transaction_point()
        },
        hnsw_append_transaction_plan(),
        result_append_transaction_plan(1),
    );
    assert_eq!(
        plan_private_oram_append_paired_checkpoint_delta_v2(
            &mismatched_payload_fixture.manifest,
            &mismatched_payload_fixture.state,
            &mismatched_payload_fixture.checkpoint,
            &mismatched_payload_fixture.hnsw_output,
            &mismatched_payload_fixture.result_output,
        ),
        Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "point_ledger"
        ))
    );
}

#[test]
fn paired_checkpoint_delta_rejects_rewrite_neighbor_missing_from_node_ledger() {
    let mut fixture = paired_append_transaction_fixture();
    let unrelated_node_id = [99; 32];
    let rewrite = &mut fixture.hnsw_output.graph_delta.neighbor_rewrites[0];
    rewrite.previous.neighbors.push(unrelated_node_id);
    rewrite.previous.neighbor_levels.push(0);
    rewrite.replacement.neighbors.push(unrelated_node_id);
    rewrite.replacement.neighbor_levels.push(0);
    let mut unrelated_position = fixture.hnsw_output.next_client_state.positions[0].clone();
    unrelated_position.node_id = BASE64URL_NOPAD.encode(&unrelated_node_id);
    fixture
        .hnsw_output
        .next_client_state
        .positions
        .push(unrelated_position);
    refresh_hnsw_prepared_commit_digest(&fixture.manifest, &mut fixture.hnsw_output);

    validate_private_oram_append_hnsw_transaction_output_v2(
        &fixture.manifest,
        &fixture.hnsw_output,
    )
    .unwrap();
    assert_eq!(
        plan_private_oram_append_paired_checkpoint_delta_v2(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            &fixture.hnsw_output,
            &fixture.result_output,
        ),
        Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "neighbor_rewrites"
        ))
    );
}

#[test]
fn paired_checkpoint_delta_rejects_mixed_mutation_identity() {
    let mut result_plan = result_append_transaction_plan(1);
    result_plan.mutation_id = digest(22);
    let fixture = paired_append_transaction_fixture_with_inputs(
        hnsw_append_transaction_point(),
        result_append_transaction_point(),
        hnsw_append_transaction_plan(),
        result_plan,
    );

    assert_eq!(
        plan_private_oram_append_paired_checkpoint_delta_v2(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            &fixture.hnsw_output,
            &fixture.result_output,
        ),
        Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "paired_identity"
        ))
    );
}

#[test]
fn paired_checkpoint_delta_rejects_a_tampered_source_checkpoint_digest() {
    let mut fixture = paired_append_transaction_fixture();
    fixture.result_output.source_checkpoint_digest = digest(99);

    assert_eq!(
        plan_private_oram_append_paired_checkpoint_delta_v2(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            &fixture.hnsw_output,
            &fixture.result_output,
        ),
        Err(PrivateOramAppendCheckpointError::Transaction(
            PrivateOramAppendTransactionError::RecoveryMarkerMismatch
        ))
    );

    let mut fixture = paired_append_transaction_fixture();
    fixture.hnsw_output.source_checkpoint_digest = digest(99);
    assert_eq!(
        plan_private_oram_append_paired_checkpoint_delta_v2(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            &fixture.hnsw_output,
            &fixture.result_output,
        ),
        Err(PrivateOramAppendCheckpointError::Transaction(
            PrivateOramAppendTransactionError::RecoveryMarkerMismatch
        ))
    );
}

#[test]
fn paired_checkpoint_delta_rejects_immediate_mutation_id_reuse() {
    let fixture = paired_append_transaction_fixture_with_inputs_and_last_mutation(
        hnsw_append_transaction_point(),
        result_append_transaction_point(),
        hnsw_append_transaction_plan(),
        result_append_transaction_plan(1),
        Some(digest(20)),
    );

    assert_eq!(
        plan_private_oram_append_paired_checkpoint_delta_v2(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            &fixture.hnsw_output,
            &fixture.result_output,
        ),
        Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "mutation_id"
        ))
    );
}

#[test]
fn paired_checkpoint_reseal_binds_exact_ciphertext_digest_and_reopens() {
    let fixture = paired_append_transaction_fixture();
    let checkpoint_key = SecretKey::from_bytes([44; 32]);
    let resealed = reseal_private_oram_append_paired_checkpoint_v2(
        &checkpoint_key,
        PrivateOramAppendPairedCheckpointResealInputV2 {
            manifest: &fixture.manifest,
            old_state: &fixture.state,
            old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
            hnsw_output: &fixture.hnsw_output,
            result_output: &fixture.result_output,
            new_state_signed_at_unix: fixture.state.signed_at_unix + 1,
        },
    )
    .unwrap();

    assert_eq!(
        resealed.new_state.client_state_digest,
        private_oram_append_client_checkpoint_v2_digest(&resealed.encrypted_checkpoint.sealed)
            .unwrap()
    );
    assert_eq!(
        resealed.encrypted_checkpoint.state_digest,
        private_oram_signed_state_v2_digest(&resealed.new_state).unwrap()
    );
    assert_eq!(
        resealed.new_state.last_mutation_id.as_deref(),
        Some(digest(20).as_str())
    );
    assert_eq!(
        resealed.new_state.state_sequence,
        fixture.state.state_sequence + 1
    );
    assert_eq!(
        open_private_oram_append_client_checkpoint_v2(
            &checkpoint_key,
            &resealed.encrypted_checkpoint,
            &fixture.manifest,
            &resealed.new_state,
        )
        .unwrap(),
        resealed.checkpoint
    );
}

#[test]
fn paired_checkpoint_reseal_rejects_an_unbound_old_checkpoint() {
    let fixture = paired_append_transaction_fixture();
    let mut unbound = fixture.old_encrypted_checkpoint.clone();
    unbound.state_digest = digest(99);

    assert_eq!(
        reseal_private_oram_append_paired_checkpoint_v2(
            &SecretKey::from_bytes([44; 32]),
            PrivateOramAppendPairedCheckpointResealInputV2 {
                manifest: &fixture.manifest,
                old_state: &fixture.state,
                old_encrypted_checkpoint: &unbound,
                hnsw_output: &fixture.hnsw_output,
                result_output: &fixture.result_output,
                new_state_signed_at_unix: fixture.state.signed_at_unix + 1,
            },
        ),
        Err(PrivateOramAppendCheckpointError::Client(
            PrivateOramAppendClientError::CheckpointStateMismatch
        ))
    );
}

#[test]
fn paired_checkpoint_reseal_randomization_changes_the_pending_artifact() {
    let fixture = paired_append_transaction_fixture();
    let checkpoint_key = SecretKey::from_bytes([44; 32]);
    let input = PrivateOramAppendPairedCheckpointResealInputV2 {
        manifest: &fixture.manifest,
        old_state: &fixture.state,
        old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
        hnsw_output: &fixture.hnsw_output,
        result_output: &fixture.result_output,
        new_state_signed_at_unix: fixture.state.signed_at_unix + 1,
    };
    let first = reseal_private_oram_append_paired_checkpoint_v2(&checkpoint_key, input).unwrap();
    let second = reseal_private_oram_append_paired_checkpoint_v2(&checkpoint_key, input).unwrap();

    assert_ne!(
        first.encrypted_checkpoint.sealed.ciphertext,
        second.encrypted_checkpoint.sealed.ciphertext
    );
    assert_ne!(
        first.new_state.client_state_digest,
        second.new_state.client_state_digest
    );
    assert_ne!(
        first.encrypted_checkpoint.state_digest,
        second.encrypted_checkpoint.state_digest
    );
    assert_eq!(first.checkpoint, second.checkpoint);
}

#[test]
fn paired_checkpoint_debug_output_redacts_client_state_and_ciphertext() {
    let fixture = paired_append_transaction_fixture();
    let checkpoint_key = SecretKey::from_bytes([44; 32]);
    let input = PrivateOramAppendPairedCheckpointResealInputV2 {
        manifest: &fixture.manifest,
        old_state: &fixture.state,
        old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
        hnsw_output: &fixture.hnsw_output,
        result_output: &fixture.result_output,
        new_state_signed_at_unix: fixture.state.signed_at_unix + 1,
    };
    let input_debug = format!("{input:?}");
    let resealed = reseal_private_oram_append_paired_checkpoint_v2(&checkpoint_key, input).unwrap();
    let output_debug = format!("{resealed:?}");
    let delta = plan_private_oram_append_paired_checkpoint_delta_v2(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        &fixture.hnsw_output,
        &fixture.result_output,
    )
    .unwrap();
    let delta_debug = format!("{delta:?}");

    for debug in [input_debug, output_debug, delta_debug] {
        assert!(!debug.contains(&fixture.manifest.collection_id));
        assert!(!debug.contains(&BASE64URL_NOPAD.encode(&[6; 32])));
        assert!(!debug.contains(&resealed.encrypted_checkpoint.sealed.ciphertext));
    }
}

#[test]
fn paired_checkpoint_reseal_rejects_a_rollback_signed_at_time() {
    let fixture = paired_append_transaction_fixture();
    assert_eq!(
        reseal_private_oram_append_paired_checkpoint_v2(
            &SecretKey::from_bytes([44; 32]),
            PrivateOramAppendPairedCheckpointResealInputV2 {
                manifest: &fixture.manifest,
                old_state: &fixture.state,
                old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
                hnsw_output: &fixture.hnsw_output,
                result_output: &fixture.result_output,
                new_state_signed_at_unix: fixture.state.signed_at_unix - 1,
            },
        ),
        Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "signed_state"
        ))
    );
}

#[test]
fn paired_mutation_finalizer_signs_and_self_validates_the_exact_pending_artifact() {
    let fixture = paired_append_transaction_fixture();
    let checkpoint_key = SecretKey::from_bytes([44; 32]);
    let key_pair = deterministic_owner_key_pair();
    let manifest_bundle =
        package_private_oram_immutable_manifest_v2(&key_pair, fixture.manifest.clone()).unwrap();
    let old_state_bundle =
        package_private_oram_signed_state_v2(&key_pair, fixture.state.clone()).unwrap();
    let manifest_digest =
        private_oram_immutable_manifest_v2_digest(&manifest_bundle.manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&old_state_bundle.state).unwrap();
    let writer_lease_digest = digest(21);
    let validation = paired_finalization_validation(
        &manifest_bundle,
        &old_state_bundle,
        &manifest_digest,
        &old_state_digest,
        &writer_lease_digest,
        &key_pair,
    );

    let finalized = finalize_private_oram_append_paired_mutation_v1(
        &checkpoint_key,
        &key_pair,
        PrivateOramAppendPairedFinalizationInputV1 {
            manifest_bundle: &manifest_bundle,
            old_state_bundle: &old_state_bundle,
            old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
            hnsw_output: fixture.hnsw_output.clone(),
            result_output: fixture.result_output.clone(),
            issued_at_unix: 1_770_000_110,
            expires_at_unix: 1_770_000_180,
            new_state_signed_at_unix: 1_770_000_120,
            validation,
        },
    )
    .unwrap();

    let mutation = &finalized.mutation_bundle.mutation;
    assert_eq!(mutation.old_state, old_state_bundle);
    assert_eq!(mutation.new_state.state.state_sequence, 8);
    assert_eq!(
        mutation.new_state.state.last_mutation_id.as_deref(),
        Some(digest(20).as_str())
    );
    assert_eq!(
        mutation.point_operation_kind,
        PrivateOramPointOperationKindV1::NoServerPointRecord
    );
    assert_eq!(
        mutation.point_operation_digest,
        private_oram_no_server_point_record_v1_digest(
            &manifest_bundle.manifest.collection_id,
            &manifest_digest,
            &digest(20),
        )
        .unwrap()
    );
    assert_eq!(
        mutation
            .writebacks
            .iter()
            .map(|writeback| (writeback.kind, writeback.index_name.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (PrivateOramIndexKindV2::Hnsw, "text"),
            (PrivateOramIndexKindV2::Result, "private-payload"),
        ]
    );
    assert_eq!(
        mutation.new_state.state.client_state_digest,
        private_oram_append_client_checkpoint_v2_digest(&finalized.encrypted_checkpoint.sealed)
            .unwrap()
    );
    assert_eq!(
        open_private_oram_append_client_checkpoint_v2(
            &checkpoint_key,
            &finalized.encrypted_checkpoint,
            &manifest_bundle.manifest,
            &mutation.new_state.state,
        )
        .unwrap(),
        finalized.checkpoint
    );

    let observed_read_transcripts = vec![
        finalized.hnsw_output.read_transcript.clone(),
        finalized.result_output.read_transcript.clone(),
    ];
    validate_private_oram_append_mutation_v1(
        &manifest_bundle,
        &finalized.mutation_bundle,
        PrivateOramAppendValidationContext {
            expected_collection_id: validation.expected_collection_id,
            expected_manifest_digest: validation.expected_manifest_digest,
            expected_owner_signing_key_id: validation.expected_owner_signing_key_id,
            expected_layout_generation: validation.expected_layout_generation,
            expected_layout_digest: validation.expected_layout_digest,
            expected_writer_lease_digest: validation.expected_writer_lease_digest,
            expected_writer_fence: validation.expected_writer_fence,
            expected_state_sequence: validation.expected_state_sequence,
            expected_old_state_digest: validation.expected_old_state_digest,
            expected_visible_point_record: None,
            observed_read_transcripts: &observed_read_transcripts,
            now_unix: validation.now_unix,
            max_mutation_ttl_secs: validation.max_mutation_ttl_secs,
            public_key: validation.public_key,
        },
    )
    .unwrap();

    let owner_prepare = project_private_oram_append_paired_owner_prepare_v1(&finalized).unwrap();
    let owner_prepare_json = serde_json::to_string(&owner_prepare).unwrap();
    let owner_prepare_value = serde_json::to_value(&owner_prepare).unwrap();
    let top_level_keys = owner_prepare_value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        top_level_keys,
        std::collections::BTreeSet::from(["indexes", "mutation_bundle", "version"])
    );
    for index_value in owner_prepare_value["indexes"].as_array().unwrap() {
        let index_keys = index_value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            index_keys,
            std::collections::BTreeSet::from([
                "index_name",
                "merkle_patch_proof",
                "ordered_encrypted_buckets",
            ])
        );
        let bucket_batch_keys = index_value["ordered_encrypted_buckets"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            bucket_batch_keys,
            std::collections::BTreeSet::from(["buckets", "kind"])
        );
        let proof_keys = index_value["merkle_patch_proof"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            proof_keys,
            std::collections::BTreeSet::from([
                "bucket_count",
                "index_epoch",
                "leaves",
                "old_root_hash",
                "version",
            ])
        );
    }
    for forbidden_field in [
        "checkpoint",
        "next_client_state",
        "graph_delta",
        "result_record",
        "final_encrypted_buckets",
        "recovery_marker",
        "position_map",
        "stash",
        "read_transcript",
    ] {
        let forbidden_json_key = format!("\"{forbidden_field}\":");
        assert!(
            !owner_prepare_json.contains(&forbidden_json_key),
            "{forbidden_field}: {owner_prepare_json}",
        );
    }
    for forbidden_value in [
        &fixture.old_encrypted_checkpoint.sealed.ciphertext,
        &finalized.hnsw_output.recovery_marker.attempt_digest,
        &finalized.result_output.recovery_marker.attempt_digest,
    ] {
        assert!(!owner_prepare_json.contains(forbidden_value));
    }
    let owner_server_read_evidence_recorder = PrivateOramServerReadEvidenceRecorderV1::new();
    let owner_server_read_evidence = vec![
        server_read_evidence(
            &owner_server_read_evidence_recorder,
            &finalized.hnsw_output.read_transcript,
        ),
        server_read_evidence(
            &owner_server_read_evidence_recorder,
            &finalized.result_output.read_transcript,
        ),
    ];
    let owner_validation = PrivateOramAppendOwnerPrepareValidationContextV1 {
        expected_collection_id: validation.expected_collection_id,
        expected_manifest_digest: validation.expected_manifest_digest,
        expected_owner_signing_key_id: validation.expected_owner_signing_key_id,
        expected_layout_generation: validation.expected_layout_generation,
        expected_layout_digest: validation.expected_layout_digest,
        expected_writer_lease_digest: validation.expected_writer_lease_digest,
        expected_writer_fence: validation.expected_writer_fence,
        expected_state_sequence: validation.expected_state_sequence,
        expected_old_state_digest: validation.expected_old_state_digest,
        expected_visible_point_record: None,
        server_read_evidence_recorder: &owner_server_read_evidence_recorder,
        server_read_evidence: &owner_server_read_evidence,
        now_unix: validation.now_unix,
        max_mutation_ttl_secs: validation.max_mutation_ttl_secs,
        public_key: validation.public_key,
    };
    let validated = validate_private_oram_append_owner_prepare_v1(
        &manifest_bundle,
        &owner_prepare,
        owner_validation,
    )
    .unwrap();
    assert_eq!(validated.mutation_bundle(), &owner_prepare.mutation_bundle);
    assert_eq!(
        validated.mutation_digest(),
        private_oram_append_mutation_v1_digest(&owner_prepare.mutation_bundle.mutation).unwrap()
    );
    assert_eq!(validated.indexes().len(), 2);
    for (index, writeback) in validated
        .indexes()
        .iter()
        .zip(&owner_prepare.mutation_bundle.mutation.writebacks)
    {
        assert_eq!(index.kind(), index.final_buckets().kind());
        assert_eq!(index.final_bucket_refs().len(), index.final_buckets().len());
        assert!(index.final_bucket_refs().len() < index.ordered_bucket_refs().len());
        assert_eq!(
            index.ordered_bucket_refs(),
            writeback.updated_buckets.as_slice()
        );
        let expected_last_refs = writeback
            .updated_buckets
            .iter()
            .cloned()
            .fold(std::collections::BTreeMap::new(), |mut refs, bucket| {
                refs.insert(bucket.bucket_id, bucket);
                refs
            })
            .into_values()
            .collect::<Vec<_>>();
        assert_eq!(index.final_bucket_refs(), expected_last_refs.as_slice());
        assert_eq!(index.old_epoch() + 1, index.new_epoch());
    }

    assert!(
        validate_private_oram_append_owner_prepare_v1(
            &manifest_bundle,
            &owner_prepare,
            PrivateOramAppendOwnerPrepareValidationContextV1 {
                server_read_evidence: &[],
                ..owner_validation
            },
        )
        .is_err()
    );

    let mut mismatched_server_evidence = owner_server_read_evidence.clone();
    let mut mismatched_server_transcript = finalized.hnsw_output.read_transcript.clone();
    mismatched_server_transcript.ordered_leaf_labels.swap(0, 1);
    mismatched_server_evidence[0] = server_read_evidence(
        &owner_server_read_evidence_recorder,
        &mismatched_server_transcript,
    );
    assert!(
        validate_private_oram_append_owner_prepare_v1(
            &manifest_bundle,
            &owner_prepare,
            PrivateOramAppendOwnerPrepareValidationContextV1 {
                server_read_evidence: &mismatched_server_evidence,
                ..owner_validation
            },
        )
        .is_err()
    );

    let foreign_server_read_evidence_recorder = PrivateOramServerReadEvidenceRecorderV1::new();
    let foreign_server_read_evidence = vec![
        server_read_evidence(
            &foreign_server_read_evidence_recorder,
            &finalized.hnsw_output.read_transcript,
        ),
        server_read_evidence(
            &foreign_server_read_evidence_recorder,
            &finalized.result_output.read_transcript,
        ),
    ];
    assert!(
        validate_private_oram_append_owner_prepare_v1(
            &manifest_bundle,
            &owner_prepare,
            PrivateOramAppendOwnerPrepareValidationContextV1 {
                server_read_evidence: &foreign_server_read_evidence,
                ..owner_validation
            },
        )
        .is_err()
    );

    let mut missing_occurrence = owner_prepare.clone();
    let PrivateOramAppendOwnerBucketBatchV1::Hnsw(buckets) =
        &mut missing_occurrence.indexes[0].ordered_encrypted_buckets
    else {
        unreachable!();
    };
    buckets.remove(0);
    assert!(
        validate_private_oram_append_owner_prepare_v1(
            &manifest_bundle,
            &missing_occurrence,
            owner_validation,
        )
        .is_err()
    );

    let mut reordered_occurrences = owner_prepare.clone();
    let PrivateOramAppendOwnerBucketBatchV1::Hnsw(buckets) =
        &mut reordered_occurrences.indexes[0].ordered_encrypted_buckets
    else {
        unreachable!();
    };
    buckets.swap(0, 1);
    assert!(
        validate_private_oram_append_owner_prepare_v1(
            &manifest_bundle,
            &reordered_occurrences,
            owner_validation,
        )
        .is_err()
    );

    let mut wrong_bucket_kind = owner_prepare.clone();
    let result_buckets = match &wrong_bucket_kind.indexes[1].ordered_encrypted_buckets {
        PrivateOramAppendOwnerBucketBatchV1::Result(buckets) => buckets.clone(),
        PrivateOramAppendOwnerBucketBatchV1::Hnsw(_) => unreachable!(),
    };
    wrong_bucket_kind.indexes[0].ordered_encrypted_buckets =
        PrivateOramAppendOwnerBucketBatchV1::Result(result_buckets);
    assert!(
        validate_private_oram_append_owner_prepare_v1(
            &manifest_bundle,
            &wrong_bucket_kind,
            owner_validation,
        )
        .is_err()
    );

    let mut duplicate_proof_leaf = owner_prepare.clone();
    let duplicate = duplicate_proof_leaf.indexes[0].merkle_patch_proof.leaves[0].clone();
    duplicate_proof_leaf.indexes[0]
        .merkle_patch_proof
        .leaves
        .insert(0, duplicate);
    assert!(
        validate_private_oram_append_owner_prepare_v1(
            &manifest_bundle,
            &duplicate_proof_leaf,
            owner_validation,
        )
        .is_err()
    );

    let mut tampered_proof = owner_prepare.clone();
    tampered_proof.indexes[0].merkle_patch_proof.old_root_hash = digest(252);
    assert!(
        validate_private_oram_append_owner_prepare_v1(
            &manifest_bundle,
            &tampered_proof,
            owner_validation,
        )
        .is_err()
    );

    let mut invalid_signature = owner_prepare.clone();
    invalid_signature.mutation_bundle.signature.sig = digest(253);
    assert!(
        validate_private_oram_append_owner_prepare_v1(
            &manifest_bundle,
            &invalid_signature,
            owner_validation,
        )
        .is_err()
    );

    let mut unknown_client_field = serde_json::to_value(&owner_prepare).unwrap();
    unknown_client_field["indexes"][0]
        .as_object_mut()
        .unwrap()
        .insert("read_transcript".to_string(), serde_json::json!({}));
    assert!(
        serde_json::from_value::<PrivateOramAppendOwnerPrepareV1>(unknown_client_field).is_err()
    );

    let durable_observations =
        private_oram_owner_prestage_read_observations_v2(&observed_read_transcripts).unwrap();
    let durable_validation = PrivateOramAppendOwnerPrestageValidationContextV2 {
        expected_collection_id: owner_validation.expected_collection_id,
        expected_manifest_digest: owner_validation.expected_manifest_digest,
        expected_owner_signing_key_id: owner_validation.expected_owner_signing_key_id,
        expected_layout_generation: owner_validation.expected_layout_generation,
        expected_layout_digest: owner_validation.expected_layout_digest,
        expected_writer_lease_digest: owner_validation.expected_writer_lease_digest,
        expected_writer_fence: owner_validation.expected_writer_fence,
        expected_state_sequence: owner_validation.expected_state_sequence,
        expected_old_state_digest: owner_validation.expected_old_state_digest,
        expected_visible_point_record: owner_validation.expected_visible_point_record,
        now_unix: owner_prepare
            .mutation_bundle
            .mutation
            .new_state
            .state
            .signed_at_unix,
        max_mutation_ttl_secs: owner_validation.max_mutation_ttl_secs,
        public_key: owner_validation.public_key,
    };
    validate_private_oram_append_owner_prepare_from_durable_recovery_v2(
        &manifest_bundle,
        &owner_prepare,
        &durable_observations,
        durable_validation,
    )
    .unwrap();
    assert!(
        validate_private_oram_append_owner_prepare_from_durable_recovery_v2(
            &manifest_bundle,
            &owner_prepare,
            &durable_observations,
            PrivateOramAppendOwnerPrestageValidationContextV2 {
                now_unix: owner_prepare.mutation_bundle.mutation.issued_at_unix,
                ..durable_validation
            },
        )
        .is_err()
    );
    let reconstructed = reconstruct_private_oram_owner_prestage_read_transcripts_v2(
        &owner_prepare,
        &durable_observations,
    )
    .unwrap();
    assert_eq!(reconstructed, observed_read_transcripts);
    let durable_json = serde_json::to_string(&durable_observations).unwrap();
    assert!(!durable_json.contains("ordered_leaf_labels"));
    assert!(!durable_json.contains("\"paths\""));

    let mut tampered_path = owner_prepare.clone();
    let tree_height = usize::try_from(durable_observations[0].tree_height).unwrap();
    let leaf_ref =
        &mut tampered_path.mutation_bundle.mutation.writebacks[0].updated_buckets[tree_height];
    let leaf_base = (1_u64 << durable_observations[0].tree_height) - 1;
    leaf_ref.bucket_id = if leaf_ref.bucket_id == leaf_base {
        leaf_base + 1
    } else {
        leaf_base
    };
    assert!(
        reconstruct_private_oram_owner_prestage_read_transcripts_v2(
            &tampered_path,
            &durable_observations,
        )
        .is_err()
    );

    let mutation = &owner_prepare.mutation_bundle.mutation;
    let owner_roster = vec![11, 12];
    let owner_roster_digest = private_oram_owner_prestage_roster_digest_v2(&owner_roster).unwrap();
    assert!(matches!(
        private_oram_owner_prestage_roster_digest_v2(&[0, 11, 12]),
        Err(PrivateOramOwnerPrestageError::InvalidField(
            "owner_peer_ids"
        ))
    ));
    let package = PrivateOramOwnerPrestagePackageV2 {
        version: PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
        collection_name: "docs".to_string(),
        collection_id: mutation.collection_id.clone(),
        mutation_id: mutation.mutation_id.clone(),
        mutation_digest: private_oram_append_mutation_v1_digest(mutation).unwrap(),
        transition_digest: digest(220),
        base_record_digest: digest(221),
        expected_aggregate_digest: digest(222),
        lease_generation: 4,
        writer_fence: mutation.writer_fence,
        coordinator_peer_id: 11,
        owner_peer_id: 12,
        vector_name: "text".to_string(),
        owner_signing_key_id: mutation.owner_signing_key_id.clone(),
        activation_registry_generation: 3,
        activation_manifest_digest: digest(223),
        parent_descriptor_digest: digest(224),
        parent_lease_acquired_record_digest: digest(225),
        owner_peer_ids: owner_roster,
        owner_roster_digest,
        immutable_manifest: manifest_bundle.clone(),
        owner_prepare: owner_prepare.clone(),
        durable_read_observations: durable_observations,
        staged_insert_frame_b64: None,
    };
    let package_bytes = encode_private_oram_owner_prestage_package_v2(&package).unwrap();
    assert_eq!(
        decode_private_oram_owner_prestage_package_v2(&package_bytes).unwrap(),
        package
    );
    let request = private_oram_owner_prestage_request_v2(
        BASE64URL_NOPAD.encode(&[7_u8; 16]),
        &package,
        &package_bytes,
    )
    .unwrap();
    let request_signature =
        sign_private_oram_owner_prestage_request_v2(&key_pair, 9, &request).unwrap();
    let peer_public_key = private_oram_peer_recovery_public_key_v1(&key_pair, 9).unwrap();
    let verified_request = validate_private_oram_owner_prestage_request_signature_v2(
        &peer_public_key,
        &request,
        &package_bytes,
        &request_signature,
    )
    .unwrap();
    validate_private_oram_owner_prestage_package_for_request_v2(
        &verified_request,
        &package,
        &package_bytes,
    )
    .unwrap();
    let mut changed_package_bytes = package_bytes.clone();
    let last = changed_package_bytes.last_mut().unwrap();
    *last ^= 1;
    assert_eq!(
        validate_private_oram_owner_prestage_request_signature_v2(
            &peer_public_key,
            &request,
            &changed_package_bytes,
            &request_signature,
        )
        .unwrap_err(),
        PrivateOramOwnerPrestageError::PackageMismatch
    );

    let receipt_bytes = br#"{"receipt":"durable"}"#;
    let response =
        private_oram_owner_prestage_response_v2(&request, receipt_bytes, digest(226)).unwrap();
    let response_signature = sign_private_oram_owner_prestage_response_v2(
        &key_pair,
        9,
        &request,
        &response,
        receipt_bytes,
    )
    .unwrap();
    let _verified_response = validate_private_oram_owner_prestage_response_signature_v2(
        &peer_public_key,
        &request,
        &response,
        receipt_bytes,
        &response_signature,
    )
    .unwrap();
    assert!(
        validate_private_oram_owner_prestage_response_signature_v2(
            &peer_public_key,
            &request,
            &response,
            br#"{"receipt":"changed"}"#,
            &response_signature,
        )
        .is_err()
    );
    assert!(matches!(
        private_oram_owner_prestage_attestation_statement_v2(
            &request,
            &response,
            br#"{"receipt":"changed"}"#,
        ),
        Err(PrivateOramOwnerPrestageError::ResponseMismatch)
    ));
    let statement =
        private_oram_owner_prestage_attestation_statement_v2(&request, &response, receipt_bytes)
            .unwrap();
    let attestation =
        sign_private_oram_owner_prestage_attestation_v2(&key_pair, 9, &statement).unwrap();
    let attestation_bytes =
        encode_private_oram_owner_prestage_attestation_v2(&attestation).unwrap();
    let decoded_attestation =
        decode_private_oram_owner_prestage_attestation_v2(&attestation_bytes).unwrap();
    let _verified_attestation = validate_private_oram_owner_prestage_attestation_for_signer_v2(
        &decoded_attestation,
        &peer_public_key,
    )
    .unwrap();
    let debug = format!("{package:?} {verified_request:?} {decoded_attestation:?}");
    assert!(!debug.contains(&mutation.mutation_id));
    assert!(!debug.contains(&package_bytes.escape_ascii().to_string()));
}

#[test]
fn paired_mutation_finalizer_rejects_untrusted_keys_context_and_prepared_bodies() {
    let fixture = paired_append_transaction_fixture();
    let checkpoint_key = SecretKey::from_bytes([44; 32]);
    let key_pair = deterministic_owner_key_pair();
    let manifest_bundle =
        package_private_oram_immutable_manifest_v2(&key_pair, fixture.manifest.clone()).unwrap();
    let old_state_bundle =
        package_private_oram_signed_state_v2(&key_pair, fixture.state.clone()).unwrap();
    let manifest_digest =
        private_oram_immutable_manifest_v2_digest(&manifest_bundle.manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&old_state_bundle.state).unwrap();
    let writer_lease_digest = digest(21);
    let validation = paired_finalization_validation(
        &manifest_bundle,
        &old_state_bundle,
        &manifest_digest,
        &old_state_digest,
        &writer_lease_digest,
        &key_pair,
    );

    let mut wrong_key_validation = validation;
    wrong_key_validation.public_key = &[99; 32];
    assert_eq!(
        finalize_private_oram_append_paired_mutation_v1(
            &checkpoint_key,
            &key_pair,
            PrivateOramAppendPairedFinalizationInputV1 {
                manifest_bundle: &manifest_bundle,
                old_state_bundle: &old_state_bundle,
                old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
                hnsw_output: fixture.hnsw_output.clone(),
                result_output: fixture.result_output.clone(),
                issued_at_unix: 1_770_000_110,
                expires_at_unix: 1_770_000_180,
                new_state_signed_at_unix: 1_770_000_120,
                validation: wrong_key_validation,
            },
        ),
        Err(PrivateOramAppendFinalizerError::SigningKeyMismatch)
    );

    let wrong_writer_lease_digest = digest(99);
    let mut wrong_context = validation;
    wrong_context.expected_writer_lease_digest = &wrong_writer_lease_digest;
    assert_eq!(
        finalize_private_oram_append_paired_mutation_v1(
            &checkpoint_key,
            &key_pair,
            PrivateOramAppendPairedFinalizationInputV1 {
                manifest_bundle: &manifest_bundle,
                old_state_bundle: &old_state_bundle,
                old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
                hnsw_output: fixture.hnsw_output.clone(),
                result_output: fixture.result_output.clone(),
                issued_at_unix: 1_770_000_110,
                expires_at_unix: 1_770_000_180,
                new_state_signed_at_unix: 1_770_000_120,
                validation: wrong_context,
            },
        ),
        Err(PrivateOramAppendFinalizerError::ContextMismatch(
            "writer_lease",
        ))
    );

    let mut expired_validation = validation;
    expired_validation.now_unix = 1_770_000_181;
    assert_eq!(
        finalize_private_oram_append_paired_mutation_v1(
            &checkpoint_key,
            &key_pair,
            PrivateOramAppendPairedFinalizationInputV1 {
                manifest_bundle: &manifest_bundle,
                old_state_bundle: &old_state_bundle,
                old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
                hnsw_output: fixture.hnsw_output.clone(),
                result_output: fixture.result_output.clone(),
                issued_at_unix: 1_770_000_110,
                expires_at_unix: 1_770_000_180,
                new_state_signed_at_unix: 1_770_000_120,
                validation: expired_validation,
            },
        ),
        Err(PrivateOramAppendFinalizerError::Mutation(
            PrivateOramMutationError::MutationExpired,
        ))
    );

    let mut tampered_hnsw_output = fixture.hnsw_output;
    let replacement = if tampered_hnsw_output.ordered_encrypted_buckets[0]
        .ciphertext
        .starts_with('A')
    {
        "B"
    } else {
        "A"
    };
    tampered_hnsw_output.ordered_encrypted_buckets[0]
        .ciphertext
        .replace_range(..1, replacement);
    assert!(matches!(
        finalize_private_oram_append_paired_mutation_v1(
            &checkpoint_key,
            &key_pair,
            PrivateOramAppendPairedFinalizationInputV1 {
                manifest_bundle: &manifest_bundle,
                old_state_bundle: &old_state_bundle,
                old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
                hnsw_output: tampered_hnsw_output,
                result_output: fixture.result_output,
                issued_at_unix: 1_770_000_110,
                expires_at_unix: 1_770_000_180,
                new_state_signed_at_unix: 1_770_000_120,
                validation,
            },
        ),
        Err(PrivateOramAppendFinalizerError::Transaction(_))
    ));
}

#[test]
fn paired_mutation_finalizer_debug_output_redacts_signed_and_encrypted_artifacts() {
    let fixture = paired_append_transaction_fixture();
    let checkpoint_key = SecretKey::from_bytes([44; 32]);
    let key_pair = deterministic_owner_key_pair();
    let manifest_bundle =
        package_private_oram_immutable_manifest_v2(&key_pair, fixture.manifest.clone()).unwrap();
    let old_state_bundle =
        package_private_oram_signed_state_v2(&key_pair, fixture.state.clone()).unwrap();
    let manifest_digest =
        private_oram_immutable_manifest_v2_digest(&manifest_bundle.manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&old_state_bundle.state).unwrap();
    let writer_lease_digest = digest(21);
    let validation = paired_finalization_validation(
        &manifest_bundle,
        &old_state_bundle,
        &manifest_digest,
        &old_state_digest,
        &writer_lease_digest,
        &key_pair,
    );
    let input = PrivateOramAppendPairedFinalizationInputV1 {
        manifest_bundle: &manifest_bundle,
        old_state_bundle: &old_state_bundle,
        old_encrypted_checkpoint: &fixture.old_encrypted_checkpoint,
        hnsw_output: fixture.hnsw_output,
        result_output: fixture.result_output,
        issued_at_unix: 1_770_000_110,
        expires_at_unix: 1_770_000_180,
        new_state_signed_at_unix: 1_770_000_120,
        validation,
    };
    let input_debug = format!("{input:?}");
    let finalized =
        finalize_private_oram_append_paired_mutation_v1(&checkpoint_key, &key_pair, input).unwrap();
    let output_debug = format!("{finalized:?}");

    for debug in [input_debug, output_debug] {
        assert!(!debug.contains(&manifest_bundle.manifest.collection_id));
        assert!(!debug.contains(&digest(20)));
        assert!(!debug.contains(&finalized.encrypted_checkpoint.sealed.ciphertext));
        assert!(!debug.contains(&finalized.mutation_bundle.signature.sig));
    }
}

#[test]
fn result_append_transaction_rejects_an_eviction_leaf_equal_to_the_position() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(1);
    let mut plan = result_append_transaction_plan(1);
    let point = result_append_transaction_point();
    plan.insert_eviction_leaf = point.initial_leaf;
    assert!(matches!(
        PrivateOramAppendResultTransactionV2::begin(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            point,
            plan,
        ),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "insert_eviction_leaf"
        ))
    ));
}

#[test]
fn result_append_insert_evicts_padding_path_and_keeps_secret_position() {
    let fixture = result_append_transaction_fixture_with_path_batch_size(1);
    let plan = result_append_transaction_plan(1);
    let point = result_append_transaction_point();
    assert_ne!(plan.insert_eviction_leaf, point.initial_leaf);
    let (output, _) = complete_result_append_transaction(&fixture, plan.clone());

    let position_label = encode_private_result_oram_leaf_label(point.initial_leaf, 2).unwrap();
    let eviction_label =
        encode_private_result_oram_leaf_label(plan.insert_eviction_leaf, 2).unwrap();
    // The insert reads/evicts the independent eviction path, never the new block's position.
    assert_eq!(
        output.read_transcript.ordered_leaf_labels[0],
        eviction_label
    );
    assert!(
        !output
            .read_transcript
            .ordered_leaf_labels
            .contains(&position_label)
    );
    // The new block is still positioned at the point's secret initial leaf.
    let token = BASE64URL_NOPAD.encode(&point.payload_fetch_token);
    let position = output
        .next_client_state
        .positions
        .iter()
        .find(|entry| entry.payload_fetch_token == token)
        .expect("inserted token has a position");
    assert_eq!(position.leaf_label, position_label);
}

#[test]
fn hnsw_append_insert_evicts_padding_path_and_keeps_secret_position() {
    let fixture = hnsw_append_transaction_fixture();
    let plan = hnsw_append_transaction_plan();
    let mut point = hnsw_append_transaction_point();
    // A position that no planned path touches: candidate 1 -> 2, rewrite path 2, padding 3/1.
    point.initial_leaf = 0;
    let (output, _) = complete_hnsw_append_transaction_with_point(&fixture, plan, point.clone());

    let position_label = encode_private_hnsw_oram_leaf_label(point.initial_leaf, 2).unwrap();
    assert!(
        !output
            .read_transcript
            .ordered_leaf_labels
            .contains(&position_label),
        "the insert must not read or evict the new node's own path"
    );
    let node_id = BASE64URL_NOPAD.encode(&point.node_id);
    let position = output
        .next_client_state
        .positions
        .iter()
        .find(|entry| entry.node_id == node_id)
        .expect("inserted node has a position");
    assert_eq!(position.leaf_label, position_label);
}
