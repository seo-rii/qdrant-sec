use std::env;

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PrivateHnswBucketAeadBaseContext,
    PrivateHnswBuildPoint, PrivateHnswClientKeys, PrivateHnswCommitSignatureContext,
    PrivateHnswManifestBuildContext, PrivateHnswOramClientConfig, PrivateHnswParams,
    PrivateResultOramBucket, PrivateResultOramBucketCommitmentContext,
    PrivateResultOramClientCommitBucketRef, PrivateResultOramCommitPlan,
    PrivateResultOramCommitSignatureContext, PrivateResultOramManifest,
    PrivateResultOramReadBucketsSignatureContext, ResultPrivacyMode, SecretKey,
    build_private_hnsw_oram_manifest_from_encrypted_index,
    build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points,
    encode_private_hnsw_oram_leaf_label, plan_private_hnsw_oram_commit_for_manifest,
    private_hnsw_bucket_commitment, private_result_oram_bucket_ciphertext_bytes,
    private_result_oram_bucket_commitment, private_result_oram_merkle_root_for_commitments,
    seal_private_hnsw_oram_plaintext_index, sign_private_hnsw_oram_commit,
    sign_private_hnsw_oram_manifest, sign_private_hnsw_oram_read_paths_for_manifest_context,
    sign_private_result_oram_commit, sign_private_result_oram_manifest,
    sign_private_result_oram_read_buckets,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use sha2::{Digest, Sha256};

const VECTOR_NAME: &str = "text";
const KEY_ID: &str = "tenant-a/vector-private-rk";
const HNSW_SIGNING_KEY_ID: &str = "tenant-a/private-hnsw-signing-v1";
const RESULT_SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v1";
const RK_EPOCH: u64 = 7;
const BASE_EPOCH: u64 = 42;
const NEXT_EPOCH: u64 = 43;

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
    let collection_id = args.next().ok_or(
        "usage: private_oram_cluster_fixture <stable-collection-uuid> \
             [default|large] [private_payload_oram_required|ids_visible]",
    )?;
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
    let hnsw = hnsw_fixture(&collection_id, &hnsw_signing_key, profile, result_privacy)?;
    let result = result_fixture(&collection_id, &result_signing_key, profile)?;

    let output = json!({
        "hnsw_public_key": BASE64URL_NOPAD.encode(hnsw_signing_key.public_key().as_ref()),
        "result_public_key": BASE64URL_NOPAD.encode(result_signing_key.public_key().as_ref()),
        "hnsw": hnsw,
        "result": result,
    });
    println!("{}", serde_json::to_string(&output)?);
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
    let mut sentinels = vec![[13_u8; 32].to_vec()];
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
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let config = PrivateHnswOramClientConfig {
        tree_height: profile.tree_height,
        bucket_size: 2,
        block_size_bytes: profile.hnsw_block_size_bytes,
        fixed_neighbor_slots: 4,
    };
    let points = fixture_points();
    let plaintext = build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
        config,
        DistanceKind::Euclid,
        2,
        1,
        2,
        &points,
        &[0, 1, 2],
    )?;
    let keys = PrivateHnswClientKeys::derive_from_resource_key_with_context(
        &SecretKey::from_bytes([13; 32]),
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
    let encrypted = seal_private_hnsw_oram_plaintext_index(
        &keys,
        base_context,
        BASE_EPOCH,
        &plaintext,
        config,
    )?;
    let manifest = build_private_hnsw_oram_manifest_from_encrypted_index(
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
            owner_signing_key_id: HNSW_SIGNING_KEY_ID,
            created_at_unix: 1_770_000_000,
        },
        &encrypted,
    )?;
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

    let mut updated_bucket = encrypted.buckets[0].clone();
    let mut raw_ciphertext = BASE64URL_NOPAD.decode(updated_bucket.ciphertext.as_bytes())?;
    let last = raw_ciphertext
        .last_mut()
        .ok_or("private HNSW fixture ciphertext must be non-empty")?;
    *last ^= 1;
    updated_bucket.index_epoch = NEXT_EPOCH;
    updated_bucket.ciphertext = BASE64URL_NOPAD.encode(&raw_ciphertext);
    updated_bucket.ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(&raw_ciphertext));
    updated_bucket.bucket_commitment = private_hnsw_bucket_commitment(
        base_context.for_bucket(updated_bucket.bucket_id, NEXT_EPOCH),
        &updated_bucket.ciphertext_sha256,
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
            signing_key_id: HNSW_SIGNING_KEY_ID,
        },
        &commit_plan,
    )?;

    Ok(json!({
        "plaintext_sentinels": plaintext_sentinels(&points),
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
    }))
}

fn result_fixture(
    collection_id: &str,
    signing_key: &Ed25519KeyPair,
    profile: FixtureProfile,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let oram = OramParams {
        kind: OramKind::PathOram,
        bucket_size: 2,
        block_size_bytes: profile.result_block_size_bytes,
        tree_height: profile.tree_height,
        path_batch_size: 1,
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
        logical_result_count: 3,
        dummy_result_count: 1,
        owner_signing_key_id: RESULT_SIGNING_KEY_ID.to_string(),
        created_at_unix: 1_770_000_000,
    };
    let initial_buckets = result_buckets(&manifest)?;
    let commitments = initial_buckets
        .iter()
        .map(|bucket| bucket.bucket_commitment.clone())
        .collect::<Vec<_>>();
    manifest.root_hash = private_result_oram_merkle_root_for_commitments(&commitments)?;
    let buckets = result_buckets(&manifest)?;
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
            signing_key_id: RESULT_SIGNING_KEY_ID,
        },
        BASE_EPOCH,
        &manifest.root_hash,
        manifest.bucket_count,
        &read_bucket_ids,
    )?;

    let mut next_manifest = manifest.clone();
    next_manifest.index_epoch = NEXT_EPOCH;
    let updated_bucket = result_bucket(0, &next_manifest)?;
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
            signing_key_id: RESULT_SIGNING_KEY_ID,
        },
        &commit_plan,
    )?;

    Ok(json!({
        "manifest": manifest,
        "manifest_signature": manifest_signature,
        "buckets": buckets,
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
    }))
}

fn result_buckets(
    manifest: &PrivateResultOramManifest,
) -> Result<Vec<PrivateResultOramBucket>, Box<dyn std::error::Error>> {
    (0..manifest.bucket_count)
        .map(|bucket_id| result_bucket(bucket_id, manifest))
        .collect()
}

fn result_bucket(
    bucket_id: u64,
    manifest: &PrivateResultOramManifest,
) -> Result<PrivateResultOramBucket, Box<dyn std::error::Error>> {
    let expected_len = private_result_oram_bucket_ciphertext_bytes(&manifest.oram)?;
    let mut raw_ciphertext = vec![0; expected_len];
    for (offset, byte) in raw_ciphertext.iter_mut().enumerate() {
        *byte = (bucket_id as u8).wrapping_add(manifest.index_epoch as u8) ^ (offset as u8);
    }
    let ciphertext = BASE64URL_NOPAD.encode(&raw_ciphertext);
    let ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(&raw_ciphertext));
    let bucket_commitment = private_result_oram_bucket_commitment(
        PrivateResultOramBucketCommitmentContext {
            collection_id: &manifest.collection_id,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            bucket_id,
            index_epoch: manifest.index_epoch,
        },
        &ciphertext_sha256,
    )?;
    Ok(PrivateResultOramBucket {
        version: 1,
        bucket_id,
        index_epoch: manifest.index_epoch,
        ciphertext,
        ciphertext_sha256,
        bucket_commitment,
    })
}
