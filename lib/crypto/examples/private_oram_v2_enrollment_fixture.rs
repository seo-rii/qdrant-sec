//! Client side of a private ORAM V2 collection enrollment for multi-process tests.
//!
//! Reads `{"manifest": <uploaded V1 HNSW manifest>, "template": <enrollment template>}` on
//! stdin and prints the signed immutable manifest and genesis state bundles of the
//! `private_oram_cluster_fixture` collection, signed with that fixture's HNSW owner key.

use std::io::Read as _;

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PRIVATE_HNSW_ORAM_V2_BINDING, PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
    PRIVATE_ORAM_SIGNED_STATE_V2_VERSION, PrivateHnswOramManifest, PrivateHnswVectorEncoding,
    PrivateOramImmutableIndexParamsV2, PrivateOramImmutableIndexV2,
    PrivateOramImmutableManifestBundleV2, PrivateOramImmutableManifestV2,
    PrivateOramIndexCapacityV2, PrivateOramIndexKindV2, PrivateOramIndexStateV2,
    PrivateOramSignedStateBundleV2, PrivateOramSignedStateV2, VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER,
    private_oram_immutable_manifest_v2_digest, sign_private_oram_immutable_manifest_v2,
    sign_private_oram_signed_state_v2,
};
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;
use serde_json::json;

/// Seed of the `private_oram_cluster_fixture` HNSW manifest signing key.
const HNSW_OWNER_KEY_SEED: [u8; 32] = [7; 32];
const MAX_NEIGHBOR_REWRITES: u32 = 1;
const MAX_CLIENT_STASH_BLOCKS: u64 = 8;

#[derive(Deserialize)]
struct Input {
    manifest: PrivateHnswOramManifest,
    template: Template,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    let Input { manifest, template } = serde_json::from_str(&raw)?;
    if manifest.collection_id != template.collection_id {
        return Err("template and manifest name different collections".into());
    }
    let hnsw = template
        .indexes
        .iter()
        .find(|index| index.kind == PrivateOramIndexKindV2::Hnsw)
        .ok_or("template has no HNSW index")?;
    if hnsw.index_name != manifest.vector_name || template.indexes.len() != 1 {
        return Err("this fixture enrolls exactly the HNSW index of the manifest".into());
    }
    let writeback_digest = hnsw
        .writeback_digest
        .clone()
        .ok_or("the HNSW index needs one V1 write-back before enrollment")?;
    let key = Ed25519KeyPair::from_seed_unchecked(&HNSW_OWNER_KEY_SEED)
        .map_err(|_| "failed to create the HNSW owner key")?;

    let oram = &manifest.oram;
    let physical_slots = manifest.bucket_count * u64::from(oram.bucket_size);
    let occupancy = manifest.logical_node_count + manifest.dummy_node_count;
    let reserved_physical_slots = physical_slots
        .checked_sub(occupancy)
        .filter(|reserved| *reserved > 0)
        .ok_or("the uploaded index leaves no reserved physical slot")?;
    // The smallest whole number of read windows that covers the rewrites, the insert and at
    // least one candidate window.
    let window = oram.path_batch_size;
    let fixed_append_read_path_count =
        (MAX_NEIGHBOR_REWRITES + 1 + window).div_ceil(window) * window;
    let fixed_append_write_bucket_count = fixed_append_read_path_count * (oram.tree_height + 1);

    let immutable = PrivateOramImmutableManifestV2 {
        version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
        collection_id: manifest.collection_id.clone(),
        manifest_nonce: BASE64URL_NOPAD.encode(&[21; 32]),
        indexes: vec![PrivateOramImmutableIndexV2 {
            index_name: manifest.vector_name.clone(),
            params: PrivateOramImmutableIndexParamsV2::Hnsw {
                provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                key_id: manifest.key_id.clone(),
                rk_id: manifest.rk_id.clone(),
                rk_epoch: manifest.rk_epoch,
                dim: manifest.dim,
                vector_encoding: PrivateHnswVectorEncoding::F32Le,
                distance: manifest.distance,
                hnsw: manifest.hnsw.clone(),
                oram: manifest.oram.clone(),
                fixed_search_budget: manifest.fixed_budget.clone(),
                max_neighbor_rewrites: MAX_NEIGHBOR_REWRITES,
            },
            capacity: PrivateOramIndexCapacityV2 {
                bucket_count: manifest.bucket_count,
                logical_capacity: occupancy,
                reserved_physical_slots,
                max_client_stash_blocks: MAX_CLIENT_STASH_BLOCKS.min(physical_slots) as u32,
                fixed_append_read_path_count,
                fixed_append_write_bucket_count,
            },
        }],
        result_privacy: manifest.result_privacy,
        owner_signing_key_id: manifest.owner_signing_key_id.clone(),
        created_at_unix: manifest.created_at_unix,
    };
    let genesis = PrivateOramSignedStateV2 {
        version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        collection_id: manifest.collection_id.clone(),
        manifest_digest: private_oram_immutable_manifest_v2_digest(&immutable)?,
        layout_generation: template.layout_generation,
        layout_digest: template.layout_digest.clone(),
        state_sequence: 0,
        indexes: vec![PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: manifest.vector_name.clone(),
            index_epoch: hnsw.index_epoch,
            root_hash: hnsw.root_hash.clone(),
            logical_count: manifest.logical_node_count,
            dummy_count: manifest.dummy_node_count,
            last_writeback_digest: writeback_digest,
        }],
        // Stands in for the digest of the client's escrowed append checkpoint set.
        client_state_digest: BASE64URL_NOPAD.encode(&[31; 32]),
        last_mutation_id: None,
        owner_signing_key_id: manifest.owner_signing_key_id.clone(),
        signed_at_unix: manifest.created_at_unix + 1,
    };
    let output = json!({
        "immutable_manifest": PrivateOramImmutableManifestBundleV2 {
            signature: sign_private_oram_immutable_manifest_v2(&key, &immutable)?,
            manifest: immutable,
        },
        "genesis_state": PrivateOramSignedStateBundleV2 {
            signature: sign_private_oram_signed_state_v2(&key, &genesis)?,
            state: genesis,
        },
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
