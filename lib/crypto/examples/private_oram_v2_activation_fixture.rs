//! Test fixture: signs a private ORAM mutation V2 activation authority bundle for a local
//! cluster. Reads `{"first_voter_peer_id", "binary_capability_digest", "peers": [{"peer_id",
//! "host", "p2p_port", "public_key"}]}` on stdin, where `public_key` is the output of
//! `qdrant --bootstrap-private-oram-peer-identity`, and prints the canonical bundle JSON (to
//! be written to `authority_bundle_path` byte for byte) and the trust anchor settings.
//! The authority key is a fixed test seed: never use this for a real cluster.

use std::io::Read;

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION, PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY,
    PrivateOramActivationAuthorityManifestV1, PrivateOramActivationPeerPinV1,
    PrivateOramActivationPeerUriSchemeV1, PrivateOramPeerRecoveryPublicKeyV1,
    package_private_oram_activation_authority_manifest_v1,
    private_oram_activation_authority_public_key_v1,
    try_private_oram_activation_cluster_identity_digest_v1,
    try_private_oram_activation_peer_uri_digest_v1,
};
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    first_voter_peer_id: u64,
    binary_capability_digest: String,
    peers: Vec<InputPeer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputPeer {
    peer_id: u64,
    host: String,
    p2p_port: u16,
    public_key: PrivateOramPeerRecoveryPublicKeyV1,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin)?;
    let input: Input = serde_json::from_str(&stdin)?;

    let authority_key = Ed25519KeyPair::from_seed_unchecked(&[10; 32])
        .map_err(|_| std::io::Error::other("failed to create the test authority key"))?;
    let authority = private_oram_activation_authority_public_key_v1(&authority_key, 1)?;
    let cluster_identity_nonce = BASE64URL_NOPAD.encode(&[1; 32]);
    let cluster_identity_digest = try_private_oram_activation_cluster_identity_digest_v1(
        &cluster_identity_nonce,
        input.first_voter_peer_id,
    )?;
    let mut peers = input
        .peers
        .into_iter()
        .map(|peer| {
            Ok(PrivateOramActivationPeerPinV1 {
                peer_id: peer.peer_id,
                peer_uri_digest: try_private_oram_activation_peer_uri_digest_v1(
                    PrivateOramActivationPeerUriSchemeV1::Http,
                    &peer.host,
                    peer.p2p_port,
                )?,
                signer: peer.public_key,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    peers.sort_by_key(|peer| peer.peer_id);
    let manifest = PrivateOramActivationAuthorityManifestV1 {
        version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
        cluster_identity_digest: cluster_identity_digest.clone(),
        cluster_identity_nonce,
        cluster_first_voter_peer_id: input.first_voter_peer_id,
        registry_generation: 1,
        parent_manifest_digest: None,
        required_capability: PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY.to_string(),
        required_binary_capability_digest: input.binary_capability_digest,
        authority_key_epoch: authority.key_epoch,
        authority_key_id: authority.key_id.clone(),
        peers,
    };
    let bundle =
        package_private_oram_activation_authority_manifest_v1(&authority_key, 1, manifest)?;

    let output = json!({
        "bundle_canonical_json": serde_json::to_string(&bundle)?,
        "authority": authority,
        "cluster_identity_digest": cluster_identity_digest,
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
