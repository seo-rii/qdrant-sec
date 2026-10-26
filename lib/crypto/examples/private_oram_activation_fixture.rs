use std::error::Error;
use std::io::{self, Read, Write};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION, PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY,
    PrivateOramActivationAuthorityManifestV1, PrivateOramActivationAuthorityPublicKeyV1,
    PrivateOramActivationPeerPinV1, PrivateOramActivationPeerUriSchemeV1,
    PrivateOramPeerRecoveryPublicKeyV1, package_private_oram_activation_authority_manifest_v1,
    private_oram_activation_authority_public_key_v1,
    try_private_oram_activation_cluster_identity_digest_v1,
    try_private_oram_activation_peer_uri_digest_v1,
};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_REQUEST_JSON_BYTES: usize = 1024 * 1024;
const MAX_PEERS: usize = 1024;
const AUTHORITY_KEY_EPOCH: u64 = 1;
const GENESIS_REGISTRY_GENERATION: u64 = 1;
const LOOPBACK_HTTP_PREFIX: &str = "http://127.0.0.1:";
const TEST_CLUSTER_NONCE_DOMAIN: &str =
    "qdrant-sec/test-fixture/private-oram-activation-cluster-nonce/v1";

// This deterministic key is process-test fixture material and must never become production authority.
const TEST_ONLY_AUTHORITY_SEED: [u8; 32] = [0x6a; 32];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivationFixtureRequest {
    cluster_first_voter_peer_id: u64,
    peers: Vec<ActivationFixturePeer>,
    required_binary_capability_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivationFixturePeer {
    peer_id: u64,
    p2p_uri: String,
    signer: PrivateOramPeerRecoveryPublicKeyV1,
}

#[derive(Serialize)]
struct ActivationFixtureOutput<'a> {
    authority_public_key: &'a PrivateOramActivationAuthorityPublicKeyV1,
    cluster_identity_digest: &'a str,
    cluster_first_voter_peer_id: u64,
    bundle_canonical_json: String,
}

fn invalid_request(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_request() -> Result<ActivationFixtureRequest, Box<dyn Error>> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(u64::try_from(MAX_REQUEST_JSON_BYTES)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_REQUEST_JSON_BYTES {
        return Err(invalid_request("activation fixture request exceeds its size limit").into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn canonical_loopback_http_port(uri: &str) -> Result<u16, io::Error> {
    let port_text = uri
        .strip_prefix(LOOPBACK_HTTP_PREFIX)
        .ok_or_else(|| invalid_request("peer p2p_uri is not canonical loopback HTTP"))?;
    let port = port_text
        .parse::<u16>()
        .map_err(|_| invalid_request("peer p2p_uri port is invalid"))?;
    if port == 0 || uri != format!("{LOOPBACK_HTTP_PREFIX}{port}") {
        return Err(invalid_request(
            "peer p2p_uri is not canonical loopback HTTP",
        ));
    }
    Ok(port)
}

fn validate_request(request: &ActivationFixtureRequest) -> Result<(), io::Error> {
    if request.cluster_first_voter_peer_id == 0 {
        return Err(invalid_request("cluster first voter peer ID is invalid"));
    }
    if request.peers.is_empty() || request.peers.len() > MAX_PEERS {
        return Err(invalid_request("activation fixture peer count is invalid"));
    }

    let mut previous_peer_id = None;
    let mut includes_first_voter = false;
    for peer in &request.peers {
        if peer.peer_id == 0 || previous_peer_id.is_some_and(|previous| previous >= peer.peer_id) {
            return Err(invalid_request(
                "activation fixture peers must have sorted unique IDs",
            ));
        }
        canonical_loopback_http_port(&peer.p2p_uri)?;
        includes_first_voter |= peer.peer_id == request.cluster_first_voter_peer_id;
        previous_peer_id = Some(peer.peer_id);
    }
    if !includes_first_voter {
        return Err(invalid_request(
            "activation fixture peers do not include the cluster first voter",
        ));
    }
    Ok(())
}

fn deterministic_cluster_nonce(
    request: &ActivationFixtureRequest,
) -> Result<String, serde_json::Error> {
    let canonical_request = serde_json::to_vec(request)?;
    let mut hasher = Sha256::new();
    hasher.update((TEST_CLUSTER_NONCE_DOMAIN.len() as u32).to_be_bytes());
    hasher.update(TEST_CLUSTER_NONCE_DOMAIN.as_bytes());
    hasher.update((canonical_request.len() as u64).to_be_bytes());
    hasher.update(canonical_request);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn main() -> Result<(), Box<dyn Error>> {
    let request = read_request()?;
    validate_request(&request)?;

    let authority_key = Ed25519KeyPair::from_seed_unchecked(&TEST_ONLY_AUTHORITY_SEED)
        .map_err(|_| io::Error::other("failed to create activation fixture authority"))?;
    let authority_public_key =
        private_oram_activation_authority_public_key_v1(&authority_key, AUTHORITY_KEY_EPOCH)?;
    let cluster_identity_nonce = deterministic_cluster_nonce(&request)?;
    let cluster_identity_digest = try_private_oram_activation_cluster_identity_digest_v1(
        &cluster_identity_nonce,
        request.cluster_first_voter_peer_id,
    )?;

    let peers = request
        .peers
        .iter()
        .map(|peer| {
            let port = canonical_loopback_http_port(&peer.p2p_uri)?;
            let peer_uri_digest = try_private_oram_activation_peer_uri_digest_v1(
                PrivateOramActivationPeerUriSchemeV1::Http,
                "127.0.0.1",
                port,
            )
            .map_err(io::Error::other)?;
            Ok(PrivateOramActivationPeerPinV1 {
                peer_id: peer.peer_id,
                peer_uri_digest,
                signer: peer.signer.clone(),
            })
        })
        .collect::<Result<Vec<_>, io::Error>>()?;

    let manifest = PrivateOramActivationAuthorityManifestV1 {
        version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
        cluster_identity_nonce,
        cluster_identity_digest: cluster_identity_digest.clone(),
        cluster_first_voter_peer_id: request.cluster_first_voter_peer_id,
        registry_generation: GENESIS_REGISTRY_GENERATION,
        parent_manifest_digest: None,
        required_capability: PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY.to_string(),
        required_binary_capability_digest: request.required_binary_capability_digest,
        authority_key_epoch: authority_public_key.key_epoch,
        authority_key_id: authority_public_key.key_id.clone(),
        peers,
    };
    let bundle = package_private_oram_activation_authority_manifest_v1(
        &authority_key,
        AUTHORITY_KEY_EPOCH,
        manifest,
    )?;
    let output = ActivationFixtureOutput {
        authority_public_key: &authority_public_key,
        cluster_identity_digest: &cluster_identity_digest,
        cluster_first_voter_peer_id: request.cluster_first_voter_peer_id,
        bundle_canonical_json: serde_json::to_string(&bundle)?,
    };

    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &output)?;
    writeln!(stdout)?;
    Ok(())
}
