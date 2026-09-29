use std::fmt::{self, Debug, Formatter};

use actix_web::{HttpResponse, post, web};
use actix_web_validator::{Json, Path};
use collection::operations::verification::new_unchecked_verification_pass;
use serde::{Deserialize, Serialize};
use storage::dispatcher::Dispatcher;
use tokio::time::Instant;
use validator::Validate;

use super::CollectionPath;
use crate::actix::auth::ActixAuth;
use crate::actix::helpers::process_response;
use crate::common::private_hnsw::{
    PrivateHnswClientSignature as CommonPrivateHnswClientSignature,
    PrivateHnswReadPadding as CommonPrivateHnswReadPadding, do_close_private_hnsw_session,
    do_commit_private_hnsw_paths, do_get_private_hnsw_manifest, do_open_private_hnsw_session,
    do_read_private_hnsw_paths, do_stage_private_hnsw_buckets_for_initial_replication,
    do_stage_private_hnsw_manifest_for_initial_replication, do_upload_private_hnsw_buckets,
    do_upload_private_hnsw_manifest,
};
use crate::settings::Settings;
use crate::tonic::api::qdrant_internal_api::{
    close_private_hnsw_session_coordinated, commit_private_hnsw_paths_coordinated,
    coordinate_private_hnsw_initial_upload, open_private_hnsw_session_coordinated,
    read_private_hnsw_paths_coordinated,
};

#[derive(Deserialize, Validate)]
struct PrivateHnswPath {
    #[validate(nested)]
    #[serde(flatten)]
    collection: CollectionPath,
    #[validate(length(min = 1, max = 128))]
    vector_name: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswClientSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateHnswClientSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswClientSignature")
            .field("alg", &self.alg)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct UploadPrivateHnswManifestRequest {
    pub manifest: qdrant_sec::PrivateHnswOramManifest,
    pub signature: qdrant_sec::PrivateHnswOramSignature,
}

impl Debug for UploadPrivateHnswManifestRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadPrivateHnswManifestRequest")
            .field("manifest", &self.manifest)
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct UploadPrivateHnswBucketsRequest {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateHnswOramBucket>,
}

impl Debug for UploadPrivateHnswBucketsRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadPrivateHnswBucketsRequest")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct OpenPrivateHnswSessionRequest {
    pub client_id: String,
    pub desired_epoch: u64,
    pub fixed_budget: bool,
    pub result_privacy: qdrant_sec::ResultPrivacyMode,
}

impl Debug for OpenPrivateHnswSessionRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenPrivateHnswSessionRequest")
            .field("client_id", &"[redacted]")
            .field("desired_epoch", &self.desired_epoch)
            .field("fixed_budget", &self.fixed_budget)
            .field("result_privacy", &self.result_privacy)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateHnswSessionResponse {
    pub session_id: String,
    pub collection_id: String,
    pub vector_name: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub manifest: qdrant_sec::PrivateHnswOramManifest,
    pub lease_expires_unix: u64,
}

impl Debug for PrivateHnswSessionResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSessionResponse")
            .field("session_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("manifest", &"[redacted]")
            .field("lease_expires_unix", &self.lease_expires_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct OramReadPathsRequest {
    pub session_id: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub paths: Vec<String>,
    pub padding: OramReadPadding,
    pub client_signature: PrivateHnswClientSignature,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct OramReadPadding {
    pub requested_paths: u32,
    pub dummy_paths_included: bool,
}

impl Debug for OramReadPadding {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OramReadPadding")
            .field("requested_paths", &"[redacted]")
            .field("dummy_paths_included", &"[redacted]")
            .finish()
    }
}

impl Debug for OramReadPathsRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OramReadPathsRequest")
            .field("session_id", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("path_count", &"[redacted]")
            .field("padding", &self.padding)
            .field("client_signature", &self.client_signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct OramReadPathsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateHnswOramBucket>,
    pub proof: OramReadProof,
}

impl Debug for OramReadPathsResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OramReadPathsResponse")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("proof", &self.proof)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct OramReadProof {
    pub kind: String,
    pub value: String,
}

impl Debug for OramReadProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OramReadProof")
            .field("kind", &self.kind)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct OramCommitRequest {
    pub session_id: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub updated_buckets: Vec<qdrant_sec::PrivateHnswOramBucket>,
    pub commit_signature: PrivateHnswClientSignature,
}

impl Debug for OramCommitRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OramCommitRequest")
            .field("session_id", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("updated_bucket_count", &"[redacted]")
            .field("commit_signature", &self.commit_signature)
            .finish()
    }
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/manifest")]
async fn upload_manifest(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<UploadPrivateHnswManifestRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = if dispatcher.consensus_state().is_some() {
        do_stage_private_hnsw_manifest_for_initial_replication(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            request.manifest,
            request.signature,
        )
        .await
    } else {
        do_upload_private_hnsw_manifest(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            request.manifest,
            request.signature,
        )
        .await
    };
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/buckets")]
async fn upload_buckets(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<UploadPrivateHnswBucketsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let coordinated_initial_replication = dispatcher.consensus_state().is_some();
    let result = if coordinated_initial_replication {
        do_stage_private_hnsw_buckets_for_initial_replication(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            request.index_epoch,
            request.root_hash,
            request.buckets,
        )
        .await
    } else {
        do_upload_private_hnsw_buckets(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            request.index_epoch,
            request.root_hash,
            request.buckets,
        )
        .await
    };
    let result = match result {
        Ok(epoch) if coordinated_initial_replication => coordinate_private_hnsw_initial_upload(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
        )
        .await
        .map(|()| epoch),
        result => result,
    };
    process_response(result, timing, None)
}

#[actix_web::get("/collections/{collection_name}/private-hnsw/{vector_name}/manifest")]
async fn get_manifest(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let timing = Instant::now();
    let result = do_get_private_hnsw_manifest(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        &path.vector_name,
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/session")]
async fn open_session(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<OpenPrivateHnswSessionRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = if dispatcher.consensus_state().is_some() {
        open_private_hnsw_session_coordinated(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            request.client_id,
            request.desired_epoch,
            request.fixed_budget,
            request.result_privacy,
        )
        .await
    } else {
        do_open_private_hnsw_session(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            request.client_id,
            request.desired_epoch,
            request.fixed_budget,
            request.result_privacy,
        )
        .await
    };
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths")]
async fn read_paths(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<OramReadPathsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let padding = CommonPrivateHnswReadPadding {
        requested_paths: request.padding.requested_paths,
        dummy_paths_included: request.padding.dummy_paths_included,
    };
    let result = if dispatcher.consensus_state().is_some() {
        read_private_hnsw_paths_coordinated(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            &request.session_id,
            request.index_epoch,
            &request.root_hash,
            request.paths,
            padding,
            request.client_signature.into(),
        )
        .await
    } else {
        do_read_private_hnsw_paths(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            &request.session_id,
            request.index_epoch,
            &request.root_hash,
            request.paths,
            padding,
            request.client_signature.into(),
        )
        .await
    };
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit")]
async fn commit_paths(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<OramCommitRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = if dispatcher.consensus_state().is_some() {
        commit_private_hnsw_paths_coordinated(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            &request.session_id,
            request.old_epoch,
            request.new_epoch,
            request.old_root_hash,
            request.new_root_hash,
            request.updated_buckets,
            request.commit_signature.into(),
        )
        .await
    } else {
        do_commit_private_hnsw_paths(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &path.vector_name,
            &request.session_id,
            request.old_epoch,
            request.new_epoch,
            request.old_root_hash,
            request.new_root_hash,
            request.updated_buckets,
            request.commit_signature.into(),
        )
        .await
    };
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close")]
async fn close_session(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswClosePath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let timing = Instant::now();
    let result = if dispatcher.consensus_state().is_some() {
        close_private_hnsw_session_coordinated(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &path.private_hnsw.collection.collection_name,
            &path.private_hnsw.vector_name,
            &path.session_id,
        )
        .await
    } else {
        do_close_private_hnsw_session(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.private_hnsw.collection.collection_name,
            &path.private_hnsw.vector_name,
            &path.session_id,
        )
        .await
    };
    process_response(result, timing, None)
}

#[derive(Deserialize, Validate)]
struct PrivateHnswClosePath {
    #[validate(nested)]
    #[serde(flatten)]
    private_hnsw: PrivateHnswPath,
    #[validate(length(min = 1))]
    session_id: String,
}

impl From<PrivateHnswClientSignature> for CommonPrivateHnswClientSignature {
    fn from(signature: PrivateHnswClientSignature) -> Self {
        Self {
            alg: signature.alg,
            key_id: signature.key_id,
            sig: signature.sig,
        }
    }
}

pub fn config_private_hnsw_api(cfg: &mut web::ServiceConfig) {
    cfg.service(upload_manifest)
        .service(upload_buckets)
        .service(get_manifest)
        .service(open_session)
        .service(read_paths)
        .service(commit_paths)
        .service(close_session);
}

#[cfg(test)]
mod private_hnsw_rest_tests {
    use std::fmt::Debug;

    use actix_web::http::StatusCode;
    use actix_web::{App, test as actix_test, web};
    use collection::private_hnsw_oram_store::{PrivateHnswOramEpochState, PrivateHnswOramStore};
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};
    use sha2::Digest;
    use storage::rbac::{Access, AccessRequirements, Auth};

    use super::*;
    use crate::common::private_hnsw_wire_fixture::{
        BASE_EPOCH, COLLECTION_ID, COLLECTION_NAME, KEY_ID, MAX_CIPHERTEXT_BYTES, NEXT_EPOCH,
        PrivateHnswRouteWireFixture, SESSION_ID, SIGNING_KEY_ID, create_plain_collection,
        create_private_hnsw_collection, create_private_hnsw_collection_with_private_result_oram,
        route_e2e_guard, test_dispatcher, test_distributed_dispatcher,
    };

    const PRIVATE_HNSW_CLIENT_STATE_REDACTION_ALIASES: &[&str] = &[
        "clientState",
        "clientStates",
        "clientStateBackup",
        "clientStateBackups",
        "client_state",
        "client_states",
        "client_state_backup",
        "client_state_backups",
        "clientStateSnapshot",
        "clientStateSnapshots",
        "client.state.snapshot",
        "client_state_snapshot",
        "client_state_snapshots",
        "clientStateCiphertext",
        "clientStateCiphertexts",
        "clientStateCiphertextHash",
        "clientStateCiphertextHashes",
        "clientStateCiphertextSha256",
        "clientStateCiphertextsSha256",
        "client_state_ciphertext",
        "client_state_ciphertexts",
        "client_state_ciphertext_hash",
        "client_state_ciphertext_hashes",
        "client_state_ciphertext_sha256",
        "client_state_ciphertexts_sha256",
        "encryptedClientState",
        "encryptedClientStates",
        "encrypted.client.state",
        "encryptedClientStateBackup",
        "encryptedClientStateBackups",
        "encrypted_client_states",
        "encrypted_client_state_backups",
        "encryptedClientStateSnapshot",
        "encryptedClientStateSnapshots",
        "encrypted.client.state.snapshot",
        "encrypted_client_state_snapshot",
        "encrypted_client_state_snapshots",
        "encryptedClientStateCiphertext",
        "encryptedClientStateCiphertexts",
        "encryptedClientStateCiphertextHash",
        "encryptedClientStateCiphertextHashes",
        "encryptedClientStateCiphertextSha256",
        "encryptedClientStateCiphertextsSha256",
        "encrypted_client_state",
        "encrypted_client_state_backup",
        "encrypted_client_state_ciphertext",
        "encrypted_client_state_ciphertexts",
        "encrypted_client_state_ciphertext_hash",
        "encrypted_client_state_ciphertext_hashes",
        "encrypted_client_state_ciphertext_sha256",
        "encrypted_client_state_ciphertexts_sha256",
        "oramPositionMap",
        "oramPositionMaps",
        "oramPositionMapBackup",
        "oramPositionMapBackups",
        "oramPositionMapSnapshot",
        "oramPositionMapSnapshots",
        "oram_position_map",
        "oram_position_maps",
        "oram_position_map_backup",
        "oram_position_map_backups",
        "oram_position_map_snapshot",
        "oram_position_map_snapshots",
        "positionMap",
        "positionMaps",
        "positionMapBackup",
        "positionMapBackups",
        "positionMapSnapshot",
        "positionMapSnapshots",
        "position_map",
        "position_maps",
        "position_map_backup",
        "position_map_backups",
        "position_map_snapshot",
        "position_map_snapshots",
        "stash",
        "stashBackup",
        "stashBackups",
        "stashSnapshot",
        "stashSnapshots",
        "stateCiphertext",
        "stateCiphertexts",
        "stateCiphertextHash",
        "stateCiphertextHashes",
        "stateCiphertextSha256",
        "stateCiphertextsSha256",
        "state_ciphertext",
        "state_ciphertexts",
        "state_ciphertext_hash",
        "state_ciphertext_hashes",
        "state_ciphertext_sha256",
        "state_ciphertexts_sha256",
        "tokenMap",
        "tokenMaps",
        "tokenMapBackup",
        "tokenMapBackups",
        "token.map.backup",
        "token.map.backups",
        "tokenMapSnapshot",
        "tokenMapSnapshots",
        "token_map",
        "token_maps",
        "token.maps",
        "token_map_backup",
        "token_map_backups",
        "token_map_snapshot",
        "token.map.snapshot",
        "token_map_snapshots",
        "token.map.snapshots",
        "tokenPositionMap",
        "tokenPositionMaps",
        "tokenPositionMapBackup",
        "tokenPositionMapBackups",
        "token.position.map.backup",
        "token.position.map.backups",
        "tokenPositionMapSnapshot",
        "tokenPositionMapSnapshots",
        "token_position_map",
        "token_position_maps",
        "token.position.maps",
        "token_position_map_backup",
        "token_position_map_backups",
        "token_position_map_snapshot",
        "token.position.map.snapshot",
        "token_position_map_snapshots",
        "token.position.map.snapshots",
    ];
    const PRIVATE_HNSW_CLIENT_STATE_FILENAME_REDACTION_ALIASES: &[&str] = &[
        "client_state_ciphertext_hash.bin",
        "client_state_ciphertext_hash.json",
        "client_state_ciphertext_hashes.bin",
        "client_state_ciphertext_hashes.json",
        "client_state_ciphertext_sha256.bin",
        "client_state_ciphertext_sha256.json",
        "client_state_ciphertexts_sha256.bin",
        "client_state_ciphertexts_sha256.json",
        "client.state.snapshot.json",
        "encrypted.client.state.json",
        "encrypted.client.state.snapshot.json",
        "encrypted_client_state_snapshot.bin",
        "encrypted_client_state_snapshot.json",
        "encrypted_client_state_snapshots.json",
        "encrypted.client.state.snapshots.json",
        "encrypted_client_state_ciphertext_hash.bin",
        "encrypted_client_state_ciphertext_hash.json",
        "encrypted_client_state_ciphertext_hashes.bin",
        "encrypted_client_state_ciphertext_hashes.json",
        "encrypted_client_state_ciphertext_sha256.bin",
        "encrypted_client_state_ciphertext_sha256.json",
        "encrypted_client_state_ciphertexts_sha256.bin",
        "encrypted_client_state_ciphertexts_sha256.json",
        "state_ciphertext_hash.bin",
        "state_ciphertext_hash.json",
        "state_ciphertext_hashes.bin",
        "state_ciphertext_hashes.json",
        "state_ciphertext_sha256.bin",
        "state_ciphertext_sha256.json",
        "state_ciphertexts_sha256.bin",
        "state_ciphertexts_sha256.json",
    ];
    const PRIVATE_HNSW_BUCKET_REDACTION_ALIASES: &[&str] = &[
        "bucket_commitment",
        "bucket.commitment",
        "bucketCommitment",
        "bucket_commitments",
        "bucket.commitments",
        "bucketCommitments",
        "ciphertext_sha256",
        "ciphertextSha256",
        "ciphertexts_sha256",
        "ciphertextsSha256",
        "updated_bucket_commitment",
        "updated.bucket.commitment",
        "updatedBucketCommitment",
        "updated_bucket_commitments",
        "updated.bucket.commitments",
        "updatedBucketCommitments",
    ];
    const PRIVATE_HNSW_ACCESS_PATTERN_REDACTION_ALIASES: &[&str] = &[
        "path_label",
        "path.label",
        "pathLabel",
        "path_labels",
        "path.labels",
        "pathLabels",
        "read_path_label",
        "read.path.label",
        "readPathLabel",
        "read_path_labels",
        "read.path.labels",
        "readPathLabels",
        "proof.value",
        "proof.values",
        "path.count",
        "path.counts",
        "leaf_label",
        "leaf.label",
        "leafLabels",
        "leaf_labels",
        "leaf.labels",
        "node_id",
        "node.id",
        "nodeId",
        "node_ids",
        "node.ids",
        "nodeIds",
        "entry_node_id",
        "entry.node.id",
        "entryNodeId",
        "entry_node_ids",
        "entry.node.ids",
        "entryNodeIds",
        "visited_node_id",
        "visited.node.id",
        "visitedNodeId",
        "visited_node_ids",
        "visited.node.ids",
        "visitedNodeIds",
        "bucket_sequence",
        "bucket.sequence",
        "bucketSequence",
        "bucket_sequences",
        "bucket.sequences",
        "bucketSequences",
        "bucket_id_sequence",
        "bucket.id.sequence",
        "bucketIdSequence",
        "bucket_id_sequences",
        "bucket.id.sequences",
        "bucketIdSequences",
    ];

    fn json_roundtrip<T>(value: &T) -> T
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        serde_json::from_value(serde_json::to_value(value).unwrap()).unwrap()
    }

    fn assert_unknown_field_rejected<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + Debug,
    {
        let mut value = serde_json::to_value(value).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".to_string(), json!("reject-me"));
        let err = serde_json::from_value::<T>(value).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    fn assert_requires_write_access(error: impl std::fmt::Display) {
        let rendered = error.to_string();
        assert!(
            rendered.contains("Global manage access is required")
                || rendered.contains("Write access to collection"),
            "expected write-access denial, got: {rendered}",
        );
        for forbidden in [
            qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
            qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
            qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
            "/private-hnsw/{vector}/session",
            "/private-result-oram/session",
            "private_hnsw_oram",
            "private_result_oram",
            "client-led private ORAM sessions",
            "session_id",
            "root_hash",
            "bucket",
            "ciphertext",
            "signature",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "write-access denial leaked private ORAM detail `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_CLIENT_STATE_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "write-access denial leaked private ORAM detail `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_CLIENT_STATE_FILENAME_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "write-access denial leaked private ORAM detail `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_ACCESS_PATTERN_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "write-access denial leaked private ORAM detail `{forbidden}`: {rendered}",
            );
        }
    }

    fn assert_private_hnsw_guard_error_redacts(rendered: &str, extra_forbidden: &[&str]) {
        for forbidden in [
            COLLECTION_NAME,
            "text_private_hnsw",
            "docs_private_hnsw_v1",
            KEY_ID,
            SIGNING_KEY_ID,
            qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
            qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
            qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
            qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
            "payload_private_result_oram",
            "docs_private_result_oram_v1",
            "private_hnsw_oram",
            "private_result_oram",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW guard leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_CLIENT_STATE_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW guard leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_CLIENT_STATE_FILENAME_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW guard leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_ACCESS_PATTERN_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW guard leaked `{forbidden}`: {rendered}",
            );
        }
        for forbidden in extra_forbidden {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW guard leaked `{forbidden}`: {rendered}",
            );
        }
    }

    fn assert_private_hnsw_route_error_redacts(rendered: &str, extra_forbidden: &[&str]) {
        for forbidden in [
            COLLECTION_NAME,
            "text_private_hnsw",
            "docs_private_hnsw_v1",
            KEY_ID,
            SIGNING_KEY_ID,
            qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
            qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
            qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
            "payload_private_result_oram",
            "docs_private_result_oram_v1",
            "private_hnsw_oram",
            "private_result_oram",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW route error leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_CLIENT_STATE_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW route error leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_CLIENT_STATE_FILENAME_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW route error leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_BUCKET_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW route error leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_HNSW_ACCESS_PATTERN_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW route error leaked `{forbidden}`: {rendered}",
            );
        }
        for forbidden in extra_forbidden {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW route error leaked `{forbidden}`: {rendered}",
            );
        }
    }

    #[test]
    fn private_hnsw_rest_request_dtos_reject_unknown_fields() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let manifest_request = UploadPrivateHnswManifestRequest {
            manifest: fixture.manifest.clone(),
            signature: fixture.manifest_signature.clone(),
        };
        assert_unknown_field_rejected(&manifest_request);

        let buckets_request = UploadPrivateHnswBucketsRequest {
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            buckets: fixture.encrypted_build.buckets.clone(),
        };
        assert_unknown_field_rejected(&buckets_request);
        let mut nested_bucket_extra = serde_json::to_value(&buckets_request).unwrap();
        nested_bucket_extra["buckets"][0]
            .as_object_mut()
            .unwrap()
            .insert("extra".to_string(), json!("payload.fetch.token"));
        let err = serde_json::from_value::<UploadPrivateHnswBucketsRequest>(nested_bucket_extra)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unknown field"), "{rendered}");
        assert!(!rendered.contains("payload.fetch.token"), "{rendered}");
        assert!(
            !rendered.contains(&fixture.encrypted_build.buckets[0].ciphertext),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
            "{rendered}"
        );

        let session_request = OpenPrivateHnswSessionRequest {
            client_id: "tenant-a/sdk-instance-1".to_string(),
            desired_epoch: BASE_EPOCH,
            fixed_budget: true,
            result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
        };
        assert_unknown_field_rejected(&session_request);

        let read_request = OramReadPathsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            paths: vec![fixture.entry_leaf_label()],
            padding: OramReadPadding {
                requested_paths: 1,
                dummy_paths_included: true,
            },
            client_signature: PrivateHnswClientSignature {
                alg: "ed25519".to_string(),
                key_id: SIGNING_KEY_ID.to_string(),
                sig: fixture.client_signature().sig,
            },
        };
        assert_unknown_field_rejected(&read_request);

        let padding = json!({
            "requested_paths": 1,
            "dummy_paths_included": true,
            "extra": "reject-me",
        });
        let err = serde_json::from_value::<OramReadPadding>(padding).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");

        let signature = json!({
            "alg": "ed25519",
            "key_id": SIGNING_KEY_ID,
            "sig": fixture.client_signature().sig,
            "extra": "reject-me",
        });
        let err = serde_json::from_value::<PrivateHnswClientSignature>(signature).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");

        let search_run = fixture.run_single_search_collect_writeback();
        let commit_request = OramCommitRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: search_run.commit_plan.old_root_hash,
            new_root_hash: search_run.commit_plan.new_root_hash,
            updated_buckets: search_run.updated_buckets,
            commit_signature: PrivateHnswClientSignature {
                alg: search_run.commit_signature.alg,
                key_id: search_run.commit_signature.key_id,
                sig: search_run.commit_signature.sig,
            },
        };
        assert_unknown_field_rejected(&commit_request);
        let mut nested_commit_bucket_extra = serde_json::to_value(&commit_request).unwrap();
        nested_commit_bucket_extra["updated_buckets"][0]
            .as_object_mut()
            .unwrap()
            .insert(
                "extra".to_string(),
                json!("encrypted.client.state.snapshot"),
            );
        let err =
            serde_json::from_value::<OramCommitRequest>(nested_commit_bucket_extra).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unknown field"), "{rendered}");
        assert!(
            !rendered.contains("encrypted.client.state.snapshot"),
            "{rendered}"
        );
    }

    #[test]
    fn private_hnsw_rest_dto_debug_redacts_sensitive_values() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let client_signature = fixture.client_signature();
        let entry_leaf_label = fixture.entry_leaf_label();
        let mut manifest = fixture.manifest.clone();
        manifest.collection_id = "client_state_manifest_collection".to_string();
        manifest.vector_name = "encrypted_client_state_manifest_vector".to_string();
        let manifest_request = UploadPrivateHnswManifestRequest {
            manifest: manifest.clone(),
            signature: fixture.manifest_signature.clone(),
        };
        let open_request = OpenPrivateHnswSessionRequest {
            client_id: "client_state_ciphertext_hash.bin".to_string(),
            desired_epoch: fixture.manifest.index_epoch,
            fixed_budget: true,
            result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
        };
        let session_response = PrivateHnswSessionResponse {
            session_id: SESSION_ID.to_string(),
            collection_id: "client_state_snapshot_session_collection".to_string(),
            vector_name: "encrypted_client_state_snapshot_session_vector".to_string(),
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            manifest,
            lease_expires_unix: 1_770_000_000,
        };
        let read_request = OramReadPathsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            paths: vec![entry_leaf_label.clone()],
            padding: OramReadPadding {
                requested_paths: 77,
                dummy_paths_included: false,
            },
            client_signature: PrivateHnswClientSignature {
                alg: "ed25519".to_string(),
                key_id: "client_state_read_key_id".to_string(),
                sig: client_signature.sig.clone(),
            },
        };
        let search_run = fixture.run_single_search_collect_writeback();
        let commit_signature = search_run.commit_signature.clone();
        let commit_old_root_hash = search_run.commit_plan.old_root_hash.clone();
        let commit_new_root_hash = search_run.commit_plan.new_root_hash.clone();
        let leaf_commitment = fixture.encrypted_build.buckets[0].bucket_commitment.clone();
        let updated_bucket = search_run.updated_buckets[0].clone();
        let commit_request = OramCommitRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: commit_old_root_hash.clone(),
            new_root_hash: commit_new_root_hash.clone(),
            updated_buckets: search_run.updated_buckets,
            commit_signature: PrivateHnswClientSignature {
                alg: commit_signature.alg,
                key_id: "encrypted_client_state_commit_key_id".to_string(),
                sig: commit_signature.sig.clone(),
            },
        };
        let buckets_request = UploadPrivateHnswBucketsRequest {
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            buckets: fixture.encrypted_build.buckets.clone(),
        };
        let read_response = OramReadPathsResponse {
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            buckets: fixture.encrypted_build.buckets.clone(),
            proof: OramReadProof {
                kind: "merkle_path_batch/v1".to_string(),
                value: "HNSW-REST-PROOF-SENTINEL".to_string(),
            },
        };

        let rendered = [
            format!("{manifest_request:?}"),
            format!("{open_request:?}"),
            format!("{session_response:?}"),
            format!("{read_request:?}"),
            format!("{commit_request:?}"),
            format!("{buckets_request:?}"),
            format!("{read_response:?}"),
        ]
        .join("\n");
        for leaked in [
            SESSION_ID.to_string(),
            fixture.encrypted_build.root_hash.clone(),
            commit_old_root_hash,
            commit_new_root_hash,
            fixture.encrypted_build.buckets[0].ciphertext.clone(),
            fixture.encrypted_build.buckets[0].ciphertext_sha256.clone(),
            leaf_commitment,
            fixture.manifest_signature.key_id.clone(),
            fixture.manifest_signature.sig.clone(),
            updated_bucket.ciphertext,
            updated_bucket.ciphertext_sha256,
            updated_bucket.bucket_commitment,
            client_signature.sig,
            commit_signature.sig,
            "client_state_manifest_collection".to_string(),
            "encrypted_client_state_manifest_vector".to_string(),
            "client_state_snapshot_session_collection".to_string(),
            "encrypted_client_state_snapshot_session_vector".to_string(),
            "client_state_read_key_id".to_string(),
            "encrypted_client_state_commit_key_id".to_string(),
            entry_leaf_label,
            "HNSW-REST-PROOF-SENTINEL".to_string(),
            "client_state_ciphertext_hash.bin".to_string(),
        ] {
            assert!(!rendered.contains(&leaked), "{rendered}");
        }
        for &alias in PRIVATE_HNSW_CLIENT_STATE_REDACTION_ALIASES {
            assert!(!rendered.contains(alias), "{rendered}");
        }
        for &alias in PRIVATE_HNSW_CLIENT_STATE_FILENAME_REDACTION_ALIASES {
            assert!(!rendered.contains(alias), "{rendered}");
        }
        for &alias in PRIVATE_HNSW_ACCESS_PATTERN_REDACTION_ALIASES {
            assert!(!rendered.contains(alias), "{rendered}");
        }
        assert!(!rendered.contains("requested_paths: 77"), "{rendered}");
        assert!(
            !rendered.contains("dummy_paths_included: false"),
            "{rendered}"
        );
        for (debug_rendered, redacted_count) in [
            (
                format!("{session_response:?}"),
                "PrivateHnswOramManifest".to_string(),
            ),
            (
                format!("{session_response:?}"),
                format!("bucket_count: {}", session_response.manifest.bucket_count),
            ),
            (
                format!("{session_response:?}"),
                format!(
                    "tree_height: {}",
                    session_response.manifest.oram.tree_height
                ),
            ),
            (
                format!("{session_response:?}"),
                format!(
                    "path_batch_size: {}",
                    session_response.manifest.oram.path_batch_size
                ),
            ),
            (format!("{read_request:?}"), "path_count: 1".to_string()),
            (
                format!("{commit_request:?}"),
                format!(
                    "updated_bucket_count: {}",
                    commit_request.updated_buckets.len()
                ),
            ),
            (
                format!("{buckets_request:?}"),
                format!("bucket_count: {}", buckets_request.buckets.len()),
            ),
            (
                format!("{read_response:?}"),
                format!("bucket_count: {}", read_response.buckets.len()),
            ),
        ] {
            assert!(
                !debug_rendered.contains(&redacted_count),
                "leaked {redacted_count} in {debug_rendered}"
            );
        }
    }

    #[test]
    fn sdk_fixture_roundtrips_through_rest_wire_dtos() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let manifest_request = UploadPrivateHnswManifestRequest {
            manifest: fixture.manifest.clone(),
            signature: fixture.manifest_signature.clone(),
        };
        assert_eq!(json_roundtrip(&manifest_request), manifest_request);

        let buckets_request = UploadPrivateHnswBucketsRequest {
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            buckets: fixture.encrypted_build.buckets.clone(),
        };
        assert_eq!(json_roundtrip(&buckets_request), buckets_request);

        let session_request = OpenPrivateHnswSessionRequest {
            client_id: "tenant-a/sdk-instance-1".to_string(),
            desired_epoch: BASE_EPOCH,
            fixed_budget: true,
            result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
        };
        assert_eq!(json_roundtrip(&session_request), session_request);

        let (_bucket_ids, batch) = fixture.read_batch_for_leaf(0);
        let read_request = OramReadPathsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            paths: vec![fixture.entry_leaf_label()],
            padding: OramReadPadding {
                requested_paths: 1,
                dummy_paths_included: true,
            },
            client_signature: PrivateHnswClientSignature {
                alg: "ed25519".to_string(),
                key_id: SIGNING_KEY_ID.to_string(),
                sig: fixture.client_signature().sig,
            },
        };
        assert_eq!(json_roundtrip(&read_request), read_request);

        let read_response = OramReadPathsResponse {
            index_epoch: batch.index_epoch,
            root_hash: batch.root_hash,
            buckets: batch.buckets,
            proof: OramReadProof {
                kind: fixture.proof_kind(),
                value: batch.proof_value,
            },
        };
        assert_eq!(json_roundtrip(&read_response), read_response);

        let search_run = fixture.run_single_search_collect_writeback();
        assert_eq!(search_run.result.hits[0].node_id, [1; 32]);
        let commit_request = OramCommitRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: search_run.commit_plan.old_root_hash,
            new_root_hash: search_run.commit_plan.new_root_hash,
            updated_buckets: search_run.updated_buckets,
            commit_signature: PrivateHnswClientSignature {
                alg: search_run.commit_signature.alg,
                key_id: search_run.commit_signature.key_id,
                sig: search_run.commit_signature.sig,
            },
        };
        assert_eq!(json_roundtrip(&commit_request), commit_request);
    }

    #[test]
    fn private_hnsw_common_ops_require_write_access_for_mutations() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let write_auth = Auth::new_internal(Access::full("private HNSW write setup"));
            let read_auth = Auth::new_internal(Access::full_ro("private HNSW read-only test"));
            let pass = new_unchecked_verification_pass();
            let write_toc = dispatcher.toc(&write_auth, &pass);
            let read_toc = dispatcher.toc(&read_auth, &pass);

            do_upload_private_hnsw_manifest(
                write_toc,
                &write_auth,
                &settings,
                "docs",
                "text",
                fixture.manifest.clone(),
                fixture.manifest_signature.clone(),
            )
            .await
            .unwrap();
            do_upload_private_hnsw_buckets(
                write_toc,
                &write_auth,
                &settings,
                "docs",
                "text",
                fixture.encrypted_build.index_epoch,
                fixture.encrypted_build.root_hash.clone(),
                fixture.encrypted_build.buckets.clone(),
            )
            .await
            .unwrap();

            do_get_private_hnsw_manifest(read_toc, &read_auth, &settings, "docs", "text")
                .await
                .unwrap();

            let read_only_manifest_upload = do_upload_private_hnsw_manifest(
                read_toc,
                &read_auth,
                &settings,
                "docs",
                "text",
                fixture.manifest.clone(),
                fixture.manifest_signature.clone(),
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_manifest_upload);

            let read_only_bucket_upload = do_upload_private_hnsw_buckets(
                read_toc,
                &read_auth,
                &settings,
                "docs",
                "text",
                fixture.encrypted_build.index_epoch,
                fixture.encrypted_build.root_hash.clone(),
                fixture.encrypted_build.buckets.clone(),
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_bucket_upload);

            let read_only_open = do_open_private_hnsw_session(
                read_toc,
                &read_auth,
                &settings,
                "docs",
                "text",
                "tenant-a/read-only-sdk".to_string(),
                BASE_EPOCH,
                true,
                qdrant_sec::ResultPrivacyMode::IdsVisible,
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_open);

            let session = do_open_private_hnsw_session(
                write_toc,
                &write_auth,
                &settings,
                "docs",
                "text",
                "tenant-a/write-sdk".to_string(),
                BASE_EPOCH,
                true,
                qdrant_sec::ResultPrivacyMode::IdsVisible,
            )
            .await
            .unwrap();
            let paths = vec![fixture.entry_leaf_label()];
            let read_signature = fixture.sign_read_paths(&paths, 1, true);
            let read_response = do_read_private_hnsw_paths(
                read_toc,
                &read_auth,
                &settings,
                "docs",
                "text",
                &session.session_id,
                BASE_EPOCH,
                &fixture.encrypted_build.root_hash,
                paths,
                CommonPrivateHnswReadPadding {
                    requested_paths: 1,
                    dummy_paths_included: true,
                },
                CommonPrivateHnswClientSignature {
                    alg: read_signature.alg,
                    key_id: read_signature.key_id,
                    sig: read_signature.sig,
                },
            )
            .await
            .unwrap();
            assert!(!read_response.buckets.is_empty());

            let search_run = fixture.run_single_search_collect_writeback();
            let read_only_commit = do_commit_private_hnsw_paths(
                read_toc,
                &read_auth,
                &settings,
                "docs",
                "text",
                &session.session_id,
                BASE_EPOCH,
                NEXT_EPOCH,
                search_run.commit_plan.old_root_hash.clone(),
                search_run.commit_plan.new_root_hash.clone(),
                search_run.updated_buckets.clone(),
                CommonPrivateHnswClientSignature {
                    alg: search_run.commit_signature.alg.clone(),
                    key_id: search_run.commit_signature.key_id.clone(),
                    sig: search_run.commit_signature.sig.clone(),
                },
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_commit);

            let read_only_close = do_close_private_hnsw_session(
                read_toc,
                &read_auth,
                &settings,
                "docs",
                "text",
                &session.session_id,
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_close);

            assert!(
                do_close_private_hnsw_session(
                    write_toc,
                    &write_auth,
                    &settings,
                    "docs",
                    "text",
                    &session.session_id,
                )
                .await
                .unwrap()
            );
        });
    }

    #[test]
    fn rest_rejects_unsafe_private_hnsw_vector_route_without_reflecting_it() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            let mut unsafe_vector_names = vec![
                (
                    "secret%20vector%20sentinel".to_string(),
                    "secret vector sentinel".to_string(),
                ),
                ("text%2Fprivate".to_string(), "text/private".to_string()),
                ("client.state".to_string(), "client.state".to_string()),
                ("position.map".to_string(), "position.map".to_string()),
                ("stash.backup".to_string(), "stash.backup".to_string()),
            ];
            unsafe_vector_names.extend(PRIVATE_HNSW_CLIENT_STATE_REDACTION_ALIASES.iter().map(
                |alias| {
                    let alias = format!("{alias}.json");
                    (alias.clone(), alias)
                },
            ));
            unsafe_vector_names.extend(
                PRIVATE_HNSW_CLIENT_STATE_FILENAME_REDACTION_ALIASES
                    .iter()
                    .map(|alias| ((*alias).to_string(), (*alias).to_string())),
            );
            for (route_vector_name, unsafe_vector_name) in unsafe_vector_names {
                let request = actix_test::TestRequest::get()
                    .uri(&format!(
                        "/collections/docs/private-hnsw/{route_vector_name}/manifest"
                    ))
                    .to_request();
                let response = actix_test::call_service(&app, request).await;
                let status = response.status();
                let body_bytes = actix_test::read_body(response).await;
                let body = String::from_utf8_lossy(&body_bytes);

                assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
                assert!(body.contains("client-led private ORAM sessions"), "{body}");
                assert!(!body.contains(unsafe_vector_name.as_str()), "{body}");
                assert!(!body.contains(route_vector_name.as_str()), "{body}");
                assert!(!body.contains("secret"), "{body}");
                assert!(!body.contains("client.state"), "{body}");
                assert!(!body.contains("position.map"), "{body}");
                assert!(!body.contains("stash.backup"), "{body}");
                for alias in PRIVATE_HNSW_CLIENT_STATE_REDACTION_ALIASES {
                    assert!(!body.contains(alias), "{body}");
                }
                assert!(!body.contains("private_hnsw_oram"), "{body}");
                assert!(!body.contains("/tmp"), "{body}");
                assert_private_hnsw_route_error_redacts(
                    &body,
                    &[
                        unsafe_vector_name.as_str(),
                        route_vector_name.as_str(),
                        "secret",
                        "client.state",
                        "position.map",
                        "stash.backup",
                        "clientStateBackup",
                        "clientStateBackups",
                        "client_state_backup",
                        "clientStateSnapshot",
                        "clientStateSnapshots",
                        "client_state_snapshot",
                        "client_state_snapshots",
                        "clientStateCiphertext",
                        "encryptedClientStateBackup",
                        "encryptedClientStateBackups",
                        "encryptedClientStateSnapshot",
                        "encryptedClientStateSnapshots",
                        "encrypted_client_state_snapshot",
                        "encrypted_client_state_snapshots",
                        "encryptedClientStateCiphertextHash",
                        "positionMapBackups",
                        "oramPositionMapBackups",
                        "stateCiphertextHash",
                        "tokenPositionMapBackups",
                        "stashBackups",
                        "/tmp",
                    ],
                );
            }

            let unsafe_vector_name = "encryptedClientStateCiphertextHashes.json";
            let paths = vec![fixture.entry_leaf_label()];
            let read_signature = fixture.sign_read_paths(&paths, 1, true);
            let read_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/docs/private-hnsw/{unsafe_vector_name}/oram/read_paths"
                    ))
                    .set_json(OramReadPathsRequest {
                        session_id: SESSION_ID.to_string(),
                        index_epoch: fixture.encrypted_build.index_epoch,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                        paths: paths.clone(),
                        padding: OramReadPadding {
                            requested_paths: 1,
                            dummy_paths_included: true,
                        },
                        client_signature: PrivateHnswClientSignature {
                            alg: read_signature.alg.clone(),
                            key_id: read_signature.key_id.clone(),
                            sig: read_signature.sig.clone(),
                        },
                    })
                    .to_request(),
            )
            .await;
            let read_status = read_response.status();
            let read_body = actix_test::read_body(read_response).await;
            let read_body = String::from_utf8_lossy(&read_body);
            assert_eq!(read_status, StatusCode::BAD_REQUEST, "{read_body}");
            assert!(
                read_body.contains("client-led private ORAM sessions"),
                "{read_body}"
            );
            assert!(!read_body.contains(unsafe_vector_name), "{read_body}");
            assert!(
                !read_body.contains(&fixture.encrypted_build.root_hash),
                "{read_body}"
            );
            assert!(!read_body.contains(SESSION_ID), "{read_body}");
            assert!(!read_body.contains(&paths[0]), "{read_body}");
            assert!(!read_body.contains(&read_signature.key_id), "{read_body}");
            assert!(!read_body.contains(&read_signature.sig), "{read_body}");
            assert!(!read_body.contains("private_hnsw_oram"), "{read_body}");
            assert_private_hnsw_route_error_redacts(
                &read_body,
                &[
                    unsafe_vector_name,
                    fixture.encrypted_build.root_hash.as_str(),
                    SESSION_ID,
                    paths[0].as_str(),
                    read_signature.key_id.as_str(),
                    read_signature.sig.as_str(),
                ],
            );

            let run = fixture.run_single_search_collect_writeback();
            let commit_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/docs/private-hnsw/{unsafe_vector_name}/oram/commit"
                    ))
                    .set_json(OramCommitRequest {
                        session_id: SESSION_ID.to_string(),
                        old_epoch: run.commit_plan.old_epoch,
                        new_epoch: run.commit_plan.new_epoch,
                        old_root_hash: run.commit_plan.old_root_hash.clone(),
                        new_root_hash: run.commit_plan.new_root_hash.clone(),
                        updated_buckets: run.updated_buckets.clone(),
                        commit_signature: PrivateHnswClientSignature {
                            alg: run.commit_signature.alg.clone(),
                            key_id: run.commit_signature.key_id.clone(),
                            sig: run.commit_signature.sig.clone(),
                        },
                    })
                    .to_request(),
            )
            .await;
            let commit_status = commit_response.status();
            let commit_body = actix_test::read_body(commit_response).await;
            let commit_body = String::from_utf8_lossy(&commit_body);
            assert_eq!(commit_status, StatusCode::BAD_REQUEST, "{commit_body}");
            assert!(
                commit_body.contains("client-led private ORAM sessions"),
                "{commit_body}"
            );
            assert!(!commit_body.contains(unsafe_vector_name), "{commit_body}");
            assert!(
                !commit_body.contains(&run.commit_plan.old_root_hash),
                "{commit_body}"
            );
            assert!(
                !commit_body.contains(&run.commit_plan.new_root_hash),
                "{commit_body}"
            );
            assert!(!commit_body.contains(SESSION_ID), "{commit_body}");
            assert!(
                !commit_body.contains(&run.commit_signature.key_id),
                "{commit_body}"
            );
            assert!(
                !commit_body.contains(&run.commit_signature.sig),
                "{commit_body}"
            );
            assert!(
                !commit_body.contains(&run.updated_buckets[0].ciphertext),
                "{commit_body}"
            );
            assert!(!commit_body.contains("private_hnsw_oram"), "{commit_body}");
            assert_private_hnsw_route_error_redacts(
                &commit_body,
                &[
                    unsafe_vector_name,
                    run.commit_plan.old_root_hash.as_str(),
                    run.commit_plan.new_root_hash.as_str(),
                    SESSION_ID,
                    run.commit_signature.key_id.as_str(),
                    run.commit_signature.sig.as_str(),
                    run.updated_buckets[0].ciphertext.as_str(),
                ],
            );
        });
    }

    #[test]
    fn rest_rejects_private_hnsw_missing_collection_encryption_without_reflecting_collection() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let collection_name = "private-hnsw-missing-encryption-secret-collection";
        actix_web::rt::System::new().block_on(async {
            create_plain_collection(&dispatcher, collection_name).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            macro_rules! assert_missing_encryption {
                ($request:expr) => {{
                    let response = actix_test::call_service(&app, $request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);

                    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
                    assert!(
                        body.contains("does not configure private HNSW ORAM encryption"),
                        "{body}"
                    );
                    assert!(!body.contains(collection_name), "{body}");
                    assert!(!body.contains("secret"), "{body}");
                    assert!(!body.contains(&fixture.manifest.root_hash), "{body}");
                    assert!(!body.contains(&fixture.manifest_signature.sig), "{body}");
                    assert!(!body.contains(&fixture.encrypted_build.root_hash), "{body}");
                    assert!(
                        !body.contains(&fixture.encrypted_build.buckets[0].ciphertext),
                        "{body}"
                    );
                    assert!(!body.contains(SESSION_ID), "{body}");
                    assert!(!body.contains("tenant-a/sdk-instance-1"), "{body}");
                }};
            }

            assert_missing_encryption!(
                actix_test::TestRequest::get()
                    .uri(&format!(
                        "/collections/{collection_name}/private-hnsw/text/manifest"
                    ))
                    .to_request()
            );

            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-hnsw/text/manifest"
                    ))
                    .set_json(UploadPrivateHnswManifestRequest {
                        manifest: fixture.manifest.clone(),
                        signature: fixture.manifest_signature.clone(),
                    })
                    .to_request()
            );

            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-hnsw/text/buckets"
                    ))
                    .set_json(UploadPrivateHnswBucketsRequest {
                        index_epoch: fixture.encrypted_build.index_epoch,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                        buckets: fixture.encrypted_build.buckets.clone(),
                    })
                    .to_request()
            );

            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-hnsw/text/session"
                    ))
                    .set_json(OpenPrivateHnswSessionRequest {
                        client_id: "tenant-a/sdk-instance-1".to_string(),
                        desired_epoch: BASE_EPOCH,
                        fixed_budget: true,
                        result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                    })
                    .to_request()
            );

            let paths = vec![fixture.entry_leaf_label()];
            let read_signature = fixture.sign_read_paths(&paths, 1, true);
            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-hnsw/text/oram/read_paths"
                    ))
                    .set_json(OramReadPathsRequest {
                        session_id: SESSION_ID.to_string(),
                        index_epoch: fixture.encrypted_build.index_epoch,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                        paths,
                        padding: OramReadPadding {
                            requested_paths: 1,
                            dummy_paths_included: true,
                        },
                        client_signature: PrivateHnswClientSignature {
                            alg: read_signature.alg,
                            key_id: read_signature.key_id,
                            sig: read_signature.sig,
                        },
                    })
                    .to_request()
            );

            let search_run = fixture.run_single_search_collect_writeback();
            let commit_signature = search_run.commit_signature.clone();
            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-hnsw/text/oram/commit"
                    ))
                    .set_json(OramCommitRequest {
                        session_id: SESSION_ID.to_string(),
                        old_epoch: search_run.commit_plan.old_epoch,
                        new_epoch: search_run.commit_plan.new_epoch,
                        old_root_hash: search_run.commit_plan.old_root_hash,
                        new_root_hash: search_run.commit_plan.new_root_hash,
                        updated_buckets: search_run.updated_buckets,
                        commit_signature: PrivateHnswClientSignature {
                            alg: commit_signature.alg,
                            key_id: commit_signature.key_id,
                            sig: commit_signature.sig,
                        },
                    })
                    .to_request()
            );

            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-hnsw/text/session/{SESSION_ID}/close"
                    ))
                    .to_request()
            );
        });
    }

    #[test]
    fn sdk_fixture_uploads_reads_and_commits_through_rest_routes() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let mut settings = fixture.route_settings();
        let alternate_signing_key_id = "tenant-a/private-hnsw-signing-v2";
        settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["signature_public_keys"][alternate_signing_key_id] =
            serde_json::json!(data_encoding::BASE64URL_NOPAD.encode(&[19_u8; 32]));
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            macro_rules! post_json_ok {
                ($uri:expr, $body:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service(&app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|err| {
                        panic!(
                            "failed to parse response body for {status}: {err}: {}",
                            String::from_utf8_lossy(&body_bytes)
                        )
                    });
                    assert_eq!(status, StatusCode::OK, "{body}");
                    assert_eq!(body["status"], "ok");
                    body["result"].clone()
                }};
            }
            macro_rules! post_json_error_contains {
                ($uri:expr, $body:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service(&app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }
            macro_rules! get_json_ok {
                ($uri:expr) => {{
                    let request = actix_test::TestRequest::get().uri($uri).to_request();
                    let response = actix_test::call_service(&app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|err| {
                        panic!(
                            "failed to parse response body for {status}: {err}: {}",
                            String::from_utf8_lossy(&body_bytes)
                        )
                    });
                    assert_eq!(status, StatusCode::OK, "{body}");
                    assert_eq!(body["status"], "ok");
                    body["result"].clone()
                }};
            }
            macro_rules! get_json_error_contains {
                ($uri:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::get().uri($uri).to_request();
                    let response = actix_test::call_service(&app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }

            let missing_manifest_read_error = get_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(
                !missing_manifest_read_error.contains("private_hnsw_oram"),
                "{missing_manifest_read_error}"
            );
            assert!(
                !missing_manifest_read_error.contains("/tmp"),
                "{missing_manifest_read_error}"
            );
            assert_private_hnsw_guard_error_redacts(&missing_manifest_read_error, &["/tmp"]);

            let missing_manifest_bucket_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                },
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(
                !missing_manifest_bucket_error.contains("private_hnsw_oram"),
                "{missing_manifest_bucket_error}"
            );
            assert!(
                !missing_manifest_bucket_error.contains("/tmp"),
                "{missing_manifest_bucket_error}"
            );
            assert_private_hnsw_guard_error_redacts(&missing_manifest_bucket_error, &["/tmp"]);

            let upload_root_before_manifest_sentinel = "AAAA";
            let malformed_root_before_manifest_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: upload_root_before_manifest_sentinel.to_string(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "root_hash must encode 32 bytes"
            );
            assert!(
                !malformed_root_before_manifest_error
                    .contains(upload_root_before_manifest_sentinel),
                "{malformed_root_before_manifest_error}"
            );
            assert!(
                !malformed_root_before_manifest_error.contains("private_hnsw_oram"),
                "{malformed_root_before_manifest_error}"
            );
            assert!(
                !malformed_root_before_manifest_error.contains("manifest"),
                "{malformed_root_before_manifest_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &malformed_root_before_manifest_error,
                &[upload_root_before_manifest_sentinel, "manifest"],
            );

            let malformed_bucket_hash_before_manifest_sentinel = "hnsw-rest-upload-hash-sentinel";
            let mut malformed_bucket_hash_before_manifest_buckets =
                fixture.encrypted_build.buckets.clone();
            malformed_bucket_hash_before_manifest_buckets[0].ciphertext_sha256 =
                malformed_bucket_hash_before_manifest_sentinel.to_string();
            let malformed_bucket_hash_before_manifest_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: malformed_bucket_hash_before_manifest_buckets,
                },
                StatusCode::BAD_REQUEST,
                "ciphertext_sha256"
            );
            assert!(
                !malformed_bucket_hash_before_manifest_error
                    .contains(malformed_bucket_hash_before_manifest_sentinel),
                "{malformed_bucket_hash_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_hash_before_manifest_error
                    .contains(&fixture.encrypted_build.root_hash),
                "{malformed_bucket_hash_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_hash_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{malformed_bucket_hash_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_hash_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{malformed_bucket_hash_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_hash_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{malformed_bucket_hash_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_hash_before_manifest_error.contains("private_hnsw_oram"),
                "{malformed_bucket_hash_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_hash_before_manifest_error.contains("manifest"),
                "{malformed_bucket_hash_before_manifest_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &malformed_bucket_hash_before_manifest_error,
                &[
                    malformed_bucket_hash_before_manifest_sentinel,
                    fixture.encrypted_build.root_hash.as_str(),
                    fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                    fixture.encrypted_build.buckets[0]
                        .ciphertext_sha256
                        .as_str(),
                    fixture.encrypted_build.buckets[0]
                        .bucket_commitment
                        .as_str(),
                    "manifest",
                ],
            );

            let malformed_bucket_commitment_before_manifest_sentinel =
                "hnsw-rest-upload-commitment-sentinel";
            let mut malformed_bucket_commitment_before_manifest_buckets =
                fixture.encrypted_build.buckets.clone();
            malformed_bucket_commitment_before_manifest_buckets[0].bucket_commitment =
                malformed_bucket_commitment_before_manifest_sentinel.to_string();
            let malformed_bucket_commitment_before_manifest_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: malformed_bucket_commitment_before_manifest_buckets,
                },
                StatusCode::BAD_REQUEST,
                "bucket_commitment"
            );
            assert!(
                !malformed_bucket_commitment_before_manifest_error
                    .contains(malformed_bucket_commitment_before_manifest_sentinel),
                "{malformed_bucket_commitment_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_commitment_before_manifest_error
                    .contains(&fixture.encrypted_build.root_hash),
                "{malformed_bucket_commitment_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_commitment_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{malformed_bucket_commitment_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_commitment_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{malformed_bucket_commitment_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_commitment_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{malformed_bucket_commitment_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_commitment_before_manifest_error.contains("private_hnsw_oram"),
                "{malformed_bucket_commitment_before_manifest_error}"
            );
            assert!(
                !malformed_bucket_commitment_before_manifest_error.contains("manifest"),
                "{malformed_bucket_commitment_before_manifest_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &malformed_bucket_commitment_before_manifest_error,
                &[
                    malformed_bucket_commitment_before_manifest_sentinel,
                    fixture.encrypted_build.root_hash.as_str(),
                    fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                    fixture.encrypted_build.buckets[0]
                        .ciphertext_sha256
                        .as_str(),
                    fixture.encrypted_build.buckets[0]
                        .bucket_commitment
                        .as_str(),
                    "manifest",
                ],
            );

            let empty_upload_before_manifest_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: Vec::new(),
                },
                StatusCode::BAD_REQUEST,
                "bucket upload must contain"
            );
            assert!(
                !empty_upload_before_manifest_error.contains(&fixture.encrypted_build.root_hash),
                "{empty_upload_before_manifest_error}"
            );
            assert!(
                !empty_upload_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{empty_upload_before_manifest_error}"
            );
            assert!(
                !empty_upload_before_manifest_error.contains("private_hnsw_oram"),
                "{empty_upload_before_manifest_error}"
            );
            assert!(
                !empty_upload_before_manifest_error.contains("manifest"),
                "{empty_upload_before_manifest_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &empty_upload_before_manifest_error,
                &[
                    fixture.encrypted_build.root_hash.as_str(),
                    fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                    "manifest",
                ],
            );

            let mut duplicate_upload_before_manifest_buckets =
                fixture.encrypted_build.buckets.clone();
            assert!(
                duplicate_upload_before_manifest_buckets.len() >= 2,
                "route fixture must contain at least two ORAM buckets"
            );
            duplicate_upload_before_manifest_buckets[1] =
                duplicate_upload_before_manifest_buckets[0].clone();
            let duplicate_upload_before_manifest_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: duplicate_upload_before_manifest_buckets,
                },
                StatusCode::BAD_REQUEST,
                "duplicate bucket"
            );
            assert!(
                !duplicate_upload_before_manifest_error
                    .contains(&fixture.encrypted_build.root_hash),
                "{duplicate_upload_before_manifest_error}"
            );
            assert!(
                !duplicate_upload_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{duplicate_upload_before_manifest_error}"
            );
            assert!(
                !duplicate_upload_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{duplicate_upload_before_manifest_error}"
            );
            assert!(
                !duplicate_upload_before_manifest_error
                    .contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{duplicate_upload_before_manifest_error}"
            );
            assert!(
                !duplicate_upload_before_manifest_error.contains("private_hnsw_oram"),
                "{duplicate_upload_before_manifest_error}"
            );
            assert!(
                !duplicate_upload_before_manifest_error.contains("manifest"),
                "{duplicate_upload_before_manifest_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &duplicate_upload_before_manifest_error,
                &[
                    fixture.encrypted_build.root_hash.as_str(),
                    fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                    fixture.encrypted_build.buckets[0]
                        .ciphertext_sha256
                        .as_str(),
                    fixture.encrypted_build.buckets[0]
                        .bucket_commitment
                        .as_str(),
                    "manifest",
                ],
            );

            let before_manifest_client_id = "tenant-a/sdk-instance-before-manifest";
            let missing_manifest_session_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: before_manifest_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(
                !missing_manifest_session_error.contains("private_hnsw_oram"),
                "{missing_manifest_session_error}"
            );
            assert!(
                !missing_manifest_session_error.contains("/tmp"),
                "{missing_manifest_session_error}"
            );
            assert!(
                !missing_manifest_session_error.contains(before_manifest_client_id),
                "{missing_manifest_session_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &missing_manifest_session_error,
                &["/tmp", before_manifest_client_id],
            );

            let auth = Auth::new_internal(Access::full("private HNSW ORAM manifest route test"));
            let collection_pass = auth
                .check_collection_access(
                    "docs",
                    AccessRequirements::new(),
                    "private_hnsw_manifest_upload_layout_test",
                )
                .unwrap();
            let pass = new_unchecked_verification_pass();
            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let manifest_store = PrivateHnswOramStore::new(collection.path(), "text").unwrap();
            let manifest_parent = manifest_store.root_path().parent().unwrap();
            std::fs::create_dir_all(manifest_parent).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                std::fs::set_permissions(manifest_parent, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            std::fs::write(manifest_store.root_path(), b"not-a-directory").unwrap();
            let malformed_manifest_layout_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.manifest_signature.clone(),
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "manifest store validation failed"
            );
            assert!(
                !malformed_manifest_layout_error.contains("private_hnsw_oram"),
                "{malformed_manifest_layout_error}"
            );
            assert!(
                !malformed_manifest_layout_error.contains("/tmp"),
                "{malformed_manifest_layout_error}"
            );
            std::fs::remove_file(manifest_store.root_path()).unwrap();

            macro_rules! assert_manifest_mismatch_error_redacts {
                ($body:expr, $signature_sig:expr) => {{
                    assert!(!$body.contains(&fixture.manifest.root_hash), "{}", $body);
                    assert!(!$body.contains($signature_sig), "{}", $body);
                    assert!(!$body.contains("private_hnsw_oram"), "{}", $body);
                    assert_private_hnsw_guard_error_redacts(
                        &$body,
                        &[fixture.manifest.root_hash.as_str(), $signature_sig],
                    );
                }};
            }

            let mut mismatched_collection_manifest = fixture.manifest.clone();
            let mismatched_collection_id = "other-collection";
            mismatched_collection_manifest.collection_id = mismatched_collection_id.to_string();
            let mismatched_collection_signature =
                fixture.sign_manifest(&mismatched_collection_manifest);
            let mismatched_collection_signature_sig = mismatched_collection_signature.sig.clone();
            let mismatched_collection_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_collection_manifest,
                    signature: mismatched_collection_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_collection_error,
                &mismatched_collection_signature_sig
            );
            assert!(
                !mismatched_collection_error.contains(mismatched_collection_id),
                "{mismatched_collection_error}"
            );

            let mut mismatched_vector_manifest = fixture.manifest.clone();
            let mismatched_vector_name = "title";
            mismatched_vector_manifest.vector_name = mismatched_vector_name.to_string();
            let mismatched_vector_signature = fixture.sign_manifest(&mismatched_vector_manifest);
            let mismatched_vector_signature_sig = mismatched_vector_signature.sig.clone();
            let mismatched_vector_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_vector_manifest,
                    signature: mismatched_vector_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_vector_error,
                &mismatched_vector_signature_sig
            );
            assert!(
                !mismatched_vector_error.contains(mismatched_vector_name),
                "{mismatched_vector_error}"
            );

            let mut mismatched_key_manifest = fixture.manifest.clone();
            let mismatched_key_id = "tenant-b/vector-private-rk";
            mismatched_key_manifest.key_id = mismatched_key_id.to_string();
            let mismatched_key_signature = fixture.sign_manifest(&mismatched_key_manifest);
            let mismatched_key_signature_sig = mismatched_key_signature.sig.clone();
            let mismatched_key_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_key_manifest,
                    signature: mismatched_key_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_key_error,
                &mismatched_key_signature_sig
            );
            assert!(
                !mismatched_key_error.contains(mismatched_key_id),
                "{mismatched_key_error}"
            );

            let mut mismatched_epoch_manifest = fixture.manifest.clone();
            mismatched_epoch_manifest.rk_epoch += 1;
            let mismatched_epoch_signature = fixture.sign_manifest(&mismatched_epoch_manifest);
            let mismatched_epoch_signature_sig = mismatched_epoch_signature.sig.clone();
            let mismatched_epoch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_epoch_manifest,
                    signature: mismatched_epoch_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_epoch_error,
                &mismatched_epoch_signature_sig
            );

            let mut mismatched_dim_manifest = fixture.manifest.clone();
            mismatched_dim_manifest.dim += 1;
            let mismatched_dim_signature = fixture.sign_manifest(&mismatched_dim_manifest);
            let mismatched_dim_signature_sig = mismatched_dim_signature.sig.clone();
            let mismatched_dim_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_dim_manifest,
                    signature: mismatched_dim_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_dim_error,
                &mismatched_dim_signature_sig
            );

            let mut mismatched_distance_manifest = fixture.manifest.clone();
            mismatched_distance_manifest.distance = qdrant_sec::DistanceKind::Cosine;
            let mismatched_distance_signature =
                fixture.sign_manifest(&mismatched_distance_manifest);
            let mismatched_distance_signature_sig = mismatched_distance_signature.sig.clone();
            let mismatched_distance_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_distance_manifest,
                    signature: mismatched_distance_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !mismatched_distance_error.contains("Cosine")
                    && !mismatched_distance_error.contains("cosine"),
                "{mismatched_distance_error}"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_distance_error,
                &mismatched_distance_signature_sig
            );

            let mut mismatched_bucket_count_manifest = fixture.manifest.clone();
            mismatched_bucket_count_manifest.bucket_count -= 1;
            let mismatched_bucket_count_signature_sig = fixture.manifest_signature.sig.clone();
            let mismatched_bucket_count_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_bucket_count_manifest,
                    signature: fixture.manifest_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_bucket_count_error,
                &mismatched_bucket_count_signature_sig
            );
            assert!(
                !mismatched_bucket_count_error.contains("bucket_count"),
                "{mismatched_bucket_count_error}"
            );

            let mut mismatched_privacy_manifest = fixture.manifest.clone();
            mismatched_privacy_manifest.result_privacy =
                qdrant_sec::ResultPrivacyMode::PrivatePayloadOramRequired;
            let mismatched_privacy_signature = fixture.sign_manifest(&mismatched_privacy_manifest);
            let mismatched_privacy_signature_sig = mismatched_privacy_signature.sig.clone();
            let mismatched_privacy_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_privacy_manifest,
                    signature: mismatched_privacy_signature,
                },
                StatusCode::BAD_REQUEST,
                "manifest result_privacy does not match runtime instance"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_privacy_error,
                &mismatched_privacy_signature_sig
            );
            assert!(
                !mismatched_privacy_error.contains("private_payload_oram_required"),
                "{mismatched_privacy_error}"
            );
            assert!(
                !mismatched_privacy_error.contains("PrivatePayloadOramRequired"),
                "{mismatched_privacy_error}"
            );

            let mut mismatched_hnsw_manifest = fixture.manifest.clone();
            mismatched_hnsw_manifest.hnsw.m = 3;
            let mismatched_hnsw_signature = fixture.sign_manifest(&mismatched_hnsw_manifest);
            let mismatched_hnsw_signature_sig = mismatched_hnsw_signature.sig.clone();
            let mismatched_hnsw_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_hnsw_manifest,
                    signature: mismatched_hnsw_signature,
                },
                StatusCode::BAD_REQUEST,
                "manifest hnsw does not match runtime instance"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_hnsw_error,
                &mismatched_hnsw_signature_sig
            );

            let mut mismatched_oram_manifest = fixture.manifest.clone();
            mismatched_oram_manifest.oram.bucket_size = 4;
            let mismatched_oram_signature = fixture.sign_manifest(&mismatched_oram_manifest);
            let mismatched_oram_signature_sig = mismatched_oram_signature.sig.clone();
            let mismatched_oram_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_oram_manifest,
                    signature: mismatched_oram_signature,
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_oram_error,
                &mismatched_oram_signature_sig
            );
            assert!(
                !mismatched_oram_error.contains("bucket_size"),
                "{mismatched_oram_error}"
            );

            let mut mismatched_fixed_budget_manifest = fixture.manifest.clone();
            mismatched_fixed_budget_manifest.fixed_budget.fixed_result_k = 2;
            let mismatched_fixed_budget_signature =
                fixture.sign_manifest(&mismatched_fixed_budget_manifest);
            let mismatched_fixed_budget_signature_sig =
                mismatched_fixed_budget_signature.sig.clone();
            let mismatched_fixed_budget_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_fixed_budget_manifest,
                    signature: mismatched_fixed_budget_signature,
                },
                StatusCode::BAD_REQUEST,
                "manifest fixed_budget does not match runtime instance"
            );
            assert_manifest_mismatch_error_redacts!(
                mismatched_fixed_budget_error,
                &mismatched_fixed_budget_signature_sig
            );
            assert!(
                !mismatched_fixed_budget_error.contains("fixed_result_k"),
                "{mismatched_fixed_budget_error}"
            );

            let signature_key_id_sentinel = "signature-key-id-sentinel";
            let unknown_manifest_key_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: qdrant_sec::PrivateHnswOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: fixture.manifest_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!unknown_manifest_key_error.contains("not configured"));
            assert!(
                !unknown_manifest_key_error.contains(signature_key_id_sentinel),
                "{unknown_manifest_key_error}"
            );
            for sentinel in [
                fixture.manifest.root_hash.as_str(),
                fixture.manifest_signature.sig.as_str(),
            ] {
                assert!(
                    !unknown_manifest_key_error.contains(sentinel),
                    "{unknown_manifest_key_error}"
                );
            }

            let mut alternate_manifest_signature = fixture.manifest_signature.clone();
            alternate_manifest_signature.key_id = alternate_signing_key_id.to_string();
            let alternate_manifest_signature_sig = alternate_manifest_signature.sig.clone();
            let alternate_manifest_key_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: alternate_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!alternate_manifest_key_error.contains("not configured"));
            assert!(
                !alternate_manifest_key_error.contains(alternate_signing_key_id),
                "{alternate_manifest_key_error}"
            );
            assert!(
                !alternate_manifest_key_error.contains(SIGNING_KEY_ID),
                "{alternate_manifest_key_error}"
            );
            for sentinel in [
                fixture.manifest.root_hash.as_str(),
                alternate_manifest_signature_sig.as_str(),
            ] {
                assert!(
                    !alternate_manifest_key_error.contains(sentinel),
                    "{alternate_manifest_key_error}"
                );
            }

            let manifest_signature_alg_sentinel = "manifest-signature-alg-sentinel";
            let unknown_key_malformed_alg_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: qdrant_sec::PrivateHnswOramSignature {
                        alg: manifest_signature_alg_sentinel.to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: fixture.manifest_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature algorithm must be ed25519"
            );
            assert!(!unknown_key_malformed_alg_error.contains("not configured"));
            assert!(
                !unknown_key_malformed_alg_error.contains(signature_key_id_sentinel),
                "{unknown_key_malformed_alg_error}"
            );
            assert!(
                !unknown_key_malformed_alg_error.contains(manifest_signature_alg_sentinel),
                "{unknown_key_malformed_alg_error}"
            );
            assert!(
                !unknown_key_malformed_alg_error.contains(&fixture.manifest_signature.sig),
                "{unknown_key_malformed_alg_error}"
            );
            assert!(
                !unknown_key_malformed_alg_error.contains(&fixture.manifest.root_hash),
                "{unknown_key_malformed_alg_error}"
            );

            let malformed_manifest_alg_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: qdrant_sec::PrivateHnswOramSignature {
                        alg: manifest_signature_alg_sentinel.to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.manifest_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature algorithm must be ed25519"
            );
            assert!(
                !malformed_manifest_alg_error.contains(manifest_signature_alg_sentinel),
                "{malformed_manifest_alg_error}"
            );
            assert!(
                !malformed_manifest_alg_error.contains(&fixture.manifest_signature.sig),
                "{malformed_manifest_alg_error}"
            );
            assert!(
                !malformed_manifest_alg_error.contains(&fixture.manifest.root_hash),
                "{malformed_manifest_alg_error}"
            );

            let manifest_signature_sentinel = "manifest-signature!sentinel";
            let unknown_key_malformed_signature_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: qdrant_sec::PrivateHnswOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: manifest_signature_sentinel.to_string(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(!unknown_key_malformed_signature_error.contains("not configured"));
            assert!(
                !unknown_key_malformed_signature_error.contains(signature_key_id_sentinel),
                "{unknown_key_malformed_signature_error}"
            );
            assert!(
                !unknown_key_malformed_signature_error.contains(manifest_signature_sentinel),
                "{unknown_key_malformed_signature_error}"
            );
            assert!(
                !unknown_key_malformed_signature_error.contains(&fixture.manifest.root_hash),
                "{unknown_key_malformed_signature_error}"
            );

            let malformed_manifest_signature_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: qdrant_sec::PrivateHnswOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: manifest_signature_sentinel.to_string(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !malformed_manifest_signature_error.contains(manifest_signature_sentinel),
                "{malformed_manifest_signature_error}"
            );
            assert!(
                !malformed_manifest_signature_error.contains(&fixture.manifest.root_hash),
                "{malformed_manifest_signature_error}"
            );

            let mut bad_manifest_signature = fixture.manifest_signature.clone();
            let replacement = if bad_manifest_signature.sig.starts_with('A') {
                "B"
            } else {
                "A"
            };
            bad_manifest_signature.sig.replace_range(0..1, replacement);
            let bad_manifest_signature_sig = bad_manifest_signature.sig.clone();
            let bad_manifest_signature_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: bad_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !bad_manifest_signature_error.contains(&bad_manifest_signature_sig),
                "{bad_manifest_signature_error}"
            );
            assert!(
                !bad_manifest_signature_error.contains(&fixture.manifest.root_hash),
                "{bad_manifest_signature_error}"
            );

            let manifest_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.manifest_signature.clone(),
                }
            );
            assert_eq!(manifest_result["index_epoch"], BASE_EPOCH);
            assert_eq!(
                manifest_result["root_hash"].as_str().unwrap(),
                fixture.encrypted_build.root_hash.as_str(),
            );
            let manifest_read = get_json_ok!("/collections/docs/private-hnsw/text/manifest");
            assert_eq!(
                manifest_read["manifest"]["root_hash"].as_str().unwrap(),
                fixture.encrypted_build.root_hash.as_str(),
            );
            assert_eq!(
                manifest_read["signature"]["sig"].as_str().unwrap(),
                fixture.manifest_signature.sig.as_str(),
            );
            let manifest_only_client_id = "tenant-a/sdk-instance-manifest-only";
            let manifest_only_session_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: manifest_only_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::NOT_FOUND,
                "encrypted bucket data is unavailable"
            );
            assert!(
                !manifest_only_session_error.contains("private_hnsw_oram"),
                "{manifest_only_session_error}"
            );
            assert!(
                !manifest_only_session_error.contains("/tmp"),
                "{manifest_only_session_error}"
            );
            assert!(
                !manifest_only_session_error.contains(manifest_only_client_id),
                "{manifest_only_session_error}"
            );

            std::fs::write(manifest_store.root_path().join("manifest.json"), b"{").unwrap();
            let malformed_manifest_store_error = get_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                StatusCode::BAD_REQUEST,
                "manifest store validation failed"
            );
            assert!(
                !malformed_manifest_store_error.contains("private_hnsw_oram"),
                "{malformed_manifest_store_error}"
            );
            assert!(
                !malformed_manifest_store_error.contains("/tmp"),
                "{malformed_manifest_store_error}"
            );
            manifest_store
                .write_manifest(&fixture.manifest, &fixture.manifest_signature)
                .unwrap();

            let current_epoch_path = manifest_store
                .root_path()
                .join("epochs")
                .join("current.json");
            let current_epoch_json = serde_json::to_vec_pretty(&PrivateHnswOramEpochState {
                index_epoch: BASE_EPOCH,
                root_hash: fixture.encrypted_build.root_hash.clone(),
            })
            .unwrap();
            std::fs::write(&current_epoch_path, b"{").unwrap();
            let malformed_upload_epoch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "current epoch validation failed"
            );
            assert!(
                !malformed_upload_epoch_error.contains("private_hnsw_oram"),
                "{malformed_upload_epoch_error}"
            );
            assert!(
                !malformed_upload_epoch_error.contains("/tmp"),
                "{malformed_upload_epoch_error}"
            );
            std::fs::write(&current_epoch_path, &current_epoch_json).unwrap();

            let bucket_upload_wrong_root = data_encoding::BASE64URL_NOPAD.encode(&[9; 32]);
            let bucket_upload_epoch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: bucket_upload_wrong_root.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "bucket upload epoch/root does not match current manifest epoch"
            );
            assert!(
                !bucket_upload_epoch_error.contains(&bucket_upload_wrong_root),
                "{bucket_upload_epoch_error}"
            );

            let bucket_upload_root_sentinel = "AAAA";
            let bucket_upload_root_shape_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: bucket_upload_root_sentinel.to_string(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "root_hash must encode 32 bytes"
            );
            assert!(
                !bucket_upload_root_shape_error.contains(bucket_upload_root_sentinel),
                "{bucket_upload_root_shape_error}"
            );
            assert!(
                !bucket_upload_root_shape_error
                    .contains("bucket upload epoch/root does not match current manifest epoch"),
                "{bucket_upload_root_shape_error}"
            );

            let empty_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: Vec::new(),
                },
                StatusCode::BAD_REQUEST,
                "bucket upload must contain"
            );
            assert!(
                !empty_bucket_upload_error.contains(&fixture.encrypted_build.root_hash),
                "{empty_bucket_upload_error}"
            );
            assert!(
                !empty_bucket_upload_error.contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{empty_bucket_upload_error}"
            );
            assert!(
                !empty_bucket_upload_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{empty_bucket_upload_error}"
            );
            assert!(
                !empty_bucket_upload_error
                    .contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{empty_bucket_upload_error}"
            );
            assert!(
                !empty_bucket_upload_error.contains("private_hnsw_oram"),
                "{empty_bucket_upload_error}"
            );
            assert!(
                !empty_bucket_upload_error.contains("manifest"),
                "{empty_bucket_upload_error}"
            );

            let mut hash_mismatch_buckets = fixture.encrypted_build.buckets.clone();
            let replacement = if hash_mismatch_buckets[0].ciphertext_sha256.starts_with('A') {
                "B"
            } else {
                "A"
            };
            hash_mismatch_buckets[0]
                .ciphertext_sha256
                .replace_range(0..1, replacement);
            let hash_mismatch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: hash_mismatch_buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "encrypted bucket store validation failed"
            );
            assert!(
                !hash_mismatch_error.contains(&hash_mismatch_buckets[0].ciphertext_sha256),
                "{hash_mismatch_error}"
            );
            assert!(
                !hash_mismatch_error.contains(&hash_mismatch_buckets[0].ciphertext),
                "{hash_mismatch_error}"
            );
            assert!(
                !hash_mismatch_error.contains(&hash_mismatch_buckets[0].bucket_commitment),
                "{hash_mismatch_error}"
            );

            let mut merkle_mismatch_buckets = fixture.encrypted_build.buckets.clone();
            merkle_mismatch_buckets[0].bucket_commitment =
                data_encoding::BASE64URL_NOPAD.encode(&[9; 32]);
            let merkle_mismatch_bucket_commitment =
                merkle_mismatch_buckets[0].bucket_commitment.clone();
            let computed_mismatch_root = qdrant_sec::private_hnsw_oram_merkle_root_for_commitments(
                &merkle_mismatch_buckets
                    .iter()
                    .map(|bucket| bucket.bucket_commitment.clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert_ne!(computed_mismatch_root, fixture.encrypted_build.root_hash);
            let commitment_context_mismatch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: merkle_mismatch_buckets,
                },
                StatusCode::BAD_REQUEST,
                "bucket commitment context mismatch"
            );
            assert!(
                !commitment_context_mismatch_error
                    .contains("initial upload bucket commitment context mismatch"),
                "{commitment_context_mismatch_error}"
            );
            assert!(
                !commitment_context_mismatch_error.contains(&computed_mismatch_root),
                "{commitment_context_mismatch_error}"
            );
            assert!(
                !commitment_context_mismatch_error.contains(&merkle_mismatch_bucket_commitment),
                "{commitment_context_mismatch_error}"
            );
            assert!(
                !commitment_context_mismatch_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{commitment_context_mismatch_error}"
            );
            assert!(
                !commitment_context_mismatch_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{commitment_context_mismatch_error}"
            );

            let upload_ciphertext_sentinel = "bucket-upload-ciphertext-sentinel";
            let mut malformed_upload_buckets = fixture.encrypted_build.buckets.clone();
            malformed_upload_buckets[0].ciphertext = upload_ciphertext_sentinel.to_string();
            let malformed_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: malformed_upload_buckets,
                },
                StatusCode::BAD_REQUEST,
                "encrypted bucket store validation failed"
            );
            assert!(
                !malformed_upload_error.contains(upload_ciphertext_sentinel),
                "{malformed_upload_error}"
            );
            assert!(
                !malformed_upload_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{malformed_upload_error}"
            );
            assert!(
                !malformed_upload_error
                    .contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{malformed_upload_error}"
            );

            let first_upload_bucket_path = manifest_store
                .root_path()
                .join("buckets")
                .join("00000000.bucket");
            assert!(
                !first_upload_bucket_path.exists(),
                "failed upload tests should not write bucket files before full preflight"
            );
            let late_upload_ciphertext_sentinel = "bucket-upload-late-ciphertext-sentinel";
            let mut late_malformed_upload_buckets = fixture.encrypted_build.buckets.clone();
            late_malformed_upload_buckets[1].ciphertext =
                late_upload_ciphertext_sentinel.to_string();
            let late_malformed_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: late_malformed_upload_buckets,
                },
                StatusCode::BAD_REQUEST,
                "encrypted bucket store validation failed"
            );
            assert!(
                !late_malformed_upload_error.contains(late_upload_ciphertext_sentinel),
                "{late_malformed_upload_error}"
            );
            assert!(
                !late_malformed_upload_error
                    .contains(&fixture.encrypted_build.buckets[1].ciphertext_sha256),
                "{late_malformed_upload_error}"
            );
            assert!(
                !late_malformed_upload_error
                    .contains(&fixture.encrypted_build.buckets[1].bucket_commitment),
                "{late_malformed_upload_error}"
            );
            assert!(
                !first_upload_bucket_path.exists(),
                "bucket upload must preflight all bucket bodies before writing any bucket file"
            );

            let mut missing_bucket_set = fixture.encrypted_build.buckets.clone();
            missing_bucket_set.pop();
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: missing_bucket_set,
                },
                StatusCode::BAD_REQUEST,
                "configured bucket count"
            );

            let mut duplicate_bucket_set = fixture.encrypted_build.buckets.clone();
            assert!(
                duplicate_bucket_set.len() >= 2,
                "route fixture must contain at least two ORAM buckets"
            );
            duplicate_bucket_set[1] = duplicate_bucket_set[0].clone();
            let duplicate_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: duplicate_bucket_set,
                },
                StatusCode::BAD_REQUEST,
                "duplicate bucket"
            );
            assert!(
                !duplicate_bucket_upload_error.contains(&fixture.encrypted_build.root_hash),
                "{duplicate_bucket_upload_error}"
            );
            assert!(
                !duplicate_bucket_upload_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{duplicate_bucket_upload_error}"
            );
            assert!(
                !duplicate_bucket_upload_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{duplicate_bucket_upload_error}"
            );
            assert!(
                !duplicate_bucket_upload_error
                    .contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{duplicate_bucket_upload_error}"
            );
            assert!(
                !duplicate_bucket_upload_error.contains("private_hnsw_oram"),
                "{duplicate_bucket_upload_error}"
            );

            let auth = Auth::new_internal(Access::full("private HNSW ORAM upload route test"));
            let collection_pass = auth
                .check_collection_access(
                    "docs",
                    AccessRequirements::new(),
                    "private_hnsw_bucket_upload_layout_test",
                )
                .unwrap();
            let pass = new_unchecked_verification_pass();
            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let upload_store = PrivateHnswOramStore::new(collection.path(), "text").unwrap();
            let upload_buckets_path = upload_store.root_path().join("buckets");
            std::fs::remove_dir_all(&upload_buckets_path).unwrap();
            std::fs::write(&upload_buckets_path, b"not-a-directory").unwrap();
            let malformed_upload_layout_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "encrypted bucket store validation failed"
            );
            assert!(
                !malformed_upload_layout_error.contains("private_hnsw_oram"),
                "{malformed_upload_layout_error}"
            );
            assert!(
                !malformed_upload_layout_error.contains("/tmp"),
                "{malformed_upload_layout_error}"
            );
            std::fs::remove_file(&upload_buckets_path).unwrap();
            upload_store.ensure_layout().unwrap();

            let bucket_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                }
            );
            assert_eq!(bucket_result["index_epoch"], BASE_EPOCH);

            std::fs::write(&current_epoch_path, b"{").unwrap();
            let corrupt_epoch_client_id = "tenant-a/sdk-instance-corrupt-epoch";
            let malformed_session_epoch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: corrupt_epoch_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "current epoch validation failed"
            );
            assert!(
                !malformed_session_epoch_error.contains("private_hnsw_oram"),
                "{malformed_session_epoch_error}"
            );
            assert!(
                !malformed_session_epoch_error.contains("/tmp"),
                "{malformed_session_epoch_error}"
            );
            assert!(
                !malformed_session_epoch_error.contains(corrupt_epoch_client_id),
                "{malformed_session_epoch_error}"
            );
            std::fs::write(&current_epoch_path, &current_epoch_json).unwrap();

            let client_id_sentinel = "session-client-id-sentinel";
            let oversized_client_id_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: format!("{client_id_sentinel}{}", "x".repeat(260)),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "client_id must be non-empty and at most 256 bytes"
            );
            assert!(
                !oversized_client_id_error.contains(client_id_sentinel),
                "{oversized_client_id_error}"
            );

            let malformed_client_id_sentinel = "session-client-id!sentinel";
            let malformed_client_id_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: malformed_client_id_sentinel.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "client_id is invalid"
            );
            assert!(
                !malformed_client_id_error.contains(malformed_client_id_sentinel),
                "{malformed_client_id_error}"
            );
            assert!(
                !malformed_client_id_error
                    .contains("client_id must be non-empty and at most 256 bytes"),
                "{malformed_client_id_error}"
            );

            let fixed_budget_client_id = "tenant-a/sdk-instance-fixed-budget-off";
            let fixed_budget_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: fixed_budget_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: false,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "strict mode requires fixed_budget=true"
            );
            assert!(
                !fixed_budget_error.contains(fixed_budget_client_id),
                "{fixed_budget_error}"
            );
            let stale_epoch_client_id = "tenant-a/sdk-instance-stale-epoch";
            let stale_epoch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: stale_epoch_client_id.to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "requested epoch"
            );
            let stale_epoch_error: Value = serde_json::from_str(&stale_epoch_error).unwrap();
            let stale_epoch_error = stale_epoch_error["status"]["error"].as_str().unwrap();
            assert!(
                !stale_epoch_error.contains(&NEXT_EPOCH.to_string()),
                "{stale_epoch_error}"
            );
            assert!(
                !stale_epoch_error.contains(&BASE_EPOCH.to_string()),
                "{stale_epoch_error}"
            );
            assert!(
                !stale_epoch_error.contains(stale_epoch_client_id),
                "{stale_epoch_error}"
            );
            let result_privacy_client_id = "tenant-a/sdk-instance-private-result";
            let result_privacy_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: result_privacy_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::PrivatePayloadOramRequired,
                },
                StatusCode::BAD_REQUEST,
                "requested result_privacy does not match manifest"
            );
            assert!(
                !result_privacy_error.contains(result_privacy_client_id),
                "{result_privacy_error}"
            );
            for sentinel in [
                fixture.encrypted_build.root_hash.as_str(),
                fixture.manifest_signature.sig.as_str(),
                "private_payload_oram_required",
            ] {
                assert!(
                    !result_privacy_error.contains(sentinel),
                    "{result_privacy_error}"
                );
            }

            let auth = Auth::new_internal(Access::full("private HNSW ORAM route test"));
            let collection_pass = auth
                .check_collection_access(
                    "docs",
                    AccessRequirements::new(),
                    "private_hnsw_active_session_upload_guard_test",
                )
                .unwrap();
            let pass = new_unchecked_verification_pass();
            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let config = collection.config_snapshot().await;
            let snapshot_guard =
                crate::common::private_hnsw::begin_private_hnsw_collection_snapshot(
                    collection.name(),
                    &config,
                )
                .unwrap()
                .unwrap();
            let active_snapshot_client_id = "tenant-a/sdk-instance-active-snapshot";
            let active_snapshot_session_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: active_snapshot_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "active collection snapshot"
            );
            assert!(
                !active_snapshot_session_error.contains(&fixture.encrypted_build.root_hash),
                "{active_snapshot_session_error}"
            );
            assert!(
                !active_snapshot_session_error.contains("private_hnsw_oram"),
                "{active_snapshot_session_error}"
            );
            assert!(
                !active_snapshot_session_error.contains(active_snapshot_client_id),
                "{active_snapshot_session_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_snapshot_session_error,
                &[
                    active_snapshot_client_id,
                    &fixture.encrypted_build.root_hash,
                    &fixture.manifest_signature.sig,
                ],
            );
            let active_snapshot_manifest_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.manifest_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "active collection snapshot"
            );
            assert!(
                !active_snapshot_manifest_upload_error.contains(&fixture.manifest.root_hash),
                "{active_snapshot_manifest_upload_error}"
            );
            assert!(
                !active_snapshot_manifest_upload_error.contains("private_hnsw_oram"),
                "{active_snapshot_manifest_upload_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_snapshot_manifest_upload_error,
                &[&fixture.manifest.root_hash, &fixture.manifest_signature.sig],
            );
            let mut active_snapshot_bucket_upload = fixture.encrypted_build.buckets.clone();
            active_snapshot_bucket_upload[0].ciphertext =
                "active-snapshot-bucket-upload-ciphertext-sentinel".to_string();
            let active_snapshot_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: active_snapshot_bucket_upload,
                },
                StatusCode::BAD_REQUEST,
                "active collection snapshot"
            );
            assert!(
                !active_snapshot_bucket_upload_error
                    .contains("active-snapshot-bucket-upload-ciphertext-sentinel"),
                "{active_snapshot_bucket_upload_error}"
            );
            assert!(
                !active_snapshot_bucket_upload_error.contains(&fixture.encrypted_build.root_hash),
                "{active_snapshot_bucket_upload_error}"
            );
            assert!(
                !active_snapshot_bucket_upload_error.contains("private_hnsw_oram"),
                "{active_snapshot_bucket_upload_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_snapshot_bucket_upload_error,
                &[
                    "active-snapshot-bucket-upload-ciphertext-sentinel",
                    &fixture.encrypted_build.root_hash,
                ],
            );
            drop(snapshot_guard);

            let lifecycle_guard =
                crate::common::snapshots::begin_private_oram_collection_lifecycle_guard(
                    &dispatcher,
                    &auth,
                    "docs",
                )
                .await
                .unwrap();
            let active_lifecycle_client_id = "tenant-a/sdk-instance-active-lifecycle";
            let active_lifecycle_session_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: active_lifecycle_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "active collection lifecycle operation"
            );
            assert!(
                !active_lifecycle_session_error.contains(&fixture.encrypted_build.root_hash),
                "{active_lifecycle_session_error}"
            );
            assert!(
                !active_lifecycle_session_error.contains("private_hnsw_oram"),
                "{active_lifecycle_session_error}"
            );
            assert!(
                !active_lifecycle_session_error.contains(active_lifecycle_client_id),
                "{active_lifecycle_session_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_lifecycle_session_error,
                &[
                    active_lifecycle_client_id,
                    &fixture.encrypted_build.root_hash,
                    &fixture.manifest_signature.sig,
                ],
            );
            let active_lifecycle_manifest_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.manifest_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "active collection lifecycle operation"
            );
            assert!(
                !active_lifecycle_manifest_upload_error.contains(&fixture.manifest.root_hash),
                "{active_lifecycle_manifest_upload_error}"
            );
            assert!(
                !active_lifecycle_manifest_upload_error.contains("private_hnsw_oram"),
                "{active_lifecycle_manifest_upload_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_lifecycle_manifest_upload_error,
                &[&fixture.manifest.root_hash, &fixture.manifest_signature.sig],
            );
            let mut active_lifecycle_bucket_upload = fixture.encrypted_build.buckets.clone();
            active_lifecycle_bucket_upload[0].ciphertext =
                "active-lifecycle-bucket-upload-ciphertext-sentinel".to_string();
            let active_lifecycle_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: active_lifecycle_bucket_upload,
                },
                StatusCode::BAD_REQUEST,
                "active collection lifecycle operation"
            );
            assert!(
                !active_lifecycle_bucket_upload_error
                    .contains("active-lifecycle-bucket-upload-ciphertext-sentinel"),
                "{active_lifecycle_bucket_upload_error}"
            );
            assert!(
                !active_lifecycle_bucket_upload_error.contains(&fixture.encrypted_build.root_hash),
                "{active_lifecycle_bucket_upload_error}"
            );
            assert!(
                !active_lifecycle_bucket_upload_error.contains("private_hnsw_oram"),
                "{active_lifecycle_bucket_upload_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_lifecycle_bucket_upload_error,
                &[
                    "active-lifecycle-bucket-upload-ciphertext-sentinel",
                    &fixture.encrypted_build.root_hash,
                ],
            );
            drop(lifecycle_guard);

            let session_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                }
            );
            let session_id = session_result["session_id"].as_str().unwrap().to_string();
            assert_eq!(session_result["collection_id"], COLLECTION_ID);
            assert_eq!(session_result["index_epoch"], BASE_EPOCH);
            let uploaded_store = PrivateHnswOramStore::new(collection.path(), "text").unwrap();
            let search_run = fixture.run_single_search_collect_writeback();

            let active_snapshot_error = crate::common::collections::do_create_snapshot(
                dispatcher.toc(&auth, &pass).clone(),
                &auth,
                "docs",
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                active_snapshot_error.contains("requires no active private ORAM session"),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains(&fixture.encrypted_build.root_hash),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains(&session_id),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains("private_hnsw_oram"),
                "{active_snapshot_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_snapshot_error,
                &[
                    &session_id,
                    &fixture.encrypted_build.root_hash,
                    &fixture.encrypted_build.buckets[0].ciphertext,
                    &fixture.manifest_signature.sig,
                ],
            );
            let active_full_snapshot_error =
                crate::common::snapshots::do_create_full_snapshot(&dispatcher, auth.clone())
                    .await
                    .unwrap_err()
                    .to_string();
            assert!(
                active_full_snapshot_error.contains("requires no active private ORAM session"),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains(&fixture.encrypted_build.root_hash),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains(&session_id),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains("private_hnsw_oram"),
                "{active_full_snapshot_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_full_snapshot_error,
                &[
                    &session_id,
                    &fixture.encrypted_build.root_hash,
                    &fixture.encrypted_build.buckets[0].ciphertext,
                    &fixture.manifest_signature.sig,
                ],
            );

            let duplicate_session_client_id = "tenant-a/sdk-instance-2";
            let duplicate_session_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: duplicate_session_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "ConcurrentWriter"
            );
            assert!(
                !duplicate_session_error.contains(duplicate_session_client_id),
                "{duplicate_session_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &duplicate_session_error,
                &[duplicate_session_client_id, &session_id],
            );

            let (refreshed_manifest, refreshed_signature) =
                fixture.sign_manifest_refresh(&search_run.commit_plan);
            let active_manifest_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: refreshed_manifest.clone(),
                    signature: refreshed_signature,
                },
                StatusCode::BAD_REQUEST,
                "requires no active session"
            );
            assert!(
                !active_manifest_upload_error.contains(&refreshed_manifest.root_hash),
                "{active_manifest_upload_error}"
            );
            assert!(
                !active_manifest_upload_error.contains(&session_id),
                "{active_manifest_upload_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_manifest_upload_error,
                &[
                    &refreshed_manifest.root_hash,
                    &refreshed_manifest.owner_signing_key_id,
                    &session_id,
                ],
            );
            assert_eq!(
                uploaded_store.read_manifest().unwrap(),
                (fixture.manifest.clone(), fixture.manifest_signature.clone())
            );

            let mut active_guard_bucket_upload = fixture.encrypted_build.buckets.clone();
            active_guard_bucket_upload[0].ciphertext =
                "active-session-bucket-upload-ciphertext-sentinel".to_string();
            let active_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: active_guard_bucket_upload,
                },
                StatusCode::BAD_REQUEST,
                "requires no active session"
            );
            assert!(
                !active_bucket_upload_error
                    .contains("active-session-bucket-upload-ciphertext-sentinel"),
                "{active_bucket_upload_error}"
            );
            assert!(
                !active_bucket_upload_error.contains(&fixture.encrypted_build.root_hash),
                "{active_bucket_upload_error}"
            );
            assert!(
                !active_bucket_upload_error.contains(&session_id),
                "{active_bucket_upload_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &active_bucket_upload_error,
                &[
                    "active-session-bucket-upload-ciphertext-sentinel",
                    &fixture.encrypted_build.root_hash,
                    &fixture.encrypted_build.buckets[0].ciphertext_sha256,
                    &fixture.encrypted_build.buckets[0].bucket_commitment,
                    &session_id,
                ],
            );
            assert_eq!(
                uploaded_store
                    .read_bucket(
                        fixture.encrypted_build.buckets[0].bucket_id,
                        BASE_EPOCH,
                        fixture.encrypted_build.bucket_count,
                        MAX_CIPHERTEXT_BYTES,
                    )
                    .unwrap(),
                fixture.encrypted_build.buckets[0]
            );

            let epoch_root_mismatch_paths = vec![fixture.entry_leaf_label()];
            let epoch_root_mismatch_signature =
                fixture.sign_read_paths(&epoch_root_mismatch_paths, 1, true);
            let read_wrong_root = data_encoding::BASE64URL_NOPAD.encode(&[9; 32]);
            let epoch_root_mismatch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: read_wrong_root.clone(),
                    paths: epoch_root_mismatch_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: epoch_root_mismatch_signature.alg,
                        key_id: epoch_root_mismatch_signature.key_id,
                        sig: epoch_root_mismatch_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "session epoch/root mismatch"
            );
            assert!(
                !epoch_root_mismatch_error.contains(&read_wrong_root),
                "{epoch_root_mismatch_error}"
            );

            let malformed_read_root_sentinel = "AAAA";
            let malformed_read_root_paths = vec![fixture.entry_leaf_label()];
            let malformed_read_root_signature =
                fixture.sign_read_paths(&malformed_read_root_paths, 1, true);
            let malformed_read_root_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: malformed_read_root_sentinel.to_string(),
                    paths: malformed_read_root_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: malformed_read_root_signature.alg,
                        key_id: malformed_read_root_signature.key_id,
                        sig: malformed_read_root_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "root_hash must encode 32 bytes"
            );
            assert!(
                !malformed_read_root_error.contains(malformed_read_root_sentinel),
                "{malformed_read_root_error}"
            );
            assert!(
                !malformed_read_root_error.contains("session epoch/root mismatch"),
                "{malformed_read_root_error}"
            );

            let path_label_sentinel = "qdrant-sec-private-hnsw-path-label-sentinel";
            let sentinel_paths = vec![path_label_sentinel.to_string()];
            let sentinel_signature = fixture.client_signature();
            let sentinel_signature_key_id = sentinel_signature.key_id.clone();
            let sentinel_signature_sig = sentinel_signature.sig.clone();
            let read_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: sentinel_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: sentinel_signature.alg,
                        key_id: sentinel_signature.key_id,
                        sig: sentinel_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(!read_error.contains(path_label_sentinel), "{read_error}");
            assert!(!read_error.contains(&session_id), "{read_error}");
            assert!(
                !read_error.contains(&fixture.encrypted_build.root_hash),
                "{read_error}"
            );
            assert!(
                !read_error.contains(&sentinel_signature_key_id),
                "{read_error}"
            );
            assert!(
                !read_error.contains(&sentinel_signature_sig),
                "{read_error}"
            );
            assert!(
                !read_error.contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{read_error}"
            );
            assert!(
                !read_error.contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{read_error}"
            );
            assert!(
                !read_error.contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{read_error}"
            );
            let oversized_path_label_sentinel =
                format!("{}{}", fixture.entry_leaf_label(), "A".repeat(128));
            let oversized_signature = fixture.client_signature();
            let oversized_signature_key_id = oversized_signature.key_id.clone();
            let oversized_signature_sig = oversized_signature.sig.clone();
            let oversized_path_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![oversized_path_label_sentinel.clone()],
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: oversized_signature.alg,
                        key_id: oversized_signature.key_id,
                        sig: oversized_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !oversized_path_error.contains(&oversized_path_label_sentinel),
                "{oversized_path_error}"
            );
            assert!(
                !oversized_path_error.contains(&session_id),
                "{oversized_path_error}"
            );
            assert!(
                !oversized_path_error.contains(&fixture.encrypted_build.root_hash),
                "{oversized_path_error}"
            );
            assert!(
                !oversized_path_error.contains(&oversized_signature_key_id),
                "{oversized_path_error}"
            );
            assert!(
                !oversized_path_error.contains(&oversized_signature_sig),
                "{oversized_path_error}"
            );
            assert!(
                !oversized_path_error.contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{oversized_path_error}"
            );
            assert!(
                !oversized_path_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{oversized_path_error}"
            );
            assert!(
                !oversized_path_error
                    .contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{oversized_path_error}"
            );
            let unauthenticated_path_label_sentinel = fixture.entry_leaf_label();
            let unauthenticated_signature_sig = fixture.client_signature().sig;
            let unauthenticated_path_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![unauthenticated_path_label_sentinel.clone()],
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: unauthenticated_signature_sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !unauthenticated_path_error.contains("leaf label"),
                "{unauthenticated_path_error}"
            );
            assert!(
                !unauthenticated_path_error.contains(&unauthenticated_path_label_sentinel),
                "{unauthenticated_path_error}"
            );
            assert!(
                !unauthenticated_path_error.contains(&fixture.encrypted_build.root_hash),
                "{unauthenticated_path_error}"
            );
            assert!(
                !unauthenticated_path_error.contains(&session_id),
                "{unauthenticated_path_error}"
            );
            assert!(
                !unauthenticated_path_error.contains(SIGNING_KEY_ID),
                "{unauthenticated_path_error}"
            );
            assert!(
                !unauthenticated_path_error.contains(&unauthenticated_signature_sig),
                "{unauthenticated_path_error}"
            );
            assert!(
                !unauthenticated_path_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{unauthenticated_path_error}"
            );
            assert!(
                !unauthenticated_path_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{unauthenticated_path_error}"
            );
            assert!(
                !unauthenticated_path_error
                    .contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{unauthenticated_path_error}"
            );
            let wrong_budget_path = fixture.entry_leaf_label();
            let wrong_budget_paths = vec![wrong_budget_path.clone()];
            let wrong_budget_signature = fixture.client_signature();
            let wrong_budget_signature_key_id = wrong_budget_signature.key_id.clone();
            let wrong_budget_signature_body = wrong_budget_signature.sig.clone();
            let wrong_budget_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: wrong_budget_paths,
                    padding: OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: wrong_budget_signature.alg,
                        key_id: wrong_budget_signature.key_id,
                        sig: wrong_budget_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "fixed path budget"
            );
            for leaked in [
                session_id.as_str(),
                fixture.encrypted_build.root_hash.as_str(),
                wrong_budget_path.as_str(),
                wrong_budget_signature_key_id.as_str(),
                wrong_budget_signature_body.as_str(),
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                fixture.encrypted_build.buckets[0]
                    .ciphertext_sha256
                    .as_str(),
                fixture.encrypted_build.buckets[0]
                    .bucket_commitment
                    .as_str(),
            ] {
                assert!(!wrong_budget_error.contains(leaked), "{wrong_budget_error}");
            }

            let missing_dummy_path = fixture.entry_leaf_label();
            let missing_dummy_paths = vec![missing_dummy_path.clone()];
            let missing_dummy_signature = fixture.client_signature();
            let missing_dummy_signature_key_id = missing_dummy_signature.key_id.clone();
            let missing_dummy_signature_body = missing_dummy_signature.sig.clone();
            let missing_dummy_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: missing_dummy_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: false,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: missing_dummy_signature.alg,
                        key_id: missing_dummy_signature.key_id,
                        sig: missing_dummy_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "fixed path budget"
            );
            for leaked in [
                session_id.as_str(),
                fixture.encrypted_build.root_hash.as_str(),
                missing_dummy_path.as_str(),
                missing_dummy_signature_key_id.as_str(),
                missing_dummy_signature_body.as_str(),
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                fixture.encrypted_build.buckets[0]
                    .ciphertext_sha256
                    .as_str(),
                fixture.encrypted_build.buckets[0]
                    .bucket_commitment
                    .as_str(),
            ] {
                assert!(
                    !missing_dummy_error.contains(leaked),
                    "{missing_dummy_error}"
                );
            }

            let invalid_signature_paths = vec![fixture.entry_leaf_label()];
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: invalid_signature_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.client_signature().sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );

            let unknown_read_key_signature_sig = fixture.client_signature().sig;
            let unknown_read_path = fixture.entry_leaf_label();
            let unknown_read_key_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![unknown_read_path.clone()],
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: unknown_read_key_signature_sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!unknown_read_key_error.contains("not configured"));
            assert!(
                !unknown_read_key_error.contains(signature_key_id_sentinel),
                "{unknown_read_key_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.encrypted_build.root_hash.as_str(),
                unknown_read_path.as_str(),
                unknown_read_key_signature_sig.as_str(),
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                fixture.encrypted_build.buckets[0]
                    .ciphertext_sha256
                    .as_str(),
                fixture.encrypted_build.buckets[0]
                    .bucket_commitment
                    .as_str(),
            ] {
                assert!(
                    !unknown_read_key_error.contains(sentinel),
                    "{unknown_read_key_error}"
                );
            }

            let alternate_read_path = fixture.entry_leaf_label();
            let mut alternate_read_signature =
                fixture.sign_read_paths(std::slice::from_ref(&alternate_read_path), 1, true);
            alternate_read_signature.key_id = alternate_signing_key_id.to_string();
            let alternate_read_signature_sig = alternate_read_signature.sig.clone();
            let alternate_read_key_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![alternate_read_path.clone()],
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: alternate_read_signature.alg,
                        key_id: alternate_read_signature.key_id,
                        sig: alternate_read_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!alternate_read_key_error.contains("not configured"));
            assert!(
                !alternate_read_key_error.contains(alternate_signing_key_id),
                "{alternate_read_key_error}"
            );
            assert!(
                !alternate_read_key_error.contains(SIGNING_KEY_ID),
                "{alternate_read_key_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.encrypted_build.root_hash.as_str(),
                alternate_read_path.as_str(),
                alternate_read_signature_sig.as_str(),
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                fixture.encrypted_build.buckets[0]
                    .ciphertext_sha256
                    .as_str(),
                fixture.encrypted_build.buckets[0]
                    .bucket_commitment
                    .as_str(),
            ] {
                assert!(
                    !alternate_read_key_error.contains(sentinel),
                    "{alternate_read_key_error}"
                );
            }

            let invalid_read_key_id_sentinel = "read-signature-key!sentinel";
            let invalid_read_key_path = fixture.entry_leaf_label();
            let invalid_read_key_sig = fixture.client_signature().sig;
            let invalid_read_key_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![invalid_read_key_path.clone()],
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: invalid_read_key_id_sentinel.to_string(),
                        sig: invalid_read_key_sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature key_id is invalid"
            );
            assert!(!invalid_read_key_error.contains("not configured"));
            assert!(
                !invalid_read_key_error.contains(invalid_read_key_id_sentinel),
                "{invalid_read_key_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.encrypted_build.root_hash.as_str(),
                invalid_read_key_path.as_str(),
                invalid_read_key_sig.as_str(),
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                fixture.encrypted_build.buckets[0]
                    .ciphertext_sha256
                    .as_str(),
                fixture.encrypted_build.buckets[0]
                    .bucket_commitment
                    .as_str(),
            ] {
                assert!(
                    !invalid_read_key_error.contains(sentinel),
                    "{invalid_read_key_error}"
                );
            }

            let signature_body_sentinel = "signature!sentinel";
            let malformed_read_signature_path = fixture.entry_leaf_label();
            let malformed_read_signature_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![malformed_read_signature_path.clone()],
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: signature_body_sentinel.to_string(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature must encode 64 bytes"
            );
            assert!(
                !malformed_read_signature_error.contains(signature_body_sentinel),
                "{malformed_read_signature_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.encrypted_build.root_hash.as_str(),
                malformed_read_signature_path.as_str(),
                SIGNING_KEY_ID,
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                fixture.encrypted_build.buckets[0]
                    .ciphertext_sha256
                    .as_str(),
                fixture.encrypted_build.buckets[0]
                    .bucket_commitment
                    .as_str(),
            ] {
                assert!(
                    !malformed_read_signature_error.contains(sentinel),
                    "{malformed_read_signature_error}"
                );
            }

            let read_signature_alg_sentinel = "rsa-pss-hnsw-read-sentinel";
            let unsupported_read_paths = vec![fixture.entry_leaf_label()];
            let mut unsupported_read_signature =
                fixture.sign_read_paths(&unsupported_read_paths, 1, true);
            unsupported_read_signature.alg = read_signature_alg_sentinel.to_string();
            let unsupported_read_path_label = unsupported_read_paths[0].clone();
            let unsupported_read_key_id = unsupported_read_signature.key_id.clone();
            let unsupported_read_sig = unsupported_read_signature.sig.clone();
            let unsupported_read_signature_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: unsupported_read_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: unsupported_read_signature.alg,
                        key_id: unsupported_read_signature.key_id,
                        sig: unsupported_read_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature algorithm must be ed25519"
            );
            assert!(
                !unsupported_read_signature_error.contains(read_signature_alg_sentinel),
                "{unsupported_read_signature_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.encrypted_build.root_hash.as_str(),
                unsupported_read_path_label.as_str(),
                unsupported_read_key_id.as_str(),
                unsupported_read_sig.as_str(),
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                fixture.encrypted_build.buckets[0]
                    .ciphertext_sha256
                    .as_str(),
                fixture.encrypted_build.buckets[0]
                    .bucket_commitment
                    .as_str(),
            ] {
                assert!(
                    !unsupported_read_signature_error.contains(sentinel),
                    "{unsupported_read_signature_error}"
                );
            }

            let out_of_range_leaf = 1_u64 << fixture.manifest.oram.tree_height;
            let out_of_range_path_label =
                data_encoding::BASE64URL_NOPAD.encode(&out_of_range_leaf.to_be_bytes());
            let out_of_range_signature = fixture.client_signature();
            let out_of_range_signature_key_id = out_of_range_signature.key_id.clone();
            let out_of_range_signature_sig = out_of_range_signature.sig.clone();
            let out_of_range_read_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![out_of_range_path_label.clone()],
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: out_of_range_signature.alg,
                        key_id: out_of_range_signature.key_id,
                        sig: out_of_range_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !out_of_range_read_error.contains("leaf label"),
                "{out_of_range_read_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.encrypted_build.root_hash.as_str(),
                out_of_range_path_label.as_str(),
                out_of_range_signature_key_id.as_str(),
                out_of_range_signature_sig.as_str(),
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                fixture.encrypted_build.buckets[0]
                    .ciphertext_sha256
                    .as_str(),
                fixture.encrypted_build.buckets[0]
                    .bucket_commitment
                    .as_str(),
            ] {
                assert!(
                    !out_of_range_read_error.contains(sentinel),
                    "{out_of_range_read_error}"
                );
            }

            let unknown_read_session_sentinel = "read-session-id-sentinel";
            let unknown_read_paths = vec![fixture.entry_leaf_label()];
            let unknown_read_signature = fixture.sign_read_paths(&unknown_read_paths, 1, true);
            let unknown_read_path = unknown_read_paths[0].clone();
            let unknown_read_signature_sig = unknown_read_signature.sig.clone();
            let unknown_read_session_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: unknown_read_session_sentinel.to_string(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: unknown_read_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: unknown_read_signature.alg,
                        key_id: unknown_read_signature.key_id,
                        sig: unknown_read_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            assert!(
                !unknown_read_session_error.contains(unknown_read_session_sentinel),
                "{unknown_read_session_error}"
            );
            for sentinel in [
                fixture.encrypted_build.root_hash.as_str(),
                unknown_read_path.as_str(),
                unknown_read_signature_sig.as_str(),
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                fixture.encrypted_build.buckets[0]
                    .ciphertext_sha256
                    .as_str(),
                fixture.encrypted_build.buckets[0]
                    .bucket_commitment
                    .as_str(),
            ] {
                assert!(
                    !unknown_read_session_error.contains(sentinel),
                    "{unknown_read_session_error}"
                );
            }

            let oversized_read_session_id = "s".repeat(129);
            let malformed_read_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_read_session_id.as_str(),
                malformed_read_session_id,
            ] {
                let invalid_session_read_paths = vec![fixture.entry_leaf_label()];
                let read_signature = fixture.sign_read_paths(&invalid_session_read_paths, 1, true);
                let invalid_session_read_path = invalid_session_read_paths[0].clone();
                let invalid_session_read_signature_sig = read_signature.sig.clone();
                let error = post_json_error_contains!(
                    "/collections/docs/private-hnsw/text/oram/read_paths",
                    OramReadPathsRequest {
                        session_id: invalid_session_id.to_string(),
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                        padding: OramReadPadding {
                            requested_paths: 1,
                            dummy_paths_included: true,
                        },
                        paths: invalid_session_read_paths,
                        client_signature: PrivateHnswClientSignature {
                            alg: read_signature.alg,
                            key_id: read_signature.key_id,
                            sig: read_signature.sig,
                        },
                    },
                    StatusCode::BAD_REQUEST,
                    "session_id is invalid"
                );
                assert!(!error.contains(invalid_session_id), "{error}");
                assert!(!error.contains("session is missing or expired"), "{error}");
                for sentinel in [
                    fixture.encrypted_build.root_hash.as_str(),
                    invalid_session_read_path.as_str(),
                    invalid_session_read_signature_sig.as_str(),
                    fixture.encrypted_build.buckets[0].ciphertext.as_str(),
                    fixture.encrypted_build.buckets[0]
                        .ciphertext_sha256
                        .as_str(),
                    fixture.encrypted_build.buckets[0]
                        .bucket_commitment
                        .as_str(),
                ] {
                    assert!(!error.contains(sentinel), "{error}");
                }
            }

            let ok_read_paths = vec![fixture.entry_leaf_label()];
            let read_signature = fixture.sign_read_paths(&ok_read_paths, 1, true);
            let read_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: ok_read_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: read_signature.alg,
                        key_id: read_signature.key_id,
                        sig: read_signature.sig,
                    },
                }
            );
            let read_response: OramReadPathsResponse = serde_json::from_value(read_result).unwrap();
            assert_eq!(read_response.index_epoch, BASE_EPOCH);
            assert_eq!(read_response.proof.kind, fixture.proof_kind());
            let opened_buckets = qdrant_sec::open_private_hnsw_oram_verified_path_batch(
                &fixture.keys,
                fixture.base_context,
                fixture.config,
                BASE_EPOCH,
                &fixture.encrypted_build.root_hash,
                fixture.encrypted_build.bucket_count,
                &read_response.proof.value,
                &read_response.buckets,
            )
            .unwrap();
            assert!(!opened_buckets.is_empty());

            let missing_bucket_id = read_response.buckets[0].bucket_id;
            let bucket_path = uploaded_store
                .root_path()
                .join("buckets")
                .join(format!("{missing_bucket_id:08}.bucket"));
            let original_bucket_bytes = std::fs::read(&bucket_path).unwrap();
            let mut mismatched_bucket = read_response.buckets[0].clone();
            mismatched_bucket.bucket_id =
                (missing_bucket_id + 1) % fixture.encrypted_build.bucket_count;
            mismatched_bucket.ciphertext =
                "private-hnsw-route-bucket-ciphertext-sentinel".to_string();
            std::fs::write(
                &bucket_path,
                serde_json::to_vec_pretty(&mismatched_bucket).unwrap(),
            )
            .unwrap();

            let mismatched_bucket_paths = vec![fixture.entry_leaf_label()];
            let mismatched_bucket_signature =
                fixture.sign_read_paths(&mismatched_bucket_paths, 1, true);
            let mismatched_bucket_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: mismatched_bucket_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: mismatched_bucket_signature.alg,
                        key_id: mismatched_bucket_signature.key_id,
                        sig: mismatched_bucket_signature.sig,
                    },
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "encrypted bucket store validation failed"
            );
            assert!(
                !mismatched_bucket_error.contains("private-hnsw-route-bucket-ciphertext-sentinel"),
                "{mismatched_bucket_error}"
            );
            assert!(
                !mismatched_bucket_error.contains(&mismatched_bucket.ciphertext),
                "{mismatched_bucket_error}"
            );
            assert!(
                !mismatched_bucket_error.contains("private_hnsw_oram"),
                "{mismatched_bucket_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &mismatched_bucket_error,
                &[
                    "private-hnsw-route-bucket-ciphertext-sentinel",
                    mismatched_bucket.ciphertext.as_str(),
                    fixture.encrypted_build.root_hash.as_str(),
                    session_id.as_str(),
                    "/tmp",
                ],
            );
            std::fs::write(&bucket_path, &original_bucket_bytes).unwrap();

            let mut proof_mismatched_bucket = read_response.buckets[0].clone();
            proof_mismatched_bucket.bucket_commitment =
                data_encoding::BASE64URL_NOPAD.encode(&[91; 32]);
            std::fs::write(
                &bucket_path,
                serde_json::to_vec_pretty(&proof_mismatched_bucket).unwrap(),
            )
            .unwrap();
            let proof_mismatch_paths = vec![fixture.entry_leaf_label()];
            let proof_mismatch_signature = fixture.sign_read_paths(&proof_mismatch_paths, 1, true);
            let proof_mismatch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: proof_mismatch_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: proof_mismatch_signature.alg,
                        key_id: proof_mismatch_signature.key_id,
                        sig: proof_mismatch_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "bucket/proof consistency validation failed"
            );
            assert!(
                !proof_mismatch_error.contains(&proof_mismatched_bucket.ciphertext),
                "{proof_mismatch_error}"
            );
            assert!(
                !proof_mismatch_error.contains("private_hnsw_oram"),
                "{proof_mismatch_error}"
            );
            assert!(
                !proof_mismatch_error.contains("/tmp"),
                "{proof_mismatch_error}"
            );
            assert_private_hnsw_guard_error_redacts(
                &proof_mismatch_error,
                &[
                    proof_mismatched_bucket.ciphertext.as_str(),
                    fixture.encrypted_build.root_hash.as_str(),
                    session_id.as_str(),
                    "/tmp",
                ],
            );
            std::fs::write(&bucket_path, &original_bucket_bytes).unwrap();

            let future_bucket = search_run.updated_buckets[0].clone();
            let future_bucket_path = uploaded_store
                .root_path()
                .join("buckets")
                .join(format!("{:08}.bucket", future_bucket.bucket_id));
            let original_future_bucket_bytes = std::fs::read(&future_bucket_path).unwrap();
            std::fs::write(
                &future_bucket_path,
                serde_json::to_vec_pretty(&future_bucket).unwrap(),
            )
            .unwrap();
            let future_bucket_paths = vec![fixture.entry_leaf_label()];
            let future_bucket_signature = fixture.sign_read_paths(&future_bucket_paths, 1, true);
            let future_bucket_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: future_bucket_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: future_bucket_signature.alg,
                        key_id: future_bucket_signature.key_id,
                        sig: future_bucket_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "encrypted bucket store validation failed"
            );
            assert!(!future_bucket_error.contains(&future_bucket.ciphertext));
            assert!(!future_bucket_error.contains(&future_bucket.ciphertext_sha256));
            assert!(!future_bucket_error.contains(&future_bucket.bucket_commitment));
            assert!(!future_bucket_error.contains("index_epoch"));
            assert!(!future_bucket_error.contains(&fixture.encrypted_build.root_hash));
            assert!(!future_bucket_error.contains(&session_id));
            assert!(!future_bucket_error.contains("private_hnsw_oram"));
            assert_private_hnsw_guard_error_redacts(
                &future_bucket_error,
                &[
                    future_bucket.ciphertext.as_str(),
                    future_bucket.ciphertext_sha256.as_str(),
                    future_bucket.bucket_commitment.as_str(),
                    "index_epoch",
                    fixture.encrypted_build.root_hash.as_str(),
                    session_id.as_str(),
                    "/tmp",
                ],
            );
            std::fs::write(&future_bucket_path, &original_future_bucket_bytes).unwrap();

            let current_epoch_path = uploaded_store
                .root_path()
                .join("epochs")
                .join("current.json");
            let original_current_epoch_bytes = std::fs::read(&current_epoch_path).unwrap();
            let stale_current_root = data_encoding::BASE64URL_NOPAD.encode(&[88; 32]);
            std::fs::write(
                &current_epoch_path,
                serde_json::to_vec_pretty(&PrivateHnswOramEpochState {
                    index_epoch: BASE_EPOCH,
                    root_hash: stale_current_root.clone(),
                })
                .unwrap(),
            )
            .unwrap();
            let stale_current_read_paths = vec![fixture.entry_leaf_label()];
            let stale_current_read_signature =
                fixture.sign_read_paths(&stale_current_read_paths, 1, true);
            let stale_current_read_session_id = session_id.clone();
            let stale_current_read_root_hash = fixture.encrypted_build.root_hash.clone();
            let stale_current_read_path_label = stale_current_read_paths[0].clone();
            let stale_current_read_signature_key_id = stale_current_read_signature.key_id.clone();
            let stale_current_read_signature_sig = stale_current_read_signature.sig.clone();
            let stale_current_read_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: stale_current_read_session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: stale_current_read_root_hash.clone(),
                    paths: stale_current_read_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: stale_current_read_signature.alg,
                        key_id: stale_current_read_signature.key_id,
                        sig: stale_current_read_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "current epoch/root does not match active session"
            );
            assert!(
                !stale_current_read_error
                    .contains("read_paths current epoch/root does not match active session"),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&stale_current_read_root_hash),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&stale_current_root),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&stale_current_read_session_id),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&stale_current_read_path_label),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&stale_current_read_signature_key_id),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&stale_current_read_signature_sig),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error
                    .contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains("private_hnsw_oram"),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains("/tmp"),
                "{stale_current_read_error}"
            );
            let stale_current_commit_session_id = session_id.clone();
            let stale_current_commit_old_root_hash = search_run.commit_plan.old_root_hash.clone();
            let stale_current_commit_new_root_hash = search_run.commit_plan.new_root_hash.clone();
            let stale_current_commit_bucket_ciphertext =
                search_run.updated_buckets[0].ciphertext.clone();
            let stale_current_commit_bucket_ciphertext_sha256 =
                search_run.updated_buckets[0].ciphertext_sha256.clone();
            let stale_current_commit_bucket_commitment =
                search_run.updated_buckets[0].bucket_commitment.clone();
            let stale_current_commit_signature_key_id = search_run.commit_signature.key_id.clone();
            let stale_current_commit_signature_sig = search_run.commit_signature.sig.clone();
            let stale_current_commit_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: stale_current_commit_session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: stale_current_commit_old_root_hash.clone(),
                    new_root_hash: stale_current_commit_new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: stale_current_commit_signature_key_id.clone(),
                        sig: stale_current_commit_signature_sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "current epoch/root does not match active session"
            );
            assert!(
                !stale_current_commit_error
                    .contains("commit current epoch/root does not match active session"),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains(&stale_current_commit_old_root_hash),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains(&stale_current_commit_new_root_hash),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains(&stale_current_root),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains(&stale_current_commit_session_id),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains(&stale_current_commit_bucket_ciphertext),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error
                    .contains(&stale_current_commit_bucket_ciphertext_sha256),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains(&stale_current_commit_bucket_commitment),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains(&stale_current_commit_signature_key_id),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains(&stale_current_commit_signature_sig),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains("private_hnsw_oram"),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains("/tmp"),
                "{stale_current_commit_error}"
            );
            std::fs::write(&current_epoch_path, original_current_epoch_bytes).unwrap();
            let original_writeback_bucket = fixture
                .encrypted_build
                .buckets
                .iter()
                .find(|bucket| bucket.bucket_id == search_run.updated_buckets[0].bucket_id)
                .unwrap();
            let stored_writeback_bucket = uploaded_store
                .read_bucket(
                    search_run.updated_buckets[0].bucket_id,
                    BASE_EPOCH,
                    fixture.encrypted_build.bucket_count,
                    MAX_CIPHERTEXT_BYTES,
                )
                .unwrap();
            assert_eq!(&stored_writeback_bucket, original_writeback_bucket);
            let assert_pre_commit_state_unchanged = || {
                assert_eq!(
                    uploaded_store.read_current_epoch().unwrap(),
                    PrivateHnswOramEpochState {
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                    }
                );
                let stored_writeback_bucket = uploaded_store
                    .read_bucket(
                        search_run.updated_buckets[0].bucket_id,
                        BASE_EPOCH,
                        fixture.encrypted_build.bucket_count,
                        MAX_CIPHERTEXT_BYTES,
                    )
                    .unwrap();
                assert_eq!(&stored_writeback_bucket, original_writeback_bucket);
            };
            assert_pre_commit_state_unchanged();

            std::fs::remove_file(&bucket_path).unwrap();

            let missing_bucket_paths = vec![fixture.entry_leaf_label()];
            let missing_bucket_signature = fixture.sign_read_paths(&missing_bucket_paths, 1, true);
            let missing_bucket_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: missing_bucket_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: missing_bucket_signature.alg,
                        key_id: missing_bucket_signature.key_id,
                        sig: missing_bucket_signature.sig,
                    },
                },
                StatusCode::NOT_FOUND,
                "encrypted bucket data is unavailable"
            );
            assert!(
                !missing_bucket_error.contains("private_hnsw_oram"),
                "{missing_bucket_error}"
            );
            assert!(
                !missing_bucket_error.contains("/tmp"),
                "{missing_bucket_error}"
            );
            let original_missing_bucket = fixture
                .encrypted_build
                .buckets
                .iter()
                .find(|bucket| bucket.bucket_id == missing_bucket_id)
                .unwrap();
            uploaded_store
                .write_bucket(
                    original_missing_bucket,
                    BASE_EPOCH,
                    fixture.encrypted_build.bucket_count,
                    MAX_CIPHERTEXT_BYTES,
                )
                .unwrap();
            assert_pre_commit_state_unchanged();

            let unknown_commit_key_signature_sig = fixture.client_signature().sig;
            let unknown_commit_key_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: unknown_commit_key_signature_sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!unknown_commit_key_error.contains("not configured"));
            assert!(
                !unknown_commit_key_error.contains(signature_key_id_sentinel),
                "{unknown_commit_key_error}"
            );
            for sentinel in [
                session_id.as_str(),
                search_run.commit_plan.old_root_hash.as_str(),
                search_run.commit_plan.new_root_hash.as_str(),
                unknown_commit_key_signature_sig.as_str(),
                search_run.updated_buckets[0].ciphertext.as_str(),
                search_run.updated_buckets[0].ciphertext_sha256.as_str(),
                search_run.updated_buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !unknown_commit_key_error.contains(sentinel),
                    "{unknown_commit_key_error}"
                );
            }

            let mut alternate_commit_signature = search_run.commit_signature.clone();
            alternate_commit_signature.key_id = alternate_signing_key_id.to_string();
            let alternate_commit_signature_sig = alternate_commit_signature.sig.clone();
            let alternate_commit_key_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: alternate_commit_signature.alg,
                        key_id: alternate_commit_signature.key_id,
                        sig: alternate_commit_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!alternate_commit_key_error.contains("not configured"));
            assert!(
                !alternate_commit_key_error.contains(alternate_signing_key_id),
                "{alternate_commit_key_error}"
            );
            assert!(
                !alternate_commit_key_error.contains(SIGNING_KEY_ID),
                "{alternate_commit_key_error}"
            );
            for sentinel in [
                session_id.as_str(),
                search_run.commit_plan.old_root_hash.as_str(),
                search_run.commit_plan.new_root_hash.as_str(),
                alternate_commit_signature_sig.as_str(),
                search_run.updated_buckets[0].ciphertext.as_str(),
                search_run.updated_buckets[0].ciphertext_sha256.as_str(),
                search_run.updated_buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !alternate_commit_key_error.contains(sentinel),
                    "{alternate_commit_key_error}"
                );
            }

            let invalid_commit_key_id_sentinel = "commit-signature-key!sentinel";
            let invalid_commit_key_sig = fixture.client_signature().sig;
            let invalid_commit_key_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: invalid_commit_key_id_sentinel.to_string(),
                        sig: invalid_commit_key_sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature key_id is invalid"
            );
            assert!(!invalid_commit_key_error.contains("not configured"));
            assert!(
                !invalid_commit_key_error.contains(invalid_commit_key_id_sentinel),
                "{invalid_commit_key_error}"
            );
            for sentinel in [
                session_id.as_str(),
                search_run.commit_plan.old_root_hash.as_str(),
                search_run.commit_plan.new_root_hash.as_str(),
                invalid_commit_key_sig.as_str(),
                search_run.updated_buckets[0].ciphertext.as_str(),
                search_run.updated_buckets[0].ciphertext_sha256.as_str(),
                search_run.updated_buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !invalid_commit_key_error.contains(sentinel),
                    "{invalid_commit_key_error}"
                );
            }

            let malformed_commit_signature_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: signature_body_sentinel.to_string(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature must encode 64 bytes"
            );
            assert!(
                !malformed_commit_signature_error.contains(signature_body_sentinel),
                "{malformed_commit_signature_error}"
            );
            for sentinel in [
                session_id.as_str(),
                search_run.commit_plan.old_root_hash.as_str(),
                search_run.commit_plan.new_root_hash.as_str(),
                SIGNING_KEY_ID,
                search_run.updated_buckets[0].ciphertext.as_str(),
                search_run.updated_buckets[0].ciphertext_sha256.as_str(),
                search_run.updated_buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !malformed_commit_signature_error.contains(sentinel),
                    "{malformed_commit_signature_error}"
                );
            }

            let commit_signature_alg_sentinel = "rsa-pss-hnsw-commit-sentinel";
            let mut unsupported_commit_signature = search_run.commit_signature.clone();
            unsupported_commit_signature.alg = commit_signature_alg_sentinel.to_string();
            let unsupported_commit_key_id = unsupported_commit_signature.key_id.clone();
            let unsupported_commit_sig = unsupported_commit_signature.sig.clone();
            let unsupported_commit_signature_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: unsupported_commit_signature.alg,
                        key_id: unsupported_commit_signature.key_id,
                        sig: unsupported_commit_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "signature algorithm must be ed25519"
            );
            assert!(
                !unsupported_commit_signature_error.contains(commit_signature_alg_sentinel),
                "{unsupported_commit_signature_error}"
            );
            for sentinel in [
                session_id.as_str(),
                search_run.commit_plan.old_root_hash.as_str(),
                search_run.commit_plan.new_root_hash.as_str(),
                unsupported_commit_key_id.as_str(),
                unsupported_commit_sig.as_str(),
                search_run.updated_buckets[0].ciphertext.as_str(),
                search_run.updated_buckets[0].ciphertext_sha256.as_str(),
                search_run.updated_buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !unsupported_commit_signature_error.contains(sentinel),
                    "{unsupported_commit_signature_error}"
                );
            }

            let unknown_commit_session_sentinel = "commit-session-id-sentinel";
            let unknown_commit_session_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: unknown_commit_session_sentinel.to_string(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            assert!(
                !unknown_commit_session_error.contains(unknown_commit_session_sentinel),
                "{unknown_commit_session_error}"
            );
            for sentinel in [
                search_run.commit_plan.old_root_hash.as_str(),
                search_run.commit_plan.new_root_hash.as_str(),
                search_run.commit_signature.sig.as_str(),
                search_run.updated_buckets[0].ciphertext.as_str(),
                search_run.updated_buckets[0].ciphertext_sha256.as_str(),
                search_run.updated_buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !unknown_commit_session_error.contains(sentinel),
                    "{unknown_commit_session_error}"
                );
            }

            let oversized_commit_session_id = "s".repeat(129);
            let malformed_commit_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_commit_session_id.as_str(),
                malformed_commit_session_id,
            ] {
                let error = post_json_error_contains!(
                    "/collections/docs/private-hnsw/text/oram/commit",
                    OramCommitRequest {
                        session_id: invalid_session_id.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                        new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                        updated_buckets: search_run.updated_buckets.clone(),
                        commit_signature: PrivateHnswClientSignature {
                            alg: search_run.commit_signature.alg.clone(),
                            key_id: search_run.commit_signature.key_id.clone(),
                            sig: search_run.commit_signature.sig.clone(),
                        },
                    },
                    StatusCode::BAD_REQUEST,
                    "session_id is invalid"
                );
                assert!(!error.contains(invalid_session_id), "{error}");
                assert!(!error.contains("session is missing or expired"), "{error}");
                for sentinel in [
                    search_run.commit_plan.old_root_hash.as_str(),
                    search_run.commit_plan.new_root_hash.as_str(),
                    search_run.commit_signature.sig.as_str(),
                    search_run.updated_buckets[0].ciphertext.as_str(),
                    search_run.updated_buckets[0].ciphertext_sha256.as_str(),
                    search_run.updated_buckets[0].bucket_commitment.as_str(),
                ] {
                    assert!(!error.contains(sentinel), "{error}");
                }
            }

            let commit_wrong_old_root = data_encoding::BASE64URL_NOPAD.encode(&[9; 32]);
            let commit_wrong_old_root_signature = fixture.client_signature();
            let commit_old_root_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_wrong_old_root.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: commit_wrong_old_root_signature.alg.clone(),
                        key_id: commit_wrong_old_root_signature.key_id.clone(),
                        sig: commit_wrong_old_root_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "commit old epoch/root does not match active session"
            );
            assert!(
                !commit_old_root_error.contains(&commit_wrong_old_root),
                "{commit_old_root_error}"
            );
            assert!(!commit_old_root_error.contains(&session_id));
            assert!(
                !commit_old_root_error.contains(&search_run.commit_plan.new_root_hash),
                "{commit_old_root_error}"
            );
            assert!(
                !commit_old_root_error.contains(&commit_wrong_old_root_signature.key_id),
                "{commit_old_root_error}"
            );
            assert!(
                !commit_old_root_error.contains(&commit_wrong_old_root_signature.sig),
                "{commit_old_root_error}"
            );
            assert!(
                !commit_old_root_error.contains(&search_run.updated_buckets[0].ciphertext),
                "{commit_old_root_error}"
            );
            assert!(
                !commit_old_root_error.contains(&search_run.updated_buckets[0].ciphertext_sha256),
                "{commit_old_root_error}"
            );
            assert!(
                !commit_old_root_error.contains(&search_run.updated_buckets[0].bucket_commitment),
                "{commit_old_root_error}"
            );

            let commit_old_root_sentinel = "AAAA";
            let commit_old_root_shape_signature = fixture.client_signature();
            let commit_old_root_shape_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_old_root_sentinel.to_string(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: commit_old_root_shape_signature.alg.clone(),
                        key_id: commit_old_root_shape_signature.key_id.clone(),
                        sig: commit_old_root_shape_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "old_root_hash must encode 32 bytes"
            );
            assert!(
                !commit_old_root_shape_error.contains(commit_old_root_sentinel),
                "{commit_old_root_shape_error}"
            );
            assert!(
                !commit_old_root_shape_error
                    .contains("commit old epoch/root does not match active session"),
                "{commit_old_root_shape_error}"
            );
            assert!(!commit_old_root_shape_error.contains(&session_id));
            assert!(
                !commit_old_root_shape_error.contains(&search_run.commit_plan.new_root_hash),
                "{commit_old_root_shape_error}"
            );
            assert!(
                !commit_old_root_shape_error.contains(&commit_old_root_shape_signature.key_id),
                "{commit_old_root_shape_error}"
            );
            assert!(
                !commit_old_root_shape_error.contains(&commit_old_root_shape_signature.sig),
                "{commit_old_root_shape_error}"
            );
            assert!(
                !commit_old_root_shape_error.contains(&search_run.updated_buckets[0].ciphertext),
                "{commit_old_root_shape_error}"
            );
            assert!(
                !commit_old_root_shape_error
                    .contains(&search_run.updated_buckets[0].ciphertext_sha256),
                "{commit_old_root_shape_error}"
            );
            assert!(
                !commit_old_root_shape_error
                    .contains(&search_run.updated_buckets[0].bucket_commitment),
                "{commit_old_root_shape_error}"
            );

            let duplicate_epoch_signature = fixture.client_signature();
            let duplicate_commit_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: BASE_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: duplicate_epoch_signature.alg.clone(),
                        key_id: duplicate_epoch_signature.key_id.clone(),
                        sig: duplicate_epoch_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "new_epoch must be exactly old_epoch + 1"
            );
            assert!(!duplicate_commit_error.contains(&session_id));
            assert!(
                !duplicate_commit_error.contains(&search_run.commit_plan.old_root_hash),
                "{duplicate_commit_error}"
            );
            assert!(
                !duplicate_commit_error.contains(&search_run.commit_plan.new_root_hash),
                "{duplicate_commit_error}"
            );
            assert!(!duplicate_commit_error.contains(&duplicate_epoch_signature.key_id));
            assert!(!duplicate_commit_error.contains(&duplicate_epoch_signature.sig));
            assert!(
                !duplicate_commit_error.contains(&search_run.updated_buckets[0].ciphertext),
                "{duplicate_commit_error}"
            );
            assert!(
                !duplicate_commit_error.contains(&search_run.updated_buckets[0].ciphertext_sha256),
                "{duplicate_commit_error}"
            );
            assert!(
                !duplicate_commit_error.contains(&search_run.updated_buckets[0].bucket_commitment),
                "{duplicate_commit_error}"
            );
            let commit_new_root_sentinel = "AAAA";
            let commit_wrong_new_root = data_encoding::BASE64URL_NOPAD.encode(&[17; 32]);
            let commit_wrong_new_root_signature = fixture.client_signature();
            let commit_new_root_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: commit_wrong_new_root.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: commit_wrong_new_root_signature.alg.clone(),
                        key_id: commit_wrong_new_root_signature.key_id.clone(),
                        sig: commit_wrong_new_root_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(!commit_new_root_error.contains("new_root_hash"));
            assert!(
                !commit_new_root_error.contains(&commit_wrong_new_root),
                "{commit_new_root_error}"
            );
            assert!(!commit_new_root_error.contains(&session_id));
            assert!(
                !commit_new_root_error.contains(&search_run.commit_plan.old_root_hash),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&commit_wrong_new_root_signature.key_id),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&commit_wrong_new_root_signature.sig),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&search_run.updated_buckets[0].ciphertext),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&search_run.updated_buckets[0].ciphertext_sha256),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&search_run.updated_buckets[0].bucket_commitment),
                "{commit_new_root_error}"
            );

            let commit_new_root_shape_signature = fixture.client_signature();
            let commit_new_root_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: commit_new_root_sentinel.to_string(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: commit_new_root_shape_signature.alg.clone(),
                        key_id: commit_new_root_shape_signature.key_id.clone(),
                        sig: commit_new_root_shape_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "new_root_hash must encode 32 bytes"
            );
            assert!(
                !commit_new_root_error.contains(commit_new_root_sentinel),
                "{commit_new_root_error}"
            );
            assert!(!commit_new_root_error.contains(&session_id));
            assert!(
                !commit_new_root_error.contains(&search_run.commit_plan.old_root_hash),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&commit_new_root_shape_signature.key_id),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&commit_new_root_shape_signature.sig),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&search_run.updated_buckets[0].ciphertext),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&search_run.updated_buckets[0].ciphertext_sha256),
                "{commit_new_root_error}"
            );
            assert!(
                !commit_new_root_error.contains(&search_run.updated_buckets[0].bucket_commitment),
                "{commit_new_root_error}"
            );
            let empty_commit_signature = fixture.client_signature();
            let empty_commit_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: Vec::new(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: empty_commit_signature.alg.clone(),
                        key_id: empty_commit_signature.key_id.clone(),
                        sig: empty_commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "updated_buckets must contain"
            );
            assert!(!empty_commit_error.contains(&session_id));
            assert!(
                !empty_commit_error.contains(&search_run.commit_plan.old_root_hash),
                "{empty_commit_error}"
            );
            assert!(
                !empty_commit_error.contains(&search_run.commit_plan.new_root_hash),
                "{empty_commit_error}"
            );
            assert!(!empty_commit_error.contains(&empty_commit_signature.key_id));
            assert!(!empty_commit_error.contains(&empty_commit_signature.sig));
            let commit_hash_sentinel = "AAAA";
            let mut malformed_hash_buckets = search_run.updated_buckets.clone();
            malformed_hash_buckets[0].ciphertext_sha256 = commit_hash_sentinel.to_string();
            let commit_hash_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: malformed_hash_buckets,
                    commit_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.client_signature().sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "ciphertext_sha256"
            );
            assert!(
                !commit_hash_error.contains(commit_hash_sentinel),
                "{commit_hash_error}"
            );
            assert!(
                !commit_hash_error.contains(&search_run.commit_plan.old_root_hash),
                "{commit_hash_error}"
            );
            assert!(
                !commit_hash_error.contains(&search_run.commit_plan.new_root_hash),
                "{commit_hash_error}"
            );
            assert!(
                !commit_hash_error.contains(&search_run.updated_buckets[0].ciphertext),
                "{commit_hash_error}"
            );
            assert!(
                !commit_hash_error.contains(&search_run.updated_buckets[0].bucket_commitment),
                "{commit_hash_error}"
            );
            assert!(
                !commit_hash_error.contains(&fixture.client_signature().sig),
                "{commit_hash_error}"
            );
            assert!(
                !commit_hash_error.contains("commit signature verification failed"),
                "{commit_hash_error}"
            );
            let commit_commitment_sentinel = "AAAA";
            let mut malformed_commitment_buckets = search_run.updated_buckets.clone();
            malformed_commitment_buckets[0].bucket_commitment =
                commit_commitment_sentinel.to_string();
            let commit_commitment_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: malformed_commitment_buckets,
                    commit_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.client_signature().sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "bucket_commitment"
            );
            assert!(
                !commit_commitment_error.contains(commit_commitment_sentinel),
                "{commit_commitment_error}"
            );
            assert!(
                !commit_commitment_error.contains(&search_run.commit_plan.old_root_hash),
                "{commit_commitment_error}"
            );
            assert!(
                !commit_commitment_error.contains(&search_run.commit_plan.new_root_hash),
                "{commit_commitment_error}"
            );
            assert!(
                !commit_commitment_error.contains(&search_run.updated_buckets[0].ciphertext),
                "{commit_commitment_error}"
            );
            assert!(
                !commit_commitment_error.contains(&search_run.updated_buckets[0].ciphertext_sha256),
                "{commit_commitment_error}"
            );
            assert!(
                !commit_commitment_error.contains(&search_run.updated_buckets[0].bucket_commitment),
                "{commit_commitment_error}"
            );
            assert!(
                !commit_commitment_error.contains(&fixture.client_signature().sig),
                "{commit_commitment_error}"
            );
            assert!(
                !commit_commitment_error.contains("commit signature verification failed"),
                "{commit_commitment_error}"
            );
            let duplicate_commit_bucket = search_run.updated_buckets[0].clone();
            let duplicate_commit_ciphertext = duplicate_commit_bucket.ciphertext.clone();
            let duplicate_commit_ciphertext_sha256 =
                duplicate_commit_bucket.ciphertext_sha256.clone();
            let duplicate_commit_bucket_commitment =
                duplicate_commit_bucket.bucket_commitment.clone();
            let duplicate_commit_buckets = vec![
                duplicate_commit_bucket.clone(),
                duplicate_commit_bucket.clone(),
            ];
            let duplicate_commit_plan = qdrant_sec::PrivateHnswClientCommitPlan {
                old_epoch: BASE_EPOCH,
                new_epoch: NEXT_EPOCH,
                old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                leaf_commitments: search_run.commit_plan.leaf_commitments.clone(),
                updated_buckets: duplicate_commit_buckets
                    .iter()
                    .map(|bucket| qdrant_sec::PrivateHnswClientCommitBucketRef {
                        bucket_id: bucket.bucket_id,
                        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                    })
                    .collect(),
            };
            let duplicate_commit_signature = search_run.commit_signature.clone();
            let duplicate_commit_old_root = duplicate_commit_plan.old_root_hash.clone();
            let duplicate_commit_new_root = duplicate_commit_plan.new_root_hash.clone();
            let duplicate_commit_signature_key_id = duplicate_commit_signature.key_id.clone();
            let duplicate_commit_signature_sig = duplicate_commit_signature.sig.clone();
            let duplicate_bucket_commit_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: duplicate_commit_old_root.clone(),
                    new_root_hash: duplicate_commit_new_root.clone(),
                    updated_buckets: duplicate_commit_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: duplicate_commit_signature.alg,
                        key_id: duplicate_commit_signature_key_id.clone(),
                        sig: duplicate_commit_signature_sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "commit updated_buckets contains duplicate bucket"
            );
            assert!(
                !duplicate_bucket_commit_error.contains("commit signature verification failed"),
                "{duplicate_bucket_commit_error}"
            );
            assert!(!duplicate_bucket_commit_error.contains("duplicate bucket id"));
            assert!(!duplicate_bucket_commit_error.contains(&session_id));
            assert!(!duplicate_bucket_commit_error.contains(&duplicate_commit_old_root));
            assert!(!duplicate_bucket_commit_error.contains(&duplicate_commit_new_root));
            assert!(!duplicate_bucket_commit_error.contains(&duplicate_commit_signature_key_id));
            assert!(!duplicate_bucket_commit_error.contains(&duplicate_commit_signature_sig));
            assert!(!duplicate_bucket_commit_error.contains(&duplicate_commit_ciphertext));
            assert!(!duplicate_bucket_commit_error.contains(&duplicate_commit_ciphertext_sha256));
            assert!(!duplicate_bucket_commit_error.contains(&duplicate_commit_bucket_commitment));
            let invalid_signature_duplicate_signature = fixture.client_signature();
            let invalid_signature_duplicate_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: duplicate_commit_buckets,
                    commit_signature: PrivateHnswClientSignature {
                        alg: invalid_signature_duplicate_signature.alg.clone(),
                        key_id: invalid_signature_duplicate_signature.key_id.clone(),
                        sig: invalid_signature_duplicate_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "commit updated_buckets contains duplicate bucket"
            );
            assert!(
                !invalid_signature_duplicate_error.contains("commit signature verification failed"),
                "{invalid_signature_duplicate_error}"
            );
            assert!(!invalid_signature_duplicate_error.contains("duplicate bucket id"));
            assert!(!invalid_signature_duplicate_error.contains(&session_id));
            assert!(
                !invalid_signature_duplicate_error.contains(&search_run.commit_plan.old_root_hash),
                "{invalid_signature_duplicate_error}"
            );
            assert!(
                !invalid_signature_duplicate_error.contains(&search_run.commit_plan.new_root_hash),
                "{invalid_signature_duplicate_error}"
            );
            assert!(
                !invalid_signature_duplicate_error
                    .contains(&invalid_signature_duplicate_signature.key_id)
            );
            assert!(
                !invalid_signature_duplicate_error
                    .contains(&invalid_signature_duplicate_signature.sig)
            );
            let mut oversized_writeback_buckets = search_run.updated_buckets.clone();
            let mut next_bucket_id = oversized_writeback_buckets
                .iter()
                .map(|bucket| bucket.bucket_id)
                .max()
                .unwrap_or(0)
                + 1;
            // The session writeback budget grows with every path the session has read, so only
            // more buckets than the whole tree is oversized for every session.
            let whole_tree = usize::try_from(fixture.manifest.bucket_count).unwrap();
            while oversized_writeback_buckets.len() <= whole_tree {
                let mut bucket = search_run.updated_buckets[0].clone();
                bucket.bucket_id = next_bucket_id;
                next_bucket_id += 1;
                oversized_writeback_buckets.push(bucket);
            }
            let oversized_commit_signature = fixture.client_signature();
            let oversized_commit_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: oversized_writeback_buckets,
                    commit_signature: PrivateHnswClientSignature {
                        alg: oversized_commit_signature.alg.clone(),
                        key_id: oversized_commit_signature.key_id.clone(),
                        sig: oversized_commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "fixed writeback budget"
            );
            assert!(!oversized_commit_error.contains("1..=3"));
            assert!(!oversized_commit_error.contains(&session_id));
            assert!(
                !oversized_commit_error.contains(&search_run.commit_plan.old_root_hash),
                "{oversized_commit_error}"
            );
            assert!(
                !oversized_commit_error.contains(&search_run.commit_plan.new_root_hash),
                "{oversized_commit_error}"
            );
            assert!(
                !oversized_commit_error.contains(&search_run.updated_buckets[0].ciphertext),
                "{oversized_commit_error}"
            );
            assert!(
                !oversized_commit_error.contains(&search_run.updated_buckets[0].ciphertext_sha256),
                "{oversized_commit_error}"
            );
            assert!(
                !oversized_commit_error.contains(&search_run.updated_buckets[0].bucket_commitment),
                "{oversized_commit_error}"
            );
            assert!(!oversized_commit_error.contains(&oversized_commit_signature.key_id));
            assert!(!oversized_commit_error.contains(&oversized_commit_signature.sig));
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.client_signature().sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );

            let commit_ciphertext_sentinel = "commit-error-ciphertext-sentinel";
            let mut malformed_commit_buckets = search_run.updated_buckets.clone();
            malformed_commit_buckets[0].ciphertext = commit_ciphertext_sentinel.to_string();
            let malformed_commit_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: malformed_commit_buckets,
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "bucket ciphertext validation failed"
            );
            assert!(
                !malformed_commit_error.contains(commit_ciphertext_sentinel),
                "{malformed_commit_error}"
            );
            assert_pre_commit_state_unchanged();

            let mut wrong_commitment_buckets = search_run.updated_buckets.clone();
            wrong_commitment_buckets[0].bucket_commitment =
                data_encoding::BASE64URL_NOPAD.encode(&[99; 32]);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: wrong_commitment_buckets,
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "commit bucket commitment context mismatch"
            );
            assert_pre_commit_state_unchanged();

            std::fs::remove_file(uploaded_store.root_path().join("merkle").join("nodes.dat"))
                .unwrap();
            let missing_commit_metadata_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::NOT_FOUND,
                "encrypted bucket store metadata is unavailable"
            );
            assert!(
                !missing_commit_metadata_error.contains("private_hnsw_oram"),
                "{missing_commit_metadata_error}"
            );
            assert!(
                !missing_commit_metadata_error.contains("/tmp"),
                "{missing_commit_metadata_error}"
            );
            assert_pre_commit_state_unchanged();
            uploaded_store
                .write_merkle_tree_from_commitments(
                    BASE_EPOCH,
                    fixture.encrypted_build.root_hash.clone(),
                    fixture
                        .encrypted_build
                        .buckets
                        .iter()
                        .map(|bucket| bucket.bucket_commitment.clone())
                        .collect(),
                )
                .unwrap();

            let commit_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                }
            );
            assert_eq!(commit_result["index_epoch"], NEXT_EPOCH);
            assert_eq!(
                commit_result["root_hash"],
                search_run.commit_plan.new_root_hash
            );
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "old epoch/root does not match active session"
            );

            let close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{session_id}/close"
                ))
                .to_request();
            let close_response = actix_test::call_service(&app, close_request).await;
            assert_eq!(close_response.status(), StatusCode::OK);
            let close_body: Value = actix_test::read_body_json(close_response).await;
            assert_eq!(close_body["result"], true);

            let missing_close_session_id = "close-session-id-sentinel";
            let missing_close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{missing_close_session_id}/close"
                ))
                .to_request();
            let missing_close_response =
                actix_test::call_service(&app, missing_close_request).await;
            assert_eq!(missing_close_response.status(), StatusCode::BAD_REQUEST);
            let missing_close_body = actix_test::read_body(missing_close_response).await;
            let missing_close_body = String::from_utf8_lossy(&missing_close_body);
            assert!(missing_close_body.contains("session is missing or already closed"));
            assert!(
                !missing_close_body.contains(missing_close_session_id),
                "{missing_close_body}"
            );

            let oversized_close_session_id = "s".repeat(129);
            let very_oversized_close_session_id = "s".repeat(257);
            let malformed_close_session_id = "bad.session-id";
            for invalid_session_id in [
                oversized_close_session_id.as_str(),
                very_oversized_close_session_id.as_str(),
                malformed_close_session_id,
            ] {
                let invalid_close_request = actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/docs/private-hnsw/text/session/{invalid_session_id}/close"
                    ))
                    .to_request();
                let invalid_close_response =
                    actix_test::call_service(&app, invalid_close_request).await;
                assert_eq!(invalid_close_response.status(), StatusCode::BAD_REQUEST);
                let invalid_close_body = actix_test::read_body(invalid_close_response).await;
                let invalid_close_body = String::from_utf8_lossy(&invalid_close_body);
                assert!(invalid_close_body.contains("session_id is invalid"));
                assert!(
                    !invalid_close_body.contains(invalid_session_id),
                    "{invalid_close_body}"
                );
                assert!(
                    !invalid_close_body.contains("session is missing or already closed"),
                    "{invalid_close_body}"
                );
            }

            let closed_read_paths = vec![fixture.entry_leaf_label()];
            let closed_read_signature = fixture.sign_read_paths(&closed_read_paths, 1, true);
            let closed_read_path = closed_read_paths[0].clone();
            let closed_read_signature_sig = closed_read_signature.sig.clone();
            let closed_read_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: closed_read_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: closed_read_signature.alg,
                        key_id: closed_read_signature.key_id,
                        sig: closed_read_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.encrypted_build.root_hash.as_str(),
                closed_read_path.as_str(),
                closed_read_signature_sig.as_str(),
                fixture.encrypted_build.buckets[0].ciphertext.as_str(),
            ] {
                assert!(!closed_read_error.contains(sentinel), "{closed_read_error}");
            }

            let closed_commit_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            for sentinel in [
                session_id.as_str(),
                search_run.commit_plan.old_root_hash.as_str(),
                search_run.commit_plan.new_root_hash.as_str(),
                search_run.commit_signature.sig.as_str(),
                search_run.updated_buckets[0].ciphertext.as_str(),
            ] {
                assert!(
                    !closed_commit_error.contains(sentinel),
                    "{closed_commit_error}"
                );
            }

            let reopened_session = post_json_ok!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-2".to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                }
            );
            assert_eq!(reopened_session["index_epoch"], NEXT_EPOCH);
            assert_eq!(
                reopened_session["root_hash"],
                search_run.commit_plan.new_root_hash
            );
            let reopened_session_id = reopened_session["session_id"].as_str().unwrap();
            let reopened_read_paths = vec![fixture.entry_leaf_label()];
            let reopened_read_signature = fixture.sign_read_paths_for_epoch(
                NEXT_EPOCH,
                &search_run.commit_plan.new_root_hash,
                &reopened_read_paths,
                1,
                true,
            );
            let reopened_read = post_json_ok!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: reopened_session_id.to_string(),
                    index_epoch: NEXT_EPOCH,
                    root_hash: search_run.commit_plan.new_root_hash.clone(),
                    paths: reopened_read_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: reopened_read_signature.alg,
                        key_id: reopened_read_signature.key_id,
                        sig: reopened_read_signature.sig,
                    },
                }
            );
            assert_eq!(reopened_read["index_epoch"], NEXT_EPOCH);
            assert_eq!(
                reopened_read["root_hash"],
                search_run.commit_plan.new_root_hash
            );
            let close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{reopened_session_id}/close"
                ))
                .to_request();
            let close_response = actix_test::call_service(&app, close_request).await;
            assert_eq!(close_response.status(), StatusCode::OK);

            let recovery_epoch = NEXT_EPOCH + 1;
            let mut recovery_commitments = fixture.leaf_commitments.clone();
            for bucket in &search_run.updated_buckets {
                recovery_commitments[bucket.bucket_id as usize] = bucket.bucket_commitment.clone();
            }
            let mut recovery_bucket = search_run.updated_buckets[0].clone();
            recovery_bucket.index_epoch = recovery_epoch;
            let mut recovery_ciphertext = data_encoding::BASE64URL_NOPAD
                .decode(recovery_bucket.ciphertext.as_bytes())
                .unwrap();
            for byte in &mut recovery_ciphertext {
                *byte ^= 0x5a;
            }
            recovery_bucket.ciphertext =
                data_encoding::BASE64URL_NOPAD.encode(&recovery_ciphertext);
            recovery_bucket.ciphertext_sha256 =
                data_encoding::BASE64URL_NOPAD.encode(&sha2::Sha256::digest(&recovery_ciphertext));
            recovery_bucket.bucket_commitment =
                qdrant_sec::private_hnsw_oram::private_hnsw_oram_bucket_commitment(
                    qdrant_sec::private_hnsw_oram::PrivateHnswOramBucketCommitmentContext {
                        collection_id: COLLECTION_ID,
                        vector_name: "text",
                        key_id: KEY_ID,
                        rk_id: KEY_ID,
                        rk_epoch: fixture.manifest.rk_epoch,
                        bucket_id: recovery_bucket.bucket_id,
                        index_epoch: recovery_epoch,
                    },
                    &recovery_bucket.ciphertext_sha256,
                )
                .unwrap();
            recovery_commitments[recovery_bucket.bucket_id as usize] =
                recovery_bucket.bucket_commitment.clone();
            let recovery_root_hash =
                PrivateHnswOramStore::merkle_root_for_commitments(&recovery_commitments).unwrap();
            let recovery_plan = qdrant_sec::PrivateHnswClientCommitPlan {
                old_epoch: NEXT_EPOCH,
                new_epoch: recovery_epoch,
                old_root_hash: search_run.commit_plan.new_root_hash.clone(),
                new_root_hash: recovery_root_hash.clone(),
                leaf_commitments: recovery_commitments,
                updated_buckets: vec![qdrant_sec::PrivateHnswClientCommitBucketRef {
                    bucket_id: recovery_bucket.bucket_id,
                    ciphertext_sha256: recovery_bucket.ciphertext_sha256.clone(),
                }],
            };
            let recovery_signature = fixture.sign_commit(&recovery_plan);
            let internal_auth = Auth::new_internal(Access::full("private HNSW recovery test"));
            let collection_pass = internal_auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new().write(),
                    "private_hnsw_recovery_test",
                )
                .unwrap();
            let collection = dispatcher
                .toc(&internal_auth, &new_unchecked_verification_pass())
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let recovery_store = PrivateHnswOramStore::new(collection.path(), "text").unwrap();
            let recovery_public_key = data_encoding::BASE64URL_NOPAD
                .decode(fixture.signing_public_key_b64().as_bytes())
                .unwrap();
            recovery_store
                .prepare_durable_writeback_with_signature(
                    &PrivateHnswOramEpochState {
                        index_epoch: NEXT_EPOCH,
                        root_hash: search_run.commit_plan.new_root_hash.clone(),
                    },
                    &PrivateHnswOramEpochState {
                        index_epoch: recovery_epoch,
                        root_hash: recovery_root_hash.clone(),
                    },
                    fixture.manifest.bucket_count,
                    std::slice::from_ref(&recovery_bucket),
                    MAX_CIPHERTEXT_BYTES,
                    &recovery_signature,
                    qdrant_sec::PrivateHnswSignatureVerification {
                        expected_key_id: SIGNING_KEY_ID,
                        public_key: &recovery_public_key,
                    },
                )
                .unwrap();
            assert!(recovery_store.pending_writeback_exists().unwrap());

            let recovered_session = post_json_ok!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-recovery-instance".to_string(),
                    desired_epoch: recovery_epoch,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                }
            );
            assert_eq!(recovered_session["index_epoch"], recovery_epoch);
            assert_eq!(recovered_session["root_hash"], recovery_root_hash);
            assert!(!recovery_store.pending_writeback_exists().unwrap());
            let recovered_session_id = recovered_session["session_id"].as_str().unwrap();
            let recovered_close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{recovered_session_id}/close"
                ))
                .to_request();
            let recovered_close_response =
                actix_test::call_service(&app, recovered_close_request).await;
            assert_eq!(recovered_close_response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn private_hnsw_rest_routes_reject_distributed_epoch_operations() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_distributed_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            macro_rules! assert_distributed_rejection {
                ($request:expr, [$($secret:expr),* $(,)?] $(,)?) => {{
                    let response = actix_test::call_service(&app, $request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
                    assert!(body.contains("consensus-backed epoch/root CAS"), "{body}");
                    $(assert!(!body.contains($secret), "{body}");)*
                }};
            }

            let distributed_client_id = "tenant-a/distributed-sdk-instance";
            let entry_leaf_label = fixture.entry_leaf_label();
            let read_signature = fixture.client_signature();
            let read_signature_sig = read_signature.sig.clone();
            let search_run = fixture.run_single_search_collect_writeback();
            let commit_old_root_hash = search_run.commit_plan.old_root_hash.clone();
            let commit_new_root_hash = search_run.commit_plan.new_root_hash.clone();
            let commit_signature_sig = search_run.commit_signature.sig.clone();
            let commit_bucket_ciphertext = search_run.updated_buckets[0].ciphertext.clone();

            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/manifest")
                    .set_json(&UploadPrivateHnswManifestRequest {
                        manifest: fixture.manifest.clone(),
                        signature: fixture.manifest_signature.clone(),
                    })
                    .to_request(),
                [
                    &fixture.manifest.root_hash,
                    &fixture.manifest_signature.sig,
                    &fixture.encrypted_build.buckets[0].ciphertext,
                ],
            );
            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/buckets")
                    .set_json(&UploadPrivateHnswBucketsRequest {
                        index_epoch: fixture.encrypted_build.index_epoch,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                        buckets: fixture.encrypted_build.buckets.clone(),
                    })
                    .to_request(),
                [
                    &fixture.encrypted_build.root_hash,
                    &fixture.encrypted_build.buckets[0].ciphertext,
                ],
            );
            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/session")
                    .set_json(&OpenPrivateHnswSessionRequest {
                        client_id: distributed_client_id.to_string(),
                        desired_epoch: BASE_EPOCH,
                        fixed_budget: true,
                        result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                    })
                    .to_request(),
                [
                    distributed_client_id,
                    &fixture.manifest.root_hash,
                    &fixture.manifest_signature.sig,
                ],
            );
            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/oram/read_paths")
                    .set_json(&OramReadPathsRequest {
                        session_id: SESSION_ID.to_string(),
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                        paths: vec![entry_leaf_label.clone()],
                        padding: OramReadPadding {
                            requested_paths: 1,
                            dummy_paths_included: true,
                        },
                        client_signature: PrivateHnswClientSignature {
                            alg: read_signature.alg.clone(),
                            key_id: read_signature.key_id.clone(),
                            sig: read_signature_sig.clone(),
                        },
                    })
                    .to_request(),
                [
                    SESSION_ID,
                    &fixture.encrypted_build.root_hash,
                    &entry_leaf_label,
                    &read_signature_sig,
                ],
            );
            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/oram/commit")
                    .set_json(&OramCommitRequest {
                        session_id: SESSION_ID.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: commit_old_root_hash.clone(),
                        new_root_hash: commit_new_root_hash.clone(),
                        updated_buckets: search_run.updated_buckets,
                        commit_signature: PrivateHnswClientSignature {
                            alg: search_run.commit_signature.alg,
                            key_id: search_run.commit_signature.key_id,
                            sig: commit_signature_sig.clone(),
                        },
                    })
                    .to_request(),
                [
                    SESSION_ID,
                    &commit_old_root_hash,
                    &commit_new_root_hash,
                    &commit_signature_sig,
                    &commit_bucket_ciphertext,
                ],
            );
        });
    }

    #[test]
    fn manifest_upload_rest_route_rejects_reserved_result_private_runtime_mode() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let mut settings = fixture.route_settings();
        settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            let response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/manifest")
                    .set_json(&UploadPrivateHnswManifestRequest {
                        manifest: fixture.manifest.clone(),
                        signature: fixture.manifest_signature.clone(),
                    })
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.contains("requires a private-result-oram/v1 payload rule"),
                "{body}"
            );
            assert!(!body.contains(&fixture.manifest.root_hash), "{body}");
            assert!(!body.contains(&fixture.manifest_signature.sig), "{body}");
        });
    }

    #[test]
    fn manifest_upload_rest_route_accepts_result_private_with_result_oram_binding() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded()
            .with_result_privacy(qdrant_sec::ResultPrivacyMode::PrivatePayloadOramRequired);
        let settings = fixture.route_settings_with_private_result_oram();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            let manifest_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/manifest")
                    .set_json(&UploadPrivateHnswManifestRequest {
                        manifest: fixture.manifest.clone(),
                        signature: fixture.manifest_signature.clone(),
                    })
                    .to_request(),
            )
            .await;
            let manifest_status = manifest_response.status();
            let manifest_body_bytes = actix_test::read_body(manifest_response).await;
            let manifest_body = String::from_utf8_lossy(&manifest_body_bytes);
            assert_eq!(manifest_status, StatusCode::OK, "{manifest_body}");

            let bucket_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/buckets")
                    .set_json(&UploadPrivateHnswBucketsRequest {
                        index_epoch: fixture.encrypted_build.index_epoch,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                        buckets: fixture.encrypted_build.buckets.clone(),
                    })
                    .to_request(),
            )
            .await;
            let bucket_status = bucket_response.status();
            let bucket_body_bytes = actix_test::read_body(bucket_response).await;
            let bucket_body = String::from_utf8_lossy(&bucket_body_bytes);
            assert_eq!(bucket_status, StatusCode::OK, "{bucket_body}");

            let session_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/session")
                    .set_json(&OpenPrivateHnswSessionRequest {
                        client_id: "tenant-a/sdk-instance-private-result".to_string(),
                        desired_epoch: BASE_EPOCH,
                        fixed_budget: true,
                        result_privacy: qdrant_sec::ResultPrivacyMode::PrivatePayloadOramRequired,
                    })
                    .to_request(),
            )
            .await;
            let session_status = session_response.status();
            let session_body_bytes = actix_test::read_body(session_response).await;
            let session_body = String::from_utf8_lossy(&session_body_bytes);
            assert_eq!(session_status, StatusCode::OK, "{session_body}");
            let session_body: Value = serde_json::from_slice(&session_body_bytes).unwrap();
            let session_id = session_body["result"]["session_id"].as_str().unwrap();
            let close_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/docs/private-hnsw/text/session/{session_id}/close"
                    ))
                    .to_request(),
            )
            .await;
            assert_eq!(close_response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn manifest_read_rest_route_revalidates_runtime_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let mut fixed_budget_drifted_settings = settings.clone();
        fixed_budget_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["fixed_budget"]["fixed_result_k"] = serde_json::json!(2);
        let mut hnsw_drifted_settings = settings.clone();
        hnsw_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["hnsw"]["m"] = serde_json::json!(3);
        let mut oram_drifted_settings = settings.clone();
        oram_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["oram"]["bucket_size"] = serde_json::json!(4);
        let mut reserved_privacy_settings = settings.clone();
        reserved_privacy_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let fixed_budget_drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(fixed_budget_drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let hnsw_drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(hnsw_drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let oram_drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(oram_drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let reserved_privacy_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(reserved_privacy_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            let upload_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/manifest")
                    .set_json(&UploadPrivateHnswManifestRequest {
                        manifest: fixture.manifest.clone(),
                        signature: fixture.manifest_signature.clone(),
                    })
                    .to_request(),
            )
            .await;
            assert_eq!(upload_response.status(), StatusCode::OK);

            let assert_manifest_error_redacts = |body: &str| {
                assert!(!body.contains(&fixture.manifest.root_hash), "{body}");
                assert!(!body.contains(&fixture.manifest_signature.sig), "{body}");
            };

            let response = actix_test::call_service(
                &fixed_budget_drifted_app,
                actix_test::TestRequest::get()
                    .uri("/collections/docs/private-hnsw/text/manifest")
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.contains("manifest fixed_budget does not match runtime instance"),
                "{body}"
            );
            assert_manifest_error_redacts(&body);

            let response = actix_test::call_service(
                &hnsw_drifted_app,
                actix_test::TestRequest::get()
                    .uri("/collections/docs/private-hnsw/text/manifest")
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.contains("manifest hnsw does not match runtime instance"),
                "{body}"
            );
            assert_manifest_error_redacts(&body);

            let response = actix_test::call_service(
                &oram_drifted_app,
                actix_test::TestRequest::get()
                    .uri("/collections/docs/private-hnsw/text/manifest")
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.contains("manifest oram does not match runtime instance"),
                "{body}"
            );
            assert_manifest_error_redacts(&body);

            let response = actix_test::call_service(
                &reserved_privacy_app,
                actix_test::TestRequest::get()
                    .uri("/collections/docs/private-hnsw/text/manifest")
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.contains("requires a private-result-oram/v1 payload rule"),
                "{body}"
            );
            assert_manifest_error_redacts(&body);
        });
    }

    #[test]
    fn bucket_upload_rest_route_revalidates_runtime_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let mut fixed_budget_drifted_settings = settings.clone();
        fixed_budget_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["fixed_budget"]["fixed_result_k"] = serde_json::json!(2);
        let mut hnsw_drifted_settings = settings.clone();
        hnsw_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["hnsw"]["m"] = serde_json::json!(3);
        let mut oram_drifted_settings = settings.clone();
        oram_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["oram"]["bucket_size"] = serde_json::json!(4);
        let mut reserved_privacy_settings = settings.clone();
        reserved_privacy_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let fixed_budget_drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(fixed_budget_drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let hnsw_drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(hnsw_drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let oram_drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(oram_drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let reserved_privacy_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(reserved_privacy_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            let upload_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/manifest")
                    .set_json(&UploadPrivateHnswManifestRequest {
                        manifest: fixture.manifest.clone(),
                        signature: fixture.manifest_signature.clone(),
                    })
                    .to_request(),
            )
            .await;
            assert_eq!(upload_response.status(), StatusCode::OK);

            let bucket_request = UploadPrivateHnswBucketsRequest {
                index_epoch: fixture.encrypted_build.index_epoch,
                root_hash: fixture.encrypted_build.root_hash.clone(),
                buckets: fixture.encrypted_build.buckets.clone(),
            };
            let assert_bucket_error_redacts = |body: &str| {
                assert!(!body.contains(&fixture.encrypted_build.root_hash), "{body}");
                assert!(
                    !body.contains(&fixture.encrypted_build.buckets[0].ciphertext),
                    "{body}"
                );
                assert!(
                    !body.contains(&fixture.encrypted_build.buckets[0].ciphertext_sha256),
                    "{body}"
                );
                assert!(
                    !body.contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
                    "{body}"
                );
            };
            let response = actix_test::call_service(
                &fixed_budget_drifted_app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/buckets")
                    .set_json(&bucket_request)
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.contains("manifest fixed_budget does not match runtime instance"),
                "{body}"
            );
            assert_bucket_error_redacts(&body);

            let response = actix_test::call_service(
                &hnsw_drifted_app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/buckets")
                    .set_json(&bucket_request)
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.contains("manifest hnsw does not match runtime instance"),
                "{body}"
            );
            assert_bucket_error_redacts(&body);

            let response = actix_test::call_service(
                &oram_drifted_app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/buckets")
                    .set_json(&bucket_request)
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.contains("manifest oram does not match runtime instance"),
                "{body}"
            );
            assert_bucket_error_redacts(&body);

            let response = actix_test::call_service(
                &reserved_privacy_app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/buckets")
                    .set_json(&bucket_request)
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.contains("requires a private-result-oram/v1 payload rule"),
                "{body}"
            );
            assert_bucket_error_redacts(&body);

            let response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-hnsw/text/buckets")
                    .set_json(&bucket_request)
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body_bytes = actix_test::read_body(response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::OK, "{body}");
        });
    }

    #[test]
    fn read_paths_rest_route_rejects_active_session_after_runtime_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["fixed_budget"]["fixed_result_k"] = serde_json::json!(2);
        let mut hnsw_drifted_settings = settings.clone();
        hnsw_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["hnsw"]["m"] = serde_json::json!(3);
        let mut reserved_privacy_settings = settings.clone();
        reserved_privacy_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");

        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let hnsw_drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(hnsw_drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let reserved_privacy_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(reserved_privacy_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            macro_rules! post_json_ok {
                ($app:expr, $uri:expr, $body:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|err| {
                        panic!(
                            "failed to parse response body for {status}: {err}: {}",
                            String::from_utf8_lossy(&body_bytes)
                        )
                    });
                    assert_eq!(status, StatusCode::OK, "{body}");
                    assert_eq!(body["status"], "ok");
                    body["result"].clone()
                }};
            }
            macro_rules! post_json_error_contains {
                ($app:expr, $uri:expr, $body:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }

            let _ = post_json_ok!(
                &app,
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.manifest_signature.clone(),
                }
            );
            let _ = post_json_ok!(
                &app,
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                }
            );
            let session = post_json_ok!(
                &app,
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                }
            );
            let session_id = session["session_id"].as_str().unwrap().to_string();

            let paths = vec![fixture.entry_leaf_label()];
            let signature = fixture.sign_read_paths(&paths, 1, true);
            let fixed_budget_drift_error = post_json_error_contains!(
                &drifted_app,
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: paths.clone(),
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: signature.alg.clone(),
                        key_id: signature.key_id.clone(),
                        sig: signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "manifest fixed_budget does not match runtime instance"
            );
            assert!(
                !fixed_budget_drift_error.contains(&fixture.encrypted_build.root_hash),
                "{fixed_budget_drift_error}"
            );
            assert!(
                !fixed_budget_drift_error.contains(&session_id),
                "{fixed_budget_drift_error}"
            );
            assert!(
                !fixed_budget_drift_error.contains(&paths[0]),
                "{fixed_budget_drift_error}"
            );
            assert!(
                !fixed_budget_drift_error.contains(&signature.key_id),
                "{fixed_budget_drift_error}"
            );
            assert!(
                !fixed_budget_drift_error.contains(&signature.sig),
                "{fixed_budget_drift_error}"
            );
            let hnsw_drift_paths = vec![fixture.entry_leaf_label()];
            let hnsw_drift_signature = fixture.sign_read_paths(&hnsw_drift_paths, 1, true);
            let hnsw_drift_error = post_json_error_contains!(
                &hnsw_drifted_app,
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: hnsw_drift_paths.clone(),
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: hnsw_drift_signature.alg.clone(),
                        key_id: hnsw_drift_signature.key_id.clone(),
                        sig: hnsw_drift_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "manifest hnsw does not match runtime instance"
            );
            assert!(
                !hnsw_drift_error.contains(&fixture.encrypted_build.root_hash),
                "{hnsw_drift_error}"
            );
            assert!(
                !hnsw_drift_error.contains(&session_id),
                "{hnsw_drift_error}"
            );
            assert!(
                !hnsw_drift_error.contains(&hnsw_drift_paths[0]),
                "{hnsw_drift_error}"
            );
            assert!(
                !hnsw_drift_error.contains(&hnsw_drift_signature.key_id),
                "{hnsw_drift_error}"
            );
            assert!(
                !hnsw_drift_error.contains(&hnsw_drift_signature.sig),
                "{hnsw_drift_error}"
            );
            let reserved_paths = vec![fixture.entry_leaf_label()];
            let reserved_signature = fixture.sign_read_paths(&reserved_paths, 1, true);
            let reserved_privacy_error = post_json_error_contains!(
                &reserved_privacy_app,
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: reserved_paths.clone(),
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: reserved_signature.alg.clone(),
                        key_id: reserved_signature.key_id.clone(),
                        sig: reserved_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "requires a private-result-oram/v1 payload rule"
            );
            assert!(
                !reserved_privacy_error.contains(&fixture.encrypted_build.root_hash),
                "{reserved_privacy_error}"
            );
            assert!(
                !reserved_privacy_error.contains(&session_id),
                "{reserved_privacy_error}"
            );
            assert!(
                !reserved_privacy_error.contains(&reserved_paths[0]),
                "{reserved_privacy_error}"
            );
            assert!(
                !reserved_privacy_error.contains(&reserved_signature.key_id),
                "{reserved_privacy_error}"
            );
            assert!(
                !reserved_privacy_error.contains(&reserved_signature.sig),
                "{reserved_privacy_error}"
            );

            let close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{session_id}/close"
                ))
                .to_request();
            let close_response = actix_test::call_service(&app, close_request).await;
            assert_eq!(close_response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn commit_rest_route_rejects_active_session_after_runtime_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["oram"]["path_batch_size"] = serde_json::json!(2);
        drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["fixed_budget"]["paths_per_round"] = serde_json::json!(2);
        let mut hnsw_drifted_settings = settings.clone();
        hnsw_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["hnsw"]["m"] = serde_json::json!(3);
        let mut reserved_privacy_settings = settings.clone();
        reserved_privacy_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");

        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let hnsw_drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(hnsw_drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;
            let reserved_privacy_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(reserved_privacy_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            macro_rules! post_json_ok {
                ($app:expr, $uri:expr, $body:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|err| {
                        panic!(
                            "failed to parse response body for {status}: {err}: {}",
                            String::from_utf8_lossy(&body_bytes)
                        )
                    });
                    assert_eq!(status, StatusCode::OK, "{body}");
                    assert_eq!(body["status"], "ok");
                    body["result"].clone()
                }};
            }
            macro_rules! post_json_error_contains {
                ($app:expr, $uri:expr, $body:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }

            let _ = post_json_ok!(
                &app,
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.manifest_signature.clone(),
                }
            );
            let _ = post_json_ok!(
                &app,
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                }
            );
            let session = post_json_ok!(
                &app,
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                }
            );
            let session_id = session["session_id"].as_str().unwrap().to_string();

            let run = fixture.run_single_search_collect_writeback();
            let oram_drift_error = post_json_error_contains!(
                &drifted_app,
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.encrypted_build.root_hash.clone(),
                    new_root_hash: run.commit_plan.new_root_hash.clone(),
                    updated_buckets: run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: run.commit_signature.alg.clone(),
                        key_id: run.commit_signature.key_id.clone(),
                        sig: run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(
                !oram_drift_error.contains(&fixture.encrypted_build.root_hash),
                "{oram_drift_error}"
            );
            assert!(
                !oram_drift_error.contains(&run.commit_plan.new_root_hash),
                "{oram_drift_error}"
            );
            assert!(
                !oram_drift_error.contains(&session_id),
                "{oram_drift_error}"
            );
            assert!(
                !oram_drift_error.contains(&run.commit_signature.key_id),
                "{oram_drift_error}"
            );
            assert!(
                !oram_drift_error.contains(&run.commit_signature.sig),
                "{oram_drift_error}"
            );
            assert!(
                !oram_drift_error.contains(&run.updated_buckets[0].ciphertext),
                "{oram_drift_error}"
            );
            let hnsw_run = fixture.run_single_search_collect_writeback();
            let hnsw_drift_error = post_json_error_contains!(
                &hnsw_drifted_app,
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.encrypted_build.root_hash.clone(),
                    new_root_hash: hnsw_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: hnsw_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: hnsw_run.commit_signature.alg.clone(),
                        key_id: hnsw_run.commit_signature.key_id.clone(),
                        sig: hnsw_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "manifest hnsw does not match runtime instance"
            );
            assert!(
                !hnsw_drift_error.contains(&fixture.encrypted_build.root_hash),
                "{hnsw_drift_error}"
            );
            assert!(
                !hnsw_drift_error.contains(&hnsw_run.commit_plan.new_root_hash),
                "{hnsw_drift_error}"
            );
            assert!(
                !hnsw_drift_error.contains(&session_id),
                "{hnsw_drift_error}"
            );
            assert!(
                !hnsw_drift_error.contains(&hnsw_run.commit_signature.key_id),
                "{hnsw_drift_error}"
            );
            assert!(
                !hnsw_drift_error.contains(&hnsw_run.commit_signature.sig),
                "{hnsw_drift_error}"
            );
            assert!(
                !hnsw_drift_error.contains(&hnsw_run.updated_buckets[0].ciphertext),
                "{hnsw_drift_error}"
            );
            let reserved_run = fixture.run_single_search_collect_writeback();
            let reserved_privacy_error = post_json_error_contains!(
                &reserved_privacy_app,
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.encrypted_build.root_hash.clone(),
                    new_root_hash: reserved_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: reserved_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: reserved_run.commit_signature.alg.clone(),
                        key_id: reserved_run.commit_signature.key_id.clone(),
                        sig: reserved_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "requires a private-result-oram/v1 payload rule"
            );
            assert!(
                !reserved_privacy_error.contains(&fixture.encrypted_build.root_hash),
                "{reserved_privacy_error}"
            );
            assert!(
                !reserved_privacy_error.contains(&reserved_run.commit_plan.new_root_hash),
                "{reserved_privacy_error}"
            );
            assert!(
                !reserved_privacy_error.contains(&session_id),
                "{reserved_privacy_error}"
            );
            assert!(
                !reserved_privacy_error.contains(&reserved_run.commit_signature.key_id),
                "{reserved_privacy_error}"
            );
            assert!(
                !reserved_privacy_error.contains(&reserved_run.commit_signature.sig),
                "{reserved_privacy_error}"
            );
            assert!(
                !reserved_privacy_error.contains(&reserved_run.updated_buckets[0].ciphertext),
                "{reserved_privacy_error}"
            );

            let close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{session_id}/close"
                ))
                .to_request();
            let close_response = actix_test::call_service(&app, close_request).await;
            assert_eq!(close_response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn read_paths_rest_route_preserves_fixed_size_bucket_sequence() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded_with_path_batch_size(2);
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
            )
            .await;

            macro_rules! post_json_ok {
                ($uri:expr, $body:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service(&app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|err| {
                        panic!(
                            "failed to parse response body for {status}: {err}: {}",
                            String::from_utf8_lossy(&body_bytes)
                        )
                    });
                    assert_eq!(status, StatusCode::OK, "{body}");
                    assert_eq!(body["status"], "ok");
                    body["result"].clone()
                }};
            }

            let _ = post_json_ok!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.manifest_signature.clone(),
                }
            );
            let _ = post_json_ok!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                }
            );
            let session = post_json_ok!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                }
            );
            let session_id = session["session_id"].as_str().unwrap().to_string();
            let paths = vec![
                qdrant_sec::encode_private_hnsw_oram_leaf_label(0, fixture.config.tree_height)
                    .unwrap(),
                qdrant_sec::encode_private_hnsw_oram_leaf_label(1, fixture.config.tree_height)
                    .unwrap(),
            ];
            let signature = fixture.sign_read_paths(&paths, 2, true);
            let read = post_json_ok!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths,
                    padding: OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: signature.alg,
                        key_id: signature.key_id,
                        sig: signature.sig,
                    },
                }
            );
            let buckets = read["buckets"].as_array().unwrap();
            let expected_bucket_count = (fixture.manifest.oram.tree_height as usize + 1) * 2;
            assert_eq!(buckets.len(), expected_bucket_count);
            assert_eq!(buckets[0]["bucket_id"], buckets[3]["bucket_id"]);
            assert_eq!(buckets[1]["bucket_id"], buckets[4]["bucket_id"]);
            let proof_value = read["proof"]["value"].as_str().unwrap();
            let proof: qdrant_sec::PrivateHnswOramMerkleProof =
                serde_json::from_str(proof_value).unwrap();
            assert_eq!(proof.leaves.len(), expected_bucket_count);
            assert_eq!(proof.leaves[0].bucket_id, proof.leaves[3].bucket_id);
            assert_eq!(proof.leaves[1].bucket_id, proof.leaves[4].bucket_id);
            let response_buckets: Vec<qdrant_sec::PrivateHnswOramBucket> =
                serde_json::from_value(read["buckets"].clone()).unwrap();
            let opened = qdrant_sec::open_private_hnsw_oram_verified_path_batch(
                &fixture.keys,
                fixture.base_context,
                fixture.config,
                BASE_EPOCH,
                &fixture.encrypted_build.root_hash,
                fixture.encrypted_build.bucket_count,
                proof_value,
                &response_buckets,
            )
            .unwrap();
            assert_eq!(opened.len(), expected_bucket_count);

            let duplicate_path = fixture.entry_leaf_label();
            let duplicate_paths = vec![duplicate_path.clone(), duplicate_path.clone()];
            let invalid_duplicate_signature_sig = fixture.client_signature().sig;
            let invalid_duplicate_request = actix_test::TestRequest::post()
                .uri("/collections/docs/private-hnsw/text/oram/read_paths")
                .set_json(OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: duplicate_paths.clone(),
                    padding: OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: invalid_duplicate_signature_sig.clone(),
                    },
                })
                .to_request();
            let invalid_duplicate_response =
                actix_test::call_service(&app, invalid_duplicate_request).await;
            assert_eq!(invalid_duplicate_response.status(), StatusCode::BAD_REQUEST);
            let invalid_duplicate_body = actix_test::read_body(invalid_duplicate_response).await;
            let invalid_duplicate_body = String::from_utf8_lossy(&invalid_duplicate_body);
            assert!(invalid_duplicate_body.contains("duplicate path label"));
            assert!(
                !invalid_duplicate_body.contains(&duplicate_path),
                "{invalid_duplicate_body}"
            );
            assert!(
                !invalid_duplicate_body.contains(&session_id),
                "{invalid_duplicate_body}"
            );
            assert!(
                !invalid_duplicate_body.contains(&fixture.encrypted_build.root_hash),
                "{invalid_duplicate_body}"
            );
            assert!(
                !invalid_duplicate_body.contains(SIGNING_KEY_ID),
                "{invalid_duplicate_body}"
            );
            assert!(
                !invalid_duplicate_body.contains(&invalid_duplicate_signature_sig),
                "{invalid_duplicate_body}"
            );
            assert!(
                !invalid_duplicate_body.contains("read_paths signature verification failed"),
                "{invalid_duplicate_body}"
            );

            let valid_signature_paths = vec![
                qdrant_sec::encode_private_hnsw_oram_leaf_label(0, fixture.config.tree_height)
                    .unwrap(),
                qdrant_sec::encode_private_hnsw_oram_leaf_label(1, fixture.config.tree_height)
                    .unwrap(),
            ];
            let duplicate_signature = fixture.sign_read_paths(&valid_signature_paths, 2, true);
            let duplicate_signature_key_id = duplicate_signature.key_id.clone();
            let duplicate_signature_sig = duplicate_signature.sig.clone();
            let duplicate_request = actix_test::TestRequest::post()
                .uri("/collections/docs/private-hnsw/text/oram/read_paths")
                .set_json(OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: duplicate_paths,
                    padding: OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: duplicate_signature.alg,
                        key_id: duplicate_signature.key_id,
                        sig: duplicate_signature.sig,
                    },
                })
                .to_request();
            let duplicate_response = actix_test::call_service(&app, duplicate_request).await;
            assert_eq!(duplicate_response.status(), StatusCode::BAD_REQUEST);
            let duplicate_body = actix_test::read_body(duplicate_response).await;
            let duplicate_body = String::from_utf8_lossy(&duplicate_body);
            assert!(duplicate_body.contains("duplicate path label"));
            assert!(
                !duplicate_body.contains(&duplicate_path),
                "{duplicate_body}"
            );
            assert!(!duplicate_body.contains(&session_id), "{duplicate_body}");
            assert!(
                !duplicate_body.contains(&fixture.encrypted_build.root_hash),
                "{duplicate_body}"
            );
            assert!(
                !duplicate_body.contains(&duplicate_signature_key_id),
                "{duplicate_body}"
            );
            assert!(
                !duplicate_body.contains(&duplicate_signature_sig),
                "{duplicate_body}"
            );
            assert!(
                !duplicate_body.contains("read_paths signature verification failed"),
                "{duplicate_body}"
            );

            let close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{session_id}/close"
                ))
                .to_request();
            let close_response = actix_test::call_service(&app, close_request).await;
            assert_eq!(close_response.status(), StatusCode::OK);
        });
    }
}
