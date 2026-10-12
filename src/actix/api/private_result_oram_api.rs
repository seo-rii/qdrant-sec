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
use crate::common::private_result_oram::{
    do_close_private_result_oram_session, do_commit_private_result_oram_buckets,
    do_get_private_result_oram_manifest, do_open_private_result_oram_session,
    do_read_private_result_oram_buckets,
    do_stage_private_result_oram_buckets_for_initial_replication,
    do_stage_private_result_oram_manifest_for_initial_replication,
    do_upload_private_result_oram_buckets, do_upload_private_result_oram_manifest,
};
use crate::settings::Settings;
use crate::tonic::api::qdrant_internal_api::{
    close_private_result_oram_session_coordinated, commit_private_result_oram_buckets_coordinated,
    coordinate_private_result_oram_initial_upload, open_private_result_oram_session_coordinated,
    read_private_result_oram_buckets_coordinated,
};

#[derive(Deserialize, Validate)]
struct PrivateResultOramPath {
    #[validate(nested)]
    #[serde(flatten)]
    collection: CollectionPath,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct UploadPrivateResultOramManifestRequest {
    pub manifest: qdrant_sec::PrivateResultOramManifest,
    pub signature: qdrant_sec::PrivateResultOramSignature,
}

impl Debug for UploadPrivateResultOramManifestRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadPrivateResultOramManifestRequest")
            .field("manifest", &self.manifest)
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct UploadPrivateResultOramBucketsRequest {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
}

impl Debug for UploadPrivateResultOramBucketsRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadPrivateResultOramBucketsRequest")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct OpenPrivateResultOramSessionRequest {
    pub client_id: String,
    pub desired_epoch: u64,
    pub fixed_budget: bool,
}

impl Debug for OpenPrivateResultOramSessionRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenPrivateResultOramSessionRequest")
            .field("client_id", &"[redacted]")
            .field("desired_epoch", &self.desired_epoch)
            .field("fixed_budget", &self.fixed_budget)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateResultOramSessionResponse {
    pub session_id: String,
    pub collection_id: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub manifest: qdrant_sec::PrivateResultOramManifest,
    pub lease_expires_unix: u64,
}

impl Debug for PrivateResultOramSessionResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramSessionResponse")
            .field("session_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("manifest", &"[redacted]")
            .field("lease_expires_unix", &self.lease_expires_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct ReadPrivateResultOramBucketsRequest {
    pub session_id: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_ids: Vec<u64>,
    pub read_signature: qdrant_sec::PrivateResultOramSignature,
}

impl Debug for ReadPrivateResultOramBucketsRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadPrivateResultOramBucketsRequest")
            .field("session_id", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_id_count", &"[redacted]")
            .field("read_signature", &self.read_signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateResultOramReadBucketsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
    pub proof: PrivateResultOramReadProof,
}

impl Debug for PrivateResultOramReadBucketsResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadBucketsResponse")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("proof", &self.proof)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateResultOramReadProof {
    pub kind: String,
    pub value: String,
}

impl Debug for PrivateResultOramReadProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadProof")
            .field("kind", &self.kind)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct CommitPrivateResultOramBucketsRequest {
    pub session_id: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub updated_buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
    pub commit_signature: qdrant_sec::PrivateResultOramSignature,
}

impl Debug for CommitPrivateResultOramBucketsRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitPrivateResultOramBucketsRequest")
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

#[post("/collections/{collection_name}/private-result-oram/manifest")]
async fn upload_manifest(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<UploadPrivateResultOramManifestRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = if dispatcher.consensus_state().is_some() {
        do_stage_private_result_oram_manifest_for_initial_replication(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            request.manifest,
            request.signature,
        )
        .await
    } else {
        do_upload_private_result_oram_manifest(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            request.manifest,
            request.signature,
        )
        .await
    };
    process_response(result, timing, None)
}

#[actix_web::get("/collections/{collection_name}/private-result-oram/manifest")]
async fn get_manifest(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let timing = Instant::now();
    let result = do_get_private_result_oram_manifest(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-result-oram/buckets")]
async fn upload_buckets(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<UploadPrivateResultOramBucketsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let coordinated_initial_replication = dispatcher.consensus_state().is_some();
    let result = if coordinated_initial_replication {
        do_stage_private_result_oram_buckets_for_initial_replication(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            request.index_epoch,
            request.root_hash,
            request.buckets,
        )
        .await
    } else {
        do_upload_private_result_oram_buckets(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            request.index_epoch,
            request.root_hash,
            request.buckets,
        )
        .await
    };
    let result = match result {
        Ok(epoch) if coordinated_initial_replication => {
            coordinate_private_result_oram_initial_upload(
                dispatcher.get_ref(),
                &auth,
                settings.get_ref(),
                &path.collection.collection_name,
            )
            .await
            .map(|()| epoch)
        }
        result => result,
    };
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-result-oram/session")]
async fn open_session(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<OpenPrivateResultOramSessionRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = if dispatcher.consensus_state().is_some() {
        open_private_result_oram_session_coordinated(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            request.client_id,
            request.desired_epoch,
            request.fixed_budget,
        )
        .await
    } else {
        do_open_private_result_oram_session(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            request.client_id,
            request.desired_epoch,
            request.fixed_budget,
        )
        .await
    };
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-result-oram/oram/read_buckets")]
async fn read_buckets(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<ReadPrivateResultOramBucketsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = if dispatcher.consensus_state().is_some() {
        read_private_result_oram_buckets_coordinated(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &request.session_id,
            request.index_epoch,
            request.root_hash,
            request.bucket_ids,
            request.read_signature,
        )
        .await
    } else {
        do_read_private_result_oram_buckets(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &request.session_id,
            request.index_epoch,
            request.root_hash,
            request.bucket_ids,
            request.read_signature,
        )
        .await
    };
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-result-oram/oram/commit")]
async fn commit_buckets(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<CommitPrivateResultOramBucketsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = if dispatcher.consensus_state().is_some() {
        commit_private_result_oram_buckets_coordinated(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &request.session_id,
            request.old_epoch,
            request.new_epoch,
            request.old_root_hash,
            request.new_root_hash,
            request.updated_buckets,
            request.commit_signature,
        )
        .await
    } else {
        do_commit_private_result_oram_buckets(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.collection.collection_name,
            &request.session_id,
            request.old_epoch,
            request.new_epoch,
            request.old_root_hash,
            request.new_root_hash,
            request.updated_buckets,
            request.commit_signature,
        )
        .await
    };
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-result-oram/session/{session_id}/close")]
async fn close_session(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramClosePath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let timing = Instant::now();
    let result = if dispatcher.consensus_state().is_some() {
        close_private_result_oram_session_coordinated(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &path.private_result_oram.collection.collection_name,
            &path.session_id,
        )
        .await
    } else {
        do_close_private_result_oram_session(
            dispatcher.toc(&auth, &new_unchecked_verification_pass()),
            &auth,
            settings.get_ref(),
            &path.private_result_oram.collection.collection_name,
            &path.session_id,
        )
        .await
    };
    process_response(result, timing, None)
}

#[derive(Deserialize, Validate)]
struct PrivateResultOramClosePath {
    #[validate(nested)]
    #[serde(flatten)]
    private_result_oram: PrivateResultOramPath,
    #[validate(length(min = 1))]
    session_id: String,
}

pub fn config_private_result_oram_api(cfg: &mut web::ServiceConfig) {
    cfg.service(upload_manifest)
        .service(get_manifest)
        .service(upload_buckets)
        .service(open_session)
        .service(read_buckets)
        .service(commit_buckets)
        .service(close_session);
}

#[cfg(test)]
mod private_result_oram_rest_tests {
    use std::collections::{BTreeMap, HashMap};
    use std::fmt::Debug;

    use actix_web::http::StatusCode;
    use actix_web::{App, test as actix_test, web};
    use collection::config::{
        CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector,
    };
    use collection::operations::types::VectorsConfig;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::private_result_oram_store::{
        PrivateResultOramEpochState, PrivateResultOramStore,
    };
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING,
        PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PrivateResultOramBucket,
        PrivateResultOramBucketCommitmentContext, PrivateResultOramClientCommitBucketRef,
        PrivateResultOramCommitPlan, PrivateResultOramCommitSignatureContext,
        PrivateResultOramManifest, PrivateResultOramReadBucketsSignatureContext,
        private_result_oram_bucket_ciphertext_bytes, private_result_oram_bucket_commitment,
        private_result_oram_merkle_root_for_commitments, sign_private_result_oram_commit,
        sign_private_result_oram_manifest, sign_private_result_oram_read_buckets,
        sign_private_result_oram_read_buckets_for_manifest_context,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use storage::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreateCollection, CreateCollectionOperation,
    };
    use storage::dispatcher::Dispatcher;
    use storage::rbac::{Access, AccessRequirements, Auth};
    use uuid::Uuid;

    use super::*;
    use crate::common::private_hnsw_wire_fixture::{
        create_plain_collection, route_e2e_guard, test_dispatcher, test_distributed_dispatcher,
    };
    use crate::settings::{CryptoInstanceConfig, CryptoSettings};

    const COLLECTION_NAME: &str = "docs";
    const COLLECTION_ID: &str = "12345678-90ab-cdef-1234-567890abcdef";
    const KEY_ID: &str = "tenant-a/result-private-rk";
    const RK_EPOCH: u64 = 7;
    const SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v1";
    const ALT_SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v2";
    const UNCONFIGURED_SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v3";
    const BASE_EPOCH: u64 = 42;
    const NEXT_EPOCH: u64 = 43;
    const SESSION_ID: &str = "session-1";
    const PRIVATE_RESULT_ORAM_CLIENT_STATE_REDACTION_ALIASES: &[&str] = &[
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
    const PRIVATE_RESULT_ORAM_CLIENT_STATE_FILENAME_REDACTION_ALIASES: &[&str] = &[
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
    const PRIVATE_RESULT_ORAM_BUCKET_REDACTION_ALIASES: &[&str] = &[
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
        "read_bucket_id",
        "read.bucket.id",
        "readBucketId",
        "read_bucket_ids",
        "read.bucket.ids",
        "readBucketIds",
        "read_bucket_id_sequence",
        "read.bucket.id.sequence",
        "readBucketIdSequence",
        "bucket_id_sequence",
        "bucket.id.sequence",
        "bucketIdSequence",
        "bucket_sequence",
        "bucket.sequence",
        "bucketSequence",
    ];

    struct PrivateResultRouteFixture {
        manifest: PrivateResultOramManifest,
        signature: qdrant_sec::PrivateResultOramSignature,
        buckets: Vec<PrivateResultOramBucket>,
        signing_key: Ed25519KeyPair,
        alt_signing_key: Ed25519KeyPair,
    }

    impl PrivateResultRouteFixture {
        fn build() -> Self {
            let signing_key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
            let alt_signing_key = Ed25519KeyPair::from_seed_unchecked(&[10; 32]).unwrap();
            let oram = OramParams {
                kind: OramKind::PathOram,
                bucket_size: 2,
                block_size_bytes: 1024,
                tree_height: 2,
                path_batch_size: 2,
            };
            let bucket_count = (1_u64 << (oram.tree_height + 1)) - 1;
            let mut manifest = PrivateResultOramManifest {
                version: 1,
                provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
                collection_id: COLLECTION_ID.to_string(),
                key_id: KEY_ID.to_string(),
                rk_id: KEY_ID.to_string(),
                rk_epoch: RK_EPOCH,
                oram: oram.clone(),
                index_epoch: BASE_EPOCH,
                root_hash: BASE64URL_NOPAD.encode(&[0; 32]),
                bucket_count,
                logical_result_count: 3,
                dummy_result_count: 1,
                owner_signing_key_id: SIGNING_KEY_ID.to_string(),
                created_at_unix: 1_770_000_000,
            };
            let buckets = (0..bucket_count)
                .map(|bucket_id| fixture_bucket(bucket_id, &manifest))
                .collect::<Vec<_>>();
            let commitments = buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>();
            manifest.root_hash =
                private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
            let buckets = (0..bucket_count)
                .map(|bucket_id| fixture_bucket(bucket_id, &manifest))
                .collect::<Vec<_>>();
            let signature = sign_private_result_oram_manifest(&signing_key, &manifest).unwrap();
            Self {
                manifest,
                signature,
                buckets,
                signing_key,
                alt_signing_key,
            }
        }

        fn settings(&self) -> Settings {
            let mut settings = Settings::new(None).unwrap();
            settings.crypto = CryptoSettings {
                zero_trust_profile: Some(crate::settings::ZERO_TRUST_PROFILE_STRICT.to_string()),
                instances: HashMap::from([(
                    "payload_result_oram_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({
                            "key_id": KEY_ID,
                            "expected_rk_id": KEY_ID,
                            "min_rk_epoch": RK_EPOCH,
                            "max_rk_epoch": RK_EPOCH,
                            "oram": {
                                "kind": "path_oram",
                                "bucket_size": self.manifest.oram.bucket_size,
                                "block_size_bytes": self.manifest.oram.block_size_bytes,
                                "tree_height": self.manifest.oram.tree_height,
                                "path_batch_size": self.manifest.oram.path_batch_size
                            },
                            "integrity": {
                                "manifest_signature_required": true,
                                "commit_signature_required": true,
                                "merkle_root_required": true
                            },
                            "signature_public_keys": {
                                SIGNING_KEY_ID: BASE64URL_NOPAD.encode(self.signing_key.public_key().as_ref()),
                                ALT_SIGNING_KEY_ID: BASE64URL_NOPAD.encode(self.alt_signing_key.public_key().as_ref())
                            }
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            };
            settings
        }

        fn commit_bucket(
            &self,
        ) -> (
            PrivateResultOramBucket,
            qdrant_sec::PrivateResultOramSignature,
            String,
        ) {
            let updated_bucket = fixture_bucket_for_epoch(0, &self.manifest, NEXT_EPOCH, &[42; 16]);
            let mut commitments = self
                .buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>();
            commitments[0] = updated_bucket.bucket_commitment.clone();
            let new_root_hash =
                private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
            let plan = PrivateResultOramCommitPlan {
                old_epoch: BASE_EPOCH,
                new_epoch: NEXT_EPOCH,
                old_root_hash: self.manifest.root_hash.clone(),
                new_root_hash: new_root_hash.clone(),
                leaf_commitments: commitments,
                updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                    bucket_id: updated_bucket.bucket_id,
                    ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
                }],
            };
            let commit_signature = sign_private_result_oram_commit(
                &self.signing_key,
                PrivateResultOramCommitSignatureContext {
                    collection_id: &self.manifest.collection_id,
                    key_id: &self.manifest.key_id,
                    rk_id: &self.manifest.rk_id,
                    rk_epoch: self.manifest.rk_epoch,
                    signing_key_id: SIGNING_KEY_ID,
                },
                &plan,
            )
            .unwrap();
            (updated_bucket, commit_signature, new_root_hash)
        }

        fn sign_manifest(
            &self,
            manifest: &PrivateResultOramManifest,
        ) -> qdrant_sec::PrivateResultOramSignature {
            sign_private_result_oram_manifest(&self.signing_key, manifest).unwrap()
        }

        fn commit_signature_with_alt_key(
            &self,
            updated_bucket: &PrivateResultOramBucket,
            new_root_hash: &str,
        ) -> qdrant_sec::PrivateResultOramSignature {
            let mut commitments = self
                .buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>();
            commitments[updated_bucket.bucket_id as usize] =
                updated_bucket.bucket_commitment.clone();
            let plan = PrivateResultOramCommitPlan {
                old_epoch: BASE_EPOCH,
                new_epoch: NEXT_EPOCH,
                old_root_hash: self.manifest.root_hash.clone(),
                new_root_hash: new_root_hash.to_string(),
                leaf_commitments: commitments,
                updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                    bucket_id: updated_bucket.bucket_id,
                    ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
                }],
            };
            sign_private_result_oram_commit(
                &self.alt_signing_key,
                PrivateResultOramCommitSignatureContext {
                    collection_id: &self.manifest.collection_id,
                    key_id: &self.manifest.key_id,
                    rk_id: &self.manifest.rk_id,
                    rk_epoch: self.manifest.rk_epoch,
                    signing_key_id: ALT_SIGNING_KEY_ID,
                },
                &plan,
            )
            .unwrap()
        }

        fn read_signature(&self, bucket_ids: &[u64]) -> qdrant_sec::PrivateResultOramSignature {
            self.read_signature_for_epoch(
                self.manifest.index_epoch,
                &self.manifest.root_hash,
                bucket_ids,
            )
        }

        fn read_signature_for_epoch(
            &self,
            index_epoch: u64,
            root_hash: &str,
            bucket_ids: &[u64],
        ) -> qdrant_sec::PrivateResultOramSignature {
            if let Ok(signature) = sign_private_result_oram_read_buckets_for_manifest_context(
                &self.signing_key,
                &self.manifest,
                index_epoch,
                root_hash,
                bucket_ids,
            ) {
                return signature;
            }
            sign_private_result_oram_read_buckets(
                &self.signing_key,
                PrivateResultOramReadBucketsSignatureContext {
                    collection_id: &self.manifest.collection_id,
                    key_id: &self.manifest.key_id,
                    rk_id: &self.manifest.rk_id,
                    rk_epoch: self.manifest.rk_epoch,
                    signing_key_id: SIGNING_KEY_ID,
                },
                index_epoch,
                root_hash,
                self.manifest.bucket_count,
                bucket_ids,
            )
            .unwrap()
        }

        fn read_signature_with_alt_key(
            &self,
            bucket_ids: &[u64],
        ) -> qdrant_sec::PrivateResultOramSignature {
            sign_private_result_oram_read_buckets(
                &self.alt_signing_key,
                PrivateResultOramReadBucketsSignatureContext {
                    collection_id: &self.manifest.collection_id,
                    key_id: &self.manifest.key_id,
                    rk_id: &self.manifest.rk_id,
                    rk_epoch: self.manifest.rk_epoch,
                    signing_key_id: ALT_SIGNING_KEY_ID,
                },
                self.manifest.index_epoch,
                &self.manifest.root_hash,
                self.manifest.bucket_count,
                bucket_ids,
            )
            .unwrap()
        }
    }

    fn fixture_bucket(
        bucket_id: u64,
        manifest: &PrivateResultOramManifest,
    ) -> PrivateResultOramBucket {
        fixture_bucket_for_epoch(
            bucket_id,
            manifest,
            manifest.index_epoch,
            &[bucket_id as u8; 16],
        )
    }

    fn fixture_bucket_for_epoch(
        bucket_id: u64,
        manifest: &PrivateResultOramManifest,
        index_epoch: u64,
        ciphertext_bytes: &[u8],
    ) -> PrivateResultOramBucket {
        let expected_len = private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
        let mut fixed_ciphertext = vec![0; expected_len];
        for (offset, byte) in fixed_ciphertext.iter_mut().enumerate() {
            let seed = ciphertext_bytes
                .get(offset % ciphertext_bytes.len().max(1))
                .copied()
                .unwrap_or(0);
            *byte = seed ^ (bucket_id as u8).wrapping_add(index_epoch as u8);
        }
        let ciphertext = BASE64URL_NOPAD.encode(&fixed_ciphertext);
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(&fixed_ciphertext));
        let bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id,
                index_epoch,
            },
            &ciphertext_sha256,
        )
        .unwrap();
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment,
        }
    }

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
            qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
            qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
            qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
            "/private-result-oram/session",
            "/private-hnsw/{vector}/session",
            "private_result_oram",
            "private_hnsw_oram",
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
        for &forbidden in PRIVATE_RESULT_ORAM_CLIENT_STATE_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "write-access denial leaked private ORAM detail `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_RESULT_ORAM_CLIENT_STATE_FILENAME_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "write-access denial leaked private ORAM detail `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_RESULT_ORAM_BUCKET_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "write-access denial leaked private ORAM detail `{forbidden}`: {rendered}",
            );
        }
    }

    fn assert_private_result_guard_error_redacts(rendered: &str, extra_forbidden: &[&str]) {
        for forbidden in [
            COLLECTION_NAME,
            "body_private_result",
            "payload_result_oram_v1",
            KEY_ID,
            SIGNING_KEY_ID,
            qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
            qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
            qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
            qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
            "private_result_oram",
            "private_hnsw_oram",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "private result ORAM guard leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_RESULT_ORAM_CLIENT_STATE_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private result ORAM guard leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_RESULT_ORAM_CLIENT_STATE_FILENAME_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private result ORAM guard leaked `{forbidden}`: {rendered}",
            );
        }
        for &forbidden in PRIVATE_RESULT_ORAM_BUCKET_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "private result ORAM guard leaked `{forbidden}`: {rendered}",
            );
        }
        for forbidden in extra_forbidden {
            assert!(
                !rendered.contains(forbidden),
                "private result ORAM guard leaked `{forbidden}`: {rendered}",
            );
        }
    }

    #[test]
    fn private_result_oram_rest_dto_debug_redacts_sensitive_values() {
        let fixture = PrivateResultRouteFixture::build();
        let mut manifest = fixture.manifest.clone();
        manifest.collection_id = "RESULT-REST-MANIFEST-COLLECTION-ID-SENTINEL".to_string();
        let manifest_request = UploadPrivateResultOramManifestRequest {
            manifest: manifest.clone(),
            signature: fixture.signature.clone(),
        };
        let open_request = OpenPrivateResultOramSessionRequest {
            client_id: "private-result-rest-client-id-sentinel".to_string(),
            desired_epoch: fixture.manifest.index_epoch,
            fixed_budget: true,
        };
        let session_response = PrivateResultOramSessionResponse {
            session_id: SESSION_ID.to_string(),
            collection_id: "RESULT-REST-SESSION-COLLECTION-ID-SENTINEL".to_string(),
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            manifest,
            lease_expires_unix: 1_770_000_000,
        };
        let read_bucket_id = 987_654;
        let next_read_bucket_id = 987_655;
        let bucket_ids = vec![read_bucket_id, next_read_bucket_id];
        let read_signature = qdrant_sec::PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: "RESULT-REST-READ-KEY-ID-SENTINEL".to_string(),
            sig: "RESULT-REST-READ-SIGNATURE-SENTINEL".to_string(),
        };
        let read_request = ReadPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            bucket_ids: bucket_ids.clone(),
            read_signature: read_signature.clone(),
        };
        let (updated_bucket, mut commit_signature, new_root_hash) = fixture.commit_bucket();
        let updated_bucket_ciphertext = updated_bucket.ciphertext.clone();
        let updated_bucket_ciphertext_sha256 = updated_bucket.ciphertext_sha256.clone();
        let updated_bucket_commitment = updated_bucket.bucket_commitment.clone();
        let leaf_commitment = fixture.buckets[0].bucket_commitment.clone();
        commit_signature.key_id = "RESULT-REST-COMMIT-KEY-ID-SENTINEL".to_string();
        let commit_request = CommitPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: fixture.manifest.root_hash.clone(),
            new_root_hash: new_root_hash.clone(),
            updated_buckets: vec![updated_bucket],
            commit_signature: commit_signature.clone(),
        };
        let buckets_request = UploadPrivateResultOramBucketsRequest {
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            buckets: fixture.buckets.clone(),
        };
        let read_response = PrivateResultOramReadBucketsResponse {
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            buckets: fixture.buckets.clone(),
            proof: PrivateResultOramReadProof {
                kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
                value: "RESULT-REST-PROOF-SENTINEL".to_string(),
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
            fixture.manifest.root_hash.clone(),
            new_root_hash,
            fixture.buckets[0].ciphertext.clone(),
            fixture.buckets[0].ciphertext_sha256.clone(),
            leaf_commitment,
            fixture.signature.key_id.clone(),
            fixture.signature.sig.clone(),
            updated_bucket_ciphertext,
            updated_bucket_ciphertext_sha256,
            updated_bucket_commitment,
            read_signature.key_id,
            read_signature.sig,
            commit_signature.key_id,
            commit_signature.sig,
            "RESULT-REST-MANIFEST-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-REST-SESSION-COLLECTION-ID-SENTINEL".to_string(),
            read_bucket_id.to_string(),
            next_read_bucket_id.to_string(),
            "RESULT-REST-PROOF-SENTINEL".to_string(),
            "private-result-rest-client-id-sentinel".to_string(),
        ] {
            assert!(!rendered.contains(&leaked), "{rendered}");
        }
        for (debug_rendered, redacted_count) in [
            (
                format!("{session_response:?}"),
                "PrivateResultOramManifest".to_string(),
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
            (
                format!("{read_request:?}"),
                format!("bucket_id_count: {}", bucket_ids.len()),
            ),
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

    async fn create_private_result_collection(dispatcher: &Dispatcher) {
        dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::CreateCollection(
                    CreateCollectionOperation::new(
                        COLLECTION_NAME.to_string(),
                        CreateCollection {
                            vectors: VectorsConfig::Multi(BTreeMap::from([(
                                "text".to_string(),
                                VectorParamsBuilder::new(2, segment::types::Distance::Euclid)
                                    .build(),
                            )])),
                            sparse_vectors: None,
                            hnsw_config: None,
                            wal_config: None,
                            optimizers_config: None,
                            shard_number: Some(1),
                            on_disk_payload: None,
                            replication_factor: None,
                            write_consistency_factor: None,
                            quantization_config: None,
                            sharding_method: None,
                            encryption: Some(CollectionEncryptionConfig {
                                version: 1,
                                key_id: Some(KEY_ID.to_string()),
                                crypto_schema_version: 1,
                                encryption_epoch: RK_EPOCH,
                                migration_state: CryptoMigrationState::Active,
                                rules: vec![EncryptionRuleRef {
                                    id: "body_private_result".to_string(),
                                    selector: EncryptionSelector::PayloadPaths {
                                        paths: vec!["body".to_string()],
                                    },
                                    instance: "payload_result_oram_v1".to_string(),
                                    binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                                }],
                            }),
                            strict_mode_config: None,
                            uuid: Some(Uuid::parse_str(COLLECTION_ID).unwrap()),
                            metadata: None,
                        },
                    )
                    .unwrap(),
                ),
                Auth::new_internal(Access::full("private result ORAM route test")),
                None,
            )
            .await
            .unwrap();
    }

    #[test]
    fn rest_rejects_private_result_missing_collection_encryption_without_reflecting_collection() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_dispatcher();
        let collection_name = "private-result-missing-encryption-secret-collection";
        actix_web::rt::System::new().block_on(async {
            create_plain_collection(&dispatcher, collection_name).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
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
                        body.contains("does not configure private result ORAM encryption"),
                        "{body}"
                    );
                    assert!(!body.contains(collection_name), "{body}");
                    assert!(!body.contains("secret"), "{body}");
                    assert!(!body.contains(&fixture.manifest.root_hash), "{body}");
                    assert!(!body.contains(&fixture.signature.sig), "{body}");
                    assert!(!body.contains(&fixture.buckets[0].ciphertext), "{body}");
                    assert!(!body.contains(SESSION_ID), "{body}");
                    assert!(!body.contains("tenant-a/sdk-instance-1"), "{body}");
                }};
            }

            assert_missing_encryption!(
                actix_test::TestRequest::get()
                    .uri(&format!(
                        "/collections/{collection_name}/private-result-oram/manifest"
                    ))
                    .to_request()
            );

            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-result-oram/manifest"
                    ))
                    .set_json(UploadPrivateResultOramManifestRequest {
                        manifest: fixture.manifest.clone(),
                        signature: fixture.signature.clone(),
                    })
                    .to_request()
            );

            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-result-oram/buckets"
                    ))
                    .set_json(UploadPrivateResultOramBucketsRequest {
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: fixture.buckets.clone(),
                    })
                    .to_request()
            );

            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-result-oram/session"
                    ))
                    .set_json(OpenPrivateResultOramSessionRequest {
                        client_id: "tenant-a/sdk-instance-1".to_string(),
                        desired_epoch: BASE_EPOCH,
                        fixed_budget: true,
                    })
                    .to_request()
            );

            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-result-oram/oram/read_buckets"
                    ))
                    .set_json(ReadPrivateResultOramBucketsRequest {
                        session_id: SESSION_ID.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        bucket_ids: read_bucket_ids.clone(),
                        read_signature: fixture.read_signature(&read_bucket_ids),
                    })
                    .to_request()
            );

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-result-oram/oram/commit"
                    ))
                    .set_json(CommitPrivateResultOramBucketsRequest {
                        session_id: SESSION_ID.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash,
                        updated_buckets: vec![updated_bucket],
                        commit_signature,
                    })
                    .to_request()
            );

            assert_missing_encryption!(
                actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/{collection_name}/private-result-oram/session/{SESSION_ID}/close"
                    ))
                    .to_request()
            );
        });
    }

    #[test]
    fn private_result_oram_rest_dtos_roundtrip() {
        let fixture = PrivateResultRouteFixture::build();
        let manifest_request = UploadPrivateResultOramManifestRequest {
            manifest: fixture.manifest.clone(),
            signature: fixture.signature.clone(),
        };
        assert_eq!(json_roundtrip(&manifest_request), manifest_request);

        let buckets_request = UploadPrivateResultOramBucketsRequest {
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            buckets: fixture.buckets.clone(),
        };
        assert_eq!(json_roundtrip(&buckets_request), buckets_request);

        let session_request = OpenPrivateResultOramSessionRequest {
            client_id: "tenant-a/sdk-instance-1".to_string(),
            desired_epoch: BASE_EPOCH,
            fixed_budget: true,
        };
        assert_eq!(json_roundtrip(&session_request), session_request);

        let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
        let read_request = ReadPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            bucket_ids: read_bucket_ids.clone(),
            read_signature: fixture.read_signature(&read_bucket_ids),
        };
        assert_eq!(json_roundtrip(&read_request), read_request);

        let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
        let commit_request = CommitPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: fixture.manifest.root_hash.clone(),
            new_root_hash,
            updated_buckets: vec![updated_bucket],
            commit_signature,
        };
        assert_eq!(json_roundtrip(&commit_request), commit_request);
    }

    #[test]
    fn private_result_oram_rest_request_dtos_reject_unknown_fields() {
        let fixture = PrivateResultRouteFixture::build();
        let manifest_request = UploadPrivateResultOramManifestRequest {
            manifest: fixture.manifest.clone(),
            signature: fixture.signature.clone(),
        };
        assert_unknown_field_rejected(&manifest_request);

        let buckets_request = UploadPrivateResultOramBucketsRequest {
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            buckets: fixture.buckets.clone(),
        };
        assert_unknown_field_rejected(&buckets_request);
        let mut nested_bucket_extra = serde_json::to_value(&buckets_request).unwrap();
        nested_bucket_extra["buckets"][0]
            .as_object_mut()
            .unwrap()
            .insert("extra".to_string(), json!("payload.fetch.token"));
        let err =
            serde_json::from_value::<UploadPrivateResultOramBucketsRequest>(nested_bucket_extra)
                .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unknown field"), "{rendered}");
        assert!(!rendered.contains("payload.fetch.token"), "{rendered}");
        assert!(
            !rendered.contains(&fixture.buckets[0].ciphertext),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&fixture.buckets[0].ciphertext_sha256),
            "{rendered}"
        );

        let session_request = OpenPrivateResultOramSessionRequest {
            client_id: "tenant-a/sdk-instance-1".to_string(),
            desired_epoch: BASE_EPOCH,
            fixed_budget: true,
        };
        assert_unknown_field_rejected(&session_request);

        let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
        let read_request = ReadPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            bucket_ids: read_bucket_ids.clone(),
            read_signature: fixture.read_signature(&read_bucket_ids),
        };
        assert_unknown_field_rejected(&read_request);

        let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
        let commit_request = CommitPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: fixture.manifest.root_hash.clone(),
            new_root_hash,
            updated_buckets: vec![updated_bucket],
            commit_signature,
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
        let err = serde_json::from_value::<CommitPrivateResultOramBucketsRequest>(
            nested_commit_bucket_extra,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unknown field"), "{rendered}");
        assert!(
            !rendered.contains("encrypted.client.state.snapshot"),
            "{rendered}"
        );
    }

    /// Leakage scan (PLAN V2-D5): result ORAM buckets sealed from distinctive payload plaintext,
    /// uploaded, rewritten by a signed commit and captured in a collection snapshot must leave no
    /// payload bytes, fetch or point token, or client key bytes under the storage, snapshot or
    /// temp directories.
    #[test]
    fn private_result_oram_payloads_store_no_plaintext_sentinels() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let resource_key = [0x5a_u8; 32];
        let keys = qdrant_sec::PrivateResultOramClientKeys::derive_from_resource_key_with_context(
            &qdrant_sec::SecretKey::from_bytes(resource_key),
            COLLECTION_ID,
            KEY_ID,
            RK_EPOCH,
        )
        .unwrap();
        let config =
            qdrant_sec::private_result_oram_client_config_from_manifest(&fixture.manifest).unwrap();
        let base_context = qdrant_sec::PrivateResultOramBucketAeadBaseContext {
            collection_id: COLLECTION_ID,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
        };
        // Blocks 0-2 are uploaded; block 3 is written by the commit.
        let blocks = (0..4_u8)
            .map(|index| qdrant_sec::PrivateResultOramPayloadBlockPlaintext {
                version: qdrant_sec::PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
                payload_fetch_token: format!("qdrant-sec-result-fetch-token-{index:02}")
                    .into_bytes()
                    .try_into()
                    .unwrap(),
                point_token: format!("qdrant-sec-result-point-token-{index:02}")
                    .into_bytes()
                    .try_into()
                    .unwrap(),
                payload: format!("{{\"body\":\"qdrant-sec-result-leak-payload-{index:02}\"}}")
                    .into_bytes(),
                deleted: false,
                generation: 1,
            })
            .collect::<Vec<_>>();
        let seal = |bucket_id: u64,
                    index_epoch: u64,
                    contents: Vec<Option<qdrant_sec::PrivateResultOramPayloadBlockPlaintext>>| {
            qdrant_sec::seal_private_result_oram_plaintext_bucket(
                &keys,
                base_context,
                index_epoch,
                &qdrant_sec::PrivateResultOramPlaintextBucket {
                    bucket_id,
                    blocks: contents,
                },
                config,
            )
            .unwrap()
        };

        let mut manifest = fixture.manifest.clone();
        let buckets = (0..manifest.bucket_count)
            .map(|bucket_id| {
                let mut contents = vec![None; config.bucket_size];
                if bucket_id < 3 {
                    contents[0] = Some(blocks[bucket_id as usize].clone());
                }
                seal(bucket_id, BASE_EPOCH, contents)
            })
            .collect::<Vec<_>>();
        let mut commitments = buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        manifest.root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let manifest_signature = fixture.sign_manifest(&manifest);

        let updated_bucket = seal(
            0,
            NEXT_EPOCH,
            vec![Some(blocks[3].clone()), Some(blocks[0].clone())],
        );
        commitments[0] = updated_bucket.bucket_commitment.clone();
        let new_root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let commit_signature = sign_private_result_oram_commit(
            &fixture.signing_key,
            PrivateResultOramCommitSignatureContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                signing_key_id: SIGNING_KEY_ID,
            },
            &PrivateResultOramCommitPlan {
                old_epoch: BASE_EPOCH,
                new_epoch: NEXT_EPOCH,
                old_root_hash: manifest.root_hash.clone(),
                new_root_hash: new_root_hash.clone(),
                leaf_commitments: commitments,
                updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                    bucket_id: updated_bucket.bucket_id,
                    ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
                }],
            },
        )
        .unwrap();

        let (temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let auth = Auth::new_internal(Access::full("private result ORAM leakage scan"));
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass);
            do_upload_private_result_oram_manifest(
                toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                manifest.clone(),
                manifest_signature,
            )
            .await
            .unwrap();
            do_upload_private_result_oram_buckets(
                toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                BASE_EPOCH,
                manifest.root_hash.clone(),
                buckets.clone(),
            )
            .await
            .unwrap();
            let session = do_open_private_result_oram_session(
                toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                "tenant-a/leak-scan-sdk".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap();
            let committed = do_commit_private_result_oram_buckets(
                toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                &session.session_id,
                BASE_EPOCH,
                NEXT_EPOCH,
                manifest.root_hash.clone(),
                new_root_hash.clone(),
                vec![updated_bucket.clone()],
                commit_signature,
            )
            .await
            .unwrap();
            assert_eq!(committed.index_epoch, NEXT_EPOCH);
            assert!(
                do_close_private_result_oram_session(
                    toc,
                    &auth,
                    &settings,
                    COLLECTION_NAME,
                    &session.session_id,
                )
                .await
                .unwrap()
            );
            crate::common::collections::do_create_snapshot(toc.clone(), &auth, COLLECTION_NAME)
                .await
                .unwrap();
        });

        let mut files = Vec::new();
        let mut pending = vec![temp.path().to_path_buf()];
        while let Some(path) = pending.pop() {
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.is_dir() {
                for entry in std::fs::read_dir(&path).unwrap() {
                    pending.push(entry.unwrap().path());
                }
            } else if metadata.is_file() {
                files.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
        let contains = |haystack: &[u8], needle: &[u8]| {
            haystack
                .windows(needle.len())
                .any(|window| window == needle)
        };
        let is_snapshot = |path: &std::path::Path| {
            path.extension()
                .is_some_and(|extension| extension == "snapshot")
        };

        // Positive control: the committed ciphertext must be visible in the store and in the
        // snapshot, or an absent sentinel would prove nothing.
        for (label, ciphertext) in [
            ("uploaded", buckets[1].ciphertext.as_bytes()),
            ("committed", updated_bucket.ciphertext.as_bytes()),
        ] {
            assert!(
                files
                    .iter()
                    .any(|(path, bytes)| !is_snapshot(path) && contains(bytes, ciphertext)),
                "{label} bucket ciphertext not found in storage; the scan reads the wrong files",
            );
            assert!(
                files
                    .iter()
                    .any(|(path, bytes)| is_snapshot(path) && contains(bytes, ciphertext)),
                "{label} bucket ciphertext not found in the snapshot archive",
            );
        }

        let mut sentinels: Vec<(String, Vec<u8>)> = vec![
            ("client resource key".to_string(), resource_key.to_vec()),
            (
                "bucket AEAD key".to_string(),
                keys.bucket_aead_key().as_bytes().to_vec(),
            ),
            (
                "payload marker".to_string(),
                b"qdrant-sec-result-leak-payload".to_vec(),
            ),
        ];
        for (index, block) in blocks.iter().enumerate() {
            for (name, bytes) in [
                ("payload", block.payload.clone()),
                ("fetch token", block.payload_fetch_token.to_vec()),
                ("point token", block.point_token.to_vec()),
            ] {
                sentinels.push((
                    format!("{name} {index} (base64url)"),
                    BASE64URL_NOPAD.encode(&bytes).into_bytes(),
                ));
                sentinels.push((format!("{name} {index}"), bytes));
            }
        }
        // One pass per file: every 8-byte window is looked up among the sentinel prefixes and
        // only a prefix hit compares the whole sentinel (preallocated WAL files are large).
        let mut by_prefix: HashMap<[u8; 8], Vec<&(String, Vec<u8>)>> = HashMap::new();
        for sentinel in &sentinels {
            let prefix: [u8; 8] = sentinel.1[..8].try_into().unwrap();
            by_prefix.entry(prefix).or_default().push(sentinel);
        }
        for (path, bytes) in &files {
            for offset in 0..bytes.len().saturating_sub(7) {
                let window: [u8; 8] = bytes[offset..offset + 8].try_into().unwrap();
                if window == [0; 8] {
                    continue;
                }
                let Some(candidates) = by_prefix.get(&window) else {
                    continue;
                };
                for (label, sentinel) in candidates {
                    assert!(
                        !bytes[offset..].starts_with(sentinel),
                        "plaintext sentinel '{label}' leaked into {}",
                        path.display(),
                    );
                }
            }
        }
    }

    #[test]
    fn private_result_oram_common_ops_require_write_access_for_mutations() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let write_auth = Auth::new_internal(Access::full("private result ORAM write setup"));
            let read_auth =
                Auth::new_internal(Access::full_ro("private result ORAM read-only test"));
            let pass = new_unchecked_verification_pass();
            let write_toc = dispatcher.toc(&write_auth, &pass);
            let read_toc = dispatcher.toc(&read_auth, &pass);

            do_upload_private_result_oram_manifest(
                write_toc,
                &write_auth,
                &settings,
                COLLECTION_NAME,
                fixture.manifest.clone(),
                fixture.signature.clone(),
            )
            .await
            .unwrap();
            do_upload_private_result_oram_buckets(
                write_toc,
                &write_auth,
                &settings,
                COLLECTION_NAME,
                fixture.manifest.index_epoch,
                fixture.manifest.root_hash.clone(),
                fixture.buckets.clone(),
            )
            .await
            .unwrap();

            do_get_private_result_oram_manifest(read_toc, &read_auth, &settings, COLLECTION_NAME)
                .await
                .unwrap();

            let read_only_manifest_upload = do_upload_private_result_oram_manifest(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                fixture.manifest.clone(),
                fixture.signature.clone(),
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_manifest_upload);

            let read_only_bucket_upload = do_upload_private_result_oram_buckets(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                fixture.manifest.index_epoch,
                fixture.manifest.root_hash.clone(),
                fixture.buckets.clone(),
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_bucket_upload);

            let read_only_open = do_open_private_result_oram_session(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                "tenant-a/read-only-sdk".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_open);

            let session = do_open_private_result_oram_session(
                write_toc,
                &write_auth,
                &settings,
                COLLECTION_NAME,
                "tenant-a/write-sdk".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap();

            let bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read_response = do_read_private_result_oram_buckets(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                &session.session_id,
                BASE_EPOCH,
                fixture.manifest.root_hash.clone(),
                bucket_ids.clone(),
                fixture.read_signature(&bucket_ids),
            )
            .await
            .unwrap();
            assert_eq!(read_response.buckets.len(), bucket_ids.len());

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let read_only_commit = do_commit_private_result_oram_buckets(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                &session.session_id,
                BASE_EPOCH,
                NEXT_EPOCH,
                fixture.manifest.root_hash.clone(),
                new_root_hash,
                vec![updated_bucket],
                commit_signature,
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_commit);

            let read_only_close = do_close_private_result_oram_session(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                &session.session_id,
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_close);

            assert!(
                do_close_private_result_oram_session(
                    write_toc,
                    &write_auth,
                    &settings,
                    COLLECTION_NAME,
                    &session.session_id,
                )
                .await
                .unwrap()
            );
        });
    }

    #[test]
    fn private_result_oram_uploads_and_reads_through_rest_routes() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
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

            let missing_manifest = get_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(!missing_manifest.contains("private_result_oram"));
            assert_private_result_guard_error_redacts(&missing_manifest, &["/tmp"]);

            let missing_manifest_upload = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(!missing_manifest_upload.contains("private_result_oram"));
            assert_private_result_guard_error_redacts(&missing_manifest_upload, &["/tmp"]);

            let upload_root_before_manifest_sentinel = "AAAA";
            let malformed_root_before_manifest = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: upload_root_before_manifest_sentinel.to_string(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "root_hash must be a base64url sha256 value"
            );
            assert!(!malformed_root_before_manifest.contains(upload_root_before_manifest_sentinel));
            assert!(!malformed_root_before_manifest.contains("private_result_oram"));
            assert!(!malformed_root_before_manifest.contains("manifest"));
            assert_private_result_guard_error_redacts(
                &malformed_root_before_manifest,
                &[upload_root_before_manifest_sentinel, "manifest"],
            );

            let malformed_bucket_hash_before_manifest_sentinel = "result-rest-upload-hash-sentinel";
            let mut malformed_bucket_hash_before_manifest_buckets = fixture.buckets.clone();
            malformed_bucket_hash_before_manifest_buckets[0].ciphertext_sha256 =
                malformed_bucket_hash_before_manifest_sentinel.to_string();
            let malformed_bucket_hash_before_manifest = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: malformed_bucket_hash_before_manifest_buckets,
                },
                StatusCode::BAD_REQUEST,
                "ciphertext_sha256"
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .contains(malformed_bucket_hash_before_manifest_sentinel)
            );
            assert!(!malformed_bucket_hash_before_manifest.contains(&fixture.manifest.root_hash));
            assert!(
                !malformed_bucket_hash_before_manifest.contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(!malformed_bucket_hash_before_manifest.contains("private_result_oram"));
            assert!(!malformed_bucket_hash_before_manifest.contains("manifest"));
            for forbidden in [
                malformed_bucket_hash_before_manifest_sentinel,
                fixture.manifest.root_hash.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
                "manifest",
                "private_result_oram",
            ] {
                assert!(
                    !malformed_bucket_hash_before_manifest.contains(forbidden),
                    "private result ORAM malformed bucket hash error leaked `{forbidden}`: {malformed_bucket_hash_before_manifest}",
                );
            }

            let malformed_bucket_commitment_before_manifest_sentinel =
                "result-rest-upload-commitment-sentinel";
            let mut malformed_bucket_commitment_before_manifest_buckets = fixture.buckets.clone();
            malformed_bucket_commitment_before_manifest_buckets[0].bucket_commitment =
                malformed_bucket_commitment_before_manifest_sentinel.to_string();
            let malformed_bucket_commitment_before_manifest = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: malformed_bucket_commitment_before_manifest_buckets,
                },
                StatusCode::BAD_REQUEST,
                "bucket_commitment"
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .contains(malformed_bucket_commitment_before_manifest_sentinel)
            );
            assert!(
                !malformed_bucket_commitment_before_manifest.contains(&fixture.manifest.root_hash)
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(!malformed_bucket_commitment_before_manifest.contains("private_result_oram"));
            assert!(!malformed_bucket_commitment_before_manifest.contains("manifest"));
            for forbidden in [
                malformed_bucket_commitment_before_manifest_sentinel,
                fixture.manifest.root_hash.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
                "manifest",
                "private_result_oram",
            ] {
                assert!(
                    !malformed_bucket_commitment_before_manifest.contains(forbidden),
                    "private result ORAM malformed bucket commitment error leaked `{forbidden}`: {malformed_bucket_commitment_before_manifest}",
                );
            }

            let empty_upload_before_manifest = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: Vec::new(),
                },
                StatusCode::BAD_REQUEST,
                "bucket upload must contain"
            );
            assert!(!empty_upload_before_manifest.contains(&fixture.manifest.root_hash));
            assert!(!empty_upload_before_manifest.contains(&fixture.buckets[0].ciphertext));
            assert!(!empty_upload_before_manifest.contains(&fixture.buckets[0].ciphertext_sha256));
            assert!(!empty_upload_before_manifest.contains(&fixture.buckets[0].bucket_commitment));
            assert!(!empty_upload_before_manifest.contains("private_result_oram"));
            assert!(!empty_upload_before_manifest.contains("manifest"));
            assert_private_result_guard_error_redacts(
                &empty_upload_before_manifest,
                &[
                    fixture.manifest.root_hash.as_str(),
                    fixture.buckets[0].ciphertext.as_str(),
                    fixture.buckets[0].ciphertext_sha256.as_str(),
                    fixture.buckets[0].bucket_commitment.as_str(),
                    "manifest",
                ],
            );

            let mut duplicate_upload_before_manifest_buckets = fixture.buckets.clone();
            assert!(
                duplicate_upload_before_manifest_buckets.len() >= 2,
                "route fixture must contain at least two ORAM buckets"
            );
            duplicate_upload_before_manifest_buckets[1] =
                duplicate_upload_before_manifest_buckets[0].clone();
            let duplicate_upload_before_manifest = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: duplicate_upload_before_manifest_buckets,
                },
                StatusCode::BAD_REQUEST,
                "duplicate bucket"
            );
            assert!(!duplicate_upload_before_manifest.contains(&fixture.manifest.root_hash));
            assert!(!duplicate_upload_before_manifest.contains(&fixture.buckets[0].ciphertext));
            assert!(
                !duplicate_upload_before_manifest.contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !duplicate_upload_before_manifest.contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(!duplicate_upload_before_manifest.contains("private_result_oram"));
            assert!(!duplicate_upload_before_manifest.contains("manifest"));
            assert_private_result_guard_error_redacts(
                &duplicate_upload_before_manifest,
                &[
                    fixture.manifest.root_hash.as_str(),
                    fixture.buckets[0].ciphertext.as_str(),
                    fixture.buckets[0].ciphertext_sha256.as_str(),
                    fixture.buckets[0].bucket_commitment.as_str(),
                    "manifest",
                ],
            );

            let unsupported_manifest_alg_sentinel = "rsa-pss-result-manifest-sentinel";
            let mut unsupported_alg_manifest_signature = fixture.signature.clone();
            unsupported_alg_manifest_signature.alg = unsupported_manifest_alg_sentinel.to_string();
            let unsupported_alg_manifest_key_id = unsupported_alg_manifest_signature.key_id.clone();
            let unsupported_alg_manifest_sig = unsupported_alg_manifest_signature.sig.clone();
            let unsupported_manifest_alg_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: unsupported_alg_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !unsupported_manifest_alg_error.contains(unsupported_manifest_alg_sentinel),
                "{unsupported_manifest_alg_error}"
            );
            assert!(
                !unsupported_manifest_alg_error.contains(&unsupported_alg_manifest_key_id),
                "{unsupported_manifest_alg_error}"
            );
            assert!(
                !unsupported_manifest_alg_error.contains(&unsupported_alg_manifest_sig),
                "{unsupported_manifest_alg_error}"
            );
            assert!(
                !unsupported_manifest_alg_error.contains(&fixture.manifest.root_hash),
                "{unsupported_manifest_alg_error}"
            );

            let manifest_signature_sentinel = "result-manifest-signature!sentinel";
            let malformed_manifest_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: qdrant_sec::PrivateResultOramSignature {
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

            let mut bad_manifest_signature = fixture.signature.clone();
            let replacement = if bad_manifest_signature.sig.starts_with('A') {
                "B"
            } else {
                "A"
            };
            bad_manifest_signature.sig.replace_range(0..1, replacement);
            let bad_manifest_signature_sig = bad_manifest_signature.sig.clone();
            let bad_manifest_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: bad_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "manifest signature verification failed"
            );
            assert!(
                !bad_manifest_signature_error.contains(&bad_manifest_signature_sig),
                "{bad_manifest_signature_error}"
            );
            assert!(
                !bad_manifest_signature_error.contains(&fixture.manifest.root_hash),
                "{bad_manifest_signature_error}"
            );

            let mut alt_manifest_signature = fixture.signature.clone();
            alt_manifest_signature.key_id = ALT_SIGNING_KEY_ID.to_string();
            let alt_manifest_signature_sig = alt_manifest_signature.sig.clone();
            let alt_manifest_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: alt_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!alt_manifest_key_error.contains(ALT_SIGNING_KEY_ID));
            assert!(!alt_manifest_key_error.contains(&fixture.manifest.owner_signing_key_id));
            for sentinel in [
                fixture.manifest.root_hash.as_str(),
                alt_manifest_signature_sig.as_str(),
            ] {
                assert!(
                    !alt_manifest_key_error.contains(sentinel),
                    "{alt_manifest_key_error}"
                );
            }

            let mut unconfigured_manifest_signature = fixture.signature.clone();
            unconfigured_manifest_signature.key_id = UNCONFIGURED_SIGNING_KEY_ID.to_string();
            let unconfigured_manifest_signature_sig = unconfigured_manifest_signature.sig.clone();
            let unconfigured_manifest_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: unconfigured_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!unconfigured_manifest_key_error.contains(UNCONFIGURED_SIGNING_KEY_ID));
            assert!(!unconfigured_manifest_key_error.contains("not configured"));
            assert!(
                !unconfigured_manifest_key_error.contains(&fixture.manifest.owner_signing_key_id)
            );
            for sentinel in [
                fixture.manifest.root_hash.as_str(),
                unconfigured_manifest_signature_sig.as_str(),
            ] {
                assert!(
                    !unconfigured_manifest_key_error.contains(sentinel),
                    "{unconfigured_manifest_key_error}"
                );
            }

            macro_rules! assert_manifest_mismatch_error_redacts {
                ($body:expr, $signature_sig:expr) => {{
                    assert!(!$body.contains(&fixture.manifest.root_hash), "{}", $body);
                    assert!(!$body.contains($signature_sig), "{}", $body);
                    assert!(!$body.contains("private_result_oram"), "{}", $body);
                    assert_private_result_guard_error_redacts(
                        &$body,
                        &[fixture.manifest.root_hash.as_str(), $signature_sig],
                    );
                }};
            }

            let mut mismatched_collection_manifest = fixture.manifest.clone();
            let mismatched_collection_id = "other-result-collection";
            mismatched_collection_manifest.collection_id = mismatched_collection_id.to_string();
            let mismatched_collection_signature =
                fixture.sign_manifest(&mismatched_collection_manifest);
            let mismatched_collection_signature_sig = mismatched_collection_signature.sig.clone();
            let mismatched_collection_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
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

            let mut mismatched_key_manifest = fixture.manifest.clone();
            let mismatched_key_id = "tenant-b/result-private-rk";
            mismatched_key_manifest.key_id = mismatched_key_id.to_string();
            let mismatched_key_signature = fixture.sign_manifest(&mismatched_key_manifest);
            let mismatched_key_signature_sig = mismatched_key_signature.sig.clone();
            let mismatched_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
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
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
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

            let mut mismatched_bucket_count_manifest = fixture.manifest.clone();
            mismatched_bucket_count_manifest.bucket_count -= 1;
            let mismatched_bucket_count_signature_sig = fixture.signature.sig.clone();
            let mismatched_bucket_count_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: mismatched_bucket_count_manifest,
                    signature: fixture.signature.clone(),
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

            let mut mismatched_oram_manifest = fixture.manifest.clone();
            mismatched_oram_manifest.oram.bucket_size = 4;
            let mismatched_oram_signature = fixture.sign_manifest(&mismatched_oram_manifest);
            let mismatched_oram_signature_sig = mismatched_oram_signature.sig.clone();
            let mismatched_oram_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
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

            let manifest_result = post_json_ok!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                }
            );
            assert_eq!(manifest_result["index_epoch"], fixture.manifest.index_epoch);
            assert_eq!(manifest_result["root_hash"], fixture.manifest.root_hash);

            let manifest_read = get_json_ok!("/collections/docs/private-result-oram/manifest");
            assert_eq!(
                manifest_read["manifest"]["root_hash"],
                fixture.manifest.root_hash
            );
            assert_eq!(manifest_read["signature"]["key_id"], SIGNING_KEY_ID);

            let bucket_upload_wrong_root = BASE64URL_NOPAD.encode(&[12; 32]);
            let bucket_upload_wrong_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: bucket_upload_wrong_root.clone(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "bucket upload epoch/root does not match current manifest epoch"
            );
            assert!(!bucket_upload_wrong_root_error.contains(&bucket_upload_wrong_root));
            assert!(!bucket_upload_wrong_root_error.contains(&fixture.buckets[0].ciphertext));
            assert!(
                !bucket_upload_wrong_root_error.contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !bucket_upload_wrong_root_error.contains(&fixture.buckets[0].bucket_commitment)
            );

            let bucket_upload_root_sentinel = "AAAA";
            let malformed_bucket_upload_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: bucket_upload_root_sentinel.to_string(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "root_hash must be a base64url sha256 value"
            );
            assert!(!malformed_bucket_upload_root_error.contains(bucket_upload_root_sentinel));

            let empty_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: Vec::new(),
                },
                StatusCode::BAD_REQUEST,
                "bucket upload must contain"
            );
            assert!(!empty_bucket_upload_error.contains(&fixture.manifest.root_hash));
            assert!(!empty_bucket_upload_error.contains(&fixture.buckets[0].ciphertext));
            assert!(!empty_bucket_upload_error.contains(&fixture.buckets[0].ciphertext_sha256));
            assert!(!empty_bucket_upload_error.contains(&fixture.buckets[0].bucket_commitment));
            assert!(!empty_bucket_upload_error.contains("private_result_oram"));
            assert!(!empty_bucket_upload_error.contains("manifest"));

            let mut hash_mismatch_buckets = fixture.buckets.clone();
            hash_mismatch_buckets[0].ciphertext =
                BASE64URL_NOPAD.encode(b"private-result-upload-ciphertext-sentinel");
            let hash_mismatch_ciphertext = hash_mismatch_buckets[0].ciphertext.clone();
            let bucket_upload_hash_mismatch_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: hash_mismatch_buckets,
                },
                StatusCode::BAD_REQUEST,
                "bucket ciphertext validation failed"
            );
            assert!(
                !bucket_upload_hash_mismatch_error
                    .contains("private-result-upload-ciphertext-sentinel")
            );
            assert!(!bucket_upload_hash_mismatch_error.contains(&hash_mismatch_ciphertext));

            let mut duplicate_bucket_set = fixture.buckets.clone();
            assert!(
                duplicate_bucket_set.len() >= 2,
                "route fixture must contain at least two ORAM buckets"
            );
            duplicate_bucket_set[1] = duplicate_bucket_set[0].clone();
            let duplicate_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: duplicate_bucket_set,
                },
                StatusCode::BAD_REQUEST,
                "duplicate bucket"
            );
            assert!(!duplicate_bucket_upload_error.contains(&fixture.manifest.root_hash));
            assert!(!duplicate_bucket_upload_error.contains(&fixture.buckets[0].ciphertext));
            assert!(!duplicate_bucket_upload_error.contains(&fixture.buckets[0].ciphertext_sha256));
            assert!(!duplicate_bucket_upload_error.contains(&fixture.buckets[0].bucket_commitment));
            assert!(!duplicate_bucket_upload_error.contains("private_result_oram"));

            let buckets_result = post_json_ok!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                }
            );
            assert_eq!(buckets_result["index_epoch"], fixture.manifest.index_epoch);

            let auth = Auth::new_internal(Access::full("private result ORAM route test"));
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new(),
                    "private_result_active_snapshot_upload_guard_test",
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
                crate::common::private_result_oram::begin_private_result_oram_collection_snapshot(
                    collection.name(),
                    &config,
                )
                .unwrap()
                .unwrap();
            let active_snapshot_client_id = "tenant-a/sdk-instance-active-snapshot";
            let active_snapshot_session_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: active_snapshot_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "active collection snapshot"
            );
            assert!(
                !active_snapshot_session_error.contains(&fixture.manifest.root_hash),
                "{active_snapshot_session_error}"
            );
            assert!(
                !active_snapshot_session_error.contains("private_result_oram"),
                "{active_snapshot_session_error}"
            );
            assert!(
                !active_snapshot_session_error.contains(active_snapshot_client_id),
                "{active_snapshot_session_error}"
            );
            assert_private_result_guard_error_redacts(
                &active_snapshot_session_error,
                &[
                    active_snapshot_client_id,
                    &fixture.manifest.root_hash,
                    &fixture.signature.sig,
                ],
            );
            let active_snapshot_manifest_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "active collection snapshot"
            );
            assert!(
                !active_snapshot_manifest_upload_error.contains(&fixture.manifest.root_hash),
                "{active_snapshot_manifest_upload_error}"
            );
            assert!(
                !active_snapshot_manifest_upload_error.contains("private_result_oram"),
                "{active_snapshot_manifest_upload_error}"
            );
            assert_private_result_guard_error_redacts(
                &active_snapshot_manifest_upload_error,
                &[&fixture.manifest.root_hash, &fixture.signature.sig],
            );
            let mut active_snapshot_bucket_upload = fixture.buckets.clone();
            active_snapshot_bucket_upload[0].ciphertext =
                "active-result-snapshot-bucket-ciphertext-sentinel".to_string();
            let active_snapshot_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: active_snapshot_bucket_upload,
                },
                StatusCode::BAD_REQUEST,
                "active collection snapshot"
            );
            assert!(
                !active_snapshot_bucket_upload_error
                    .contains("active-result-snapshot-bucket-ciphertext-sentinel"),
                "{active_snapshot_bucket_upload_error}"
            );
            assert!(
                !active_snapshot_bucket_upload_error.contains(&fixture.manifest.root_hash),
                "{active_snapshot_bucket_upload_error}"
            );
            assert!(
                !active_snapshot_bucket_upload_error.contains("private_result_oram"),
                "{active_snapshot_bucket_upload_error}"
            );
            assert_private_result_guard_error_redacts(
                &active_snapshot_bucket_upload_error,
                &[
                    "active-result-snapshot-bucket-ciphertext-sentinel",
                    &fixture.manifest.root_hash,
                ],
            );
            drop(snapshot_guard);

            let lifecycle_guard =
                crate::common::snapshots::begin_private_oram_collection_lifecycle_guard(
                    &dispatcher,
                    &auth,
                    COLLECTION_NAME,
                )
                .await
                .unwrap();
            let active_lifecycle_client_id = "tenant-a/sdk-instance-active-lifecycle";
            let active_lifecycle_session_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: active_lifecycle_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "active collection lifecycle operation"
            );
            assert!(
                !active_lifecycle_session_error.contains(&fixture.manifest.root_hash),
                "{active_lifecycle_session_error}"
            );
            assert!(
                !active_lifecycle_session_error.contains("private_result_oram"),
                "{active_lifecycle_session_error}"
            );
            assert!(
                !active_lifecycle_session_error.contains(active_lifecycle_client_id),
                "{active_lifecycle_session_error}"
            );
            assert_private_result_guard_error_redacts(
                &active_lifecycle_session_error,
                &[
                    active_lifecycle_client_id,
                    &fixture.manifest.root_hash,
                    &fixture.signature.sig,
                ],
            );
            let active_lifecycle_manifest_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "active collection lifecycle operation"
            );
            assert!(
                !active_lifecycle_manifest_upload_error.contains(&fixture.manifest.root_hash),
                "{active_lifecycle_manifest_upload_error}"
            );
            assert!(
                !active_lifecycle_manifest_upload_error.contains("private_result_oram"),
                "{active_lifecycle_manifest_upload_error}"
            );
            assert_private_result_guard_error_redacts(
                &active_lifecycle_manifest_upload_error,
                &[&fixture.manifest.root_hash, &fixture.signature.sig],
            );
            let mut active_lifecycle_bucket_upload = fixture.buckets.clone();
            active_lifecycle_bucket_upload[0].ciphertext =
                "active-result-lifecycle-bucket-ciphertext-sentinel".to_string();
            let active_lifecycle_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: active_lifecycle_bucket_upload,
                },
                StatusCode::BAD_REQUEST,
                "active collection lifecycle operation"
            );
            assert!(
                !active_lifecycle_bucket_upload_error
                    .contains("active-result-lifecycle-bucket-ciphertext-sentinel"),
                "{active_lifecycle_bucket_upload_error}"
            );
            assert!(
                !active_lifecycle_bucket_upload_error.contains(&fixture.manifest.root_hash),
                "{active_lifecycle_bucket_upload_error}"
            );
            assert!(
                !active_lifecycle_bucket_upload_error.contains("private_result_oram"),
                "{active_lifecycle_bucket_upload_error}"
            );
            assert_private_result_guard_error_redacts(
                &active_lifecycle_bucket_upload_error,
                &[
                    "active-result-lifecycle-bucket-ciphertext-sentinel",
                    &fixture.manifest.root_hash,
                ],
            );
            drop(lifecycle_guard);

            let client_id_sentinel = "result-session-client-id-sentinel";
            let oversized_client_id_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: format!("{client_id_sentinel}{}", "x".repeat(260)),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "client_id must be non-empty and at most 256 bytes"
            );
            assert!(
                !oversized_client_id_error.contains(client_id_sentinel),
                "{oversized_client_id_error}"
            );

            let malformed_client_id_sentinel = "result-session-client-id!sentinel";
            let malformed_client_id_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: malformed_client_id_sentinel.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
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
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: fixed_budget_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: false,
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
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: stale_epoch_client_id.to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
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

            let session_result = post_json_ok!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }
            );
            let session_id = session_result["session_id"].as_str().unwrap().to_string();
            assert_eq!(session_result["collection_id"], COLLECTION_ID);
            assert_eq!(session_result["index_epoch"], BASE_EPOCH);

            let uploaded_store = PrivateResultOramStore::new(collection.path());
            let current_epoch_path = uploaded_store
                .root_path()
                .join("epochs")
                .join("current.json");
            let original_current_epoch_bytes = std::fs::read(&current_epoch_path).unwrap();
            let stale_current_root = BASE64URL_NOPAD.encode(&[88; 32]);
            std::fs::write(
                &current_epoch_path,
                serde_json::to_vec_pretty(&PrivateResultOramEpochState {
                    index_epoch: BASE_EPOCH,
                    root_hash: stale_current_root.clone(),
                })
                .unwrap(),
            )
            .unwrap();

            let stale_current_read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let stale_current_read_signature =
                fixture.read_signature(&stale_current_read_bucket_ids);
            let stale_current_read_session_id = session_id.clone();
            let stale_current_read_root_hash = fixture.manifest.root_hash.clone();
            let stale_current_read_signature_key_id = stale_current_read_signature.key_id.clone();
            let stale_current_read_signature_sig = stale_current_read_signature.sig.clone();
            let stale_current_read_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: stale_current_read_session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: stale_current_read_root_hash.clone(),
                    bucket_ids: stale_current_read_bucket_ids,
                    read_signature: stale_current_read_signature,
                },
                StatusCode::BAD_REQUEST,
                "current epoch/root does not match active session"
            );
            assert!(
                !stale_current_read_error
                    .contains("read_buckets current epoch/root does not match active session"),
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
                !stale_current_read_error.contains(&stale_current_read_signature_key_id),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&stale_current_read_signature_sig),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&fixture.buckets[0].ciphertext),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&fixture.buckets[0].ciphertext_sha256),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains(&fixture.buckets[0].bucket_commitment),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains("private_result_oram"),
                "{stale_current_read_error}"
            );
            assert!(
                !stale_current_read_error.contains("/tmp"),
                "{stale_current_read_error}"
            );

            let (
                stale_current_updated_bucket,
                stale_current_commit_signature,
                stale_current_new_root,
            ) = fixture.commit_bucket();
            let stale_current_commit_session_id = session_id.clone();
            let stale_current_commit_old_root_hash = fixture.manifest.root_hash.clone();
            let stale_current_commit_signature_key_id =
                stale_current_commit_signature.key_id.clone();
            let stale_current_commit_signature_sig = stale_current_commit_signature.sig.clone();
            let stale_current_commit_bucket_ciphertext =
                stale_current_updated_bucket.ciphertext.clone();
            let stale_current_commit_bucket_ciphertext_sha256 =
                stale_current_updated_bucket.ciphertext_sha256.clone();
            let stale_current_commit_bucket_commitment =
                stale_current_updated_bucket.bucket_commitment.clone();
            let stale_current_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: stale_current_commit_session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: stale_current_commit_old_root_hash.clone(),
                    new_root_hash: stale_current_new_root.clone(),
                    updated_buckets: vec![stale_current_updated_bucket],
                    commit_signature: stale_current_commit_signature,
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
                !stale_current_commit_error.contains(&stale_current_new_root),
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
                !stale_current_commit_error.contains(&stale_current_commit_signature_key_id),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains(&stale_current_commit_signature_sig),
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
                !stale_current_commit_error.contains("private_result_oram"),
                "{stale_current_commit_error}"
            );
            assert!(
                !stale_current_commit_error.contains("/tmp"),
                "{stale_current_commit_error}"
            );
            std::fs::write(&current_epoch_path, original_current_epoch_bytes).unwrap();

            let duplicate_session_client_id = "tenant-a/sdk-instance-2";
            let duplicate_session_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: duplicate_session_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "active session"
            );
            assert!(
                !duplicate_session_error.contains(duplicate_session_client_id),
                "{duplicate_session_error}"
            );
            assert_private_result_guard_error_redacts(
                &duplicate_session_error,
                &[duplicate_session_client_id, &session_id],
            );

            let active_manifest_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "upload requires no active session"
            );
            assert!(!active_manifest_upload_error.contains(&fixture.manifest.root_hash));
            assert!(!active_manifest_upload_error.contains(&session_id));
            assert_private_result_guard_error_redacts(
                &active_manifest_upload_error,
                &[
                    &fixture.manifest.root_hash,
                    &fixture.signature.sig,
                    &session_id,
                ],
            );

            let active_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "upload requires no active session"
            );
            assert!(!active_bucket_upload_error.contains(&fixture.buckets[0].ciphertext));
            assert!(!active_bucket_upload_error.contains(&fixture.manifest.root_hash));
            assert!(!active_bucket_upload_error.contains(&session_id));
            assert_private_result_guard_error_redacts(
                &active_bucket_upload_error,
                &[
                    &fixture.buckets[0].ciphertext,
                    &fixture.manifest.root_hash,
                    &session_id,
                ],
            );

            let active_snapshot_error = crate::common::collections::do_create_snapshot(
                dispatcher.toc(&auth, &pass).clone(),
                &auth,
                COLLECTION_NAME,
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                active_snapshot_error.contains("requires no active private ORAM session"),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains(&fixture.manifest.root_hash),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains(&session_id),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains(&fixture.buckets[0].ciphertext),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains("private_result_oram"),
                "{active_snapshot_error}"
            );
            assert_private_result_guard_error_redacts(
                &active_snapshot_error,
                &[
                    &session_id,
                    &fixture.manifest.root_hash,
                    &fixture.buckets[0].ciphertext,
                    &fixture.signature.sig,
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
                !active_full_snapshot_error.contains(&fixture.manifest.root_hash),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains(&session_id),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains(&fixture.buckets[0].ciphertext),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains("private_result_oram"),
                "{active_full_snapshot_error}"
            );
            assert_private_result_guard_error_redacts(
                &active_full_snapshot_error,
                &[
                    &session_id,
                    &fixture.manifest.root_hash,
                    &fixture.buckets[0].ciphertext,
                    &fixture.signature.sig,
                ],
            );

            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read_result = post_json_ok!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&read_bucket_ids),
                }
            );
            assert_eq!(
                read_result["proof"]["kind"],
                PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND
            );
            assert_eq!(read_result["buckets"].as_array().unwrap().len(), 6);
            assert_eq!(read_result["buckets"][0]["bucket_id"], 0);
            let read_response: PrivateResultOramReadBucketsResponse =
                serde_json::from_value(read_result).unwrap();

            let proof_mismatched_bucket_id = read_response.buckets[0].bucket_id;
            let bucket_path = uploaded_store
                .root_path()
                .join("buckets")
                .join(format!("{proof_mismatched_bucket_id:08}.bucket"));
            let original_bucket_bytes = std::fs::read(&bucket_path).unwrap();
            let mut proof_mismatched_bucket = read_response.buckets[0].clone();
            proof_mismatched_bucket.bucket_commitment =
                data_encoding::BASE64URL_NOPAD.encode(&[91; 32]);
            std::fs::write(
                &bucket_path,
                serde_json::to_vec_pretty(&proof_mismatched_bucket).unwrap(),
            )
            .unwrap();
            let proof_mismatch_signature = fixture.read_signature(&read_bucket_ids);
            let proof_mismatch_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: proof_mismatch_signature,
                },
                StatusCode::BAD_REQUEST,
                "encrypted bucket store validation failed"
            );
            assert!(
                !proof_mismatch_error.contains(&proof_mismatched_bucket.ciphertext),
                "{proof_mismatch_error}"
            );
            assert!(!proof_mismatch_error.contains(&fixture.manifest.root_hash));
            assert!(!proof_mismatch_error.contains(&session_id));
            assert!(!proof_mismatch_error.contains("private_result_oram"));
            assert!(!proof_mismatch_error.contains("/tmp"));
            assert_private_result_guard_error_redacts(
                &proof_mismatch_error,
                &[
                    proof_mismatched_bucket.ciphertext.as_str(),
                    fixture.manifest.root_hash.as_str(),
                    session_id.as_str(),
                    "/tmp",
                ],
            );
            std::fs::write(&bucket_path, &original_bucket_bytes).unwrap();

            let (future_bucket, _, _) = fixture.commit_bucket();
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
            let future_bucket_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&read_bucket_ids),
                },
                StatusCode::BAD_REQUEST,
                "encrypted bucket store validation failed"
            );
            assert!(!future_bucket_error.contains(&future_bucket.ciphertext));
            assert!(!future_bucket_error.contains(&future_bucket.ciphertext_sha256));
            assert!(!future_bucket_error.contains(&future_bucket.bucket_commitment));
            assert!(!future_bucket_error.contains("index_epoch"));
            assert!(!future_bucket_error.contains(&fixture.manifest.root_hash));
            assert!(!future_bucket_error.contains(&session_id));
            assert!(!future_bucket_error.contains("private_result_oram"));
            assert_private_result_guard_error_redacts(
                &future_bucket_error,
                &[
                    future_bucket.ciphertext.as_str(),
                    future_bucket.ciphertext_sha256.as_str(),
                    future_bucket.bucket_commitment.as_str(),
                    "index_epoch",
                    fixture.manifest.root_hash.as_str(),
                    session_id.as_str(),
                    "/tmp",
                ],
            );
            std::fs::write(&future_bucket_path, &original_future_bucket_bytes).unwrap();

            let read_wrong_root = BASE64URL_NOPAD.encode(&[9; 32]);
            let read_wrong_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: read_wrong_root.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&read_bucket_ids),
                },
                StatusCode::BAD_REQUEST,
                "session epoch/root mismatch"
            );
            assert!(!read_wrong_root_error.contains(&read_wrong_root));
            assert!(!read_wrong_root_error.contains(&fixture.buckets[0].ciphertext));

            let read_root_sentinel = "AAAA";
            let malformed_read_root_signature = fixture.read_signature(&read_bucket_ids);
            let malformed_read_root_signature_key_id = malformed_read_root_signature.key_id.clone();
            let malformed_read_root_signature_sig = malformed_read_root_signature.sig.clone();
            let malformed_read_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: read_root_sentinel.to_string(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: malformed_read_root_signature,
                },
                StatusCode::BAD_REQUEST,
                "root_hash must be a base64url sha256 value"
            );
            assert!(!malformed_read_root_error.contains(read_root_sentinel));
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                malformed_read_root_signature_key_id.as_str(),
                malformed_read_root_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
            ] {
                assert!(
                    !malformed_read_root_error.contains(sentinel),
                    "{malformed_read_root_error}"
                );
            }

            let wrong_read_signature = fixture.read_signature(&[0, 1, 4, 0, 1, 3]);
            let invalid_read_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: wrong_read_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "read_buckets signature verification failed"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                wrong_read_signature.key_id.as_str(),
                wrong_read_signature.sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
            ] {
                assert!(
                    !invalid_read_signature_error.contains(sentinel),
                    "{invalid_read_signature_error}"
                );
            }

            let invalid_signature_bad_path_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: vec![0, 2, 3, 0, 1, 4],
                    read_signature: wrong_read_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "read_buckets signature verification failed"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                wrong_read_signature.key_id.as_str(),
                wrong_read_signature.sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !invalid_signature_bad_path_error.contains(sentinel),
                    "{invalid_signature_bad_path_error}"
                );
            }
            assert!(!invalid_signature_bad_path_error.contains("valid ORAM paths"));

            let out_of_range_bucket_id_sentinel = fixture.manifest.bucket_count + 123_456;
            let invalid_signature_out_of_range_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: vec![0, 1, out_of_range_bucket_id_sentinel, 0, 1, 4],
                    read_signature: wrong_read_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "read_buckets signature verification failed"
            );
            assert!(
                !invalid_signature_out_of_range_error
                    .contains(&out_of_range_bucket_id_sentinel.to_string())
            );
            assert!(
                !invalid_signature_out_of_range_error.contains(&wrong_read_signature.key_id)
            );
            assert!(!invalid_signature_out_of_range_error.contains(&wrong_read_signature.sig));
            assert!(!invalid_signature_out_of_range_error.contains(&fixture.buckets[0].ciphertext));
            assert!(
                !invalid_signature_out_of_range_error
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !invalid_signature_out_of_range_error
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(!invalid_signature_out_of_range_error.contains(&fixture.manifest.root_hash));
            assert!(!invalid_signature_out_of_range_error.contains(&session_id));
            assert!(!invalid_signature_out_of_range_error.contains("bucket id is out of range"));

            let unconfigured_read_key_id_sentinel = "tenant-a/private-result-signing-v1-unknown";
            let mut unconfigured_read_key_signature = fixture.read_signature(&read_bucket_ids);
            unconfigured_read_key_signature.key_id = unconfigured_read_key_id_sentinel.to_string();
            let unconfigured_read_key_signature_sig = unconfigured_read_key_signature.sig.clone();
            let unconfigured_read_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: unconfigured_read_key_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!unconfigured_read_key_error.contains("not configured"));
            assert!(
                !unconfigured_read_key_error.contains(unconfigured_read_key_id_sentinel),
                "{unconfigured_read_key_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                unconfigured_read_key_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !unconfigured_read_key_error.contains(sentinel),
                    "{unconfigured_read_key_error}"
                );
            }

            let malformed_read_key_id_sentinel = "result-read-signature-key!sentinel";
            let mut malformed_read_key_signature = fixture.read_signature(&read_bucket_ids);
            malformed_read_key_signature.key_id = malformed_read_key_id_sentinel.to_string();
            let malformed_read_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: malformed_read_key_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !malformed_read_key_error.contains(malformed_read_key_id_sentinel),
                "{malformed_read_key_error}"
            );
            assert!(!malformed_read_key_error.contains("owner_signing_key_id"));
            let expected_read_signature = fixture.read_signature(&read_bucket_ids);
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                expected_read_signature.sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !malformed_read_key_error.contains(sentinel),
                    "{malformed_read_key_error}"
                );
            }

            let alt_read_signature = fixture.read_signature_with_alt_key(&read_bucket_ids);
            let alt_read_signature_sig = alt_read_signature.sig.clone();
            let alt_read_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: alt_read_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!alt_read_key_error.contains(ALT_SIGNING_KEY_ID));
            assert!(!alt_read_key_error.contains(&fixture.manifest.owner_signing_key_id));
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                alt_read_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !alt_read_key_error.contains(sentinel),
                    "{alt_read_key_error}"
                );
            }

            let signature_body_sentinel = "signature!sentinel";
            let malformed_read_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: qdrant_sec::PrivateResultOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: signature_body_sentinel.to_string(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !malformed_read_signature_error.contains(signature_body_sentinel),
                "{malformed_read_signature_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                SIGNING_KEY_ID,
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !malformed_read_signature_error.contains(sentinel),
                    "{malformed_read_signature_error}"
                );
            }

            let read_signature_alg_sentinel = "rsa-pss-result-read-sentinel";
            let mut unsupported_read_signature = fixture.read_signature(&read_bucket_ids);
            unsupported_read_signature.alg = read_signature_alg_sentinel.to_string();
            let unsupported_read_key_id = unsupported_read_signature.key_id.clone();
            let unsupported_read_sig = unsupported_read_signature.sig.clone();
            let unsupported_read_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: unsupported_read_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !unsupported_read_signature_error.contains(read_signature_alg_sentinel),
                "{unsupported_read_signature_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                unsupported_read_key_id.as_str(),
                unsupported_read_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !unsupported_read_signature_error.contains(sentinel),
                    "{unsupported_read_signature_error}"
                );
            }

            let deduped_bucket_ids = vec![0, 1, 3, 4];
            let deduped_path_signature = fixture.read_signature(&read_bucket_ids);
            let deduped_path_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: deduped_bucket_ids.clone(),
                    read_signature: deduped_path_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "whole ORAM paths"
            );
            assert!(!deduped_path_error.contains(&fixture.buckets[0].ciphertext));
            assert!(!deduped_path_error.contains(&fixture.buckets[0].ciphertext_sha256));
            assert!(!deduped_path_error.contains(&fixture.buckets[0].bucket_commitment));
            assert!(!deduped_path_error.contains(&fixture.manifest.root_hash));
            assert!(!deduped_path_error.contains(&session_id));
            assert!(!deduped_path_error.contains(&deduped_path_signature.key_id));
            assert!(!deduped_path_error.contains(&deduped_path_signature.sig));

            let under_budget_bucket_ids = vec![0, 1, 3];
            let under_budget_signature = fixture.read_signature(&read_bucket_ids);
            let under_budget_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: under_budget_bucket_ids.clone(),
                    read_signature: under_budget_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "fixed path budget"
            );
            assert!(!under_budget_error.contains(&fixture.buckets[0].ciphertext));
            assert!(!under_budget_error.contains(&fixture.buckets[0].ciphertext_sha256));
            assert!(!under_budget_error.contains(&fixture.buckets[0].bucket_commitment));
            assert!(!under_budget_error.contains(&fixture.manifest.root_hash));
            assert!(!under_budget_error.contains(&session_id));
            assert!(!under_budget_error.contains(&under_budget_signature.key_id));
            assert!(!under_budget_error.contains(&under_budget_signature.sig));

            let duplicate_path_bucket_ids = vec![0, 1, 3, 0, 1, 3];
            let duplicate_path_signature = fixture.read_signature(&read_bucket_ids);
            let duplicate_path_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: duplicate_path_bucket_ids.clone(),
                    read_signature: duplicate_path_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "duplicate ORAM path"
            );
            assert!(!duplicate_path_error.contains(&fixture.buckets[0].ciphertext));
            assert!(!duplicate_path_error.contains(&fixture.buckets[0].ciphertext_sha256));
            assert!(!duplicate_path_error.contains(&fixture.buckets[0].bucket_commitment));
            assert!(!duplicate_path_error.contains(&fixture.manifest.root_hash));
            assert!(!duplicate_path_error.contains(&session_id));
            assert!(!duplicate_path_error.contains(&duplicate_path_signature.key_id));
            assert!(!duplicate_path_error.contains(&duplicate_path_signature.sig));
            assert!(!duplicate_path_error.contains("read_buckets signature verification failed"));

            let malformed_path_bucket_ids = vec![0, 2, 3, 0, 1, 4];
            let malformed_path_signature = fixture.read_signature(&read_bucket_ids);
            let malformed_path_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: malformed_path_bucket_ids,
                    read_signature: malformed_path_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "read_buckets signature verification failed"
            );
            assert!(!malformed_path_error.contains(&fixture.manifest.root_hash));
            assert!(!malformed_path_error.contains(&session_id));
            assert!(!malformed_path_error.contains(&malformed_path_signature.sig));
            assert!(!malformed_path_error.contains(&fixture.buckets[0].ciphertext));
            assert!(!malformed_path_error.contains(&fixture.buckets[0].ciphertext_sha256));
            assert!(!malformed_path_error.contains(&fixture.buckets[0].bucket_commitment));
            assert!(!malformed_path_error.contains("valid ORAM paths"));

            let unknown_read_session_sentinel = "read-session-id-sentinel";
            let unknown_read_session_signature = fixture.read_signature(&read_bucket_ids);
            let unknown_read_session_signature_sig = unknown_read_session_signature.sig.clone();
            let unknown_read_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: unknown_read_session_sentinel.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: unknown_read_session_signature,
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            assert!(
                !unknown_read_error.contains(unknown_read_session_sentinel),
                "{unknown_read_error}"
            );
            for sentinel in [
                fixture.manifest.root_hash.as_str(),
                unknown_read_session_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !unknown_read_error.contains(sentinel),
                    "{unknown_read_error}"
                );
            }

            let oversized_read_session_id = "s".repeat(129);
            let malformed_read_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_read_session_id.as_str(),
                malformed_read_session_id,
            ] {
                let invalid_read_signature = fixture.read_signature(&read_bucket_ids);
                let invalid_read_signature_sig = invalid_read_signature.sig.clone();
                let error = post_json_error_contains!(
                    "/collections/docs/private-result-oram/oram/read_buckets",
                    ReadPrivateResultOramBucketsRequest {
                        session_id: invalid_session_id.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        bucket_ids: read_bucket_ids.clone(),
                        read_signature: invalid_read_signature,
                    },
                    StatusCode::BAD_REQUEST,
                    "session_id is invalid"
                );
                assert!(!error.contains(invalid_session_id), "{error}");
                assert!(!error.contains("session is missing or expired"), "{error}");
                for sentinel in [
                    fixture.manifest.root_hash.as_str(),
                    invalid_read_signature_sig.as_str(),
                ] {
                    assert!(!error.contains(sentinel), "{error}");
                }
            }

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let unknown_commit_session_sentinel = "commit-session-id-sentinel";
            let unknown_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: unknown_commit_session_sentinel.to_string(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            assert!(
                !unknown_commit_error.contains(unknown_commit_session_sentinel),
                "{unknown_commit_error}"
            );
            for sentinel in [
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                commit_signature.sig.as_str(),
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !unknown_commit_error.contains(sentinel),
                    "{unknown_commit_error}"
                );
            }

            let oversized_commit_session_id = "s".repeat(129);
            let malformed_commit_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_commit_session_id.as_str(),
                malformed_commit_session_id,
            ] {
                let error = post_json_error_contains!(
                    "/collections/docs/private-result-oram/oram/commit",
                    CommitPrivateResultOramBucketsRequest {
                        session_id: invalid_session_id.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: vec![updated_bucket.clone()],
                        commit_signature: commit_signature.clone(),
                    },
                    StatusCode::BAD_REQUEST,
                    "session_id is invalid"
                );
                assert!(!error.contains(invalid_session_id), "{error}");
                assert!(!error.contains("session is missing or expired"), "{error}");
                for sentinel in [
                    fixture.manifest.root_hash.as_str(),
                    new_root_hash.as_str(),
                    commit_signature.sig.as_str(),
                    updated_bucket.ciphertext.as_str(),
                    updated_bucket.ciphertext_sha256.as_str(),
                    updated_bucket.bucket_commitment.as_str(),
                ] {
                    assert!(!error.contains(sentinel), "{error}");
                }
            }

            let commit_wrong_old_root = BASE64URL_NOPAD.encode(&[10; 32]);
            let commit_wrong_old_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_wrong_old_root.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit old epoch/root does not match active session"
            );
            assert!(!commit_wrong_old_root_error.contains(&commit_wrong_old_root));
            assert!(!commit_wrong_old_root_error.contains(&updated_bucket.ciphertext));
            assert!(!commit_wrong_old_root_error.contains(&updated_bucket.ciphertext_sha256));
            assert!(!commit_wrong_old_root_error.contains(&updated_bucket.bucket_commitment));
            assert!(!commit_wrong_old_root_error.contains(&new_root_hash));
            assert!(!commit_wrong_old_root_error.contains(&session_id));
            assert!(!commit_wrong_old_root_error.contains(&commit_signature.key_id));
            assert!(!commit_wrong_old_root_error.contains(&commit_signature.sig));

            let commit_old_root_sentinel = "AAAA";
            let malformed_commit_old_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_old_root_sentinel.to_string(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "old_root_hash must be a base64url sha256 value"
            );
            assert!(!malformed_commit_old_root_error.contains(commit_old_root_sentinel));
            assert!(!malformed_commit_old_root_error.contains(&new_root_hash));
            assert!(!malformed_commit_old_root_error.contains(&session_id));
            assert!(!malformed_commit_old_root_error.contains(&commit_signature.key_id));
            assert!(!malformed_commit_old_root_error.contains(&commit_signature.sig));
            assert!(!malformed_commit_old_root_error.contains(&updated_bucket.ciphertext));
            assert!(!malformed_commit_old_root_error.contains(&updated_bucket.ciphertext_sha256));
            assert!(!malformed_commit_old_root_error.contains(&updated_bucket.bucket_commitment));

            let commit_wrong_new_root = BASE64URL_NOPAD.encode(&[11; 32]);
            let commit_wrong_new_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: commit_wrong_new_root.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit signature verification failed"
            );
            assert!(!commit_wrong_new_root_error.contains(&commit_wrong_new_root));
            assert!(!commit_wrong_new_root_error.contains(&commit_signature.sig));
            assert!(!commit_wrong_new_root_error.contains(&fixture.manifest.root_hash));
            assert!(!commit_wrong_new_root_error.contains(&session_id));
            assert!(!commit_wrong_new_root_error.contains(&commit_signature.key_id));
            assert!(!commit_wrong_new_root_error.contains(&updated_bucket.ciphertext));
            assert!(!commit_wrong_new_root_error.contains(&updated_bucket.ciphertext_sha256));
            assert!(!commit_wrong_new_root_error.contains(&updated_bucket.bucket_commitment));

            let commit_new_root_sentinel = "AAAA";
            let malformed_commit_new_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: commit_new_root_sentinel.to_string(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "new_root_hash must be a base64url sha256 value"
            );
            assert!(!malformed_commit_new_root_error.contains(commit_new_root_sentinel));
            assert!(!malformed_commit_new_root_error.contains(&fixture.manifest.root_hash));
            assert!(!malformed_commit_new_root_error.contains(&session_id));
            assert!(!malformed_commit_new_root_error.contains(&commit_signature.key_id));
            assert!(!malformed_commit_new_root_error.contains(&commit_signature.sig));
            assert!(!malformed_commit_new_root_error.contains(&updated_bucket.ciphertext));
            assert!(!malformed_commit_new_root_error.contains(&updated_bucket.ciphertext_sha256));
            assert!(!malformed_commit_new_root_error.contains(&updated_bucket.bucket_commitment));

            let empty_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit updated_buckets must contain"
            );
            assert!(!empty_commit_error.contains(&commit_signature.sig));
            assert!(!empty_commit_error.contains(&fixture.manifest.root_hash));
            assert!(!empty_commit_error.contains(&new_root_hash));
            assert!(!empty_commit_error.contains(&session_id));
            assert!(!empty_commit_error.contains(&commit_signature.key_id));

            let commit_hash_sentinel = "AAAA";
            let mut malformed_hash_commit_buckets = vec![updated_bucket.clone()];
            malformed_hash_commit_buckets[0].ciphertext_sha256 = commit_hash_sentinel.to_string();
            let malformed_hash_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: malformed_hash_commit_buckets,
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "ciphertext_sha256"
            );
            assert!(!malformed_hash_commit_error.contains(commit_hash_sentinel));
            assert!(!malformed_hash_commit_error.contains(&fixture.manifest.root_hash));
            assert!(!malformed_hash_commit_error.contains(&new_root_hash));
            assert!(!malformed_hash_commit_error.contains(&updated_bucket.ciphertext));
            assert!(!malformed_hash_commit_error.contains(&updated_bucket.bucket_commitment));
            assert!(!malformed_hash_commit_error.contains(&session_id));
            assert!(!malformed_hash_commit_error.contains(&commit_signature.key_id));
            assert!(!malformed_hash_commit_error.contains(&commit_signature.sig));
            assert!(
                !malformed_hash_commit_error.contains("commit signature verification failed"),
                "{malformed_hash_commit_error}"
            );

            let commit_commitment_sentinel = "AAAA";
            let mut malformed_commitment_commit_buckets = vec![updated_bucket.clone()];
            malformed_commitment_commit_buckets[0].bucket_commitment =
                commit_commitment_sentinel.to_string();
            let malformed_commitment_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: malformed_commitment_commit_buckets,
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "bucket_commitment"
            );
            assert!(!malformed_commitment_commit_error.contains(commit_commitment_sentinel));
            assert!(!malformed_commitment_commit_error.contains(&fixture.manifest.root_hash));
            assert!(!malformed_commitment_commit_error.contains(&new_root_hash));
            assert!(!malformed_commitment_commit_error.contains(&updated_bucket.ciphertext));
            assert!(!malformed_commitment_commit_error.contains(&updated_bucket.ciphertext_sha256));
            assert!(!malformed_commitment_commit_error.contains(&updated_bucket.bucket_commitment));
            assert!(!malformed_commitment_commit_error.contains(&session_id));
            assert!(!malformed_commitment_commit_error.contains(&commit_signature.key_id));
            assert!(!malformed_commitment_commit_error.contains(&commit_signature.sig));
            assert!(
                !malformed_commitment_commit_error.contains("commit signature verification failed"),
                "{malformed_commitment_commit_error}"
            );

            let oversized_commit_buckets = (0_u64..8)
                .map(|bucket_id| {
                    let mut bucket = updated_bucket.clone();
                    bucket.bucket_id = bucket_id;
                    bucket
                })
                .collect();
            let oversized_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: oversized_commit_buckets,
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit updated_buckets must contain"
            );
            assert!(!oversized_commit_error.contains(&updated_bucket.ciphertext));
            assert!(!oversized_commit_error.contains(&updated_bucket.ciphertext_sha256));
            assert!(!oversized_commit_error.contains(&updated_bucket.bucket_commitment));
            assert!(!oversized_commit_error.contains("1..=3"));
            assert!(!oversized_commit_error.contains("duplicate bucket id"));
            assert!(!oversized_commit_error.contains(&fixture.manifest.root_hash));
            assert!(!oversized_commit_error.contains(&new_root_hash));
            assert!(!oversized_commit_error.contains(&session_id));
            assert!(!oversized_commit_error.contains(&commit_signature.key_id));
            assert!(!oversized_commit_error.contains(&commit_signature.sig));

            let wrong_commit_signature = fixture.signature.clone();
            let invalid_commit_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: wrong_commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit signature verification failed"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                wrong_commit_signature.key_id.as_str(),
                wrong_commit_signature.sig.as_str(),
                updated_bucket.ciphertext.as_str(),
            ] {
                assert!(
                    !invalid_commit_signature_error.contains(sentinel),
                    "{invalid_commit_signature_error}"
                );
            }

            let duplicate_commit_buckets = vec![updated_bucket.clone(), updated_bucket.clone()];
            let duplicate_commit_plan = PrivateResultOramCommitPlan {
                old_epoch: BASE_EPOCH,
                new_epoch: NEXT_EPOCH,
                old_root_hash: fixture.manifest.root_hash.clone(),
                new_root_hash: new_root_hash.clone(),
                leaf_commitments: fixture
                    .buckets
                    .iter()
                    .map(|bucket| bucket.bucket_commitment.clone())
                    .collect(),
                updated_buckets: duplicate_commit_buckets
                    .iter()
                    .map(|bucket| PrivateResultOramClientCommitBucketRef {
                        bucket_id: bucket.bucket_id,
                        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                    })
                    .collect(),
            };
            let duplicate_commit_signature = commit_signature.clone();
            let duplicate_commit_old_root = duplicate_commit_plan.old_root_hash.clone();
            let duplicate_commit_new_root = duplicate_commit_plan.new_root_hash.clone();
            let duplicate_commit_signature_key_id = duplicate_commit_signature.key_id.clone();
            let duplicate_commit_signature_sig = duplicate_commit_signature.sig.clone();
            let duplicate_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: duplicate_commit_old_root.clone(),
                    new_root_hash: duplicate_commit_new_root.clone(),
                    updated_buckets: duplicate_commit_buckets.clone(),
                    commit_signature: duplicate_commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit updated_buckets contains duplicate bucket"
            );
            assert!(
                !duplicate_commit_error.contains("commit signature verification failed"),
                "{duplicate_commit_error}"
            );
            assert!(!duplicate_commit_error.contains(&duplicate_commit_old_root));
            assert!(!duplicate_commit_error.contains(&duplicate_commit_new_root));
            assert!(!duplicate_commit_error.contains(&session_id));
            assert!(!duplicate_commit_error.contains(&duplicate_commit_signature_key_id));
            assert!(!duplicate_commit_error.contains(&duplicate_commit_signature_sig));
            assert!(!duplicate_commit_error.contains(&updated_bucket.ciphertext));
            assert!(!duplicate_commit_error.contains(&updated_bucket.ciphertext_sha256));
            assert!(!duplicate_commit_error.contains(&updated_bucket.bucket_commitment));

            let invalid_signature_duplicate_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone(), updated_bucket.clone()],
                    commit_signature: wrong_commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit updated_buckets contains duplicate bucket"
            );
            assert!(
                !invalid_signature_duplicate_commit_error
                    .contains("commit signature verification failed"),
                "{invalid_signature_duplicate_commit_error}"
            );
            assert!(
                !invalid_signature_duplicate_commit_error.contains(&fixture.manifest.root_hash)
            );
            assert!(!invalid_signature_duplicate_commit_error.contains(&new_root_hash));
            assert!(!invalid_signature_duplicate_commit_error.contains(&session_id));
            assert!(
                !invalid_signature_duplicate_commit_error.contains(&wrong_commit_signature.key_id)
            );
            assert!(
                !invalid_signature_duplicate_commit_error.contains(&wrong_commit_signature.sig)
            );
            assert!(!invalid_signature_duplicate_commit_error.contains(&updated_bucket.ciphertext));
            assert!(
                !invalid_signature_duplicate_commit_error
                    .contains(&updated_bucket.ciphertext_sha256)
            );
            assert!(
                !invalid_signature_duplicate_commit_error
                    .contains(&updated_bucket.bucket_commitment)
            );

            let unconfigured_commit_key_id_sentinel = "tenant-a/private-result-signing-v1-unknown";
            let mut unconfigured_commit_key_signature = commit_signature.clone();
            unconfigured_commit_key_signature.key_id =
                unconfigured_commit_key_id_sentinel.to_string();
            let unconfigured_commit_key_signature_sig =
                unconfigured_commit_key_signature.sig.clone();
            let unconfigured_commit_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: unconfigured_commit_key_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!unconfigured_commit_key_error.contains("not configured"));
            assert!(
                !unconfigured_commit_key_error.contains(unconfigured_commit_key_id_sentinel),
                "{unconfigured_commit_key_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                unconfigured_commit_key_signature_sig.as_str(),
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !unconfigured_commit_key_error.contains(sentinel),
                    "{unconfigured_commit_key_error}"
                );
            }

            let malformed_commit_key_id_sentinel = "result-commit-signature-key!sentinel";
            let mut malformed_commit_key_signature = commit_signature.clone();
            malformed_commit_key_signature.key_id = malformed_commit_key_id_sentinel.to_string();
            let malformed_commit_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: malformed_commit_key_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !malformed_commit_key_error.contains(malformed_commit_key_id_sentinel),
                "{malformed_commit_key_error}"
            );
            assert!(!malformed_commit_key_error.contains("owner_signing_key_id"));
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                commit_signature.sig.as_str(),
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !malformed_commit_key_error.contains(sentinel),
                    "{malformed_commit_key_error}"
                );
            }

            let alt_commit_signature =
                fixture.commit_signature_with_alt_key(&updated_bucket, &new_root_hash);
            let alt_commit_signature_sig = alt_commit_signature.sig.clone();
            let alt_commit_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: alt_commit_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!alt_commit_key_error.contains(ALT_SIGNING_KEY_ID));
            assert!(!alt_commit_key_error.contains(&fixture.manifest.owner_signing_key_id));
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                alt_commit_signature_sig.as_str(),
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !alt_commit_key_error.contains(sentinel),
                    "{alt_commit_key_error}"
                );
            }

            let commit_signature_body_sentinel = "commit-signature!sentinel";
            let malformed_commit_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: qdrant_sec::PrivateResultOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: commit_signature_body_sentinel.to_string(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !malformed_commit_signature_error.contains(commit_signature_body_sentinel),
                "{malformed_commit_signature_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                SIGNING_KEY_ID,
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !malformed_commit_signature_error.contains(sentinel),
                    "{malformed_commit_signature_error}"
                );
            }

            let commit_signature_alg_sentinel = "rsa-pss-result-commit-sentinel";
            let mut unsupported_commit_signature = commit_signature.clone();
            unsupported_commit_signature.alg = commit_signature_alg_sentinel.to_string();
            let unsupported_commit_key_id = unsupported_commit_signature.key_id.clone();
            let unsupported_commit_sig = unsupported_commit_signature.sig.clone();
            let unsupported_commit_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: unsupported_commit_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !unsupported_commit_signature_error.contains(commit_signature_alg_sentinel),
                "{unsupported_commit_signature_error}"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                unsupported_commit_key_id.as_str(),
                unsupported_commit_sig.as_str(),
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !unsupported_commit_signature_error.contains(sentinel),
                    "{unsupported_commit_signature_error}"
                );
            }

            let commit_result = post_json_ok!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                }
            );
            assert_eq!(commit_result["index_epoch"], NEXT_EPOCH);
            assert_eq!(commit_result["root_hash"], new_root_hash);

            let stale_commit_old_root_hash = fixture.manifest.root_hash.clone();
            let stale_commit_new_root_hash = new_root_hash.clone();
            let stale_commit_session_id = session_id.clone();
            let stale_commit_signature_key_id = commit_signature.key_id.clone();
            let stale_commit_signature_sig = commit_signature.sig.clone();
            let stale_commit_bucket_ciphertext = updated_bucket.ciphertext.clone();
            let stale_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: stale_commit_session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: stale_commit_old_root_hash.clone(),
                    new_root_hash: stale_commit_new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket],
                    commit_signature,
                },
                StatusCode::BAD_REQUEST,
                "old epoch/root"
            );
            assert!(!stale_commit_error.contains(&fixture.buckets[0].ciphertext));
            assert!(!stale_commit_error.contains(&stale_commit_old_root_hash));
            assert!(!stale_commit_error.contains(&stale_commit_new_root_hash));
            assert!(!stale_commit_error.contains(&stale_commit_session_id));
            assert!(!stale_commit_error.contains(&stale_commit_signature_key_id));
            assert!(!stale_commit_error.contains(&stale_commit_signature_sig));
            assert!(!stale_commit_error.contains(&stale_commit_bucket_ciphertext));

            let close_uri =
                format!("/collections/docs/private-result-oram/session/{session_id}/close");
            let _ = post_json_ok!(close_uri.as_str(), serde_json::json!({}));

            let closed_read_signature = fixture.read_signature(&read_bucket_ids);
            let closed_read_signature_sig = closed_read_signature.sig.clone();
            let closed_read_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: closed_read_signature,
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                closed_read_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(!closed_read_error.contains(sentinel), "{closed_read_error}");
            }

            let (closed_commit_bucket, closed_commit_signature, closed_commit_new_root_hash) =
                fixture.commit_bucket();
            let closed_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: closed_commit_new_root_hash.clone(),
                    updated_buckets: vec![closed_commit_bucket.clone()],
                    commit_signature: closed_commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            for sentinel in [
                session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                closed_commit_new_root_hash.as_str(),
                closed_commit_signature.sig.as_str(),
                closed_commit_bucket.ciphertext.as_str(),
                closed_commit_bucket.ciphertext_sha256.as_str(),
                closed_commit_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !closed_commit_error.contains(sentinel),
                    "{closed_commit_error}"
                );
            }

            let reopened_session = post_json_ok!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/result-sdk-instance-2".to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                }
            );
            assert_eq!(reopened_session["index_epoch"], NEXT_EPOCH);
            assert_eq!(reopened_session["root_hash"], new_root_hash);
            let reopened_session_id = reopened_session["session_id"].as_str().unwrap();
            let reopened_read_signature =
                fixture.read_signature_for_epoch(NEXT_EPOCH, &new_root_hash, &read_bucket_ids);
            let reopened_read = post_json_ok!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: reopened_session_id.to_string(),
                    index_epoch: NEXT_EPOCH,
                    root_hash: new_root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: reopened_read_signature,
                }
            );
            assert_eq!(reopened_read["index_epoch"], NEXT_EPOCH);
            assert_eq!(reopened_read["root_hash"], new_root_hash);
            let reopened_close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-result-oram/session/{reopened_session_id}/close"
                ))
                .to_request();
            let reopened_close_response =
                actix_test::call_service(&app, reopened_close_request).await;
            assert_eq!(reopened_close_response.status(), StatusCode::OK);

            let recovery_epoch = NEXT_EPOCH + 1;
            let recovery_bucket =
                fixture_bucket_for_epoch(1, &fixture.manifest, recovery_epoch, &[77; 16]);
            let mut recovery_commitments = fixture
                .buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>();
            recovery_commitments[0] = closed_commit_bucket.bucket_commitment.clone();
            recovery_commitments[1] = recovery_bucket.bucket_commitment.clone();
            let recovery_root_hash =
                private_result_oram_merkle_root_for_commitments(&recovery_commitments).unwrap();
            let recovery_plan = PrivateResultOramCommitPlan {
                old_epoch: NEXT_EPOCH,
                new_epoch: recovery_epoch,
                old_root_hash: new_root_hash.clone(),
                new_root_hash: recovery_root_hash.clone(),
                leaf_commitments: recovery_commitments,
                updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                    bucket_id: recovery_bucket.bucket_id,
                    ciphertext_sha256: recovery_bucket.ciphertext_sha256.clone(),
                }],
            };
            let recovery_signature = sign_private_result_oram_commit(
                &fixture.signing_key,
                PrivateResultOramCommitSignatureContext {
                    collection_id: &fixture.manifest.collection_id,
                    key_id: &fixture.manifest.key_id,
                    rk_id: &fixture.manifest.rk_id,
                    rk_epoch: fixture.manifest.rk_epoch,
                    signing_key_id: SIGNING_KEY_ID,
                },
                &recovery_plan,
            )
            .unwrap();
            let internal_auth = Auth::new_internal(Access::full("private result recovery test"));
            let collection_pass = internal_auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new().write(),
                    "private_result_recovery_test",
                )
                .unwrap();
            let collection = dispatcher
                .toc(&internal_auth, &new_unchecked_verification_pass())
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let recovery_store = PrivateResultOramStore::new(collection.path());
            recovery_store
                .prepare_durable_writeback_with_signature(
                    &PrivateResultOramEpochState {
                        index_epoch: NEXT_EPOCH,
                        root_hash: new_root_hash.clone(),
                    },
                    &PrivateResultOramEpochState {
                        index_epoch: recovery_epoch,
                        root_hash: recovery_root_hash.clone(),
                    },
                    fixture.manifest.bucket_count,
                    std::slice::from_ref(&recovery_bucket),
                    private_result_oram_bucket_ciphertext_bytes(&fixture.manifest.oram).unwrap(),
                    &recovery_signature,
                    qdrant_sec::PrivateResultOramSignatureVerification {
                        expected_key_id: SIGNING_KEY_ID,
                        public_key: fixture.signing_key.public_key().as_ref(),
                    },
                )
                .unwrap();
            assert!(recovery_store.pending_writeback_exists().unwrap());

            let recovered_session = post_json_ok!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/result-sdk-recovery-instance".to_string(),
                    desired_epoch: recovery_epoch,
                    fixed_budget: true,
                }
            );
            assert_eq!(recovered_session["index_epoch"], recovery_epoch);
            assert_eq!(recovered_session["root_hash"], recovery_root_hash);
            assert!(!recovery_store.pending_writeback_exists().unwrap());
            let recovered_session_id = recovered_session["session_id"].as_str().unwrap();
            let recovered_close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-result-oram/session/{recovered_session_id}/close"
                ))
                .to_request();
            let recovered_close_response =
                actix_test::call_service(&app, recovered_close_request).await;
            assert_eq!(recovered_close_response.status(), StatusCode::OK);

            let missing_close_session_id = "close-session-id-sentinel";
            let missing_close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-result-oram/session/{missing_close_session_id}/close"
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
                        "/collections/docs/private-result-oram/session/{invalid_session_id}/close"
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
        });
    }

    #[test]
    fn setup_rest_routes_revalidate_runtime_oram_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("payload_result_oram_v1")
            .unwrap()
            .options["oram"]["tree_height"] = json!(1);
        let (_temp, dispatcher) = test_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;
            let drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;

            macro_rules! post_json_ok_on {
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
            macro_rules! post_json_error_contains_on {
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
            macro_rules! get_json_error_contains_on {
                ($app:expr, $uri:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::get().uri($uri).to_request();
                    let response = actix_test::call_service($app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }

            let drifted_manifest_upload_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(
                !drifted_manifest_upload_error.contains("tree_height"),
                "{drifted_manifest_upload_error}"
            );
            assert!(
                !drifted_manifest_upload_error.contains(&fixture.manifest.root_hash),
                "{drifted_manifest_upload_error}"
            );
            assert!(
                !drifted_manifest_upload_error.contains(&fixture.signature.sig),
                "{drifted_manifest_upload_error}"
            );

            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                }
            );

            let drifted_manifest_read_error = get_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/manifest",
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(
                !drifted_manifest_read_error.contains("tree_height"),
                "{drifted_manifest_read_error}"
            );
            assert!(
                !drifted_manifest_read_error.contains(&fixture.manifest.root_hash),
                "{drifted_manifest_read_error}"
            );
            assert!(
                !drifted_manifest_read_error.contains(&fixture.signature.sig),
                "{drifted_manifest_read_error}"
            );

            let missing_bucket_client_id = "tenant-a/sdk-instance-missing-buckets-test";
            let missing_bucket_session_error = post_json_error_contains_on!(
                &app,
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: missing_bucket_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::NOT_FOUND,
                "encrypted bucket data is unavailable"
            );
            assert!(
                !missing_bucket_session_error.contains("private_result_oram"),
                "{missing_bucket_session_error}"
            );
            assert!(
                !missing_bucket_session_error.contains("/tmp"),
                "{missing_bucket_session_error}"
            );
            assert!(
                !missing_bucket_session_error.contains(missing_bucket_client_id),
                "{missing_bucket_session_error}"
            );

            let drifted_bucket_upload_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(
                !drifted_bucket_upload_error.contains("tree_height"),
                "{drifted_bucket_upload_error}"
            );
            assert!(
                !drifted_bucket_upload_error.contains(&fixture.manifest.root_hash),
                "{drifted_bucket_upload_error}"
            );
            assert!(
                !drifted_bucket_upload_error.contains(&fixture.buckets[0].ciphertext),
                "{drifted_bucket_upload_error}"
            );
            assert!(
                !drifted_bucket_upload_error.contains(&fixture.buckets[0].ciphertext_sha256),
                "{drifted_bucket_upload_error}"
            );
            assert!(
                !drifted_bucket_upload_error.contains(&fixture.buckets[0].bucket_commitment),
                "{drifted_bucket_upload_error}"
            );

            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                }
            );

            let setup_drift_client_id = "tenant-a/sdk-instance-setup-drift-test";
            let drifted_session_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: setup_drift_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(
                !drifted_session_error.contains("tree_height"),
                "{drifted_session_error}"
            );
            assert!(
                !drifted_session_error.contains(&fixture.manifest.root_hash),
                "{drifted_session_error}"
            );
            assert!(
                !drifted_session_error.contains(setup_drift_client_id),
                "{drifted_session_error}"
            );
        });
    }

    #[test]
    fn active_session_rest_read_rejects_runtime_oram_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("payload_result_oram_v1")
            .unwrap()
            .options["oram"]["tree_height"] = json!(1);
        let (_temp, dispatcher) = test_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;
            let drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;

            macro_rules! post_json_ok_on {
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
            macro_rules! post_json_error_contains_on {
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

            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                }
            );
            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                }
            );
            let session_result = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-drift-test".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }
            );
            let session_id = session_result["session_id"].as_str().unwrap().to_string();

            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read_signature = fixture.read_signature(&read_bucket_ids);
            let drift_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: read_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(!drift_error.contains("tree_height"), "{drift_error}");
            assert!(
                !drift_error.contains(&fixture.manifest.root_hash),
                "{drift_error}"
            );
            assert!(!drift_error.contains(&session_id), "{drift_error}");
            assert!(
                !drift_error.contains(&read_signature.key_id),
                "{drift_error}"
            );
            assert!(!drift_error.contains(&read_signature.sig), "{drift_error}");

            let close_uri =
                format!("/collections/docs/private-result-oram/session/{session_id}/close");
            let closed = post_json_ok_on!(&app, close_uri.as_str(), serde_json::json!({}));
            assert_eq!(closed, json!(true));
        });
    }

    #[test]
    fn active_session_rest_commit_rejects_runtime_oram_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("payload_result_oram_v1")
            .unwrap()
            .options["oram"]["tree_height"] = json!(1);
        let (_temp, dispatcher) = test_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;
            let drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;

            macro_rules! post_json_ok_on {
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
            macro_rules! post_json_error_contains_on {
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

            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                }
            );
            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                }
            );
            let session_result = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-commit-drift-test".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }
            );
            let session_id = session_result["session_id"].as_str().unwrap().to_string();

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let drift_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(!drift_error.contains("tree_height"), "{drift_error}");
            assert!(
                !drift_error.contains(&fixture.manifest.root_hash),
                "{drift_error}"
            );
            assert!(!drift_error.contains(&new_root_hash), "{drift_error}");
            assert!(!drift_error.contains(&session_id), "{drift_error}");
            assert!(
                !drift_error.contains(&commit_signature.key_id),
                "{drift_error}"
            );
            assert!(
                !drift_error.contains(&commit_signature.sig),
                "{drift_error}"
            );
            assert!(
                !drift_error.contains(&updated_bucket.ciphertext),
                "{drift_error}"
            );

            let close_uri =
                format!("/collections/docs/private-result-oram/session/{session_id}/close");
            let closed = post_json_ok_on!(&app, close_uri.as_str(), serde_json::json!({}));
            assert_eq!(closed, json!(true));
        });
    }

    #[test]
    fn private_result_oram_rest_routes_reject_distributed_epoch_operations() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_distributed_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
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

            let distributed_client_id = "tenant-a/distributed-result-sdk-instance";
            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read_signature = fixture.read_signature(&read_bucket_ids);
            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let first_bucket_ciphertext = fixture.buckets[0].ciphertext.clone();
            let updated_bucket_ciphertext = updated_bucket.ciphertext.clone();

            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-result-oram/manifest")
                    .set_json(&UploadPrivateResultOramManifestRequest {
                        manifest: fixture.manifest.clone(),
                        signature: fixture.signature.clone(),
                    })
                    .to_request(),
                [
                    &fixture.manifest.root_hash,
                    &fixture.signature.sig,
                    &first_bucket_ciphertext,
                ],
            );
            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-result-oram/buckets")
                    .set_json(&UploadPrivateResultOramBucketsRequest {
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: fixture.buckets.clone(),
                    })
                    .to_request(),
                [&fixture.manifest.root_hash, &first_bucket_ciphertext],
            );
            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-result-oram/session")
                    .set_json(&OpenPrivateResultOramSessionRequest {
                        client_id: distributed_client_id.to_string(),
                        desired_epoch: BASE_EPOCH,
                        fixed_budget: true,
                    })
                    .to_request(),
                [
                    distributed_client_id,
                    &fixture.manifest.root_hash,
                    &fixture.signature.sig
                ],
            );
            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-result-oram/oram/read_buckets")
                    .set_json(&ReadPrivateResultOramBucketsRequest {
                        session_id: SESSION_ID.to_string(),
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.manifest.root_hash.clone(),
                        bucket_ids: read_bucket_ids.clone(),
                        read_signature: read_signature.clone(),
                    })
                    .to_request(),
                [
                    SESSION_ID,
                    &fixture.manifest.root_hash,
                    &read_signature.sig,
                    &first_bucket_ciphertext,
                ],
            );
            assert_distributed_rejection!(
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-result-oram/oram/commit")
                    .set_json(&CommitPrivateResultOramBucketsRequest {
                        session_id: SESSION_ID.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: vec![updated_bucket],
                        commit_signature: commit_signature.clone(),
                    })
                    .to_request(),
                [
                    SESSION_ID,
                    &fixture.manifest.root_hash,
                    &new_root_hash,
                    &commit_signature.sig,
                    &updated_bucket_ciphertext,
                ],
            );
        });
    }
}
