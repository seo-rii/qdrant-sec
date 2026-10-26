use std::sync::Arc;
use std::time::Instant;

use api::grpc::qdrant as grpc;
use api::grpc::qdrant::private_result_oram_server::PrivateResultOram;
use collection::operations::verification::new_unchecked_verification_pass;
use common::validation::validate_collection_name_legacy;
use qdrant_sec::{
    OramKind, OramParams, PrivateResultOramBucket, PrivateResultOramManifest,
    PrivateResultOramSignature,
};
use storage::dispatcher::Dispatcher;
use tonic::{Request, Response, Status, async_trait};

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
use crate::tonic::auth::extract_auth;

const ORAM_KIND_PATH_ORAM: i32 = 1;

pub struct PrivateResultOramService {
    dispatcher: Arc<Dispatcher>,
    settings: Settings,
}

impl PrivateResultOramService {
    pub fn new(dispatcher: Arc<Dispatcher>, settings: Settings) -> Self {
        Self {
            dispatcher,
            settings,
        }
    }
}

#[async_trait]
impl PrivateResultOram for PrivateResultOramService {
    async fn get_private_result_oram_manifest(
        &self,
        mut request: Request<grpc::GetPrivateResultOramManifestRequest>,
    ) -> Result<Response<grpc::GetPrivateResultOramManifestResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let pass = new_unchecked_verification_pass();

        let record = do_get_private_result_oram_manifest(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
        )
        .await?;

        Ok(Response::new(grpc::GetPrivateResultOramManifestResponse {
            manifest: Some(manifest_to_proto(record.manifest)),
            signature: Some(signature_to_proto(record.signature)),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn upload_private_result_oram_manifest(
        &self,
        mut request: Request<grpc::UploadPrivateResultOramManifestRequest>,
    ) -> Result<Response<grpc::PrivateResultOramEpochResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let manifest = manifest_from_proto(required(request.manifest, "manifest")?)?;
        let signature = signature_from_proto(required(request.signature, "signature")?);
        let pass = new_unchecked_verification_pass();

        let epoch = if self.dispatcher.consensus_state().is_some() {
            do_stage_private_result_oram_manifest_for_initial_replication(
                self.dispatcher.toc(&auth, &pass),
                &auth,
                &self.settings,
                &request.collection_name,
                manifest,
                signature,
            )
            .await?
        } else {
            do_upload_private_result_oram_manifest(
                self.dispatcher.toc(&auth, &pass),
                &auth,
                &self.settings,
                &request.collection_name,
                manifest,
                signature,
            )
            .await?
        };

        Ok(Response::new(grpc::PrivateResultOramEpochResponse {
            index_epoch: epoch.index_epoch,
            root_hash: epoch.root_hash,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn upload_private_result_oram_buckets(
        &self,
        mut request: Request<grpc::UploadPrivateResultOramBucketsRequest>,
    ) -> Result<Response<grpc::PrivateResultOramEpochResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let buckets = request
            .buckets
            .into_iter()
            .map(bucket_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let pass = new_unchecked_verification_pass();

        let coordinated_initial_replication = self.dispatcher.consensus_state().is_some();
        let epoch = if coordinated_initial_replication {
            do_stage_private_result_oram_buckets_for_initial_replication(
                self.dispatcher.toc(&auth, &pass),
                &auth,
                &self.settings,
                &request.collection_name,
                request.index_epoch,
                request.root_hash,
                buckets,
            )
            .await?
        } else {
            do_upload_private_result_oram_buckets(
                self.dispatcher.toc(&auth, &pass),
                &auth,
                &self.settings,
                &request.collection_name,
                request.index_epoch,
                request.root_hash,
                buckets,
            )
            .await?
        };
        if coordinated_initial_replication {
            coordinate_private_result_oram_initial_upload(
                &self.dispatcher,
                &auth,
                &self.settings,
                &request.collection_name,
            )
            .await?;
        }

        Ok(Response::new(grpc::PrivateResultOramEpochResponse {
            index_epoch: epoch.index_epoch,
            root_hash: epoch.root_hash,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn open_private_result_oram_session(
        &self,
        mut request: Request<grpc::OpenPrivateResultOramSessionRequest>,
    ) -> Result<Response<grpc::OpenPrivateResultOramSessionResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let pass = new_unchecked_verification_pass();

        let session = if self.dispatcher.consensus_state().is_some() {
            open_private_result_oram_session_coordinated(
                &self.dispatcher,
                &auth,
                &self.settings,
                &request.collection_name,
                request.client_id,
                request.desired_epoch,
                request.fixed_budget,
            )
            .await?
        } else {
            do_open_private_result_oram_session(
                self.dispatcher.toc(&auth, &pass),
                &auth,
                &self.settings,
                &request.collection_name,
                request.client_id,
                request.desired_epoch,
                request.fixed_budget,
            )
            .await?
        };

        Ok(Response::new(grpc::OpenPrivateResultOramSessionResponse {
            session_id: session.session_id,
            collection_id: session.collection_id,
            index_epoch: session.index_epoch,
            root_hash: session.root_hash,
            manifest: Some(manifest_to_proto(session.manifest)),
            lease_expires_unix: session.lease_expires_unix,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn read_private_result_oram_buckets(
        &self,
        mut request: Request<grpc::ReadPrivateResultOramBucketsRequest>,
    ) -> Result<Response<grpc::ReadPrivateResultOramBucketsResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let pass = new_unchecked_verification_pass();
        let read_signature =
            signature_from_proto(required(request.read_signature, "read_signature")?);

        let response = if self.dispatcher.consensus_state().is_some() {
            read_private_result_oram_buckets_coordinated(
                &self.dispatcher,
                &auth,
                &self.settings,
                &request.collection_name,
                &request.session_id,
                request.index_epoch,
                request.root_hash,
                request.bucket_ids,
                read_signature,
            )
            .await?
        } else {
            do_read_private_result_oram_buckets(
                self.dispatcher.toc(&auth, &pass),
                &auth,
                &self.settings,
                &request.collection_name,
                &request.session_id,
                request.index_epoch,
                request.root_hash,
                request.bucket_ids,
                read_signature,
            )
            .await?
        };

        Ok(Response::new(grpc::ReadPrivateResultOramBucketsResponse {
            index_epoch: response.index_epoch,
            root_hash: response.root_hash,
            buckets: response.buckets.into_iter().map(bucket_to_proto).collect(),
            proof: Some(grpc::PrivateResultOramReadProof {
                kind: response.proof.kind,
                value: response.proof.value,
            }),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn commit_private_result_oram_buckets(
        &self,
        mut request: Request<grpc::CommitPrivateResultOramBucketsRequest>,
    ) -> Result<Response<grpc::PrivateResultOramEpochResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let updated_buckets = request
            .updated_buckets
            .into_iter()
            .map(bucket_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let commit_signature =
            signature_from_proto(required(request.commit_signature, "commit_signature")?);
        let pass = new_unchecked_verification_pass();

        let epoch = if self.dispatcher.consensus_state().is_some() {
            commit_private_result_oram_buckets_coordinated(
                &self.dispatcher,
                &auth,
                &self.settings,
                &request.collection_name,
                &request.session_id,
                request.old_epoch,
                request.new_epoch,
                request.old_root_hash,
                request.new_root_hash,
                updated_buckets,
                commit_signature,
            )
            .await?
        } else {
            do_commit_private_result_oram_buckets(
                self.dispatcher.toc(&auth, &pass),
                &auth,
                &self.settings,
                &request.collection_name,
                &request.session_id,
                request.old_epoch,
                request.new_epoch,
                request.old_root_hash,
                request.new_root_hash,
                updated_buckets,
                commit_signature,
            )
            .await?
        };

        Ok(Response::new(grpc::PrivateResultOramEpochResponse {
            index_epoch: epoch.index_epoch,
            root_hash: epoch.root_hash,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn close_private_result_oram_session(
        &self,
        mut request: Request<grpc::ClosePrivateResultOramSessionRequest>,
    ) -> Result<Response<grpc::ClosePrivateResultOramSessionResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let pass = new_unchecked_verification_pass();

        let closed = if self.dispatcher.consensus_state().is_some() {
            close_private_result_oram_session_coordinated(
                &self.dispatcher,
                &auth,
                &self.settings,
                &request.collection_name,
                &request.session_id,
            )
            .await?
        } else {
            do_close_private_result_oram_session(
                self.dispatcher.toc(&auth, &pass),
                &auth,
                &self.settings,
                &request.collection_name,
                &request.session_id,
            )
            .await?
        };

        Ok(Response::new(grpc::ClosePrivateResultOramSessionResponse {
            closed,
            time: timing.elapsed().as_secs_f64(),
        }))
    }
}

fn validate_collection(collection_name: &str) -> Result<(), Status> {
    if collection_name.is_empty() || collection_name.len() > 255 {
        return Err(Status::invalid_argument(
            "collection_name must be non-empty and at most 255 bytes",
        ));
    }
    validate_collection_name_legacy(collection_name)
        .map_err(|_| Status::invalid_argument("collection_name is invalid"))?;
    Ok(())
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, Status> {
    value.ok_or_else(|| Status::invalid_argument(format!("{field} is required")))
}

pub(crate) fn manifest_to_proto(
    manifest: PrivateResultOramManifest,
) -> grpc::PrivateResultOramManifest {
    grpc::PrivateResultOramManifest {
        version: manifest.version as u32,
        provider: manifest.provider,
        binding: manifest.binding,
        collection_id: manifest.collection_id,
        key_id: manifest.key_id,
        rk_id: manifest.rk_id,
        rk_epoch: manifest.rk_epoch,
        oram: Some(grpc::OramParams {
            kind: oram_kind_to_proto(manifest.oram.kind),
            bucket_size: manifest.oram.bucket_size,
            block_size_bytes: manifest.oram.block_size_bytes,
            tree_height: manifest.oram.tree_height,
            path_batch_size: manifest.oram.path_batch_size,
        }),
        index_epoch: manifest.index_epoch,
        root_hash: manifest.root_hash,
        bucket_count: manifest.bucket_count,
        logical_result_count: manifest.logical_result_count,
        dummy_result_count: manifest.dummy_result_count,
        owner_signing_key_id: manifest.owner_signing_key_id,
        created_at_unix: manifest.created_at_unix,
    }
}

pub(crate) fn manifest_from_proto(
    manifest: grpc::PrivateResultOramManifest,
) -> Result<PrivateResultOramManifest, Status> {
    let version = u16::try_from(manifest.version)
        .map_err(|_| Status::invalid_argument("manifest.version exceeds u16"))?;
    let oram = required(manifest.oram, "manifest.oram")?;
    Ok(PrivateResultOramManifest {
        version,
        provider: manifest.provider,
        binding: manifest.binding,
        collection_id: manifest.collection_id,
        key_id: manifest.key_id,
        rk_id: manifest.rk_id,
        rk_epoch: manifest.rk_epoch,
        oram: OramParams {
            kind: oram_kind_from_proto(oram.kind)?,
            bucket_size: oram.bucket_size,
            block_size_bytes: oram.block_size_bytes,
            tree_height: oram.tree_height,
            path_batch_size: oram.path_batch_size,
        },
        index_epoch: manifest.index_epoch,
        root_hash: manifest.root_hash,
        bucket_count: manifest.bucket_count,
        logical_result_count: manifest.logical_result_count,
        dummy_result_count: manifest.dummy_result_count,
        owner_signing_key_id: manifest.owner_signing_key_id,
        created_at_unix: manifest.created_at_unix,
    })
}

pub(crate) fn bucket_to_proto(bucket: PrivateResultOramBucket) -> grpc::PrivateResultOramBucket {
    grpc::PrivateResultOramBucket {
        version: bucket.version as u32,
        bucket_id: bucket.bucket_id,
        index_epoch: bucket.index_epoch,
        ciphertext: bucket.ciphertext,
        ciphertext_sha256: bucket.ciphertext_sha256,
        bucket_commitment: bucket.bucket_commitment,
    }
}

pub(crate) fn bucket_from_proto(
    bucket: grpc::PrivateResultOramBucket,
) -> Result<PrivateResultOramBucket, Status> {
    let version = u16::try_from(bucket.version)
        .map_err(|_| Status::invalid_argument("bucket.version exceeds u16"))?;
    Ok(PrivateResultOramBucket {
        version,
        bucket_id: bucket.bucket_id,
        index_epoch: bucket.index_epoch,
        ciphertext: bucket.ciphertext,
        ciphertext_sha256: bucket.ciphertext_sha256,
        bucket_commitment: bucket.bucket_commitment,
    })
}

pub(crate) fn signature_to_proto(
    signature: PrivateResultOramSignature,
) -> grpc::PrivateResultOramSignature {
    grpc::PrivateResultOramSignature {
        alg: signature.alg,
        key_id: signature.key_id,
        sig: signature.sig,
    }
}

pub(crate) fn signature_from_proto(
    signature: grpc::PrivateResultOramSignature,
) -> PrivateResultOramSignature {
    PrivateResultOramSignature {
        alg: signature.alg,
        key_id: signature.key_id,
        sig: signature.sig,
    }
}

fn oram_kind_to_proto(kind: OramKind) -> i32 {
    match kind {
        OramKind::PathOram => ORAM_KIND_PATH_ORAM,
    }
}

fn oram_kind_from_proto(value: i32) -> Result<OramKind, Status> {
    match value {
        ORAM_KIND_PATH_ORAM => Ok(OramKind::PathOram),
        _ => Err(Status::invalid_argument(
            "private result ORAM kind is unspecified or unsupported",
        )),
    }
}

#[cfg(test)]
mod private_result_oram_grpc_tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

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
        PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING,
        PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PrivateResultOramBucket,
        PrivateResultOramBucketCommitmentContext, PrivateResultOramClientCommitBucketRef,
        PrivateResultOramCommitPlan, PrivateResultOramCommitSignatureContext,
        PrivateResultOramReadBucketsSignatureContext, private_result_oram_bucket_ciphertext_bytes,
        private_result_oram_bucket_commitment, private_result_oram_merkle_root_for_commitments,
        sign_private_result_oram_commit, sign_private_result_oram_manifest,
        sign_private_result_oram_read_buckets,
        sign_private_result_oram_read_buckets_for_manifest_context,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use storage::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreateCollection, CreateCollectionOperation,
    };
    use storage::dispatcher::Dispatcher;
    use storage::rbac::{Access, AccessRequirements, Auth};
    use tonic::Code;
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
        "encryptedClientStateBackup",
        "encryptedClientStateBackups",
        "encrypted_client_states",
        "encrypted_client_state_backups",
        "encryptedClientStateSnapshot",
        "encryptedClientStateSnapshots",
        "encrypted.client.state",
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
        "payloadFetchToken",
        "payloadFetchTokens",
        "payload_fetch_token",
        "payload_fetch_tokens",
        "payload.fetch.token",
        "payload.fetch.tokens",
        "tokenPositionMap",
        "tokenPositionMaps",
        "tokenPositionMapBackup",
        "tokenPositionMapBackups",
        "token.position.map",
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
        "encrypted.client.state.snapshot.bin",
        "encrypted.client.state.snapshot.json",
        "encrypted_client_state_snapshot.bin",
        "encrypted_client_state_snapshot.json",
        "encrypted_client_state_snapshots.json",
        "encrypted.client.state.snapshots.json",
        "token.map.backup.json",
        "token.position.map.backup.json",
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
    const PRIVATE_RESULT_ORAM_READ_ACCESS_REDACTION_ALIASES: &[&str] = &[
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

    fn request_with_auth<T>(message: T, auth: &Auth) -> Request<T> {
        let mut request = Request::new(message);
        request.extensions_mut().insert(auth.clone());
        request
    }

    fn assert_grpc_requires_write_access(error: Status) {
        assert_eq!(error.code(), Code::PermissionDenied);
        let rendered = error.message();
        assert!(
            rendered.contains("Global manage access is required")
                || rendered.contains("Write access to collection"),
            "expected write-access denial, got: {rendered}",
        );
        for forbidden in [
            qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
            qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
            qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
            qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
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
        for &forbidden in PRIVATE_RESULT_ORAM_READ_ACCESS_REDACTION_ALIASES {
            assert!(
                !rendered.contains(forbidden),
                "write-access denial leaked private ORAM detail `{forbidden}`: {rendered}",
            );
        }
    }

    fn assert_private_result_guard_message_redacts(rendered: &str, extra_forbidden: &[&str]) {
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
        for &forbidden in PRIVATE_RESULT_ORAM_READ_ACCESS_REDACTION_ALIASES {
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
                Auth::new_internal(Access::full("private result ORAM gRPC route test")),
                None,
            )
            .await
            .unwrap();
    }

    #[test]
    fn grpc_rejects_private_result_missing_collection_encryption_without_reflecting_collection() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_dispatcher();
        let collection_name = "private-result-grpc-missing-encryption-secret-collection";
        actix_web::rt::System::new().block_on(async {
            create_plain_collection(&dispatcher, collection_name).await;
            let service =
                PrivateResultOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            macro_rules! assert_missing_encryption {
                ($call:expr) => {{
                    let err = $call.await.unwrap_err();

                    assert_eq!(err.code(), Code::InvalidArgument);
                    assert!(
                        err.message()
                            .contains("does not configure private result ORAM encryption"),
                        "{}",
                        err.message()
                    );
                    assert!(!err.message().contains(collection_name));
                    assert!(!err.message().contains("secret"));
                    assert!(!err.message().contains(&fixture.manifest.root_hash));
                    assert!(!err.message().contains(&fixture.signature.sig));
                    assert!(!err.message().contains(&fixture.buckets[0].ciphertext));
                    assert!(!err.message().contains(SESSION_ID));
                    assert!(!err.message().contains("tenant-a/sdk-instance-1"));
                }};
            }

            assert_missing_encryption!(PrivateResultOram::get_private_result_oram_manifest(
                &service,
                Request::new(grpc::GetPrivateResultOramManifestRequest {
                    collection_name: collection_name.to_string(),
                }),
            ));

            assert_missing_encryption!(PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: collection_name.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            ));

            assert_missing_encryption!(PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: collection_name.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            ));

            assert_missing_encryption!(PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: collection_name.to_string(),
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            ));

            let read_bucket_id = 0;
            let read_bucket_ids = vec![read_bucket_id, 1, 3, read_bucket_id, 1, 4];
            let read_signature = fixture.read_signature(&read_bucket_ids);
            assert_missing_encryption!(PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: collection_name.to_string(),
                    session_id: SESSION_ID.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(read_signature)),
                }),
            ));

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            assert_missing_encryption!(PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: collection_name.to_string(),
                    session_id: SESSION_ID.to_string(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash,
                    updated_buckets: vec![bucket_to_proto(updated_bucket)],
                    commit_signature: Some(signature_to_proto(commit_signature)),
                }),
            ));

            assert_missing_encryption!(PrivateResultOram::close_private_result_oram_session(
                &service,
                Request::new(grpc::ClosePrivateResultOramSessionRequest {
                    collection_name: collection_name.to_string(),
                    session_id: SESSION_ID.to_string(),
                }),
            ));
        });
    }

    #[test]
    fn grpc_private_result_oram_mutations_require_write_access_without_private_oram_details() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let service =
                PrivateResultOramService::new(Arc::new(dispatcher.clone()), settings.clone());
            let write_auth =
                Auth::new_internal(Access::full("private result ORAM gRPC write setup"));
            let read_auth =
                Auth::new_internal(Access::full_ro("private result ORAM gRPC read-only test"));

            PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                request_with_auth(
                    grpc::UploadPrivateResultOramManifestRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                        signature: Some(signature_to_proto(fixture.signature.clone())),
                    },
                    &write_auth,
                ),
            )
            .await
            .unwrap();
            PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                request_with_auth(
                    grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: fixture
                            .buckets
                            .clone()
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    },
                    &write_auth,
                ),
            )
            .await
            .unwrap();

            PrivateResultOram::get_private_result_oram_manifest(
                &service,
                request_with_auth(
                    grpc::GetPrivateResultOramManifestRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                    },
                    &read_auth,
                ),
            )
            .await
            .unwrap();

            let err = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                request_with_auth(
                    grpc::UploadPrivateResultOramManifestRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                        signature: Some(signature_to_proto(fixture.signature.clone())),
                    },
                    &read_auth,
                ),
            )
            .await
            .unwrap_err();
            assert_grpc_requires_write_access(err);

            let err = PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                request_with_auth(
                    grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: fixture
                            .buckets
                            .clone()
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    },
                    &read_auth,
                ),
            )
            .await
            .unwrap_err();
            assert_grpc_requires_write_access(err);

            let err = PrivateResultOram::open_private_result_oram_session(
                &service,
                request_with_auth(
                    grpc::OpenPrivateResultOramSessionRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        client_id: "tenant-a/read-only-sdk".to_string(),
                        desired_epoch: BASE_EPOCH,
                        fixed_budget: true,
                    },
                    &read_auth,
                ),
            )
            .await
            .unwrap_err();
            assert_grpc_requires_write_access(err);

            let session = PrivateResultOram::open_private_result_oram_session(
                &service,
                request_with_auth(
                    grpc::OpenPrivateResultOramSessionRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        client_id: "tenant-a/write-sdk".to_string(),
                        desired_epoch: BASE_EPOCH,
                        fixed_budget: true,
                    },
                    &write_auth,
                ),
            )
            .await
            .unwrap()
            .into_inner();

            let bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read_response = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                request_with_auth(
                    grpc::ReadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id.clone(),
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.manifest.root_hash.clone(),
                        bucket_ids: bucket_ids.clone(),
                        read_signature: Some(signature_to_proto(
                            fixture.read_signature(&bucket_ids),
                        )),
                    },
                    &read_auth,
                ),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(read_response.buckets.len(), bucket_ids.len());

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let err = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                request_with_auth(
                    grpc::CommitPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id.clone(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash,
                        updated_buckets: vec![bucket_to_proto(updated_bucket)],
                        commit_signature: Some(signature_to_proto(commit_signature)),
                    },
                    &read_auth,
                ),
            )
            .await
            .unwrap_err();
            assert_grpc_requires_write_access(err);

            let err = PrivateResultOram::close_private_result_oram_session(
                &service,
                request_with_auth(
                    grpc::ClosePrivateResultOramSessionRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id.clone(),
                    },
                    &read_auth,
                ),
            )
            .await
            .unwrap_err();
            assert_grpc_requires_write_access(err);

            PrivateResultOram::close_private_result_oram_session(
                &service,
                request_with_auth(
                    grpc::ClosePrivateResultOramSessionRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id,
                    },
                    &write_auth,
                ),
            )
            .await
            .unwrap();
        });
    }

    #[test]
    fn manifest_proto_roundtrip_preserves_private_result_fields() {
        let fixture = PrivateResultRouteFixture::build();
        let proto = manifest_to_proto(fixture.manifest.clone());

        assert_eq!(proto.oram.as_ref().unwrap().kind, ORAM_KIND_PATH_ORAM);
        assert_eq!(manifest_from_proto(proto).unwrap(), fixture.manifest);
    }

    #[test]
    fn manifest_proto_rejects_unspecified_oram_and_missing_nested_fields() {
        let unsupported = 987_654;
        let fixture = PrivateResultRouteFixture::build();

        let mut proto = manifest_to_proto(fixture.manifest.clone());
        proto.oram.as_mut().unwrap().kind = 0;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("kind"));

        let mut proto = manifest_to_proto(fixture.manifest.clone());
        proto.oram.as_mut().unwrap().kind = unsupported;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("kind"));
        assert!(!err.message().contains(&unsupported.to_string()));

        let mut proto = manifest_to_proto(fixture.manifest);
        proto.oram = None;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest.oram"));

        let err = required::<grpc::PrivateResultOramManifest>(None, "manifest").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest"));

        let err =
            required::<grpc::PrivateResultOramSignature>(None, "commit_signature").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("commit_signature"));

        let err = required::<grpc::PrivateResultOramSignature>(None, "read_signature").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("read_signature"));
    }

    #[test]
    fn proto_enum_conversions_reject_unknown_values_without_reflecting_value() {
        for unsupported in [0, 987_654] {
            let err = oram_kind_from_proto(unsupported).unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("kind"));
            assert!(!err.message().contains(&unsupported.to_string()));
        }
    }

    #[test]
    fn manifest_and_bucket_proto_reject_version_overflow_without_reflecting_value() {
        let fixture = PrivateResultRouteFixture::build();
        let mut manifest = manifest_to_proto(fixture.manifest);
        manifest.version = u32::MAX;
        let err = manifest_from_proto(manifest).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest.version"));
        assert!(!err.message().contains(&u32::MAX.to_string()));

        let err = bucket_from_proto(grpc::PrivateResultOramBucket {
            version: u32::MAX,
            bucket_id: 1,
            index_epoch: 42,
            ciphertext: "payload.fetch.token".to_string(),
            ciphertext_sha256: "encrypted_client_state_ciphertext_sha256".to_string(),
            bucket_commitment: "stashSnapshot".to_string(),
        })
        .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("bucket.version"));
        assert!(!err.message().contains(&u32::MAX.to_string()));
        assert!(
            !err.message().contains("payload.fetch.token"),
            "{}",
            err.message()
        );
        assert!(
            !err.message().contains("bucket.commitment"),
            "{}",
            err.message()
        );
        assert!(
            !err.message().contains("encrypted_client_state"),
            "{}",
            err.message()
        );
        assert!(
            !err.message().contains("stashSnapshot"),
            "{}",
            err.message()
        );
    }

    #[test]
    fn route_param_validation_rejects_oversized_values_without_reflecting_them() {
        let collection_sentinel = "result-grpc-collection-route-sentinel";
        let oversized_collection = format!("{collection_sentinel}{}", "x".repeat(256));
        let err = validate_collection(&oversized_collection).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("collection_name"));
        assert!(!err.message().contains(collection_sentinel));
        assert!(!err.message().contains(&oversized_collection));
    }

    #[test]
    fn route_param_validation_rejects_malformed_collection_without_reflecting_it() {
        for malformed_collection in [
            "result-grpc-collection-route-sentinel/child",
            "result-grpc-collection-route-sentinel\0child",
        ] {
            let err = validate_collection(malformed_collection).unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("collection_name"));
            assert!(!err.message().contains(malformed_collection));
            assert!(
                !err.message()
                    .contains("result-grpc-collection-route-sentinel")
            );
            assert!(!err.message().contains("child"));
        }
    }

    #[test]
    fn private_result_oram_uploads_and_reads_through_grpc_service() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let service = PrivateResultOramService::new(Arc::new(dispatcher.clone()), settings);

            let missing_manifest = PrivateResultOram::get_private_result_oram_manifest(
                &service,
                Request::new(grpc::GetPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(missing_manifest.code(), Code::NotFound);
            assert!(!missing_manifest.message().contains("private_result_oram"));
            assert_private_result_guard_message_redacts(missing_manifest.message(), &["/tmp"]);

            let upload_root_before_manifest_sentinel = "AAAA";
            let malformed_root_before_manifest =
                PrivateResultOram::upload_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: upload_root_before_manifest_sentinel.to_string(),
                        buckets: fixture
                            .buckets
                            .clone()
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(malformed_root_before_manifest.code(), Code::InvalidArgument);
            assert!(
                malformed_root_before_manifest
                    .message()
                    .contains("root_hash must be a base64url sha256 value")
            );
            assert!(
                !malformed_root_before_manifest
                    .message()
                    .contains(upload_root_before_manifest_sentinel)
            );
            assert!(
                !malformed_root_before_manifest
                    .message()
                    .contains("private_result_oram")
            );
            assert!(
                !malformed_root_before_manifest
                    .message()
                    .contains("manifest")
            );
            assert_private_result_guard_message_redacts(
                malformed_root_before_manifest.message(),
                &[upload_root_before_manifest_sentinel, "manifest"],
            );

            let malformed_bucket_hash_before_manifest_sentinel = "result-grpc-upload-hash-sentinel";
            let mut malformed_bucket_hash_before_manifest_buckets = fixture.buckets.clone();
            malformed_bucket_hash_before_manifest_buckets[0].ciphertext_sha256 =
                malformed_bucket_hash_before_manifest_sentinel.to_string();
            let malformed_bucket_hash_before_manifest =
                PrivateResultOram::upload_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: malformed_bucket_hash_before_manifest_buckets
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(
                malformed_bucket_hash_before_manifest.code(),
                Code::InvalidArgument
            );
            assert!(
                malformed_bucket_hash_before_manifest
                    .message()
                    .contains("ciphertext_sha256")
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .message()
                    .contains(malformed_bucket_hash_before_manifest_sentinel)
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .message()
                    .contains("private_result_oram")
            );
            assert!(
                !malformed_bucket_hash_before_manifest
                    .message()
                    .contains("manifest")
            );
            assert_private_result_guard_message_redacts(
                malformed_bucket_hash_before_manifest.message(),
                &[
                    malformed_bucket_hash_before_manifest_sentinel,
                    fixture.manifest.root_hash.as_str(),
                    fixture.buckets[0].ciphertext.as_str(),
                    fixture.buckets[0].ciphertext_sha256.as_str(),
                    fixture.buckets[0].bucket_commitment.as_str(),
                    "manifest",
                ],
            );

            let malformed_bucket_commitment_before_manifest_sentinel =
                "result-grpc-upload-commitment-sentinel";
            let mut malformed_bucket_commitment_before_manifest_buckets = fixture.buckets.clone();
            malformed_bucket_commitment_before_manifest_buckets[0].bucket_commitment =
                malformed_bucket_commitment_before_manifest_sentinel.to_string();
            let malformed_bucket_commitment_before_manifest =
                PrivateResultOram::upload_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: malformed_bucket_commitment_before_manifest_buckets
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(
                malformed_bucket_commitment_before_manifest.code(),
                Code::InvalidArgument
            );
            assert!(
                malformed_bucket_commitment_before_manifest
                    .message()
                    .contains("bucket_commitment")
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .message()
                    .contains(malformed_bucket_commitment_before_manifest_sentinel)
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .message()
                    .contains("private_result_oram")
            );
            assert!(
                !malformed_bucket_commitment_before_manifest
                    .message()
                    .contains("manifest")
            );
            assert_private_result_guard_message_redacts(
                malformed_bucket_commitment_before_manifest.message(),
                &[
                    malformed_bucket_commitment_before_manifest_sentinel,
                    fixture.manifest.root_hash.as_str(),
                    fixture.buckets[0].ciphertext.as_str(),
                    fixture.buckets[0].ciphertext_sha256.as_str(),
                    fixture.buckets[0].bucket_commitment.as_str(),
                    "manifest",
                ],
            );

            let empty_upload_before_manifest =
                PrivateResultOram::upload_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: Vec::new(),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(empty_upload_before_manifest.code(), Code::InvalidArgument);
            assert!(
                empty_upload_before_manifest
                    .message()
                    .contains("bucket upload must contain")
            );
            assert!(
                !empty_upload_before_manifest
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !empty_upload_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !empty_upload_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !empty_upload_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(
                !empty_upload_before_manifest
                    .message()
                    .contains("private_result_oram")
            );
            assert!(!empty_upload_before_manifest.message().contains("manifest"));
            assert_private_result_guard_message_redacts(
                empty_upload_before_manifest.message(),
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
            let duplicate_upload_before_manifest =
                PrivateResultOram::upload_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: duplicate_upload_before_manifest_buckets
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(
                duplicate_upload_before_manifest.code(),
                Code::InvalidArgument
            );
            assert!(
                duplicate_upload_before_manifest
                    .message()
                    .contains("duplicate bucket")
            );
            assert!(
                !duplicate_upload_before_manifest
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !duplicate_upload_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !duplicate_upload_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !duplicate_upload_before_manifest
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(
                !duplicate_upload_before_manifest
                    .message()
                    .contains("private_result_oram")
            );
            assert!(
                !duplicate_upload_before_manifest
                    .message()
                    .contains("manifest")
            );
            assert_private_result_guard_message_redacts(
                duplicate_upload_before_manifest.message(),
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
            let unsupported_manifest_alg = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(unsupported_alg_manifest_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(unsupported_manifest_alg.code(), Code::InvalidArgument);
            assert!(
                unsupported_manifest_alg
                    .message()
                    .contains("request validation failed")
            );
            assert!(
                !unsupported_manifest_alg
                    .message()
                    .contains(unsupported_manifest_alg_sentinel),
                "{}",
                unsupported_manifest_alg.message()
            );
            assert!(
                !unsupported_manifest_alg
                    .message()
                    .contains(&unsupported_alg_manifest_key_id),
                "{}",
                unsupported_manifest_alg.message()
            );
            assert!(
                !unsupported_manifest_alg
                    .message()
                    .contains(&unsupported_alg_manifest_sig),
                "{}",
                unsupported_manifest_alg.message()
            );
            assert!(
                !unsupported_manifest_alg
                    .message()
                    .contains(&fixture.manifest.root_hash),
                "{}",
                unsupported_manifest_alg.message()
            );

            let manifest_signature_sentinel = "result-manifest-signature!sentinel";
            let malformed_manifest_signature =
                PrivateResultOram::upload_private_result_oram_manifest(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramManifestRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                        signature: Some(grpc::PrivateResultOramSignature {
                            alg: "ed25519".to_string(),
                            key_id: SIGNING_KEY_ID.to_string(),
                            sig: manifest_signature_sentinel.to_string(),
                        }),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(malformed_manifest_signature.code(), Code::InvalidArgument);
            assert!(
                malformed_manifest_signature
                    .message()
                    .contains("request validation failed")
            );
            assert!(
                !malformed_manifest_signature
                    .message()
                    .contains(manifest_signature_sentinel),
                "{}",
                malformed_manifest_signature.message()
            );
            assert!(
                !malformed_manifest_signature
                    .message()
                    .contains(&fixture.manifest.root_hash),
                "{}",
                malformed_manifest_signature.message()
            );

            let mut bad_manifest_signature = fixture.signature.clone();
            let replacement = if bad_manifest_signature.sig.starts_with('A') {
                "B"
            } else {
                "A"
            };
            bad_manifest_signature.sig.replace_range(0..1, replacement);
            let bad_manifest_signature_sig = bad_manifest_signature.sig.clone();
            let bad_manifest_signature = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(bad_manifest_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(bad_manifest_signature.code(), Code::InvalidArgument);
            assert!(
                bad_manifest_signature
                    .message()
                    .contains("manifest signature verification failed")
            );
            assert!(
                !bad_manifest_signature
                    .message()
                    .contains(&bad_manifest_signature_sig),
                "{}",
                bad_manifest_signature.message()
            );
            assert!(
                !bad_manifest_signature
                    .message()
                    .contains(&fixture.manifest.root_hash),
                "{}",
                bad_manifest_signature.message()
            );

            let mut alt_manifest_signature = fixture.signature.clone();
            alt_manifest_signature.key_id = ALT_SIGNING_KEY_ID.to_string();
            let alt_manifest_signature_sig = alt_manifest_signature.sig.clone();
            let alt_manifest_key = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(alt_manifest_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(alt_manifest_key.code(), Code::InvalidArgument);
            assert!(
                alt_manifest_key
                    .message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!alt_manifest_key.message().contains(ALT_SIGNING_KEY_ID));
            assert!(
                !alt_manifest_key
                    .message()
                    .contains(&fixture.manifest.owner_signing_key_id)
            );
            for sentinel in [
                fixture.manifest.root_hash.as_str(),
                alt_manifest_signature_sig.as_str(),
            ] {
                assert!(
                    !alt_manifest_key.message().contains(sentinel),
                    "{}",
                    alt_manifest_key.message()
                );
            }

            let mut unconfigured_manifest_signature = fixture.signature.clone();
            unconfigured_manifest_signature.key_id = UNCONFIGURED_SIGNING_KEY_ID.to_string();
            let unconfigured_manifest_signature_sig = unconfigured_manifest_signature.sig.clone();
            let unconfigured_manifest_key = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(unconfigured_manifest_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(unconfigured_manifest_key.code(), Code::InvalidArgument);
            assert!(
                unconfigured_manifest_key
                    .message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(
                !unconfigured_manifest_key
                    .message()
                    .contains(UNCONFIGURED_SIGNING_KEY_ID)
            );
            assert!(
                !unconfigured_manifest_key
                    .message()
                    .contains("not configured")
            );
            assert!(
                !unconfigured_manifest_key
                    .message()
                    .contains(&fixture.manifest.owner_signing_key_id)
            );
            for sentinel in [
                fixture.manifest.root_hash.as_str(),
                unconfigured_manifest_signature_sig.as_str(),
            ] {
                assert!(
                    !unconfigured_manifest_key.message().contains(sentinel),
                    "{}",
                    unconfigured_manifest_key.message()
                );
            }

            macro_rules! assert_manifest_mismatch_error_redacts {
                ($message:expr, $signature_sig:expr) => {{
                    assert!(
                        !$message.contains(&fixture.manifest.root_hash),
                        "{}",
                        $message
                    );
                    assert!(!$message.contains($signature_sig), "{}", $message);
                    assert!(!$message.contains("private_result_oram"), "{}", $message);
                    assert_private_result_guard_message_redacts(
                        $message,
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
            let err = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_collection_manifest)),
                    signature: Some(signature_to_proto(mismatched_collection_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert_manifest_mismatch_error_redacts!(
                err.message(),
                &mismatched_collection_signature_sig
            );
            assert!(!err.message().contains(mismatched_collection_id));

            let mut mismatched_key_manifest = fixture.manifest.clone();
            let mismatched_key_id = "tenant-b/result-private-rk";
            mismatched_key_manifest.key_id = mismatched_key_id.to_string();
            let mismatched_key_signature = fixture.sign_manifest(&mismatched_key_manifest);
            let mismatched_key_signature_sig = mismatched_key_signature.sig.clone();
            let err = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_key_manifest)),
                    signature: Some(signature_to_proto(mismatched_key_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert_manifest_mismatch_error_redacts!(err.message(), &mismatched_key_signature_sig);
            assert!(!err.message().contains(mismatched_key_id));

            let mut mismatched_epoch_manifest = fixture.manifest.clone();
            mismatched_epoch_manifest.rk_epoch += 1;
            let mismatched_epoch_signature = fixture.sign_manifest(&mismatched_epoch_manifest);
            let mismatched_epoch_signature_sig = mismatched_epoch_signature.sig.clone();
            let err = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_epoch_manifest)),
                    signature: Some(signature_to_proto(mismatched_epoch_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert_manifest_mismatch_error_redacts!(err.message(), &mismatched_epoch_signature_sig);

            let mut mismatched_bucket_count_manifest = fixture.manifest.clone();
            mismatched_bucket_count_manifest.bucket_count -= 1;
            let mismatched_bucket_count_signature_sig = fixture.signature.sig.clone();
            let err = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_bucket_count_manifest)),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert_manifest_mismatch_error_redacts!(
                err.message(),
                &mismatched_bucket_count_signature_sig
            );
            assert!(!err.message().contains("bucket_count"));

            let mut mismatched_oram_manifest = fixture.manifest.clone();
            mismatched_oram_manifest.oram.bucket_size = 4;
            let mismatched_oram_signature = fixture.sign_manifest(&mismatched_oram_manifest);
            let mismatched_oram_signature_sig = mismatched_oram_signature.sig.clone();
            let err = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_oram_manifest)),
                    signature: Some(signature_to_proto(mismatched_oram_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert_manifest_mismatch_error_redacts!(err.message(), &mismatched_oram_signature_sig);
            assert!(!err.message().contains("bucket_size"));

            let manifest_epoch = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(manifest_epoch.index_epoch, BASE_EPOCH);
            assert_eq!(manifest_epoch.root_hash, fixture.manifest.root_hash);

            let manifest_read = PrivateResultOram::get_private_result_oram_manifest(
                &service,
                Request::new(grpc::GetPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(
                manifest_read.manifest.unwrap().root_hash,
                fixture.manifest.root_hash
            );
            assert_eq!(manifest_read.signature.unwrap().key_id, SIGNING_KEY_ID);

            let bucket_upload_wrong_root = BASE64URL_NOPAD.encode(&[12; 32]);
            let bucket_upload_wrong_root_err =
                PrivateResultOram::upload_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: bucket_upload_wrong_root.clone(),
                        buckets: fixture
                            .buckets
                            .clone()
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(bucket_upload_wrong_root_err.code(), Code::InvalidArgument);
            assert!(
                bucket_upload_wrong_root_err
                    .message()
                    .contains("bucket upload epoch/root does not match current manifest epoch")
            );
            assert!(
                !bucket_upload_wrong_root_err
                    .message()
                    .contains(&bucket_upload_wrong_root)
            );
            assert!(
                !bucket_upload_wrong_root_err
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !bucket_upload_wrong_root_err
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !bucket_upload_wrong_root_err
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );

            let bucket_upload_root_sentinel = "AAAA";
            let malformed_bucket_upload_root_err =
                PrivateResultOram::upload_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: bucket_upload_root_sentinel.to_string(),
                        buckets: fixture
                            .buckets
                            .clone()
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(
                malformed_bucket_upload_root_err.code(),
                Code::InvalidArgument
            );
            assert!(
                malformed_bucket_upload_root_err
                    .message()
                    .contains("root_hash must be a base64url sha256 value")
            );
            assert!(
                !malformed_bucket_upload_root_err
                    .message()
                    .contains(bucket_upload_root_sentinel)
            );

            let empty_bucket_upload = PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: Vec::new(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(empty_bucket_upload.code(), Code::InvalidArgument);
            assert!(
                empty_bucket_upload
                    .message()
                    .contains("bucket upload must contain")
            );
            assert!(
                !empty_bucket_upload
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !empty_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !empty_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !empty_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(
                !empty_bucket_upload
                    .message()
                    .contains("private_result_oram")
            );
            assert!(!empty_bucket_upload.message().contains("manifest"));

            let mut hash_mismatch_buckets = fixture.buckets.clone();
            hash_mismatch_buckets[0].ciphertext =
                BASE64URL_NOPAD.encode(b"private-result-upload-ciphertext-sentinel");
            let hash_mismatch_ciphertext = hash_mismatch_buckets[0].ciphertext.clone();
            let bucket_upload_hash_mismatch_err =
                PrivateResultOram::upload_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: hash_mismatch_buckets
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(
                bucket_upload_hash_mismatch_err.code(),
                Code::InvalidArgument
            );
            assert!(
                bucket_upload_hash_mismatch_err
                    .message()
                    .contains("bucket ciphertext validation failed")
            );
            assert!(
                !bucket_upload_hash_mismatch_err
                    .message()
                    .contains("private-result-upload-ciphertext-sentinel")
            );
            assert!(
                !bucket_upload_hash_mismatch_err
                    .message()
                    .contains(&hash_mismatch_ciphertext)
            );

            let mut duplicate_bucket_set = fixture.buckets.clone();
            assert!(
                duplicate_bucket_set.len() >= 2,
                "route fixture must contain at least two ORAM buckets"
            );
            duplicate_bucket_set[1] = duplicate_bucket_set[0].clone();
            let duplicate_bucket_upload = PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: duplicate_bucket_set
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(duplicate_bucket_upload.code(), Code::InvalidArgument);
            assert!(
                duplicate_bucket_upload
                    .message()
                    .contains("duplicate bucket")
            );
            assert!(
                !duplicate_bucket_upload
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !duplicate_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !duplicate_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !duplicate_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(
                !duplicate_bucket_upload
                    .message()
                    .contains("private_result_oram")
            );

            let bucket_epoch = PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(bucket_epoch.index_epoch, BASE_EPOCH);

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
            let err = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: active_snapshot_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("active collection snapshot"));
            assert!(!err.message().contains(&fixture.manifest.root_hash));
            assert!(!err.message().contains("private_result_oram"));
            assert!(!err.message().contains(active_snapshot_client_id));
            assert_private_result_guard_message_redacts(
                err.message(),
                &[
                    active_snapshot_client_id,
                    &fixture.manifest.root_hash,
                    &fixture.signature.sig,
                ],
            );
            let err = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("active collection snapshot"));
            assert!(!err.message().contains(&fixture.manifest.root_hash));
            assert!(!err.message().contains("private_result_oram"));
            assert_private_result_guard_message_redacts(
                err.message(),
                &[&fixture.manifest.root_hash, &fixture.signature.sig],
            );
            let mut active_snapshot_bucket_upload = fixture.buckets.clone();
            active_snapshot_bucket_upload[0].ciphertext =
                "active-result-snapshot-bucket-ciphertext-sentinel".to_string();
            let err = PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: active_snapshot_bucket_upload
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("active collection snapshot"));
            assert!(
                !err.message()
                    .contains("active-result-snapshot-bucket-ciphertext-sentinel")
            );
            assert!(
                !err.message().contains(&fixture.manifest.root_hash),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("private_result_oram"));
            assert_private_result_guard_message_redacts(
                err.message(),
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
            let err = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: active_lifecycle_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("active collection lifecycle operation")
            );
            assert!(!err.message().contains(&fixture.manifest.root_hash));
            assert!(!err.message().contains("private_result_oram"));
            assert!(!err.message().contains(active_lifecycle_client_id));
            assert_private_result_guard_message_redacts(
                err.message(),
                &[
                    active_lifecycle_client_id,
                    &fixture.manifest.root_hash,
                    &fixture.signature.sig,
                ],
            );
            let err = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("active collection lifecycle operation")
            );
            assert!(!err.message().contains(&fixture.manifest.root_hash));
            assert!(!err.message().contains("private_result_oram"));
            assert_private_result_guard_message_redacts(
                err.message(),
                &[&fixture.manifest.root_hash, &fixture.signature.sig],
            );
            let mut active_lifecycle_bucket_upload = fixture.buckets.clone();
            active_lifecycle_bucket_upload[0].ciphertext =
                "active-result-lifecycle-bucket-ciphertext-sentinel".to_string();
            let err = PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: active_lifecycle_bucket_upload
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("active collection lifecycle operation")
            );
            assert!(
                !err.message()
                    .contains("active-result-lifecycle-bucket-ciphertext-sentinel")
            );
            assert!(
                !err.message().contains(&fixture.manifest.root_hash),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("private_result_oram"));
            assert_private_result_guard_message_redacts(
                err.message(),
                &[
                    "active-result-lifecycle-bucket-ciphertext-sentinel",
                    &fixture.manifest.root_hash,
                ],
            );
            drop(lifecycle_guard);

            let client_id_sentinel = "result-session-client-id-sentinel";
            let err = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: format!("{client_id_sentinel}{}", "x".repeat(260)),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("client_id must be non-empty and at most 256 bytes")
            );
            assert!(
                !err.message().contains(client_id_sentinel),
                "{}",
                err.message()
            );

            let malformed_client_id_sentinel = "result-session-client-id!sentinel";
            let err = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: malformed_client_id_sentinel.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("client_id is invalid"));
            assert!(
                !err.message().contains(malformed_client_id_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains("client_id must be non-empty and at most 256 bytes"),
                "{}",
                err.message()
            );

            let fixed_budget_client_id = "tenant-a/sdk-instance-fixed-budget-off";
            let err = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: fixed_budget_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: false,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("strict mode requires fixed_budget=true")
            );
            assert!(
                !err.message().contains(fixed_budget_client_id),
                "{}",
                err.message()
            );

            let stale_epoch_client_id = "tenant-a/sdk-instance-stale-epoch";
            let err = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: stale_epoch_client_id.to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("requested epoch"));
            assert!(!err.message().contains(&NEXT_EPOCH.to_string()));
            assert!(!err.message().contains(&BASE_EPOCH.to_string()));
            assert!(!err.message().contains(stale_epoch_client_id));

            let session = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(session.collection_id, COLLECTION_ID);
            assert_eq!(session.index_epoch, BASE_EPOCH);

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
            let stale_current_read_session_id = session.session_id.clone();
            let stale_current_read_root_hash = fixture.manifest.root_hash.clone();
            let stale_current_read_signature_key_id = stale_current_read_signature.key_id.clone();
            let stale_current_read_signature_sig = stale_current_read_signature.sig.clone();
            let err = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: stale_current_read_session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: stale_current_read_root_hash.clone(),
                    bucket_ids: stale_current_read_bucket_ids,
                    read_signature: Some(signature_to_proto(stale_current_read_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("current epoch/root does not match active session")
            );
            assert!(
                !err.message()
                    .contains("read_buckets current epoch/root does not match active session")
            );
            assert!(
                !err.message().contains(&stale_current_read_root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&stale_current_root),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&stale_current_read_session_id),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&stale_current_read_signature_key_id),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&stale_current_read_signature_sig),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&fixture.buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&fixture.buckets[0].ciphertext_sha256),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&fixture.buckets[0].bucket_commitment),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("private_result_oram"));
            assert!(!err.message().contains("/tmp"));

            let (
                stale_current_updated_bucket,
                stale_current_commit_signature,
                stale_current_new_root,
            ) = fixture.commit_bucket();
            let stale_current_commit_session_id = session.session_id.clone();
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
            let err = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: stale_current_commit_session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: stale_current_commit_old_root_hash.clone(),
                    new_root_hash: stale_current_new_root.clone(),
                    updated_buckets: vec![bucket_to_proto(stale_current_updated_bucket)],
                    commit_signature: Some(signature_to_proto(stale_current_commit_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("current epoch/root does not match active session")
            );
            assert!(
                !err.message()
                    .contains("commit current epoch/root does not match active session")
            );
            assert!(
                !err.message().contains(&stale_current_commit_old_root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&stale_current_new_root),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&stale_current_root),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&stale_current_commit_session_id),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&stale_current_commit_signature_key_id),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&stale_current_commit_signature_sig),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&stale_current_commit_bucket_ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&stale_current_commit_bucket_ciphertext_sha256),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&stale_current_commit_bucket_commitment),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("private_result_oram"));
            assert!(!err.message().contains("/tmp"));
            std::fs::write(&current_epoch_path, original_current_epoch_bytes).unwrap();

            let duplicate_session_client_id = "tenant-a/sdk-instance-2";
            let duplicate_session = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: duplicate_session_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(duplicate_session.code(), Code::InvalidArgument);
            assert!(duplicate_session.message().contains("active session"));
            assert!(
                !duplicate_session
                    .message()
                    .contains(duplicate_session_client_id)
            );
            assert_private_result_guard_message_redacts(
                duplicate_session.message(),
                &[duplicate_session_client_id, &session.session_id],
            );

            let active_manifest_upload = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(active_manifest_upload.code(), Code::InvalidArgument);
            assert!(
                active_manifest_upload
                    .message()
                    .contains("upload requires no active session")
            );
            assert!(
                !active_manifest_upload
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !active_manifest_upload
                    .message()
                    .contains(&session.session_id)
            );
            assert_private_result_guard_message_redacts(
                active_manifest_upload.message(),
                &[
                    &fixture.manifest.root_hash,
                    &fixture.signature.sig,
                    &session.session_id,
                ],
            );

            let active_bucket_upload = PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(active_bucket_upload.code(), Code::InvalidArgument);
            assert!(
                active_bucket_upload
                    .message()
                    .contains("upload requires no active session")
            );
            assert!(
                !active_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !active_bucket_upload
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!active_bucket_upload.message().contains(&session.session_id));
            assert_private_result_guard_message_redacts(
                active_bucket_upload.message(),
                &[
                    &fixture.buckets[0].ciphertext,
                    &fixture.manifest.root_hash,
                    &session.session_id,
                ],
            );

            let active_snapshot_error = crate::common::collections::do_create_snapshot(
                Arc::new(dispatcher.clone()),
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
                !active_snapshot_error.contains(&session.session_id),
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
            assert_private_result_guard_message_redacts(
                &active_snapshot_error,
                &[
                    &session.session_id,
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
                !active_full_snapshot_error.contains(&session.session_id),
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
            assert_private_result_guard_message_redacts(
                &active_full_snapshot_error,
                &[
                    &session.session_id,
                    &fixture.manifest.root_hash,
                    &fixture.buckets[0].ciphertext,
                    &fixture.signature.sig,
                ],
            );

            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(
                        fixture.read_signature(&read_bucket_ids),
                    )),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(
                read.proof.unwrap().kind,
                PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND
            );
            assert_eq!(read.buckets.len(), 6);
            assert_eq!(read.buckets[0].bucket_id, 0);
            let proof_mismatched_bucket_id = read.buckets[0].bucket_id;
            let bucket_path = uploaded_store
                .root_path()
                .join("buckets")
                .join(format!("{proof_mismatched_bucket_id:08}.bucket"));
            let original_bucket_bytes = std::fs::read(&bucket_path).unwrap();
            let mut proof_mismatched_bucket = bucket_from_proto(read.buckets[0].clone()).unwrap();
            proof_mismatched_bucket.bucket_commitment =
                data_encoding::BASE64URL_NOPAD.encode(&[91; 32]);
            std::fs::write(
                &bucket_path,
                serde_json::to_vec_pretty(&proof_mismatched_bucket).unwrap(),
            )
            .unwrap();
            let proof_mismatch_signature = fixture.read_signature(&read_bucket_ids);
            let proof_mismatch_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(proof_mismatch_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(proof_mismatch_read.code(), Code::InvalidArgument);
            assert!(
                proof_mismatch_read
                    .message()
                    .contains("encrypted bucket store validation failed")
            );
            assert!(
                !proof_mismatch_read
                    .message()
                    .contains(&proof_mismatched_bucket.ciphertext),
                "{}",
                proof_mismatch_read.message()
            );
            assert!(
                !proof_mismatch_read
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!proof_mismatch_read.message().contains(&session.session_id));
            assert!(
                !proof_mismatch_read
                    .message()
                    .contains("private_result_oram")
            );
            assert!(!proof_mismatch_read.message().contains("/tmp"));
            assert_private_result_guard_message_redacts(
                proof_mismatch_read.message(),
                &[
                    proof_mismatched_bucket.ciphertext.as_str(),
                    fixture.manifest.root_hash.as_str(),
                    session.session_id.as_str(),
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
            let future_bucket_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(
                        fixture.read_signature(&read_bucket_ids),
                    )),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(future_bucket_read.code(), Code::InvalidArgument);
            assert!(
                future_bucket_read
                    .message()
                    .contains("encrypted bucket store validation failed")
            );
            assert!(
                !future_bucket_read
                    .message()
                    .contains(&future_bucket.ciphertext)
            );
            assert!(
                !future_bucket_read
                    .message()
                    .contains(&future_bucket.ciphertext_sha256)
            );
            assert!(
                !future_bucket_read
                    .message()
                    .contains(&future_bucket.bucket_commitment)
            );
            assert!(!future_bucket_read.message().contains("index_epoch"));
            assert!(
                !future_bucket_read
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!future_bucket_read.message().contains(&session.session_id));
            assert!(!future_bucket_read.message().contains("private_result_oram"));
            assert_private_result_guard_message_redacts(
                future_bucket_read.message(),
                &[
                    future_bucket.ciphertext.as_str(),
                    future_bucket.ciphertext_sha256.as_str(),
                    future_bucket.bucket_commitment.as_str(),
                    "index_epoch",
                    fixture.manifest.root_hash.as_str(),
                    session.session_id.as_str(),
                    "/tmp",
                ],
            );
            std::fs::write(&future_bucket_path, &original_future_bucket_bytes).unwrap();

            let read_wrong_root = BASE64URL_NOPAD.encode(&[9; 32]);
            let read_wrong_root_err = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: read_wrong_root.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(
                        fixture.read_signature(&read_bucket_ids),
                    )),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(read_wrong_root_err.code(), Code::InvalidArgument);
            assert!(
                read_wrong_root_err
                    .message()
                    .contains("session epoch/root mismatch")
            );
            assert!(!read_wrong_root_err.message().contains(&read_wrong_root));
            assert!(
                !read_wrong_root_err
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );

            let read_root_sentinel = "AAAA";
            let malformed_read_root_signature = fixture.read_signature(&read_bucket_ids);
            let malformed_read_root_signature_key_id = malformed_read_root_signature.key_id.clone();
            let malformed_read_root_signature_sig = malformed_read_root_signature.sig.clone();
            let malformed_read_root_err = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: read_root_sentinel.to_string(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(malformed_read_root_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(malformed_read_root_err.code(), Code::InvalidArgument);
            assert!(
                malformed_read_root_err
                    .message()
                    .contains("root_hash must be a base64url sha256 value")
            );
            assert!(
                !malformed_read_root_err
                    .message()
                    .contains(read_root_sentinel)
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                malformed_read_root_signature_key_id.as_str(),
                malformed_read_root_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
            ] {
                assert!(
                    !malformed_read_root_err.message().contains(sentinel),
                    "{}",
                    malformed_read_root_err.message()
                );
            }

            let wrong_read_signature = fixture.read_signature(&[0, 1, 4, 0, 1, 3]);
            let invalid_read_signature = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(wrong_read_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(invalid_read_signature.code(), Code::InvalidArgument);
            assert!(
                invalid_read_signature
                    .message()
                    .contains("read_buckets signature verification failed")
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                wrong_read_signature.key_id.as_str(),
                wrong_read_signature.sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !invalid_read_signature.message().contains(sentinel),
                    "{}",
                    invalid_read_signature.message()
                );
            }

            let invalid_signature_bad_path = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: vec![0, 2, 3, 0, 1, 4],
                    read_signature: Some(signature_to_proto(wrong_read_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(invalid_signature_bad_path.code(), Code::InvalidArgument);
            assert!(
                invalid_signature_bad_path
                    .message()
                    .contains("read_buckets signature verification failed")
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                wrong_read_signature.key_id.as_str(),
                wrong_read_signature.sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
            ] {
                assert!(
                    !invalid_signature_bad_path.message().contains(sentinel),
                    "{}",
                    invalid_signature_bad_path.message()
                );
            }
            assert!(
                !invalid_signature_bad_path
                    .message()
                    .contains("valid ORAM paths")
            );

            let invalid_signature_out_of_range =
                PrivateResultOram::read_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id.clone(),
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.manifest.root_hash.clone(),
                        bucket_ids: vec![0, 1, fixture.manifest.bucket_count, 0, 1, 4],
                        read_signature: Some(signature_to_proto(wrong_read_signature.clone())),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(invalid_signature_out_of_range.code(), Code::InvalidArgument);
            assert!(
                invalid_signature_out_of_range
                    .message()
                    .contains("read_buckets signature verification failed")
            );
            assert!(
                !invalid_signature_out_of_range
                    .message()
                    .contains(&wrong_read_signature.sig)
            );
            assert!(
                !invalid_signature_out_of_range
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !invalid_signature_out_of_range
                    .message()
                    .contains(&session.session_id)
            );
            assert!(
                !invalid_signature_out_of_range
                    .message()
                    .contains("bucket id is out of range")
            );
            assert!(
                !invalid_signature_out_of_range
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !invalid_signature_out_of_range
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !invalid_signature_out_of_range
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );

            let unconfigured_read_key_id_sentinel = "tenant-a/private-result-signing-v1-unknown";
            let mut unconfigured_read_key_signature = fixture.read_signature(&read_bucket_ids);
            unconfigured_read_key_signature.key_id = unconfigured_read_key_id_sentinel.to_string();
            let unconfigured_read_key_signature_sig = unconfigured_read_key_signature.sig.clone();
            let unconfigured_read_key = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(unconfigured_read_key_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(unconfigured_read_key.code(), Code::InvalidArgument);
            assert!(
                unconfigured_read_key
                    .message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!unconfigured_read_key.message().contains("not configured"));
            assert!(
                !unconfigured_read_key
                    .message()
                    .contains(unconfigured_read_key_id_sentinel)
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                unconfigured_read_key_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !unconfigured_read_key.message().contains(sentinel),
                    "{}",
                    unconfigured_read_key.message()
                );
            }

            let malformed_read_key_id_sentinel = "result-read-signature-key!sentinel";
            let mut malformed_read_key_signature = fixture.read_signature(&read_bucket_ids);
            malformed_read_key_signature.key_id = malformed_read_key_id_sentinel.to_string();
            let malformed_read_key = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(malformed_read_key_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(malformed_read_key.code(), Code::InvalidArgument);
            assert!(
                malformed_read_key
                    .message()
                    .contains("request validation failed")
            );
            assert!(
                !malformed_read_key
                    .message()
                    .contains(malformed_read_key_id_sentinel)
            );
            assert!(
                !malformed_read_key
                    .message()
                    .contains("owner_signing_key_id")
            );
            let expected_read_signature = fixture.read_signature(&read_bucket_ids);
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                expected_read_signature.sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !malformed_read_key.message().contains(sentinel),
                    "{}",
                    malformed_read_key.message()
                );
            }

            let alt_read_signature = fixture.read_signature_with_alt_key(&read_bucket_ids);
            let alt_read_signature_sig = alt_read_signature.sig.clone();
            let alt_read_key = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(alt_read_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(alt_read_key.code(), Code::InvalidArgument);
            assert!(
                alt_read_key
                    .message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!alt_read_key.message().contains(ALT_SIGNING_KEY_ID));
            assert!(
                !alt_read_key
                    .message()
                    .contains(&fixture.manifest.owner_signing_key_id)
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                alt_read_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !alt_read_key.message().contains(sentinel),
                    "{}",
                    alt_read_key.message()
                );
            }

            let signature_body_sentinel = "signature!sentinel";
            let malformed_read_signature = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(grpc::PrivateResultOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: signature_body_sentinel.to_string(),
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(malformed_read_signature.code(), Code::InvalidArgument);
            assert!(
                malformed_read_signature
                    .message()
                    .contains("request validation failed")
            );
            assert!(
                !malformed_read_signature
                    .message()
                    .contains(signature_body_sentinel)
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                SIGNING_KEY_ID,
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !malformed_read_signature.message().contains(sentinel),
                    "{}",
                    malformed_read_signature.message()
                );
            }

            let read_signature_alg_sentinel = "rsa-pss-result-read-sentinel";
            let mut unsupported_read_signature = fixture.read_signature(&read_bucket_ids);
            unsupported_read_signature.alg = read_signature_alg_sentinel.to_string();
            let unsupported_read_key_id = unsupported_read_signature.key_id.clone();
            let unsupported_read_sig = unsupported_read_signature.sig.clone();
            let unsupported_read_signature = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(unsupported_read_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(unsupported_read_signature.code(), Code::InvalidArgument);
            assert!(
                unsupported_read_signature
                    .message()
                    .contains("request validation failed")
            );
            assert!(
                !unsupported_read_signature
                    .message()
                    .contains(read_signature_alg_sentinel)
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                unsupported_read_key_id.as_str(),
                unsupported_read_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !unsupported_read_signature.message().contains(sentinel),
                    "{}",
                    unsupported_read_signature.message()
                );
            }

            let deduped_bucket_ids = vec![0, 1, 3, 4];
            let deduped_path_signature = fixture.read_signature(&read_bucket_ids);
            let deduped_path_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: deduped_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(deduped_path_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(deduped_path_read.code(), Code::InvalidArgument);
            assert!(deduped_path_read.message().contains("whole ORAM paths"));
            assert!(
                !deduped_path_read
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !deduped_path_read
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !deduped_path_read
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(
                !deduped_path_read
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!deduped_path_read.message().contains(&session.session_id));
            assert!(
                !deduped_path_read
                    .message()
                    .contains(&deduped_path_signature.key_id)
            );
            assert!(
                !deduped_path_read
                    .message()
                    .contains(&deduped_path_signature.sig)
            );

            let under_budget_bucket_ids = vec![0, 1, 3];
            let under_budget_signature = fixture.read_signature(&read_bucket_ids);
            let under_budget_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: under_budget_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(under_budget_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(under_budget_read.code(), Code::InvalidArgument);
            assert!(under_budget_read.message().contains("fixed path budget"));
            assert!(
                !under_budget_read
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !under_budget_read
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !under_budget_read
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(
                !under_budget_read
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!under_budget_read.message().contains(&session.session_id));
            assert!(
                !under_budget_read
                    .message()
                    .contains(&under_budget_signature.key_id)
            );
            assert!(
                !under_budget_read
                    .message()
                    .contains(&under_budget_signature.sig)
            );

            let duplicate_path_bucket_ids = vec![0, 1, 3, 0, 1, 3];
            let duplicate_path_signature = fixture.read_signature(&read_bucket_ids);
            let duplicate_path_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: duplicate_path_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(duplicate_path_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(duplicate_path_read.code(), Code::InvalidArgument);
            assert!(
                duplicate_path_read
                    .message()
                    .contains("duplicate ORAM path")
            );
            assert!(
                !duplicate_path_read
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !duplicate_path_read
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !duplicate_path_read
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(
                !duplicate_path_read
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!duplicate_path_read.message().contains(&session.session_id));
            assert!(
                !duplicate_path_read
                    .message()
                    .contains(&duplicate_path_signature.key_id)
            );
            assert!(
                !duplicate_path_read
                    .message()
                    .contains(&duplicate_path_signature.sig)
            );
            assert!(
                !duplicate_path_read
                    .message()
                    .contains("read_buckets signature verification failed")
            );

            let malformed_path_bucket_ids = vec![0, 2, 3, 0, 1, 4];
            let malformed_path_signature = fixture.read_signature(&read_bucket_ids);
            let malformed_path_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: malformed_path_bucket_ids,
                    read_signature: Some(signature_to_proto(malformed_path_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(malformed_path_read.code(), Code::InvalidArgument);
            assert!(
                malformed_path_read
                    .message()
                    .contains("read_buckets signature verification failed")
            );
            assert!(
                !malformed_path_read
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!malformed_path_read.message().contains(&session.session_id));
            assert!(
                !malformed_path_read
                    .message()
                    .contains(&malformed_path_signature.sig)
            );
            assert!(
                !malformed_path_read
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !malformed_path_read
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !malformed_path_read
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );
            assert!(!malformed_path_read.message().contains("valid ORAM paths"));

            let unknown_read_session_sentinel = "read-session-id-sentinel";
            let unknown_read_session_signature = fixture.read_signature(&read_bucket_ids);
            let unknown_read_session_signature_sig = unknown_read_session_signature.sig.clone();
            let unknown_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: unknown_read_session_sentinel.to_string(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(unknown_read_session_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(unknown_read.code(), Code::InvalidArgument);
            assert!(
                unknown_read
                    .message()
                    .contains("session is missing or expired")
            );
            assert!(
                !unknown_read
                    .message()
                    .contains(unknown_read_session_sentinel),
                "{}",
                unknown_read.message()
            );
            for sentinel in [
                fixture.manifest.root_hash.as_str(),
                unknown_read_session_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !unknown_read.message().contains(sentinel),
                    "{}",
                    unknown_read.message()
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
                let err = PrivateResultOram::read_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: invalid_session_id.to_string(),
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.manifest.root_hash.clone(),
                        bucket_ids: read_bucket_ids.clone(),
                        read_signature: Some(signature_to_proto(invalid_read_signature)),
                    }),
                )
                .await
                .unwrap_err();
                assert_eq!(err.code(), Code::InvalidArgument);
                assert!(err.message().contains("session_id is invalid"));
                assert!(
                    !err.message().contains(invalid_session_id),
                    "{}",
                    err.message()
                );
                assert!(
                    !err.message().contains("session is missing or expired"),
                    "{}",
                    err.message()
                );
                for sentinel in [
                    fixture.manifest.root_hash.as_str(),
                    invalid_read_signature_sig.as_str(),
                ] {
                    assert!(!err.message().contains(sentinel), "{}", err.message());
                }
            }

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let unknown_commit_session_sentinel = "commit-session-id-sentinel";
            let unknown_commit = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: unknown_commit_session_sentinel.to_string(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(unknown_commit.code(), Code::InvalidArgument);
            assert!(
                unknown_commit
                    .message()
                    .contains("session is missing or expired")
            );
            assert!(
                !unknown_commit
                    .message()
                    .contains(unknown_commit_session_sentinel),
                "{}",
                unknown_commit.message()
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
                    !unknown_commit.message().contains(sentinel),
                    "{}",
                    unknown_commit.message()
                );
            }

            let oversized_commit_session_id = "s".repeat(129);
            let malformed_commit_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_commit_session_id.as_str(),
                malformed_commit_session_id,
            ] {
                let err = PrivateResultOram::commit_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: invalid_session_id.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                        commit_signature: Some(signature_to_proto(commit_signature.clone())),
                    }),
                )
                .await
                .unwrap_err();
                assert_eq!(err.code(), Code::InvalidArgument);
                assert!(err.message().contains("session_id is invalid"));
                assert!(
                    !err.message().contains(invalid_session_id),
                    "{}",
                    err.message()
                );
                assert!(
                    !err.message().contains("session is missing or expired"),
                    "{}",
                    err.message()
                );
                for sentinel in [
                    fixture.manifest.root_hash.as_str(),
                    new_root_hash.as_str(),
                    commit_signature.sig.as_str(),
                    updated_bucket.ciphertext.as_str(),
                    updated_bucket.ciphertext_sha256.as_str(),
                    updated_bucket.bucket_commitment.as_str(),
                ] {
                    assert!(!err.message().contains(sentinel), "{}", err.message());
                }
            }

            let commit_wrong_old_root = BASE64URL_NOPAD.encode(&[10; 32]);
            let commit_wrong_old_root_err = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_wrong_old_root.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(commit_wrong_old_root_err.code(), Code::InvalidArgument);
            assert!(
                commit_wrong_old_root_err
                    .message()
                    .contains("commit old epoch/root does not match active session")
            );
            assert!(
                !commit_wrong_old_root_err
                    .message()
                    .contains(&commit_wrong_old_root)
            );
            assert!(
                !commit_wrong_old_root_err
                    .message()
                    .contains(&updated_bucket.ciphertext)
            );
            assert!(
                !commit_wrong_old_root_err
                    .message()
                    .contains(&updated_bucket.ciphertext_sha256)
            );
            assert!(
                !commit_wrong_old_root_err
                    .message()
                    .contains(&updated_bucket.bucket_commitment)
            );
            assert!(!commit_wrong_old_root_err.message().contains(&new_root_hash));
            assert!(
                !commit_wrong_old_root_err
                    .message()
                    .contains(&session.session_id)
            );
            assert!(
                !commit_wrong_old_root_err
                    .message()
                    .contains(&commit_signature.key_id)
            );
            assert!(
                !commit_wrong_old_root_err
                    .message()
                    .contains(&commit_signature.sig)
            );

            let commit_old_root_sentinel = "AAAA";
            let malformed_commit_old_root_err =
                PrivateResultOram::commit_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id.clone(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: commit_old_root_sentinel.to_string(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                        commit_signature: Some(signature_to_proto(commit_signature.clone())),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(malformed_commit_old_root_err.code(), Code::InvalidArgument);
            assert!(
                malformed_commit_old_root_err
                    .message()
                    .contains("old_root_hash must be a base64url sha256 value")
            );
            assert!(
                !malformed_commit_old_root_err
                    .message()
                    .contains(commit_old_root_sentinel)
            );
            assert!(
                !malformed_commit_old_root_err
                    .message()
                    .contains(&new_root_hash)
            );
            assert!(
                !malformed_commit_old_root_err
                    .message()
                    .contains(&session.session_id)
            );
            assert!(
                !malformed_commit_old_root_err
                    .message()
                    .contains(&commit_signature.key_id)
            );
            assert!(
                !malformed_commit_old_root_err
                    .message()
                    .contains(&commit_signature.sig)
            );
            assert!(
                !malformed_commit_old_root_err
                    .message()
                    .contains(&updated_bucket.ciphertext)
            );
            assert!(
                !malformed_commit_old_root_err
                    .message()
                    .contains(&updated_bucket.ciphertext_sha256)
            );
            assert!(
                !malformed_commit_old_root_err
                    .message()
                    .contains(&updated_bucket.bucket_commitment)
            );

            let commit_wrong_new_root = BASE64URL_NOPAD.encode(&[11; 32]);
            let commit_wrong_new_root_err = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: commit_wrong_new_root.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(commit_wrong_new_root_err.code(), Code::InvalidArgument);
            assert!(
                commit_wrong_new_root_err
                    .message()
                    .contains("commit signature verification failed")
            );
            assert!(
                !commit_wrong_new_root_err
                    .message()
                    .contains(&commit_wrong_new_root)
            );
            assert!(
                !commit_wrong_new_root_err
                    .message()
                    .contains(&commit_signature.sig)
            );
            assert!(
                !commit_wrong_new_root_err
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !commit_wrong_new_root_err
                    .message()
                    .contains(&session.session_id)
            );
            assert!(
                !commit_wrong_new_root_err
                    .message()
                    .contains(&commit_signature.key_id)
            );
            assert!(
                !commit_wrong_new_root_err
                    .message()
                    .contains(&updated_bucket.ciphertext)
            );
            assert!(
                !commit_wrong_new_root_err
                    .message()
                    .contains(&updated_bucket.ciphertext_sha256)
            );
            assert!(
                !commit_wrong_new_root_err
                    .message()
                    .contains(&updated_bucket.bucket_commitment)
            );

            let commit_new_root_sentinel = "AAAA";
            let malformed_commit_new_root_err =
                PrivateResultOram::commit_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id.clone(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: commit_new_root_sentinel.to_string(),
                        updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                        commit_signature: Some(signature_to_proto(commit_signature.clone())),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(malformed_commit_new_root_err.code(), Code::InvalidArgument);
            assert!(
                malformed_commit_new_root_err
                    .message()
                    .contains("new_root_hash must be a base64url sha256 value")
            );
            assert!(
                !malformed_commit_new_root_err
                    .message()
                    .contains(commit_new_root_sentinel)
            );
            assert!(
                !malformed_commit_new_root_err
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !malformed_commit_new_root_err
                    .message()
                    .contains(&session.session_id)
            );
            assert!(
                !malformed_commit_new_root_err
                    .message()
                    .contains(&commit_signature.key_id)
            );
            assert!(
                !malformed_commit_new_root_err
                    .message()
                    .contains(&commit_signature.sig)
            );
            assert!(
                !malformed_commit_new_root_err
                    .message()
                    .contains(&updated_bucket.ciphertext)
            );
            assert!(
                !malformed_commit_new_root_err
                    .message()
                    .contains(&updated_bucket.ciphertext_sha256)
            );
            assert!(
                !malformed_commit_new_root_err
                    .message()
                    .contains(&updated_bucket.bucket_commitment)
            );

            let empty_commit = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![],
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(empty_commit.code(), Code::InvalidArgument);
            assert!(
                empty_commit
                    .message()
                    .contains("commit updated_buckets must contain")
            );
            assert!(!empty_commit.message().contains(&commit_signature.sig));
            assert!(!empty_commit.message().contains(&fixture.manifest.root_hash));
            assert!(!empty_commit.message().contains(&new_root_hash));
            assert!(!empty_commit.message().contains(&session.session_id));
            assert!(!empty_commit.message().contains(&commit_signature.key_id));

            let commit_hash_sentinel = "AAAA";
            let mut malformed_hash_commit_buckets = vec![updated_bucket.clone()];
            malformed_hash_commit_buckets[0].ciphertext_sha256 = commit_hash_sentinel.to_string();
            let malformed_hash_commit = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: malformed_hash_commit_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(malformed_hash_commit.code(), Code::InvalidArgument);
            assert!(
                malformed_hash_commit
                    .message()
                    .contains("ciphertext_sha256")
            );
            assert!(
                !malformed_hash_commit
                    .message()
                    .contains(commit_hash_sentinel)
            );
            assert!(
                !malformed_hash_commit
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!malformed_hash_commit.message().contains(&new_root_hash));
            assert!(
                !malformed_hash_commit
                    .message()
                    .contains(&session.session_id)
            );
            assert!(
                !malformed_hash_commit
                    .message()
                    .contains(&updated_bucket.ciphertext)
            );
            assert!(
                !malformed_hash_commit
                    .message()
                    .contains(&updated_bucket.bucket_commitment)
            );
            assert!(
                !malformed_hash_commit
                    .message()
                    .contains(&commit_signature.key_id)
            );
            assert!(
                !malformed_hash_commit
                    .message()
                    .contains(&commit_signature.sig)
            );
            assert!(
                !malformed_hash_commit
                    .message()
                    .contains("commit signature verification failed")
            );

            let commit_commitment_sentinel = "AAAA";
            let mut malformed_commitment_commit_buckets = vec![updated_bucket.clone()];
            malformed_commitment_commit_buckets[0].bucket_commitment =
                commit_commitment_sentinel.to_string();
            let malformed_commitment_commit =
                PrivateResultOram::commit_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id.clone(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: malformed_commitment_commit_buckets
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                        commit_signature: Some(signature_to_proto(commit_signature.clone())),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(malformed_commitment_commit.code(), Code::InvalidArgument);
            assert!(
                malformed_commitment_commit
                    .message()
                    .contains("bucket_commitment")
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains(commit_commitment_sentinel)
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains(&new_root_hash)
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains(&updated_bucket.ciphertext)
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains(&updated_bucket.ciphertext_sha256)
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains(&updated_bucket.bucket_commitment)
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains(&session.session_id)
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains(&commit_signature.key_id)
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains(&commit_signature.sig)
            );
            assert!(
                !malformed_commitment_commit
                    .message()
                    .contains("commit signature verification failed")
            );

            let oversized_commit = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: (0_u64..8)
                        .map(|bucket_id| {
                            let mut bucket = updated_bucket.clone();
                            bucket.bucket_id = bucket_id;
                            bucket_to_proto(bucket)
                        })
                        .collect(),
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(oversized_commit.code(), Code::InvalidArgument);
            assert!(
                oversized_commit
                    .message()
                    .contains("commit updated_buckets must contain")
            );
            assert!(
                !oversized_commit
                    .message()
                    .contains(&updated_bucket.ciphertext)
            );
            assert!(
                !oversized_commit
                    .message()
                    .contains(&updated_bucket.ciphertext_sha256)
            );
            assert!(
                !oversized_commit
                    .message()
                    .contains(&updated_bucket.bucket_commitment)
            );
            assert!(!oversized_commit.message().contains("duplicate bucket id"));
            assert!(
                !oversized_commit
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!oversized_commit.message().contains(&new_root_hash));
            assert!(!oversized_commit.message().contains(&session.session_id));
            assert!(
                !oversized_commit
                    .message()
                    .contains(&commit_signature.key_id)
            );
            assert!(!oversized_commit.message().contains(&commit_signature.sig));

            let wrong_commit_signature = fixture.signature.clone();
            let invalid_commit_signature = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(wrong_commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(invalid_commit_signature.code(), Code::InvalidArgument);
            assert!(
                invalid_commit_signature
                    .message()
                    .contains("commit signature verification failed")
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                wrong_commit_signature.key_id.as_str(),
                wrong_commit_signature.sig.as_str(),
                updated_bucket.ciphertext.as_str(),
            ] {
                assert!(
                    !invalid_commit_signature.message().contains(sentinel),
                    "{}",
                    invalid_commit_signature.message()
                );
            }

            let duplicate_commit_buckets = vec![updated_bucket.clone(), updated_bucket.clone()];
            let leaf_commitment = fixture.buckets[0].bucket_commitment.clone();
            assert!(
                fixture
                    .buckets
                    .iter()
                    .any(|bucket| bucket.bucket_commitment == leaf_commitment)
            );
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
            let duplicate_commit = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: duplicate_commit_old_root.clone(),
                    new_root_hash: duplicate_commit_new_root.clone(),
                    updated_buckets: duplicate_commit_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(duplicate_commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(duplicate_commit.code(), Code::InvalidArgument);
            assert!(
                duplicate_commit
                    .message()
                    .contains("commit updated_buckets contains duplicate bucket")
            );
            assert!(
                !duplicate_commit
                    .message()
                    .contains("commit signature verification failed")
            );
            assert!(
                !duplicate_commit
                    .message()
                    .contains(&duplicate_commit_old_root)
            );
            assert!(
                !duplicate_commit
                    .message()
                    .contains(&duplicate_commit_new_root)
            );
            assert!(!duplicate_commit.message().contains(&session.session_id));
            assert!(
                !duplicate_commit
                    .message()
                    .contains(&duplicate_commit_signature_key_id)
            );
            assert!(
                !duplicate_commit
                    .message()
                    .contains(&duplicate_commit_signature_sig)
            );
            assert!(
                !duplicate_commit
                    .message()
                    .contains(&updated_bucket.ciphertext)
            );
            assert!(
                !duplicate_commit
                    .message()
                    .contains(&updated_bucket.ciphertext_sha256)
            );
            assert!(
                !duplicate_commit
                    .message()
                    .contains(&updated_bucket.bucket_commitment)
            );

            let invalid_signature_duplicate_bucket =
                PrivateResultOram::commit_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id.clone(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: vec![
                            bucket_to_proto(updated_bucket.clone()),
                            bucket_to_proto(updated_bucket.clone()),
                        ],
                        commit_signature: Some(signature_to_proto(wrong_commit_signature.clone())),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(
                invalid_signature_duplicate_bucket.code(),
                Code::InvalidArgument
            );
            assert!(
                invalid_signature_duplicate_bucket
                    .message()
                    .contains("commit updated_buckets contains duplicate bucket")
            );
            assert!(
                !invalid_signature_duplicate_bucket
                    .message()
                    .contains("commit signature verification failed")
            );
            assert!(
                !invalid_signature_duplicate_bucket
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !invalid_signature_duplicate_bucket
                    .message()
                    .contains(&new_root_hash)
            );
            assert!(
                !invalid_signature_duplicate_bucket
                    .message()
                    .contains(&session.session_id)
            );
            assert!(
                !invalid_signature_duplicate_bucket
                    .message()
                    .contains(&wrong_commit_signature.key_id)
            );
            assert!(
                !invalid_signature_duplicate_bucket
                    .message()
                    .contains(&wrong_commit_signature.sig)
            );
            assert!(
                !invalid_signature_duplicate_bucket
                    .message()
                    .contains(&updated_bucket.ciphertext)
            );
            assert!(
                !invalid_signature_duplicate_bucket
                    .message()
                    .contains(&updated_bucket.ciphertext_sha256)
            );
            assert!(
                !invalid_signature_duplicate_bucket
                    .message()
                    .contains(&updated_bucket.bucket_commitment)
            );

            let unconfigured_commit_key_id_sentinel = "tenant-a/private-result-signing-v1-unknown";
            let mut unconfigured_commit_key_signature = commit_signature.clone();
            unconfigured_commit_key_signature.key_id =
                unconfigured_commit_key_id_sentinel.to_string();
            let unconfigured_commit_key_signature_sig =
                unconfigured_commit_key_signature.sig.clone();
            let unconfigured_commit_key = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(unconfigured_commit_key_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(unconfigured_commit_key.code(), Code::InvalidArgument);
            assert!(
                unconfigured_commit_key
                    .message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!unconfigured_commit_key.message().contains("not configured"));
            assert!(
                !unconfigured_commit_key
                    .message()
                    .contains(unconfigured_commit_key_id_sentinel)
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                unconfigured_commit_key_signature_sig.as_str(),
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !unconfigured_commit_key.message().contains(sentinel),
                    "{}",
                    unconfigured_commit_key.message()
                );
            }

            let malformed_commit_key_id_sentinel = "result-commit-signature-key!sentinel";
            let mut malformed_commit_key_signature = commit_signature.clone();
            malformed_commit_key_signature.key_id = malformed_commit_key_id_sentinel.to_string();
            let malformed_commit_key = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(malformed_commit_key_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(malformed_commit_key.code(), Code::InvalidArgument);
            assert!(
                malformed_commit_key
                    .message()
                    .contains("request validation failed")
            );
            assert!(
                !malformed_commit_key
                    .message()
                    .contains(malformed_commit_key_id_sentinel)
            );
            assert!(
                !malformed_commit_key
                    .message()
                    .contains("owner_signing_key_id")
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                commit_signature.sig.as_str(),
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !malformed_commit_key.message().contains(sentinel),
                    "{}",
                    malformed_commit_key.message()
                );
            }

            let alt_commit_signature =
                fixture.commit_signature_with_alt_key(&updated_bucket, &new_root_hash);
            let alt_commit_signature_sig = alt_commit_signature.sig.clone();
            let alt_commit_key = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(alt_commit_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(alt_commit_key.code(), Code::InvalidArgument);
            assert!(
                alt_commit_key
                    .message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!alt_commit_key.message().contains(ALT_SIGNING_KEY_ID));
            assert!(
                !alt_commit_key
                    .message()
                    .contains(&fixture.manifest.owner_signing_key_id)
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                alt_commit_signature_sig.as_str(),
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !alt_commit_key.message().contains(sentinel),
                    "{}",
                    alt_commit_key.message()
                );
            }

            let commit_signature_body_sentinel = "commit-signature!sentinel";
            let malformed_commit_signature = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(grpc::PrivateResultOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: commit_signature_body_sentinel.to_string(),
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(malformed_commit_signature.code(), Code::InvalidArgument);
            assert!(
                malformed_commit_signature
                    .message()
                    .contains("request validation failed")
            );
            assert!(
                !malformed_commit_signature
                    .message()
                    .contains(commit_signature_body_sentinel)
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                SIGNING_KEY_ID,
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !malformed_commit_signature.message().contains(sentinel),
                    "{}",
                    malformed_commit_signature.message()
                );
            }

            let commit_signature_alg_sentinel = "rsa-pss-result-commit-sentinel";
            let mut unsupported_commit_signature = commit_signature.clone();
            unsupported_commit_signature.alg = commit_signature_alg_sentinel.to_string();
            let unsupported_commit_key_id = unsupported_commit_signature.key_id.clone();
            let unsupported_commit_sig = unsupported_commit_signature.sig.clone();
            let unsupported_commit_signature =
                PrivateResultOram::commit_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: session.session_id.clone(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                        commit_signature: Some(signature_to_proto(unsupported_commit_signature)),
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(unsupported_commit_signature.code(), Code::InvalidArgument);
            assert!(
                unsupported_commit_signature
                    .message()
                    .contains("request validation failed")
            );
            assert!(
                !unsupported_commit_signature
                    .message()
                    .contains(commit_signature_alg_sentinel)
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                new_root_hash.as_str(),
                unsupported_commit_key_id.as_str(),
                unsupported_commit_sig.as_str(),
                updated_bucket.ciphertext.as_str(),
                updated_bucket.ciphertext_sha256.as_str(),
                updated_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !unsupported_commit_signature.message().contains(sentinel),
                    "{}",
                    unsupported_commit_signature.message()
                );
            }

            let committed = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(committed.index_epoch, NEXT_EPOCH);
            assert_eq!(committed.root_hash, new_root_hash);

            let stale_commit_new_root = new_root_hash.clone();
            let stale_commit_session_id = session.session_id.clone();
            let stale_commit_signature_key_id = commit_signature.key_id.clone();
            let stale_commit_signature_sig = commit_signature.sig.clone();
            let stale_commit_bucket_ciphertext = updated_bucket.ciphertext.clone();
            let stale_commit = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: stale_commit_session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: stale_commit_new_root.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket)],
                    commit_signature: Some(signature_to_proto(commit_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(stale_commit.code(), Code::InvalidArgument);
            assert!(stale_commit.message().contains("old epoch/root"));
            assert!(!stale_commit.message().contains(&fixture.manifest.root_hash));
            assert!(!stale_commit.message().contains(&stale_commit_new_root));
            assert!(!stale_commit.message().contains(&stale_commit_session_id));
            assert!(
                !stale_commit
                    .message()
                    .contains(&stale_commit_signature_key_id)
            );
            assert!(!stale_commit.message().contains(&stale_commit_signature_sig));
            assert!(
                !stale_commit
                    .message()
                    .contains(&stale_commit_bucket_ciphertext)
            );

            let closed = PrivateResultOram::close_private_result_oram_session(
                &service,
                Request::new(grpc::ClosePrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);

            let closed_read_signature = fixture.read_signature(&read_bucket_ids);
            let closed_read_signature_sig = closed_read_signature.sig.clone();
            let closed_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(closed_read_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(closed_read.code(), Code::InvalidArgument);
            assert!(
                closed_read
                    .message()
                    .contains("session is missing or expired")
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                closed_read_signature_sig.as_str(),
                fixture.buckets[0].ciphertext.as_str(),
                fixture.buckets[0].ciphertext_sha256.as_str(),
                fixture.buckets[0].bucket_commitment.as_str(),
            ] {
                assert!(
                    !closed_read.message().contains(sentinel),
                    "{}",
                    closed_read.message()
                );
            }

            let (closed_commit_bucket, closed_commit_signature, closed_commit_new_root_hash) =
                fixture.commit_bucket();
            let closed_commit = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: closed_commit_new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(closed_commit_bucket.clone())],
                    commit_signature: Some(signature_to_proto(closed_commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(closed_commit.code(), Code::InvalidArgument);
            assert!(
                closed_commit
                    .message()
                    .contains("session is missing or expired")
            );
            for sentinel in [
                session.session_id.as_str(),
                fixture.manifest.root_hash.as_str(),
                closed_commit_new_root_hash.as_str(),
                closed_commit_signature.sig.as_str(),
                closed_commit_bucket.ciphertext.as_str(),
                closed_commit_bucket.ciphertext_sha256.as_str(),
                closed_commit_bucket.bucket_commitment.as_str(),
            ] {
                assert!(
                    !closed_commit.message().contains(sentinel),
                    "{}",
                    closed_commit.message()
                );
            }

            let reopened = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: "tenant-a/result-sdk-instance-2".to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(reopened.index_epoch, NEXT_EPOCH);
            assert_eq!(reopened.root_hash, new_root_hash);
            let reopened_read_signature =
                fixture.read_signature_for_epoch(NEXT_EPOCH, &new_root_hash, &read_bucket_ids);
            let reopened_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: reopened.session_id.clone(),
                    index_epoch: NEXT_EPOCH,
                    root_hash: new_root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(reopened_read_signature)),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(reopened_read.index_epoch, NEXT_EPOCH);
            assert_eq!(reopened_read.root_hash, new_root_hash);
            let reopened_closed = PrivateResultOram::close_private_result_oram_session(
                &service,
                Request::new(grpc::ClosePrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: reopened.session_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(reopened_closed.closed);

            let missing_close_session_id = "close-session-id-sentinel";
            let missing_close = PrivateResultOram::close_private_result_oram_session(
                &service,
                Request::new(grpc::ClosePrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: missing_close_session_id.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(missing_close.code(), Code::InvalidArgument);
            assert!(
                missing_close
                    .message()
                    .contains("session is missing or already closed")
            );
            assert!(
                !missing_close.message().contains(missing_close_session_id),
                "{}",
                missing_close.message()
            );

            let oversized_close_session_id = "s".repeat(129);
            let malformed_close_session_id = "bad.session-id";
            for invalid_session_id in [
                oversized_close_session_id.as_str(),
                malformed_close_session_id,
            ] {
                let err = PrivateResultOram::close_private_result_oram_session(
                    &service,
                    Request::new(grpc::ClosePrivateResultOramSessionRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: invalid_session_id.to_string(),
                    }),
                )
                .await
                .unwrap_err();
                assert_eq!(err.code(), Code::InvalidArgument);
                assert!(err.message().contains("session_id is invalid"));
                assert!(
                    !err.message().contains(invalid_session_id),
                    "{}",
                    err.message()
                );
                assert!(
                    !err.message()
                        .contains("session is missing or already closed"),
                    "{}",
                    err.message()
                );
            }
        });
    }

    #[test]
    fn distributed_initial_staging_builds_validated_result_replication_bundle() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_distributed_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let auth = Auth::new_internal(Access::full("private result initial staging test"));
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass);

            let manifest_epoch =
                do_stage_private_result_oram_manifest_for_initial_replication(
                    toc,
                    &auth,
                    &settings,
                    COLLECTION_NAME,
                    fixture.manifest.clone(),
                    fixture.signature.clone(),
                )
                .await
                .unwrap();
            assert_eq!(manifest_epoch.index_epoch, fixture.manifest.index_epoch);
            assert_eq!(manifest_epoch.root_hash, fixture.manifest.root_hash);

            let bucket_epoch = do_stage_private_result_oram_buckets_for_initial_replication(
                toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                fixture.manifest.index_epoch,
                fixture.manifest.root_hash.clone(),
                fixture.buckets.clone(),
            )
            .await
            .unwrap();
            assert_eq!(bucket_epoch, manifest_epoch);

            let bundle = crate::common::private_result_oram::do_export_private_result_oram_initial_replication_bundle(
                toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                1024 * 1024,
            )
            .await
            .unwrap();
            assert_eq!(bundle.manifest, fixture.manifest);
            assert_eq!(bundle.manifest_signature, fixture.signature);
            assert_eq!(bundle.buckets, fixture.buckets);

            let recovery =
                crate::common::private_result_oram::do_inspect_private_result_oram_recovery(
                    toc,
                    &auth,
                    &settings,
                    COLLECTION_NAME,
                )
                .await
                .unwrap();
            assert_eq!(recovery.collection_id, COLLECTION_ID);
            assert_eq!(recovery.current, manifest_epoch);
            assert!(recovery.pending.is_none());
        });
    }

    #[test]
    fn private_result_oram_grpc_routes_reject_distributed_epoch_operations() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_distributed_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let service = PrivateResultOramService::new(Arc::new(dispatcher.clone()), settings);
            let manifest_root_hash = fixture.manifest.root_hash.clone();
            let manifest_signature = fixture.signature.sig.clone();
            let first_bucket_ciphertext = fixture.buckets[0].ciphertext.clone();

            macro_rules! assert_distributed_status {
                ($result:expr, [$($secret:expr),* $(,)?] $(,)?) => {{
                    let err = ($result).await.unwrap_err();
                    assert_eq!(err.code(), Code::InvalidArgument);
                    assert!(err.message().contains("consensus-backed epoch/root CAS"));
                    $(assert!(!err.message().contains($secret), "{}", err.message());)*
                }};
            }

            let distributed_client_id = "tenant-a/distributed-result-sdk-instance";
            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read_signature = fixture.read_signature(&read_bucket_ids);
            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let updated_bucket_ciphertext = updated_bucket.ciphertext.clone();

            assert_distributed_status!(
                PrivateResultOram::upload_private_result_oram_manifest(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramManifestRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                        signature: Some(signature_to_proto(fixture.signature.clone())),
                    }),
                ),
                [
                    &manifest_root_hash,
                    &manifest_signature,
                    &first_bucket_ciphertext
                ],
            );
            assert_distributed_status!(
                PrivateResultOram::upload_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: fixture
                            .buckets
                            .clone()
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                    }),
                ),
                [&manifest_root_hash, &first_bucket_ciphertext],
            );
            assert_distributed_status!(
                PrivateResultOram::open_private_result_oram_session(
                    &service,
                    Request::new(grpc::OpenPrivateResultOramSessionRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        client_id: distributed_client_id.to_string(),
                        desired_epoch: BASE_EPOCH,
                        fixed_budget: true,
                    }),
                ),
                [
                    distributed_client_id,
                    &manifest_root_hash,
                    &manifest_signature
                ],
            );
            assert_distributed_status!(
                PrivateResultOram::read_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: SESSION_ID.to_string(),
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.manifest.root_hash.clone(),
                        bucket_ids: read_bucket_ids.clone(),
                        read_signature: Some(signature_to_proto(read_signature.clone())),
                    }),
                ),
                [
                    SESSION_ID,
                    &manifest_root_hash,
                    &read_signature.sig,
                    &first_bucket_ciphertext
                ],
            );
            assert_distributed_status!(
                PrivateResultOram::commit_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: SESSION_ID.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: vec![bucket_to_proto(updated_bucket)],
                        commit_signature: Some(signature_to_proto(commit_signature.clone())),
                    }),
                ),
                [
                    SESSION_ID,
                    &manifest_root_hash,
                    &new_root_hash,
                    &commit_signature.sig,
                    &updated_bucket_ciphertext,
                ],
            );
        });
    }

    #[test]
    fn setup_grpc_routes_revalidate_runtime_oram_policy_drift() {
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
            let service =
                PrivateResultOramService::new(Arc::new(dispatcher.clone()), settings.clone());
            let drifted_service =
                PrivateResultOramService::new(Arc::new(dispatcher.clone()), drifted_settings);

            let drifted_manifest_upload = PrivateResultOram::upload_private_result_oram_manifest(
                &drifted_service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(drifted_manifest_upload.code(), Code::InvalidArgument);
            assert!(
                drifted_manifest_upload
                    .message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert!(!drifted_manifest_upload.message().contains("tree_height"));
            assert!(
                !drifted_manifest_upload
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !drifted_manifest_upload
                    .message()
                    .contains(&fixture.signature.sig)
            );

            PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap();

            let drifted_manifest_read = PrivateResultOram::get_private_result_oram_manifest(
                &drifted_service,
                Request::new(grpc::GetPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(drifted_manifest_read.code(), Code::InvalidArgument);
            assert!(
                drifted_manifest_read
                    .message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert!(!drifted_manifest_read.message().contains("tree_height"));
            assert!(
                !drifted_manifest_read
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !drifted_manifest_read
                    .message()
                    .contains(&fixture.signature.sig)
            );

            let missing_bucket_client_id = "tenant-a/sdk-instance-missing-buckets-test";
            let missing_bucket_session = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: missing_bucket_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(missing_bucket_session.code(), Code::NotFound);
            assert!(
                missing_bucket_session
                    .message()
                    .contains("encrypted bucket data is unavailable")
            );
            assert!(
                !missing_bucket_session
                    .message()
                    .contains("private_result_oram")
            );
            assert!(!missing_bucket_session.message().contains("/tmp"));
            assert!(
                !missing_bucket_session
                    .message()
                    .contains(missing_bucket_client_id)
            );

            let drifted_bucket_upload = PrivateResultOram::upload_private_result_oram_buckets(
                &drifted_service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(drifted_bucket_upload.code(), Code::InvalidArgument);
            assert!(
                drifted_bucket_upload
                    .message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert!(!drifted_bucket_upload.message().contains("tree_height"));
            assert!(
                !drifted_bucket_upload
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(
                !drifted_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );
            assert!(
                !drifted_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].ciphertext_sha256)
            );
            assert!(
                !drifted_bucket_upload
                    .message()
                    .contains(&fixture.buckets[0].bucket_commitment)
            );

            PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap();

            let setup_drift_client_id = "tenant-a/sdk-instance-setup-drift-test";
            let drifted_session = PrivateResultOram::open_private_result_oram_session(
                &drifted_service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: setup_drift_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(drifted_session.code(), Code::InvalidArgument);
            assert!(
                drifted_session
                    .message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert!(!drifted_session.message().contains("tree_height"));
            assert!(
                !drifted_session
                    .message()
                    .contains(&fixture.manifest.root_hash)
            );
            assert!(!drifted_session.message().contains(setup_drift_client_id));
        });
    }

    #[test]
    fn active_session_grpc_read_rejects_runtime_oram_policy_drift() {
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
            let service =
                PrivateResultOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap();

            PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap();

            let session = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-drift-test".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap()
            .into_inner();

            let drifted_service =
                PrivateResultOramService::new(Arc::new(dispatcher.clone()), drifted_settings);
            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read_signature = fixture.read_signature(&read_bucket_ids);
            let err = PrivateResultOram::read_private_result_oram_buckets(
                &drifted_service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(read_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert!(!err.message().contains("tree_height"));
            assert!(!err.message().contains(&fixture.manifest.root_hash));
            assert!(!err.message().contains(&session.session_id));
            assert!(!err.message().contains(&read_signature.key_id));
            assert!(!err.message().contains(&read_signature.sig));

            let closed = PrivateResultOram::close_private_result_oram_session(
                &service,
                Request::new(grpc::ClosePrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);
        });
    }

    #[test]
    fn active_session_grpc_commit_rejects_runtime_oram_policy_drift() {
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
            let service =
                PrivateResultOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap();

            PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap();

            let session = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-commit-drift-test".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap()
            .into_inner();

            let drifted_service =
                PrivateResultOramService::new(Arc::new(dispatcher.clone()), drifted_settings);
            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let err = PrivateResultOram::commit_private_result_oram_buckets(
                &drifted_service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert!(!err.message().contains("tree_height"));
            assert!(!err.message().contains(&fixture.manifest.root_hash));
            assert!(!err.message().contains(&new_root_hash));
            assert!(!err.message().contains(&session.session_id));
            assert!(!err.message().contains(&commit_signature.key_id));
            assert!(!err.message().contains(&commit_signature.sig));
            assert!(!err.message().contains(&updated_bucket.ciphertext));

            let closed = PrivateResultOram::close_private_result_oram_session(
                &service,
                Request::new(grpc::ClosePrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);
        });
    }
}
