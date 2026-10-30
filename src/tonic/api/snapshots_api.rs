use std::sync::Arc;
use std::time::Instant;

use api::grpc::qdrant::shard_snapshots_server::ShardSnapshots;
use api::grpc::qdrant::snapshots_server::Snapshots;
use api::grpc::qdrant::{
    CreateFullSnapshotRequest, CreateShardSnapshotRequest, CreateSnapshotRequest,
    CreateSnapshotResponse, DeleteFullSnapshotRequest, DeleteShardSnapshotRequest,
    DeleteSnapshotRequest, DeleteSnapshotResponse, ListFullSnapshotsRequest,
    ListShardSnapshotsRequest, ListSnapshotsRequest, ListSnapshotsResponse,
    RecoverShardSnapshotRequest, RecoverSnapshotResponse,
};
use collection::operations::verification::new_unchecked_verification_pass;
use storage::content_manager::snapshots::{
    do_delete_collection_snapshot, do_delete_full_snapshot, do_list_full_snapshots,
};
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::Dispatcher;
use tonic::{Request, Response, Status, async_trait};

use super::{validate, validate_and_log};
use crate::common;
use crate::common::collections::{do_create_snapshot, do_list_snapshots};
use crate::common::http_client::HttpClient;
use crate::common::snapshots::do_create_full_snapshot;
use crate::settings::Settings;
use crate::tonic::auth::extract_auth;

pub struct SnapshotsService {
    dispatcher: Arc<Dispatcher>,
}

impl SnapshotsService {
    pub fn new(dispatcher: Arc<Dispatcher>) -> Self {
        Self { dispatcher }
    }
}

#[async_trait]
impl Snapshots for SnapshotsService {
    async fn create(
        &self,
        mut request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        validate(request.get_ref())?;
        let auth = extract_auth(&mut request);
        let collection_name = request.into_inner().collection_name;
        let timing = Instant::now();
        let dispatcher = self.dispatcher.clone();

        let response = do_create_snapshot(dispatcher, &auth, &collection_name).await?;

        Ok(Response::new(CreateSnapshotResponse {
            snapshot_description: Some(response.into()),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn list(
        &self,
        mut request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        validate(request.get_ref())?;

        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let ListSnapshotsRequest { collection_name } = request.into_inner();

        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();

        let snapshots =
            do_list_snapshots(self.dispatcher.toc(&auth, &pass), &auth, &collection_name).await?;

        Ok(Response::new(ListSnapshotsResponse {
            snapshot_descriptions: snapshots.into_iter().map(|s| s.into()).collect(),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn delete(
        &self,
        mut request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        validate(request.get_ref())?;

        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let DeleteSnapshotRequest {
            collection_name,
            snapshot_name,
        } = request.into_inner();

        let _response =
            do_delete_collection_snapshot(&self.dispatcher, auth, &collection_name, &snapshot_name)
                .await?;

        Ok(Response::new(DeleteSnapshotResponse {
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn create_full(
        &self,
        mut request: Request<CreateFullSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        validate(request.get_ref())?;

        let timing = Instant::now();
        let auth = extract_auth(&mut request);

        let response = do_create_full_snapshot(&self.dispatcher, auth.clone()).await?;

        Ok(Response::new(CreateSnapshotResponse {
            snapshot_description: Some(response.into()),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn list_full(
        &self,
        mut request: Request<ListFullSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        validate(request.get_ref())?;
        let timing = Instant::now();
        let auth = extract_auth(&mut request);

        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();

        let snapshots = do_list_full_snapshots(self.dispatcher.toc(&auth, &pass), auth).await?;
        Ok(Response::new(ListSnapshotsResponse {
            snapshot_descriptions: snapshots.into_iter().map(|s| s.into()).collect(),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn delete_full(
        &self,
        mut request: Request<DeleteFullSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        validate(request.get_ref())?;

        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let snapshot_name = request.into_inner().snapshot_name;

        let _response = do_delete_full_snapshot(&self.dispatcher, auth, &snapshot_name).await?;

        Ok(Response::new(DeleteSnapshotResponse {
            time: timing.elapsed().as_secs_f64(),
        }))
    }
}

pub struct ShardSnapshotsService {
    toc: Arc<TableOfContent>,
    http_client: HttpClient,
    settings: Settings,
}

impl ShardSnapshotsService {
    pub fn new(toc: Arc<TableOfContent>, http_client: HttpClient, settings: Settings) -> Self {
        Self {
            toc,
            http_client,
            settings,
        }
    }
}

#[async_trait]
impl ShardSnapshots for ShardSnapshotsService {
    async fn create(
        &self,
        mut request: Request<CreateShardSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_and_log(&request);

        let timing = Instant::now();

        let snapshot_description = common::snapshots::create_shard_snapshot(
            self.toc.clone(),
            &auth,
            request.collection_name,
            request.shard_id,
        )
        .await?;

        Ok(Response::new(CreateSnapshotResponse {
            snapshot_description: Some(snapshot_description.into()),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn list(
        &self,
        mut request: Request<ListShardSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_and_log(&request);

        let timing = Instant::now();

        let snapshot_descriptions = common::snapshots::list_shard_snapshots(
            self.toc.clone(),
            &auth,
            request.collection_name,
            request.shard_id,
        )
        .await?;

        Ok(Response::new(ListSnapshotsResponse {
            snapshot_descriptions: snapshot_descriptions.into_iter().map(Into::into).collect(),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn delete(
        &self,
        mut request: Request<DeleteShardSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_and_log(&request);

        let timing = Instant::now();

        common::snapshots::delete_shard_snapshot(
            self.toc.clone(),
            &auth,
            request.collection_name,
            request.shard_id,
            request.snapshot_name,
        )
        .await?;

        Ok(Response::new(DeleteSnapshotResponse {
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn recover(
        &self,
        mut request: Request<RecoverShardSnapshotRequest>,
    ) -> Result<Response<RecoverSnapshotResponse>, Status> {
        let auth = extract_auth(&mut request);
        let request = request.into_inner();

        validate_and_log(&request);

        let RecoverShardSnapshotRequest {
            collection_name,
            shard_id,
            snapshot_location,
            snapshot_priority,
            checksum,
            api_key,
        } = request;

        let timing = Instant::now();

        common::snapshots::recover_shard_snapshot(
            self.toc.clone(),
            &auth,
            collection_name,
            shard_id,
            snapshot_location.try_into()?,
            snapshot_priority.try_into()?,
            checksum,
            self.http_client.clone(),
            api_key,
            Some(self.settings.clone()),
        )
        .await?;

        Ok(Response::new(RecoverSnapshotResponse {
            time: timing.elapsed().as_secs_f64(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use api::grpc::qdrant::shard_snapshots_server::ShardSnapshots;
    use api::grpc::qdrant::snapshots_server::Snapshots;
    use api::grpc::qdrant::{
        ShardSnapshotLocation, ShardSnapshotPriority, shard_snapshot_location,
    };
    use storage::rbac::{Access, Auth};

    use super::*;
    use crate::common::private_hnsw::{
        do_close_private_hnsw_session, do_open_private_hnsw_session,
        do_upload_private_hnsw_buckets, do_upload_private_hnsw_manifest,
    };
    use crate::common::private_hnsw_wire_fixture::{
        BASE_EPOCH, COLLECTION_NAME, PrivateHnswRouteWireFixture, PrivateResultOramRouteFixture,
        VECTOR_NAME, create_private_hnsw_collection,
        create_private_hnsw_collection_with_private_result_oram, route_e2e_guard, test_dispatcher,
    };
    use crate::common::private_result_oram::{
        do_close_private_result_oram_session, do_open_private_result_oram_session,
        do_upload_private_result_oram_buckets, do_upload_private_result_oram_manifest,
    };
    use crate::common::snapshots::begin_private_oram_collection_lifecycle_guard;

    #[test]
    fn collection_and_full_snapshot_reject_private_oram_lifecycle_window() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = Arc::new(dispatcher);
        let service = SnapshotsService::new(dispatcher.clone());

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.as_ref()).await;

            let auth = Auth::new_internal(Access::full("private ORAM snapshot tonic route test"));
            let _lifecycle_guard = begin_private_oram_collection_lifecycle_guard(
                dispatcher.as_ref(),
                &auth,
                COLLECTION_NAME,
            )
            .await
            .expect("private ORAM lifecycle guard should open");

            let create_err = Snapshots::create(
                &service,
                Request::new(CreateSnapshotRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                }),
            )
            .await
            .expect_err("private ORAM collection snapshot must reject active lifecycle operation");
            assert_eq!(create_err.code(), tonic::Code::InvalidArgument);
            assert!(
                create_err.message().contains(
                    "collection snapshot requires no active collection lifecycle operation"
                ),
                "{create_err}",
            );
            for forbidden in [
                COLLECTION_NAME,
                "text_private_hnsw",
                "docs_private_hnsw_v1",
                "tenant-a/vector-private-rk",
                "tenant-a/private-hnsw-signing-v1",
                qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
                "payload_private_result_oram",
                "docs_private_result_oram_v1",
                "tenant-a/private-result-signing-v1",
                qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
                "private_hnsw_oram",
                "private_result_oram",
            ] {
                assert!(!create_err.message().contains(forbidden), "{create_err}");
            }

            let create_full_err =
                Snapshots::create_full(&service, Request::new(CreateFullSnapshotRequest {}))
                    .await
                    .expect_err(
                        "private ORAM full snapshot must reject active lifecycle operation",
                    );
            assert_eq!(create_full_err.code(), tonic::Code::InvalidArgument);
            assert!(
                create_full_err.message().contains(
                    "collection snapshot requires no active collection lifecycle operation"
                ),
                "{create_full_err}",
            );
            for forbidden in [
                COLLECTION_NAME,
                "text_private_hnsw",
                "docs_private_hnsw_v1",
                "tenant-a/vector-private-rk",
                "tenant-a/private-hnsw-signing-v1",
                qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
                "payload_private_result_oram",
                "docs_private_result_oram_v1",
                "tenant-a/private-result-signing-v1",
                qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
                "private_hnsw_oram",
                "private_result_oram",
            ] {
                assert!(
                    !create_full_err.message().contains(forbidden),
                    "{create_full_err}"
                );
            }
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collection_and_full_snapshot_reject_active_private_oram_session() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = Arc::new(dispatcher);
        let service = SnapshotsService::new(dispatcher.clone());

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.as_ref()).await;

            let auth = Auth::new_internal(Access::full("private ORAM active tonic snapshot test"));
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();
            do_upload_private_hnsw_manifest(
                &toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                fixture.manifest.clone(),
                fixture.manifest_signature.clone(),
            )
            .await
            .unwrap();
            do_upload_private_hnsw_buckets(
                &toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                fixture.encrypted_build.index_epoch,
                fixture.encrypted_build.root_hash.clone(),
                fixture.encrypted_build.buckets.clone(),
            )
            .await
            .unwrap();
            let session = do_open_private_hnsw_session(
                &toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                "tenant-a/sdk-active-tonic-snapshot-test".to_string(),
                BASE_EPOCH,
                true,
                qdrant_sec::ResultPrivacyMode::IdsVisible,
            )
            .await
            .unwrap();

            let create_err = Snapshots::create(
                &service,
                Request::new(CreateSnapshotRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                }),
            )
            .await
            .expect_err("private ORAM collection snapshot must reject active session");
            assert_eq!(create_err.code(), tonic::Code::InvalidArgument);
            assert!(
                create_err
                    .message()
                    .contains("collection snapshot requires no active private ORAM session"),
                "{create_err}",
            );
            assert!(
                !create_err
                    .message()
                    .contains(&fixture.encrypted_build.root_hash),
                "{create_err}"
            );
            assert!(
                !create_err
                    .message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{create_err}"
            );
            assert!(
                !create_err
                    .message()
                    .contains(&fixture.manifest_signature.sig),
                "{create_err}"
            );
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/sdk-active-tonic-snapshot-test",
                &fixture.encrypted_build.buckets[0].ciphertext_sha256,
                &fixture.encrypted_build.buckets[0].bucket_commitment,
                "bucket.commitment",
                "text_private_hnsw",
                "docs_private_hnsw_v1",
                "tenant-a/vector-private-rk",
                "tenant-a/private-hnsw-signing-v1",
                qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
                "private_hnsw_oram",
            ] {
                assert!(!create_err.message().contains(forbidden), "{create_err}");
            }

            let create_full_err =
                Snapshots::create_full(&service, Request::new(CreateFullSnapshotRequest {}))
                    .await
                    .expect_err("private ORAM full snapshot must reject active session");
            assert_eq!(create_full_err.code(), tonic::Code::InvalidArgument);
            assert!(
                create_full_err
                    .message()
                    .contains("collection snapshot requires no active private ORAM session"),
                "{create_full_err}",
            );
            assert!(
                !create_full_err
                    .message()
                    .contains(&fixture.encrypted_build.root_hash),
                "{create_full_err}"
            );
            assert!(
                !create_full_err
                    .message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{create_full_err}"
            );
            assert!(
                !create_full_err
                    .message()
                    .contains(&fixture.manifest_signature.sig),
                "{create_full_err}"
            );
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/sdk-active-tonic-snapshot-test",
                &fixture.encrypted_build.buckets[0].ciphertext_sha256,
                &fixture.encrypted_build.buckets[0].bucket_commitment,
                "bucket.commitment",
                "text_private_hnsw",
                "docs_private_hnsw_v1",
                "tenant-a/vector-private-rk",
                "tenant-a/private-hnsw-signing-v1",
                qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
                "private_hnsw_oram",
            ] {
                assert!(
                    !create_full_err.message().contains(forbidden),
                    "{create_full_err}"
                );
            }

            do_close_private_hnsw_session(
                &toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                &session.session_id,
            )
            .await
            .unwrap();
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collection_and_full_snapshot_reject_active_private_result_oram_session() {
        let _guard = route_e2e_guard();
        let hnsw_fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let result_fixture = PrivateResultOramRouteFixture::build();
        let settings = result_fixture.route_settings_with_private_hnsw(&hnsw_fixture);
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = Arc::new(dispatcher);
        let service = SnapshotsService::new(dispatcher.clone());

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(dispatcher.as_ref()).await;

            let auth = Auth::new_internal(Access::full(
                "private result ORAM active tonic snapshot test",
            ));
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();
            do_upload_private_result_oram_manifest(
                &toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                result_fixture.manifest.clone(),
                result_fixture.signature.clone(),
            )
            .await
            .unwrap();
            do_upload_private_result_oram_buckets(
                &toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                result_fixture.manifest.index_epoch,
                result_fixture.manifest.root_hash.clone(),
                result_fixture.buckets.clone(),
            )
            .await
            .unwrap();
            let session = do_open_private_result_oram_session(
                &toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                "tenant-a/result-sdk-active-tonic-snapshot-test".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap();

            let create_err = Snapshots::create(
                &service,
                Request::new(CreateSnapshotRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                }),
            )
            .await
            .expect_err("private result ORAM collection snapshot must reject active session");
            assert_eq!(create_err.code(), tonic::Code::InvalidArgument);
            assert!(
                create_err
                    .message()
                    .contains("collection snapshot requires no active private ORAM session"),
                "{create_err}",
            );
            assert!(
                !create_err
                    .message()
                    .contains(&result_fixture.manifest.root_hash),
                "{create_err}"
            );
            assert!(
                !create_err
                    .message()
                    .contains(&result_fixture.buckets[0].ciphertext),
                "{create_err}"
            );
            assert!(
                !create_err.message().contains(&result_fixture.signature.sig),
                "{create_err}"
            );
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/result-sdk-active-tonic-snapshot-test",
                &result_fixture.buckets[0].ciphertext_sha256,
                &result_fixture.buckets[0].bucket_commitment,
                "bucket.commitment",
                "payload_private_result_oram",
                "docs_private_result_oram_v1",
                "tenant-a/vector-private-rk",
                "tenant-a/private-result-signing-v1",
                qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
                "text_private_hnsw",
                "docs_private_hnsw_v1",
                qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
                "private_result_oram",
            ] {
                assert!(!create_err.message().contains(forbidden), "{create_err}");
            }

            let create_full_err =
                Snapshots::create_full(&service, Request::new(CreateFullSnapshotRequest {}))
                    .await
                    .expect_err("private result ORAM full snapshot must reject active session");
            assert_eq!(create_full_err.code(), tonic::Code::InvalidArgument);
            assert!(
                create_full_err
                    .message()
                    .contains("collection snapshot requires no active private ORAM session"),
                "{create_full_err}",
            );
            assert!(
                !create_full_err
                    .message()
                    .contains(&result_fixture.manifest.root_hash),
                "{create_full_err}"
            );
            assert!(
                !create_full_err
                    .message()
                    .contains(&result_fixture.buckets[0].ciphertext),
                "{create_full_err}"
            );
            assert!(
                !create_full_err
                    .message()
                    .contains(&result_fixture.signature.sig),
                "{create_full_err}"
            );
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/result-sdk-active-tonic-snapshot-test",
                &result_fixture.buckets[0].ciphertext_sha256,
                &result_fixture.buckets[0].bucket_commitment,
                "bucket.commitment",
                "payload_private_result_oram",
                "docs_private_result_oram_v1",
                "tenant-a/vector-private-rk",
                "tenant-a/private-result-signing-v1",
                qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
                "text_private_hnsw",
                "docs_private_hnsw_v1",
                qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
                "private_result_oram",
            ] {
                assert!(
                    !create_full_err.message().contains(forbidden),
                    "{create_full_err}"
                );
            }

            do_close_private_result_oram_session(
                &toc,
                &auth,
                &settings,
                COLLECTION_NAME,
                &session.session_id,
            )
            .await
            .unwrap();
        });
    }

    #[test]
    fn shard_snapshot_methods_reject_private_oram_collection() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("private ORAM shard snapshot tonic test"));
        let pass = new_unchecked_verification_pass();
        let settings = Settings::new(None).unwrap();
        let service = ShardSnapshotsService::new(
            dispatcher.toc(&auth, &pass).clone(),
            HttpClient::from_settings(&settings).unwrap(),
            settings,
        );

        fn assert_private_oram_shard_snapshot_error(err: Status, operation: &str) {
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
            assert!(
                err.message().contains(
                    "shard snapshot operations for private ORAM collections are disabled"
                ),
                "{operation}: {err}",
            );
            assert!(
                err.message()
                    .contains("collection snapshot/restore preflight"),
                "{operation}: {err}",
            );
            for forbidden in [
                operation,
                COLLECTION_NAME,
                "text_private_hnsw",
                "docs_private_hnsw_v1",
                "tenant-a/vector-private-rk",
                "tenant-a/private-hnsw-signing-v1",
                qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
                "payload_private_result_oram",
                "docs_private_result_oram_v1",
                "tenant-a/private-result-signing-v1",
                qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
                "snapshot-1.snapshot",
                "private-oram-shard-recovery-sentinel",
                "private-oram-shard-checksum-sentinel",
                "private-oram-shard-api-key-sentinel",
                "private_hnsw_oram",
                "private_result_oram",
            ] {
                assert!(!err.message().contains(forbidden), "{operation}: {err}");
            }
        }

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;

            let list_err = ShardSnapshots::list(
                &service,
                Request::new(ListShardSnapshotsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    shard_id: 0,
                }),
            )
            .await
            .expect_err("private ORAM shard snapshot listing must fail closed");
            assert_private_oram_shard_snapshot_error(list_err, "shard snapshot listing");

            let create_err = ShardSnapshots::create(
                &service,
                Request::new(CreateShardSnapshotRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    shard_id: 0,
                }),
            )
            .await
            .expect_err("private ORAM shard snapshot creation must fail closed");
            assert_private_oram_shard_snapshot_error(create_err, "shard snapshot creation");

            let delete_err = ShardSnapshots::delete(
                &service,
                Request::new(DeleteShardSnapshotRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    shard_id: 0,
                    snapshot_name: "snapshot-1.snapshot".to_string(),
                }),
            )
            .await
            .expect_err("private ORAM shard snapshot deletion must fail closed");
            assert_private_oram_shard_snapshot_error(delete_err, "shard snapshot deletion");

            let recover_err = ShardSnapshots::recover(
                &service,
                Request::new(RecoverShardSnapshotRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    shard_id: 0,
                    snapshot_location: Some(ShardSnapshotLocation {
                        location: Some(shard_snapshot_location::Location::Path(
                            "private-oram-shard-recovery-sentinel.snapshot".to_string(),
                        )),
                    }),
                    snapshot_priority: ShardSnapshotPriority::NoSync as i32,
                    checksum: Some("private-oram-shard-checksum-sentinel".to_string()),
                    api_key: Some("private-oram-shard-api-key-sentinel".to_string()),
                }),
            )
            .await
            .expect_err("private ORAM shard snapshot recovery must fail closed");
            assert_private_oram_shard_snapshot_error(recover_err, "shard snapshot recovery");
        });
    }
}
