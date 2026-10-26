use std::fmt;
use std::future::{Ready, ready};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ::common::tempfile_ext::MaybeTempPath;
use actix_multipart::form::MultipartForm;
use actix_multipart::form::tempfile::TempFile;
use actix_web::{FromRequest, Responder, Result, delete, get, post, put, web};
use actix_web_validator as valid;
use collection::common::file_utils::move_file;
use collection::common::sha_256;
use collection::common::snapshot_stream::SnapshotStream;
use collection::config::CollectionConfigInternal;
use collection::operations::snapshot_ops::{
    ShardSnapshotRecover, SnapshotPriority, SnapshotRecover,
};
use collection::operations::types::CollectionError;
use collection::operations::verification::new_unchecked_verification_pass;
use collection::shards::shard_holder::shard_not_found_error;
use fs_err as fs;
use fs_err::tokio as tokio_fs;
use futures::{FutureExt as _, StreamExt as _, TryFutureExt as _};
use reqwest::Url;
use schemars::JsonSchema;
use segment::common::BYTES_IN_MB;
use serde::{Deserialize, Serialize};
use shard::snapshots::snapshot_data::SnapshotData;
use shard::snapshots::snapshot_manifest::{RecoveryType, SnapshotManifest};
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::content_manager::snapshots::recover::do_recover_from_snapshot;
use storage::content_manager::snapshots::{
    do_delete_collection_snapshot, do_delete_full_snapshot, do_list_full_snapshots,
};
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::Dispatcher;
use storage::rbac::{AccessRequirements, CollectionMultipass};
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;
use validator::Validate;

use super::{
    CollectionPath, CollectionShardPath, CollectionShardSnapshotPath, CollectionSnapshotPath,
    StrictCollectionPath,
};
use crate::actix::auth::{ActixAuth, take_auth_from_request};
use crate::actix::helpers::{self, HttpError};
use crate::common;
use crate::common::auth::Auth;
use crate::common::collections::*;
use crate::common::crypto::validate_recovered_collection_crypto_config;
use crate::common::http_client::HttpClient;
use crate::common::private_hnsw::validate_recovered_private_hnsw_oram_snapshot_signatures;
use crate::common::private_result_oram::validate_recovered_private_result_oram_snapshot_signatures;
use crate::common::snapshots::{
    begin_private_oram_collection_recovery, do_create_full_snapshot,
    redacted_snapshot_url_for_message, try_take_partial_snapshot_recovery_lock,
    validate_snapshot_peer_base_url_policy, validate_snapshot_url_api_key_policy,
};
use crate::settings::Settings;

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct SnapshotUploadingParam {
    pub wait: Option<bool>,
    pub priority: Option<SnapshotPriority>,

    /// Optional SHA256 checksum to verify snapshot integrity before recovery.
    #[serde(default)]
    #[validate(custom(function = "::common::validation::validate_sha256_hash"))]
    pub checksum: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct SnapshottingParam {
    pub wait: Option<bool>,
}

#[derive(Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotEncryptedPayloadExportMode {
    Raw,
}

impl<'de> Deserialize<'de> for SnapshotEncryptedPayloadExportMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "raw" => Ok(Self::Raw),
            _ => Err(serde::de::Error::custom(
                "snapshot archive export only supports encrypted_payload=raw; \
                 use /collections/{collection_name}/points/export?encrypted_payload=redacted \
                 or encrypted_payload=decrypted for audited payload export",
            )),
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema, Validate, Default)]
pub struct SnapshotExportParam {
    /// Snapshot archives are storage-level exports. They can only stream raw
    /// encrypted markers; decrypted/redacted payload export needs a separate
    /// audited data-export API.
    #[serde(default)]
    pub encrypted_payload: Option<SnapshotEncryptedPayloadExportMode>,
}

#[derive(MultipartForm)]
pub struct SnapshottingForm {
    snapshot: TempFile,
}

struct SnapshotManageAuth {
    auth: Auth,
    multipass: CollectionMultipass,
}

impl FromRequest for SnapshotManageAuth {
    type Error = HttpError;
    type Future = Ready<std::result::Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let auth = take_auth_from_request(req);
        match auth.check_global_access(
            AccessRequirements::new().manage(),
            "snapshot_upload_preflight",
        ) {
            Ok(multipass) => ready(Ok(Self { auth, multipass })),
            Err(err) => ready(Err(HttpError::from(err))),
        }
    }
}

// Actix specific code
pub async fn do_get_full_snapshot(
    toc: &TableOfContent,
    auth: &Auth,
    snapshot_name: &str,
) -> Result<SnapshotStream, HttpError> {
    auth.check_global_access(
        AccessRequirements::new().snapshot_export(),
        "get_full_snapshot",
    )?;
    let snapshots_storage_manager = toc.get_snapshots_storage_manager()?;
    let snapshot_path =
        snapshots_storage_manager.get_full_snapshot_path(toc.snapshots_path(), snapshot_name)?;
    let snapshot_stream = snapshots_storage_manager
        .get_snapshot_stream(&snapshot_path)
        .await?;
    Ok(snapshot_stream)
}

pub async fn do_save_uploaded_snapshot(
    toc: &TableOfContent,
    collection_name: &str,
    snapshot: TempFile,
) -> Result<(Url, PathBuf), StorageError> {
    let filename = snapshot
        .file_name
        // Sanitize the file name:
        // - only take the top level path (no directories such as ../)
        // - require the file name to be valid UTF-8
        .and_then(|x| {
            Path::new(&x)
                .file_name()
                .map(|filename| filename.to_owned())
        })
        .and_then(|x| x.to_str().map(|x| x.to_owned()))
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let collection_snapshot_path = toc.snapshots_path_for_collection(collection_name);
    if !collection_snapshot_path.exists() {
        log::debug!("Creating missing collection snapshots directory for {collection_name}");
        toc.create_snapshots_path(collection_name).await?;
    }

    let path = collection_snapshot_path.join(filename);

    move_file(snapshot.file.path(), &path).await?;

    let absolute_path = fs::canonicalize(&path)?;

    let snapshot_location = Url::from_file_path(&absolute_path).map_err(|_| {
        StorageError::service_error(format!(
            "Failed to convert path to URL: {}",
            absolute_path.display()
        ))
    })?;

    Ok((snapshot_location, absolute_path))
}

// Actix specific code
pub async fn do_get_snapshot(
    toc: &TableOfContent,
    auth: &Auth,
    collection_name: &str,
    snapshot_name: &str,
) -> Result<SnapshotStream, HttpError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().extras().snapshot_export(),
        "get_snapshot",
    )?;
    let collection: Arc<collection::collection::Collection> =
        toc.get_collection(&collection_pass).await?;
    let snapshot_storage_manager = collection.get_snapshots_storage_manager()?;
    let snapshot_path =
        snapshot_storage_manager.get_snapshot_path(collection.snapshots_path(), snapshot_name)?;
    let snapshot_stream = snapshot_storage_manager
        .get_snapshot_stream(&snapshot_path)
        .await?;
    Ok(snapshot_stream)
}

#[get("/collections/{collection_name}/snapshots")]
async fn list_snapshots(
    dispatcher: web::Data<Dispatcher>,
    collection: valid::Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // Nothing to verify.
    let pass = new_unchecked_verification_pass();

    helpers::time(do_list_snapshots(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection.collection_name,
    ))
    .await
}

#[post("/collections/{collection_name}/snapshots")]
async fn create_snapshot(
    dispatcher: web::Data<Dispatcher>,
    collection: valid::Path<CollectionPath>,
    params: valid::Query<SnapshottingParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let collection_name = collection.into_inner().collection_name;

    let future =
        async move { do_create_snapshot(dispatcher.into_inner(), &auth, &collection_name).await };

    helpers::time_or_accept(future, params.wait.unwrap_or(true)).await
}

#[post("/collections/{collection_name}/snapshots/upload")]
async fn upload_snapshot(
    dispatcher: web::Data<Dispatcher>,
    http_client: web::Data<HttpClient>,
    settings: web::Data<Settings>,
    collection: valid::Path<StrictCollectionPath>,
    SnapshotManageAuth { auth, .. }: SnapshotManageAuth,
    MultipartForm(form): MultipartForm<SnapshottingForm>,
    params: valid::Query<SnapshotUploadingParam>,
) -> impl Responder {
    let wait = params.wait;

    // Nothing to verify.
    let pass = new_unchecked_verification_pass();

    let future = async move {
        let settings = settings.get_ref().clone();
        let snapshot = form.snapshot;

        if let Some(checksum) = &params.checksum {
            let snapshot_checksum = sha_256::hash_file(snapshot.file.path()).await?;
            if !sha_256::hashes_equal(&snapshot_checksum, checksum) {
                return Err(StorageError::checksum_mismatch(snapshot_checksum, checksum));
            }
        }

        let private_oram_recovery_guard = begin_private_oram_collection_recovery(
            dispatcher.get_ref(),
            &auth,
            &collection.collection_name,
        )
        .await?;
        let (snapshot_location, uploaded_snapshot_path) = do_save_uploaded_snapshot(
            dispatcher.toc(&auth, &pass),
            &collection.collection_name,
            snapshot,
        )
        .await?;

        let recovery_result = async {
            let _private_oram_recovery_guard = private_oram_recovery_guard;
            // Snapshot is a local file, we do not need an API key for that
            let http_client = http_client.client(None)?;

            let snapshot_recover = SnapshotRecover {
                location: snapshot_location,
                priority: params.priority,
                checksum: None,
                api_key: None,
            };

            do_recover_from_snapshot(
                dispatcher.get_ref(),
                &collection.collection_name,
                snapshot_recover,
                auth,
                http_client,
                Some(Arc::new(
                    move |collection_name: &str,
                          snapshot_config: &CollectionConfigInternal,
                          snapshot_path: &Path| {
                        validate_recovered_collection_crypto_config(
                            &settings,
                            collection_name,
                            snapshot_config,
                        )?;
                        validate_recovered_private_hnsw_oram_snapshot_signatures(
                            &settings,
                            collection_name,
                            snapshot_config,
                            snapshot_path,
                        )?;
                        validate_recovered_private_result_oram_snapshot_signatures(
                            &settings,
                            collection_name,
                            snapshot_config,
                            snapshot_path,
                        )
                    },
                )),
            )
            .await
        }
        .await;

        if recovery_result.is_err() {
            match tokio_fs::remove_file(&uploaded_snapshot_path).await {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    log::warn!(
                        "Failed to remove uploaded snapshot artifact after failed recovery for collection {}: {err}",
                        collection.collection_name,
                    );
                }
            }
        }

        recovery_result
    };

    helpers::time_or_accept(future, wait.unwrap_or(true)).await
}

#[put("/collections/{collection_name}/snapshots/recover")]
async fn recover_from_snapshot(
    dispatcher: web::Data<Dispatcher>,
    http_client: web::Data<HttpClient>,
    settings: web::Data<Settings>,
    collection: valid::Path<CollectionPath>,
    request: valid::Json<SnapshotRecover>,
    params: valid::Query<SnapshottingParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let future = async move {
        let settings = settings.get_ref().clone();
        let snapshot_recover = request.into_inner();
        validate_snapshot_url_api_key_policy(
            &snapshot_recover.location,
            snapshot_recover.api_key.as_deref(),
            "collection snapshot recovery",
        )?;
        let http_client = http_client.client(snapshot_recover.api_key.as_deref())?;
        let _private_oram_recovery_guard = begin_private_oram_collection_recovery(
            dispatcher.get_ref(),
            &auth,
            &collection.collection_name,
        )
        .await?;

        do_recover_from_snapshot(
            dispatcher.get_ref(),
            &collection.collection_name,
            snapshot_recover,
            auth,
            http_client,
            Some(Arc::new(
                move |collection_name: &str,
                      snapshot_config: &CollectionConfigInternal,
                      snapshot_path: &Path| {
                    validate_recovered_collection_crypto_config(
                        &settings,
                        collection_name,
                        snapshot_config,
                    )?;
                    validate_recovered_private_hnsw_oram_snapshot_signatures(
                        &settings,
                        collection_name,
                        snapshot_config,
                        snapshot_path,
                    )?;
                    validate_recovered_private_result_oram_snapshot_signatures(
                        &settings,
                        collection_name,
                        snapshot_config,
                        snapshot_path,
                    )
                },
            )),
        )
        .await
    };

    helpers::time_or_accept(future, params.wait.unwrap_or(true)).await
}

#[get("/collections/{collection_name}/snapshots/{snapshot_name}")]
async fn get_snapshot(
    dispatcher: web::Data<Dispatcher>,
    path: valid::Path<CollectionSnapshotPath>,
    _query: valid::Query<SnapshotExportParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // Nothing to verify.
    let pass = new_unchecked_verification_pass();

    let CollectionSnapshotPath {
        collection_name,
        snapshot_name,
    } = path.into_inner();
    do_get_snapshot(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection_name,
        &snapshot_name,
    )
    .await
}

#[get("/snapshots")]
async fn list_full_snapshots(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    helpers::time(do_list_full_snapshots(dispatcher.toc(&auth, &pass), auth)).await
}

#[post("/snapshots")]
async fn create_full_snapshot(
    dispatcher: web::Data<Dispatcher>,
    params: valid::Query<SnapshottingParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let future = async move { do_create_full_snapshot(dispatcher.get_ref(), auth.clone()).await };
    helpers::time_or_accept(future, params.wait.unwrap_or(true)).await
}

#[get("/snapshots/{snapshot_name}")]
async fn get_full_snapshot(
    dispatcher: web::Data<Dispatcher>,
    path: web::Path<String>,
    _query: valid::Query<SnapshotExportParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let snapshot_name = path.into_inner();
    do_get_full_snapshot(dispatcher.toc(&auth, &pass), &auth, &snapshot_name).await
}

#[delete("/snapshots/{snapshot_name}")]
async fn delete_full_snapshot(
    dispatcher: web::Data<Dispatcher>,
    path: web::Path<String>,
    params: valid::Query<SnapshottingParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let future = async move {
        let snapshot_name = path.into_inner();
        do_delete_full_snapshot(dispatcher.get_ref(), auth, &snapshot_name).await
    };

    helpers::time_or_accept(future, params.wait.unwrap_or(true)).await
}

#[delete("/collections/{collection_name}/snapshots/{snapshot_name}")]
async fn delete_collection_snapshot(
    dispatcher: web::Data<Dispatcher>,
    path: valid::Path<CollectionSnapshotPath>,
    params: valid::Query<SnapshottingParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let future = async move {
        let CollectionSnapshotPath {
            collection_name,
            snapshot_name,
        } = path.into_inner();

        do_delete_collection_snapshot(dispatcher.get_ref(), auth, &collection_name, &snapshot_name)
            .await
    };

    helpers::time_or_accept(future, params.wait.unwrap_or(true)).await
}

#[get("/collections/{collection_name}/shards/{shard}/snapshots")]
async fn list_shard_snapshots(
    dispatcher: web::Data<Dispatcher>,
    path: valid::Path<CollectionShardPath>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let CollectionShardPath {
        collection_name,
        shard,
    } = path.into_inner();

    let future = common::snapshots::list_shard_snapshots(
        dispatcher.toc(&auth, &pass).clone(),
        &auth,
        collection_name,
        shard,
    )
    .map_err(Into::into);

    helpers::time(future).await
}

#[post("/collections/{collection_name}/shards/{shard}/snapshots")]
async fn create_shard_snapshot(
    dispatcher: web::Data<Dispatcher>,
    path: valid::Path<CollectionShardPath>,
    query: web::Query<SnapshottingParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let CollectionShardPath {
        collection_name,
        shard,
    } = path.into_inner();
    let future = async move {
        common::snapshots::create_shard_snapshot(
            dispatcher.toc(&auth, &pass).clone(),
            &auth,
            collection_name,
            shard,
        )
        .await
    };

    helpers::time_or_accept(future, query.wait.unwrap_or(true)).await
}

#[get("/collections/{collection_name}/shards/{shard}/snapshot")]
async fn stream_shard_snapshot(
    dispatcher: web::Data<Dispatcher>,
    path: valid::Path<CollectionShardPath>,
    _query: valid::Query<SnapshotExportParam>,
    ActixAuth(auth): ActixAuth,
) -> Result<SnapshotStream, HttpError> {
    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let CollectionShardPath {
        collection_name,
        shard,
    } = path.into_inner();
    Ok(common::snapshots::stream_shard_snapshot(
        dispatcher.toc(&auth, &pass).clone(),
        &auth,
        collection_name,
        shard,
        None,
    )
    .await?)
}

// TODO: `PUT` (same as `recover_from_snapshot`) or `POST`!?
#[put("/collections/{collection_name}/shards/{shard}/snapshots/recover")]
async fn recover_shard_snapshot(
    dispatcher: web::Data<Dispatcher>,
    http_client: web::Data<HttpClient>,
    settings: web::Data<Settings>,
    path: valid::Path<CollectionShardPath>,
    query: web::Query<SnapshottingParam>,
    web::Json(request): web::Json<ShardSnapshotRecover>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let future = async move {
        let CollectionShardPath {
            collection_name: collection,
            shard,
        } = path.into_inner();

        common::snapshots::recover_shard_snapshot(
            dispatcher.toc(&auth, &pass).clone(),
            &auth,
            collection,
            shard,
            request.location,
            request.priority.unwrap_or_default(),
            request.checksum,
            http_client.as_ref().clone(),
            request.api_key,
            Some(settings.get_ref().clone()),
        )
        .await?;

        Ok(true)
    };

    helpers::time_or_accept(future, query.wait.unwrap_or(true)).await
}

// TODO: `POST` (same as `upload_snapshot`) or `PUT`!?
#[post("/collections/{collection_name}/shards/{shard}/snapshots/upload")]
async fn upload_shard_snapshot(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: valid::Path<CollectionShardPath>,
    query: web::Query<SnapshotUploadingParam>,
    SnapshotManageAuth { auth, multipass }: SnapshotManageAuth,
    MultipartForm(form): MultipartForm<SnapshottingForm>,
) -> impl Responder {
    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let CollectionShardPath {
        collection_name: collection,
        shard,
    } = path.into_inner();
    let SnapshotUploadingParam {
        wait,
        priority,
        checksum,
    } = query.into_inner();
    let settings = settings.get_ref().clone();

    // - `recover_shard_snapshot_impl` is *not* cancel safe
    //   - but the task is *spawned* on the runtime and won't be cancelled, if request is cancelled

    let future = cancel::future::spawn_cancel_on_drop(async move |cancel| {
        let collection_pass = multipass.issue_pass(&collection);

        let cancel_safe = async {
            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await?;
            collection.assert_shard_exists(shard).await?;
            collection
                .validate_private_oram_shard_snapshot_allowed("shard snapshot upload recovery")
                .await?;

            if let Some(checksum) = checksum {
                let snapshot_checksum = sha_256::hash_file(form.snapshot.file.path()).await?;
                if !sha_256::hashes_equal(&snapshot_checksum, &checksum) {
                    return Err(StorageError::checksum_mismatch(snapshot_checksum, checksum));
                }
            }

            Ok(collection)
        };

        let collection = cancel::future::cancel_on_token(cancel.clone(), cancel_safe).await??;

        let snapshot_data =
            SnapshotData::Packed(MaybeTempPath::from(form.snapshot.file.into_temp_path()));

        // `recover_shard_snapshot_impl` is *not* cancel safe
        common::snapshots::recover_shard_snapshot_impl(
            dispatcher.toc(&auth, &pass),
            &collection,
            shard,
            snapshot_data,
            priority.unwrap_or_default(),
            RecoveryType::Full,
            cancel,
            Some(&settings),
        )
        .await?;

        Ok(())
    })
    .map(|res| res.map_err(Into::into).and_then(|res| res));

    helpers::time_or_accept(future, wait.unwrap_or(true)).await
}

#[get("/collections/{collection_name}/shards/{shard}/snapshots/{snapshot}")]
async fn download_shard_snapshot(
    dispatcher: web::Data<Dispatcher>,
    path: valid::Path<CollectionShardSnapshotPath>,
    _query: valid::Query<SnapshotExportParam>,
    ActixAuth(auth): ActixAuth,
) -> Result<impl Responder, HttpError> {
    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let CollectionShardSnapshotPath {
        collection_name: collection,
        shard,
        snapshot,
    } = path.into_inner();
    let collection_pass = auth.check_collection_access(
        &collection,
        AccessRequirements::new().extras().snapshot_export(),
        "download_shard_snapshot",
    )?;
    let collection = dispatcher
        .toc(&auth, &pass)
        .get_collection(&collection_pass)
        .await?;
    collection
        .validate_private_oram_shard_snapshot_allowed("shard snapshot download")
        .await?;
    let snapshots_storage_manager = collection.get_snapshots_storage_manager()?;
    let snapshot_path = collection
        .shards_holder()
        .read()
        .await
        .get_shard_snapshot_path(collection.snapshots_path(), shard, &snapshot)
        .await?;
    let snapshot_stream = snapshots_storage_manager
        .get_snapshot_stream(&snapshot_path)
        .await?;
    Ok(snapshot_stream)
}

#[delete("/collections/{collection_name}/shards/{shard}/snapshots/{snapshot}")]
async fn delete_shard_snapshot(
    dispatcher: web::Data<Dispatcher>,
    path: valid::Path<CollectionShardSnapshotPath>,
    query: web::Query<SnapshottingParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let CollectionShardSnapshotPath {
        collection_name: collection,
        shard,
        snapshot,
    } = path.into_inner();
    let future = async move {
        common::snapshots::delete_shard_snapshot(
            dispatcher.toc(&auth, &pass).clone(),
            &auth,
            collection,
            shard,
            snapshot,
        )
        .await
        .map(|_| true)
    };

    helpers::time_or_accept(future, query.wait.unwrap_or(true)).await
}

#[post("/collections/{collection_name}/shards/{shard}/snapshot/partial/create")]
async fn create_partial_snapshot(
    dispatcher: web::Data<Dispatcher>,
    path: valid::Path<CollectionShardPath>,
    _query: valid::Query<SnapshotExportParam>,
    manifest: web::Json<SnapshotManifest>,
    ActixAuth(auth): ActixAuth,
) -> Result<SnapshotStream, HttpError> {
    let CollectionShardPath {
        collection_name: collection,
        shard,
    } = path.into_inner();
    let manifest = manifest.into_inner();

    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let snapshot_stream = common::snapshots::stream_shard_snapshot(
        dispatcher.toc(&auth, &pass).clone(),
        &auth,
        collection,
        shard,
        Some(manifest),
    )
    .await?;

    Ok(snapshot_stream)
}

#[post("/collections/{collection_name}/shards/{shard}/snapshot/partial/recover")]
async fn recover_partial_snapshot(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: valid::Path<CollectionShardPath>,
    query: web::Query<SnapshotUploadingParam>,
    SnapshotManageAuth { auth, multipass }: SnapshotManageAuth,
    MultipartForm(form): MultipartForm<SnapshottingForm>,
) -> impl Responder {
    let CollectionShardPath {
        collection_name: collection,
        shard,
    } = path.into_inner();

    let SnapshotUploadingParam {
        wait,
        priority,
        checksum,
    } = query.into_inner();
    let settings = settings.get_ref().clone();

    // nothing to verify.
    let pass = new_unchecked_verification_pass();

    let try_take_recovery_lock_future =
        try_take_partial_snapshot_recovery_lock(&dispatcher, &collection, shard, &auth, &pass);

    let recovery_lock = match try_take_recovery_lock_future.await {
        Ok(recovery_lock) => recovery_lock,

        Err(StorageError::ShardUnavailable { .. }) => {
            return helpers::already_in_progress_response();
        }

        Err(err) => {
            return helpers::process_response_error(err, tokio::time::Instant::now(), None);
        }
    };

    let future = cancel::future::spawn_cancel_on_drop(async move |cancel| {
        let _recovery_lock = recovery_lock;

        let collection_pass = multipass.issue_pass(&collection);

        let cancel_safe = async {
            if let Some(checksum) = checksum {
                let snapshot_checksum = sha_256::hash_file(form.snapshot.file.path()).await?;
                if !sha_256::hashes_equal(&snapshot_checksum, &checksum) {
                    return Err(StorageError::checksum_mismatch(snapshot_checksum, checksum));
                }
            }

            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await?;
            collection.assert_shard_exists(shard).await?;

            Ok(collection)
        };

        let collection = cancel::future::cancel_on_token(cancel.clone(), cancel_safe).await??;

        let snapshot_data =
            SnapshotData::Packed(MaybeTempPath::from(form.snapshot.file.into_temp_path()));

        // `recover_shard_snapshot_impl` is *not* cancel safe
        common::snapshots::recover_shard_snapshot_impl(
            dispatcher.toc(&auth, &pass),
            &collection,
            shard,
            snapshot_data,
            priority.unwrap_or_default(),
            RecoveryType::Partial,
            cancel,
            Some(&settings),
        )
        .await?;

        Ok(())
    })
    .map(|res| res.map_err(Into::into).and_then(|res| res));

    helpers::time_or_accept(future, wait.unwrap_or(true)).await
}

#[derive(Clone, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct PartialSnapshotRecoverFrom {
    peer_url: Url,
    api_key: Option<String>,
}

impl fmt::Debug for PartialSnapshotRecoverFrom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartialSnapshotRecoverFrom")
            .field(
                "peer_url",
                &redacted_snapshot_url_for_message(&self.peer_url),
            )
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[post("/collections/{collection_name}/shards/{shard}/snapshot/partial/recover_from")]
async fn recover_partial_snapshot_from(
    dispatcher: web::Data<Dispatcher>,
    http_client: web::Data<HttpClient>,
    settings: web::Data<Settings>,
    path: valid::Path<CollectionShardPath>,
    query: web::Query<SnapshottingParam>,
    web::Json(request): web::Json<PartialSnapshotRecoverFrom>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let CollectionShardPath {
        collection_name,
        shard: shard_id,
    } = path.into_inner();
    let PartialSnapshotRecoverFrom { peer_url, api_key } = request;
    let SnapshottingParam { wait } = query.into_inner();
    let settings = settings.get_ref().clone();

    // nothing to verify
    let pass = new_unchecked_verification_pass();

    let try_take_recovery_lock_future = try_take_partial_snapshot_recovery_lock(
        &dispatcher,
        &collection_name,
        shard_id,
        &auth,
        &pass,
    );

    let recovery_lock = match try_take_recovery_lock_future.await {
        Ok(recovery_lock) => recovery_lock,

        Err(StorageError::ShardUnavailable { .. }) => {
            return helpers::already_in_progress_response();
        }

        Err(err) => {
            return helpers::process_response_error(err, tokio::time::Instant::now(), None);
        }
    };

    let future = cancel::future::spawn_cancel_on_drop(async move |cancel| {
        let _recovery_lock = recovery_lock;
        let download_start_time = tokio::time::Instant::now();

        let cancel_safe = async {
            let toc = dispatcher.toc(&auth, &pass);

            let collection_pass = auth
                .check_global_access(AccessRequirements::new().manage(), "recover_partial_snapshot_from")?
                .issue_pass(&collection_name)
                .into_static();

            let collection = toc.get_collection(&collection_pass).await?;
            collection.assert_shard_exists(shard_id).await?;

            validate_snapshot_url_api_key_policy(
                &peer_url,
                api_key.as_deref(),
                "partial snapshot recover_from",
            )?;
            validate_snapshot_peer_base_url_policy(&peer_url, "partial snapshot recover_from")?;
            let http_client = http_client.client(api_key.as_deref())?;

            let encoded_collection_name = urlencoding::encode(&collection_name);
            let mut create_snapshot_url = peer_url;
            create_snapshot_url.set_path(&format!(
                "/collections/{encoded_collection_name}/shards/{shard_id}/snapshot/partial/create"
            ));

            // Empty snapshot manifest allows us to use partial snapshots even if local shard doesn't exist
            let snapshot_manifest = match collection.get_partial_snapshot_manifest(shard_id).await {
                Ok(manifest) => manifest,
                Err(CollectionError::NotFound { .. }) => SnapshotManifest::default(),
                Err(err) => return Err(StorageError::from(err))
            };

            let download_dir = toc.optional_temp_or_snapshot_temp_path()?;
            let (partial_snapshot_file, partial_snapshot_temp_path) = tempfile::Builder::new()
                .prefix("partial-snapshot")
                .suffix(".download")
                .tempfile_in(&download_dir)?
                .into_parts();
            let partial_snapshot_file = fs::File::from_parts::<&Path>(
                partial_snapshot_file,
                partial_snapshot_temp_path.as_ref(),
            );

            let response = http_client
                .post(create_snapshot_url)
                .json(&snapshot_manifest)
                .send()
                .await?
                .error_for_status()?;

            if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                let shard_holder = collection.shards_holder();
                let shard_holder = shard_holder.read().await;
                let replica_set = shard_holder
                    .get_shard(shard_id)
                    .ok_or_else(|| shard_not_found_error(shard_id))?;

                // The replica is up to date so we bump the recovered timestamp
                // This prevents CM from immediately trying to recover again
                replica_set.partial_snapshot_meta.snapshot_recovered();
                return Err(StorageError::EmptyPartialSnapshot { shard_id });
            }

            let mut partial_snapshot_file =
                tokio::io::BufWriter::new(tokio_fs::File::from_std(partial_snapshot_file));

            let mut partial_snapshot_stream = response.bytes_stream();
            let mut total_bytes_downloaded = 0u64;

            while let Some(chunk) = partial_snapshot_stream.next().await {
                let chunk = chunk?;
                total_bytes_downloaded += chunk.len() as u64;
                partial_snapshot_file.write_all(&chunk).await?;
            }

            partial_snapshot_file.flush().await?;

            StorageResult::Ok((collection, partial_snapshot_temp_path, total_bytes_downloaded))
        };

        let create_partial_snapshot_result =
            cancel::future::cancel_on_token(cancel.clone(), cancel_safe).await?;

        let (collection, partial_snapshot_temp_path, bytes_downloaded) =
            match create_partial_snapshot_result {
                Ok(output) => output,
                Err(StorageError::EmptyPartialSnapshot { .. }) => return Ok(false),
                Err(err) => return Err(err),
            };

        let download_duration = download_start_time.elapsed();
        let total_size_mb = bytes_downloaded as f64 / BYTES_IN_MB as f64;
        let download_speed_mbps = total_size_mb / download_duration.as_secs_f64();

        log::debug!(
            "Partial snapshot download completed: path={}, size={:.2} MB, duration={:.2}s, speed={:.2} MB/s, shard_id={}",
            partial_snapshot_temp_path.display(),
            total_size_mb,
            download_duration.as_secs_f64(),
            download_speed_mbps,
            shard_id
        );

        let snapshot_data =
            SnapshotData::Packed(MaybeTempPath::from(partial_snapshot_temp_path));

        common::snapshots::recover_shard_snapshot_impl(
            dispatcher.toc(&auth, &pass),
            &collection,
            shard_id,
            snapshot_data,
            SnapshotPriority::NoSync,
            RecoveryType::Partial,
            cancel,
            Some(&settings),
        )
        .await?;

        Ok(true)
    })
    .map(|res| res.map_err(Into::into).and_then(|res| res));

    helpers::time_or_accept(future, wait.unwrap_or(true)).await
}

#[get("/collections/{collection_name}/shards/{shard}/snapshot/partial/manifest")]
async fn get_partial_snapshot_manifest(
    dispatcher: web::Data<Dispatcher>,
    path: valid::Path<CollectionShardPath>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let CollectionShardPath {
        collection_name: collection,
        shard,
    } = path.into_inner();
    let pass = new_unchecked_verification_pass();

    let future = async move {
        let collection_pass = auth
            .check_global_access(
                AccessRequirements::new().extras(),
                "get_partial_snapshot_manifest",
            )?
            .issue_pass(&collection);

        dispatcher
            .toc(&auth, &pass)
            .get_collection(&collection_pass)
            .await?
            .get_partial_snapshot_manifest(shard)
            .await
            .map_err(StorageError::from)
    };

    helpers::time(future).await
}

#[cfg(test)]
mod tests {
    use actix_web::{HttpMessage as _, test as actix_test};
    use futures::FutureExt as _;
    use storage::rbac::{Access, AuthType};

    use super::*;
    use crate::common::private_hnsw::{
        begin_private_hnsw_collection_snapshot, do_close_private_hnsw_session,
        do_open_private_hnsw_session, do_upload_private_hnsw_buckets,
        do_upload_private_hnsw_manifest,
    };
    use crate::common::private_hnsw_wire_fixture::{
        BASE_EPOCH, COLLECTION_NAME, PrivateHnswRouteWireFixture, PrivateResultOramRouteFixture,
        VECTOR_NAME, create_private_hnsw_collection,
        create_private_hnsw_collection_with_private_result_oram, route_e2e_guard, test_dispatcher,
    };
    use crate::common::private_result_oram::{
        begin_private_result_oram_collection_snapshot, do_close_private_result_oram_session,
        do_open_private_result_oram_session, do_upload_private_result_oram_buckets,
        do_upload_private_result_oram_manifest,
    };
    use crate::common::snapshots::begin_private_oram_collection_lifecycle_guard;

    #[test]
    fn snapshot_export_encrypted_payload_mode_is_raw_only() {
        let omitted: SnapshotExportParam = serde_urlencoded::from_str("").unwrap();
        assert_eq!(omitted.encrypted_payload, None);

        let raw: SnapshotExportParam = serde_urlencoded::from_str("encrypted_payload=raw").unwrap();
        assert_eq!(
            raw.encrypted_payload,
            Some(SnapshotEncryptedPayloadExportMode::Raw)
        );

        for mode in ["decrypted", "redacted"] {
            let err = match serde_urlencoded::from_str::<SnapshotExportParam>(&format!(
                "encrypted_payload={mode}"
            )) {
                Ok(_) => {
                    panic!("snapshot archive export must reject non-raw encrypted payload modes")
                }
                Err(err) => err,
            };
            let rendered = err.to_string();
            assert!(
                rendered.contains("points/export"),
                "snapshot export error should point users to audited points export: {rendered}",
            );
            assert!(
                rendered.contains("encrypted_payload=raw"),
                "snapshot export error should explain raw archive mode: {rendered}",
            );
        }
    }

    #[test]
    fn partial_snapshot_recover_from_debug_redacts_remote_credentials() {
        let request = PartialSnapshotRecoverFrom {
            peer_url: Url::parse(
                "https://partial-user:partial-password@example.com?token=qdrant-sec-partial-query-token#qdrant-sec-partial-fragment",
            )
            .unwrap(),
            api_key: Some("qdrant-sec-partial-api-key".to_string()),
        };

        let rendered = format!("{request:?}");

        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(rendered.contains("example.com"), "{rendered}");
        assert!(!rendered.contains("partial-user"), "{rendered}");
        assert!(!rendered.contains("partial-password"), "{rendered}");
        assert!(
            !rendered.contains("qdrant-sec-partial-query-token"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-partial-fragment"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-partial-api-key"),
            "{rendered}"
        );
    }

    #[test]
    fn snapshot_manage_auth_extracts_manage_access_before_payload() {
        let req = actix_test::TestRequest::default().to_http_request();
        req.extensions_mut().insert(Auth::new(
            Access::full("snapshot upload test"),
            None,
            None,
            AuthType::None,
            None,
        ));
        let mut payload = actix_web::dev::Payload::None;

        let result = SnapshotManageAuth::from_request(&req, &mut payload)
            .now_or_never()
            .expect("snapshot manage auth extractor is ready");

        let SnapshotManageAuth { auth, multipass } = result.unwrap();
        auth.check_global_access(AccessRequirements::new().manage(), "test")
            .unwrap();
        let _collection_pass = multipass.issue_pass("test_collection");
    }

    #[test]
    fn snapshot_manage_auth_rejects_read_only_access_before_payload() {
        let req = actix_test::TestRequest::default().to_http_request();
        req.extensions_mut().insert(Auth::new(
            Access::full_ro("snapshot upload test"),
            None,
            None,
            AuthType::None,
            None,
        ));
        let mut payload = actix_web::dev::Payload::None;

        let result = SnapshotManageAuth::from_request(&req, &mut payload)
            .now_or_never()
            .expect("snapshot manage auth extractor is ready");

        assert!(result.is_err());
    }

    #[test]
    fn collection_and_full_snapshot_reject_private_oram_lifecycle_window() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.get_ref()).await;

            let auth = Auth::new_internal(Access::full("private ORAM snapshot route test"));
            let _lifecycle_guard = begin_private_oram_collection_lifecycle_guard(
                dispatcher.get_ref(),
                &auth,
                COLLECTION_NAME,
            )
            .await
            .expect("private ORAM lifecycle guard should open");

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            let request = actix_web::test::TestRequest::post()
                .uri("/collections/docs/snapshots")
                .to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            let body = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(
                body.contains(
                    "collection snapshot requires no active collection lifecycle operation"
                ),
                "{body}",
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
                assert!(!body.contains(forbidden), "{body}");
            }

            let request = actix_web::test::TestRequest::post()
                .uri("/snapshots")
                .to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            let body = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(
                body.contains(
                    "collection snapshot requires no active collection lifecycle operation"
                ),
                "{body}",
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
                assert!(!body.contains(forbidden), "{body}");
            }
        });
    }

    #[test]
    fn collection_and_full_snapshot_reject_active_private_oram_session() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.get_ref()).await;

            let auth = Auth::new_internal(Access::full("private ORAM active snapshot route test"));
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.get_ref().toc(&auth, &pass).clone();
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
                "tenant-a/sdk-active-snapshot-route-test".to_string(),
                BASE_EPOCH,
                true,
                qdrant_sec::ResultPrivacyMode::IdsVisible,
            )
            .await
            .unwrap();

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            for uri in ["/collections/docs/snapshots", "/snapshots"] {
                let request = actix_web::test::TestRequest::post().uri(uri).to_request();
                let response = actix_web::test::call_service(&app, request).await;
                assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
                let body = actix_web::body::to_bytes(response.into_body())
                    .await
                    .unwrap();
                let body = std::str::from_utf8(&body).unwrap();
                assert!(
                    body.contains("collection snapshot requires no active private ORAM session"),
                    "{uri}: {body}",
                );
                assert!(
                    !body.contains(&fixture.encrypted_build.root_hash),
                    "{uri}: {body}"
                );
                assert!(
                    !body.contains(&fixture.encrypted_build.buckets[0].ciphertext),
                    "{uri}: {body}"
                );
                assert!(
                    !body.contains(&fixture.manifest_signature.sig),
                    "{uri}: {body}"
                );
                for forbidden in [
                    COLLECTION_NAME,
                    &session.session_id,
                    "tenant-a/sdk-active-snapshot-route-test",
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
                    assert!(!body.contains(forbidden), "{uri}: {body}");
                }
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

    #[test]
    fn collection_and_full_snapshot_reject_active_private_result_oram_session() {
        let _guard = route_e2e_guard();
        let hnsw_fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let result_fixture = PrivateResultOramRouteFixture::build();
        let settings = result_fixture.route_settings_with_private_hnsw(&hnsw_fixture);
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(dispatcher.get_ref()).await;

            let auth = Auth::new_internal(Access::full(
                "private result ORAM active snapshot route test",
            ));
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.get_ref().toc(&auth, &pass).clone();
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
                "tenant-a/result-sdk-active-snapshot-route-test".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap();

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            for uri in ["/collections/docs/snapshots", "/snapshots"] {
                let request = actix_web::test::TestRequest::post().uri(uri).to_request();
                let response = actix_web::test::call_service(&app, request).await;
                assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
                let body = actix_web::body::to_bytes(response.into_body())
                    .await
                    .unwrap();
                let body = std::str::from_utf8(&body).unwrap();
                assert!(
                    body.contains("collection snapshot requires no active private ORAM session"),
                    "{uri}: {body}",
                );
                assert!(
                    !body.contains(&result_fixture.manifest.root_hash),
                    "{uri}: {body}"
                );
                assert!(
                    !body.contains(&result_fixture.buckets[0].ciphertext),
                    "{uri}: {body}"
                );
                assert!(
                    !body.contains(&result_fixture.signature.sig),
                    "{uri}: {body}"
                );
                for forbidden in [
                    COLLECTION_NAME,
                    &session.session_id,
                    "tenant-a/result-sdk-active-snapshot-route-test",
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
                    assert!(!body.contains(forbidden), "{uri}: {body}");
                }
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
    fn partial_snapshot_manifest_rejects_private_oram_collection() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.get_ref()).await;

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            let request = actix_web::test::TestRequest::get()
                .uri("/collections/docs/shards/0/snapshot/partial/manifest")
                .to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            let body = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(
                body.contains(
                    "shard snapshot operations for private ORAM collections are disabled"
                ),
                "{body}",
            );
            assert!(
                body.contains("collection snapshot/restore preflight"),
                "{body}"
            );
            for forbidden in [
                COLLECTION_NAME,
                "partial shard snapshot manifest",
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
                assert!(!body.contains(forbidden), "{body}");
            }
        });
    }

    #[test]
    fn shard_snapshot_routes_reject_private_oram_collection() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.get_ref()).await;

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            for (method, uri) in [
                (
                    actix_web::http::Method::GET,
                    "/collections/docs/shards/0/snapshots",
                ),
                (
                    actix_web::http::Method::POST,
                    "/collections/docs/shards/0/snapshots",
                ),
                (
                    actix_web::http::Method::GET,
                    "/collections/docs/shards/0/snapshot",
                ),
                (
                    actix_web::http::Method::GET,
                    "/collections/docs/shards/0/snapshots/snapshot-1.snapshot",
                ),
                (
                    actix_web::http::Method::DELETE,
                    "/collections/docs/shards/0/snapshots/snapshot-1.snapshot",
                ),
            ] {
                let request = actix_web::test::TestRequest::default()
                    .method(method)
                    .uri(uri)
                    .to_request();
                let response = actix_web::test::call_service(&app, request).await;
                assert_eq!(
                    response.status(),
                    actix_web::http::StatusCode::BAD_REQUEST,
                    "{uri}",
                );
                let body = actix_web::body::to_bytes(response.into_body())
                    .await
                    .unwrap();
                let body = std::str::from_utf8(&body).unwrap();
                assert!(
                    body.contains(
                        "shard snapshot operations for private ORAM collections are disabled"
                    ),
                    "{uri}: {body}",
                );
                assert!(
                    body.contains("collection snapshot/restore preflight"),
                    "{uri}: {body}",
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
                    "snapshot-1.snapshot",
                    "private_hnsw_oram",
                    "private_result_oram",
                ] {
                    assert!(!body.contains(forbidden), "{uri}: {body}");
                }
            }
        });
    }

    #[test]
    fn shard_snapshot_recovery_routes_reject_private_oram_collection() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);
        let settings = Settings::new(None).unwrap();
        let http_client = web::Data::new(HttpClient::from_settings(&settings).unwrap());
        let settings = web::Data::new(settings);

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.get_ref()).await;

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .app_data(http_client.clone())
                    .app_data(settings.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            for (method, uri, body) in [
                (
                    actix_web::http::Method::PUT,
                    "/collections/docs/shards/0/snapshots/recover",
                    serde_json::json!({
                        "location": "file:///tmp/private-oram-shard-recovery-sentinel.snapshot"
                    }),
                ),
                (
                    actix_web::http::Method::POST,
                    "/collections/docs/shards/0/snapshot/partial/recover_from",
                    serde_json::json!({
                        "peer_url": "https://example.test?token=private-oram-partial-token-sentinel",
                        "api_key": "private-oram-partial-api-key-sentinel"
                    }),
                ),
            ] {
                let request = actix_web::test::TestRequest::default()
                    .method(method)
                    .uri(uri)
                    .set_json(body)
                    .to_request();
                let response = actix_web::test::call_service(&app, request).await;
                assert_eq!(
                    response.status(),
                    actix_web::http::StatusCode::BAD_REQUEST,
                    "{uri}",
                );
                let body = actix_web::body::to_bytes(response.into_body())
                    .await
                    .unwrap();
                let body = std::str::from_utf8(&body).unwrap();
                assert!(
                    body.contains(
                        "shard snapshot operations for private ORAM collections are disabled"
                    ),
                    "{uri}: {body}",
                );
                assert!(
                    body.contains("collection snapshot/restore preflight"),
                    "{uri}: {body}",
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
                    "private-oram-shard-recovery-sentinel",
                    "private-oram-partial-token-sentinel",
                    "private-oram-partial-api-key-sentinel",
                    "private_hnsw_oram",
                    "private_result_oram",
                ] {
                    assert!(!body.contains(forbidden), "{uri}: {body}");
                }
            }
        });
    }

    #[test]
    fn recover_snapshot_rejects_private_oram_snapshot_window() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);
        let settings = Settings::new(None).unwrap();
        let http_client = web::Data::new(HttpClient::from_settings(&settings).unwrap());
        let settings = web::Data::new(settings);

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.get_ref()).await;

            let auth = Auth::new_internal(Access::full("private ORAM snapshot recovery test"));
            let pass = new_unchecked_verification_pass();
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new().manage(),
                    "private_oram_recovery_route_test",
                )
                .unwrap();
            let collection = dispatcher
                .get_ref()
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let config = collection.config_snapshot().await;
            let _snapshot_guard =
                begin_private_hnsw_collection_snapshot(collection.name(), &config)
                    .expect("private HNSW snapshot guard should open");

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .app_data(http_client.clone())
                    .app_data(settings.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            let request = actix_web::test::TestRequest::put()
                .uri("/collections/docs/snapshots/recover")
                .set_json(serde_json::json!({
                    "location": "file:///tmp/private-oram-recovery-sentinel.snapshot"
                }))
                .to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            let body = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(
                body.contains("lifecycle operation requires no active collection snapshot"),
                "{body}",
            );
            for forbidden in [
                COLLECTION_NAME,
                "private_oram_recovery_route_test",
                "private-oram-recovery-sentinel",
                "text_private_hnsw",
                "docs_private_hnsw_v1",
                "tenant-a/vector-private-rk",
                "tenant-a/private-hnsw-signing-v1",
                qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
                "private_hnsw_oram",
            ] {
                assert!(!body.contains(forbidden), "{body}");
            }
        });
    }

    #[test]
    fn recover_snapshot_rejects_private_result_oram_snapshot_window() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);
        let settings = Settings::new(None).unwrap();
        let http_client = web::Data::new(HttpClient::from_settings(&settings).unwrap());
        let settings = web::Data::new(settings);

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(dispatcher.get_ref()).await;

            let auth =
                Auth::new_internal(Access::full("private result ORAM snapshot recovery test"));
            let pass = new_unchecked_verification_pass();
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new().manage(),
                    "private_result_oram_recovery_route_test",
                )
                .unwrap();
            let collection = dispatcher
                .get_ref()
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let config = collection.config_snapshot().await;
            let _snapshot_guard =
                begin_private_result_oram_collection_snapshot(collection.name(), &config)
                    .expect("private result ORAM snapshot guard should open");

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .app_data(http_client.clone())
                    .app_data(settings.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            let request = actix_web::test::TestRequest::put()
                .uri("/collections/docs/snapshots/recover")
                .set_json(serde_json::json!({
                    "location": "file:///tmp/private-result-oram-recovery-sentinel.snapshot"
                }))
                .to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            let body = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(
                body.contains("lifecycle operation requires no active collection snapshot"),
                "{body}",
            );
            for forbidden in [
                COLLECTION_NAME,
                "private_result_oram_recovery_route_test",
                "private-result-oram-recovery-sentinel",
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
                assert!(!body.contains(forbidden), "{body}");
            }
        });
    }

    #[test]
    fn recover_snapshot_rejects_active_private_oram_session() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);
        let http_client = web::Data::new(HttpClient::from_settings(&settings).unwrap());
        let route_settings = web::Data::new(settings.clone());

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.get_ref()).await;

            let auth = Auth::new_internal(Access::full("private ORAM active recovery route test"));
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.get_ref().toc(&auth, &pass).clone();
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
                "tenant-a/sdk-active-recovery-route-test".to_string(),
                BASE_EPOCH,
                true,
                qdrant_sec::ResultPrivacyMode::IdsVisible,
            )
            .await
            .unwrap();

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .app_data(http_client.clone())
                    .app_data(route_settings.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            let request = actix_web::test::TestRequest::put()
                .uri("/collections/docs/snapshots/recover")
                .set_json(serde_json::json!({
                    "location": "file:///tmp/private-oram-active-recovery-sentinel.snapshot"
                }))
                .to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            let body = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(
                body.contains("lifecycle operation requires no active private ORAM session"),
                "{body}",
            );
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/sdk-active-recovery-route-test",
                &fixture.encrypted_build.root_hash,
                &fixture.encrypted_build.buckets[0].ciphertext,
                &fixture.encrypted_build.buckets[0].ciphertext_sha256,
                &fixture.encrypted_build.buckets[0].bucket_commitment,
                "bucket.commitment",
                &fixture.manifest_signature.sig,
                "private-oram-active-recovery-sentinel",
                "text_private_hnsw",
                "docs_private_hnsw_v1",
                "tenant-a/vector-private-rk",
                "tenant-a/private-hnsw-signing-v1",
                qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
                qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
                "private_hnsw_oram",
            ] {
                assert!(!body.contains(forbidden), "{body}");
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

    #[test]
    fn recover_snapshot_rejects_active_private_result_oram_session() {
        let _guard = route_e2e_guard();
        let hnsw_fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let result_fixture = PrivateResultOramRouteFixture::build();
        let settings = result_fixture.route_settings_with_private_hnsw(&hnsw_fixture);
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);
        let http_client = web::Data::new(HttpClient::from_settings(&settings).unwrap());
        let route_settings = web::Data::new(settings.clone());

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(dispatcher.get_ref()).await;

            let auth = Auth::new_internal(Access::full(
                "private result ORAM active recovery route test",
            ));
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.get_ref().toc(&auth, &pass).clone();
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
                "tenant-a/result-sdk-active-recovery-route-test".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap();

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .app_data(http_client.clone())
                    .app_data(route_settings.clone())
                    .configure(config_snapshots_api),
            )
            .await;

            let request = actix_web::test::TestRequest::put()
                .uri("/collections/docs/snapshots/recover")
                .set_json(serde_json::json!({
                    "location": "file:///tmp/private-result-oram-active-recovery-sentinel.snapshot"
                }))
                .to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            let body = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(
                body.contains("lifecycle operation requires no active private ORAM session"),
                "{body}",
            );
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/result-sdk-active-recovery-route-test",
                &result_fixture.manifest.root_hash,
                &result_fixture.buckets[0].ciphertext,
                &result_fixture.buckets[0].ciphertext_sha256,
                &result_fixture.buckets[0].bucket_commitment,
                "bucket.commitment",
                &result_fixture.signature.sig,
                "private-result-oram-active-recovery-sentinel",
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
                assert!(!body.contains(forbidden), "{body}");
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
}

// Configure services
pub fn config_snapshots_api(cfg: &mut web::ServiceConfig) {
    cfg.service(list_snapshots)
        .service(create_snapshot)
        .service(upload_snapshot)
        .service(recover_from_snapshot)
        .service(get_snapshot)
        .service(list_full_snapshots)
        .service(create_full_snapshot)
        .service(get_full_snapshot)
        .service(delete_full_snapshot)
        .service(delete_collection_snapshot)
        .service(list_shard_snapshots)
        .service(create_shard_snapshot)
        .service(stream_shard_snapshot)
        .service(recover_shard_snapshot)
        .service(upload_shard_snapshot)
        .service(download_shard_snapshot)
        .service(delete_shard_snapshot)
        .service(create_partial_snapshot)
        .service(recover_partial_snapshot)
        .service(recover_partial_snapshot_from)
        .service(get_partial_snapshot_manifest);
}
