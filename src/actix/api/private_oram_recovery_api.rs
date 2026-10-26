use std::fmt::{self, Debug, Formatter};
use std::future::{Ready, ready};

use actix_multipart::form::MultipartForm;
use actix_multipart::form::tempfile::TempFile;
use actix_multipart::form::text::Text;
use actix_web::http::header::{CACHE_CONTROL, HeaderValue};
use actix_web::{FromRequest, HttpRequest, HttpResponse, get, post, web};
use actix_web_validator::{Json, Path};
use collection::operations::verification::new_unchecked_verification_pass;
use serde::{Deserialize, Serialize};
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::dispatcher::Dispatcher;
use storage::rbac::AccessRequirements;
use tokio::time::Instant;
use validator::Validate;

use super::CollectionPath;
use crate::actix::auth::take_auth_from_request;
use crate::actix::helpers::{HttpError, process_response};
use crate::common::auth::Auth;
use crate::common::private_oram_recovery::{
    PrivateOramExternalRecoveryChunk, do_abort_private_oram_external_recovery,
    do_begin_private_oram_external_recovery, do_commit_private_oram_external_recovery,
    do_export_private_oram_external_recovery_checkpoint_context,
    do_get_private_oram_external_recovery_status, do_upload_private_oram_external_recovery_chunk,
    do_verify_private_oram_external_recovery,
};
use crate::settings::Settings;

const PRIVATE_ORAM_RECOVERY_TOKEN_HEADER: &str = "x-qdrant-private-oram-recovery-token";

#[derive(Clone, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct BeginPrivateOramExternalRecoveryRequest {
    pub checkpoint: qdrant_sec::PrivateOramExternalRecoveryCheckpoint,
    pub signature: qdrant_sec::PrivateOramRecoverySignature,
}

impl Debug for BeginPrivateOramExternalRecoveryRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeginPrivateOramExternalRecoveryRequest")
            .field("checkpoint", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramExternalRecoveryOperationRequest {
    #[validate(length(equal = 43))]
    pub operation_token: String,
}

#[derive(Clone, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct ExportPrivateOramExternalRecoveryCheckpointRequest {
    pub expected_committed_backup_generation: u64,
    pub backup_generation: u64,
    #[validate(length(equal = 43))]
    pub client_recovery_state_digest: String,
    #[validate(length(min = 1, max = 256))]
    pub owner_signing_key_id: String,
}

impl Debug for ExportPrivateOramExternalRecoveryCheckpointRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportPrivateOramExternalRecoveryCheckpointRequest")
            .field("expected_committed_backup_generation", &"[redacted]")
            .field("backup_generation", &"[redacted]")
            .field("client_recovery_state_digest", &"[redacted]")
            .field("owner_signing_key_id", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramExternalRecoveryOperationRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryOperationRequest")
            .field("operation_token", &"[redacted]")
            .finish()
    }
}

#[derive(MultipartForm)]
#[multipart(deny_unknown_fields)]
#[multipart(duplicate_field = "deny")]
struct PrivateOramExternalRecoveryUploadForm {
    #[multipart(limit = "64 B")]
    operation_token: Text<String>,
    #[multipart(limit = "32 B")]
    chunk_index: Text<u64>,
    #[multipart(limit = "128 B")]
    chunk_sha256: Text<String>,
    #[multipart(limit = "8 MiB")]
    chunk: TempFile,
}

struct PrivateOramRecoveryManageAuth(Auth);

impl FromRequest for PrivateOramRecoveryManageAuth {
    type Error = HttpError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let auth = take_auth_from_request(req);
        match auth.check_global_access(
            AccessRequirements::new().manage(),
            "private_oram_external_recovery_preflight",
        ) {
            Ok(_) => ready(Ok(Self(auth))),
            Err(error) => ready(Err(HttpError::from(error))),
        }
    }
}

#[post("/collections/{collection_name}/private-oram/recovery/begin")]
async fn begin_recovery(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<CollectionPath>,
    PrivateOramRecoveryManageAuth(auth): PrivateOramRecoveryManageAuth,
    request: Json<BeginPrivateOramExternalRecoveryRequest>,
) -> HttpResponse {
    let timing = Instant::now();
    let path = path.into_inner();
    let request = request.into_inner();
    let result = do_begin_private_oram_external_recovery(
        dispatcher.get_ref(),
        &auth,
        settings.get_ref(),
        &path.collection_name,
        qdrant_sec::PrivateOramExternalRecoveryCheckpointBundle {
            checkpoint: request.checkpoint,
            signature: request.signature,
        },
    )
    .await;
    process_recovery_response(result, timing)
}

#[post("/collections/{collection_name}/private-oram/recovery/export-context")]
async fn export_recovery_checkpoint_context(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<CollectionPath>,
    PrivateOramRecoveryManageAuth(auth): PrivateOramRecoveryManageAuth,
    request: Json<ExportPrivateOramExternalRecoveryCheckpointRequest>,
) -> HttpResponse {
    let timing = Instant::now();
    let path = path.into_inner();
    let request = request.into_inner();
    let result = do_export_private_oram_external_recovery_checkpoint_context(
        dispatcher.get_ref(),
        &auth,
        settings.get_ref(),
        &path.collection_name,
        request.expected_committed_backup_generation,
        request.backup_generation,
        &request.client_recovery_state_digest,
        &request.owner_signing_key_id,
    )
    .await;
    process_recovery_response(result, timing)
}

#[post("/collections/{collection_name}/private-oram/recovery/upload")]
async fn upload_recovery_chunk(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<CollectionPath>,
    PrivateOramRecoveryManageAuth(auth): PrivateOramRecoveryManageAuth,
    MultipartForm(form): MultipartForm<PrivateOramExternalRecoveryUploadForm>,
) -> HttpResponse {
    let timing = Instant::now();
    let path = path.into_inner();
    let operation_token = form.operation_token.into_inner();
    let chunk_index = form.chunk_index.into_inner();
    let chunk_sha256 = form.chunk_sha256.into_inner();
    let result = do_upload_private_oram_external_recovery_chunk(
        dispatcher.get_ref(),
        &auth,
        settings.get_ref(),
        &path.collection_name,
        PrivateOramExternalRecoveryChunk {
            operation_token: &operation_token,
            chunk_index,
            path: form.chunk.file.path(),
            sha256: &chunk_sha256,
        },
    )
    .await;
    process_recovery_response(result, timing)
}

#[get("/collections/{collection_name}/private-oram/recovery/status")]
async fn recovery_status(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<CollectionPath>,
    request: HttpRequest,
    PrivateOramRecoveryManageAuth(auth): PrivateOramRecoveryManageAuth,
) -> HttpResponse {
    let timing = Instant::now();
    let path = path.into_inner();
    let result = match operation_token_from_header(&request) {
        Ok(operation_token) => {
            do_get_private_oram_external_recovery_status(
                dispatcher.get_ref(),
                &auth,
                settings.get_ref(),
                &path.collection_name,
                &operation_token,
            )
            .await
        }
        Err(error) => Err(error),
    };
    process_recovery_response(result, timing)
}

#[post("/collections/{collection_name}/private-oram/recovery/verify")]
async fn verify_recovery(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<CollectionPath>,
    PrivateOramRecoveryManageAuth(auth): PrivateOramRecoveryManageAuth,
    request: Json<PrivateOramExternalRecoveryOperationRequest>,
) -> HttpResponse {
    let timing = Instant::now();
    let path = path.into_inner();
    let request = request.into_inner();
    let result = do_verify_private_oram_external_recovery(
        dispatcher.get_ref(),
        &auth,
        settings.get_ref(),
        &path.collection_name,
        &request.operation_token,
    )
    .await;
    process_recovery_response(result, timing)
}

#[post("/collections/{collection_name}/private-oram/recovery/abort")]
async fn abort_recovery(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<CollectionPath>,
    PrivateOramRecoveryManageAuth(auth): PrivateOramRecoveryManageAuth,
    request: Json<PrivateOramExternalRecoveryOperationRequest>,
) -> HttpResponse {
    let timing = Instant::now();
    let path = path.into_inner();
    let request = request.into_inner();
    let result = do_abort_private_oram_external_recovery(
        dispatcher.get_ref(),
        &auth,
        settings.get_ref(),
        &path.collection_name,
        &request.operation_token,
    )
    .await;
    process_recovery_response(result, timing)
}

#[post("/collections/{collection_name}/private-oram/recovery/commit")]
async fn commit_recovery(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<CollectionPath>,
    PrivateOramRecoveryManageAuth(auth): PrivateOramRecoveryManageAuth,
    request: Json<PrivateOramExternalRecoveryOperationRequest>,
) -> HttpResponse {
    let timing = Instant::now();
    let path = path.into_inner();
    let request = request.into_inner();
    let runtime = dispatcher
        .toc(&auth, &new_unchecked_verification_pass())
        .general_runtime_handle()
        .clone();
    let result = runtime
        .spawn(async move {
            do_commit_private_oram_external_recovery(
                dispatcher.get_ref(),
                &auth,
                settings.get_ref(),
                &path.collection_name,
                &request.operation_token,
            )
            .await
        })
        .await
        .map_err(|_| {
            StorageError::service_error("private ORAM external recovery commit task failed")
        })
        .and_then(|result| result);
    process_recovery_response(result, timing)
}

fn process_recovery_response<T: Serialize>(
    result: StorageResult<T>,
    timing: Instant,
) -> HttpResponse {
    let mut response = process_response(result, timing, None);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn operation_token_from_header(request: &HttpRequest) -> StorageResult<String> {
    let token = request
        .headers()
        .get(PRIVATE_ORAM_RECOVERY_TOKEN_HEADER)
        .ok_or_else(invalid_recovery_request)?
        .to_str()
        .map_err(|_| invalid_recovery_request())?;
    if token.len() != 43 {
        return Err(invalid_recovery_request());
    }
    Ok(token.to_string())
}

fn invalid_recovery_request() -> StorageError {
    StorageError::bad_request("private ORAM external recovery request is invalid")
}

pub fn config_private_oram_recovery_api(cfg: &mut web::ServiceConfig) {
    cfg.service(begin_recovery)
        .service(export_recovery_checkpoint_context)
        .service(upload_recovery_chunk)
        .service(recovery_status)
        .service(verify_recovery)
        .service(commit_recovery)
        .service(abort_recovery);
}

#[cfg(test)]
mod tests {
    use actix_web::HttpMessage as _;
    use actix_web::test::TestRequest;
    use futures::FutureExt as _;
    use storage::rbac::{Access, AuthType};

    use super::*;

    #[test]
    fn recovery_request_debug_redacts_checkpoint_and_operation_token() {
        let token = "private-oram-recovery-operation-token-sentinel";
        let operation = PrivateOramExternalRecoveryOperationRequest {
            operation_token: token.to_string(),
        };
        let rendered = format!("{operation:?}");
        assert!(!rendered.contains(token));
        assert!(rendered.contains("[redacted]"));

        let client_state_digest = "client-recovery-state-digest-sentinel";
        let signing_key_id = "private-oram-recovery-key-sentinel";
        let export = ExportPrivateOramExternalRecoveryCheckpointRequest {
            expected_committed_backup_generation: 17,
            backup_generation: 18,
            client_recovery_state_digest: client_state_digest.to_string(),
            owner_signing_key_id: signing_key_id.to_string(),
        };
        let rendered = format!("{export:?}");
        assert!(!rendered.contains("17"));
        assert!(!rendered.contains("18"));
        assert!(!rendered.contains(client_state_digest));
        assert!(!rendered.contains(signing_key_id));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn status_token_header_is_required_and_not_read_from_query() {
        let token = "A".repeat(43);
        let request = TestRequest::get()
            .uri("/collections/docs/private-oram/recovery/status?operation_token=query-sentinel")
            .insert_header((PRIVATE_ORAM_RECOVERY_TOKEN_HEADER, token.as_str()))
            .to_http_request();
        assert_eq!(operation_token_from_header(&request).unwrap(), token);

        let request = TestRequest::get()
            .uri("/collections/docs/private-oram/recovery/status?operation_token=query-sentinel")
            .to_http_request();
        let rendered = operation_token_from_header(&request)
            .unwrap_err()
            .to_string();
        assert!(!rendered.contains("query-sentinel"));
    }

    #[test]
    fn recovery_manage_auth_is_checked_before_multipart_payload() {
        let request = TestRequest::default().to_http_request();
        request.extensions_mut().insert(Auth::new(
            Access::full("private ORAM recovery upload test"),
            None,
            None,
            AuthType::None,
            None,
        ));
        let mut payload = actix_web::dev::Payload::None;

        let result = PrivateOramRecoveryManageAuth::from_request(&request, &mut payload)
            .now_or_never()
            .expect("private ORAM recovery auth extractor is ready");
        assert!(result.is_ok());
    }

    #[test]
    fn recovery_manage_auth_rejects_read_only_before_multipart_payload() {
        let request = TestRequest::default().to_http_request();
        request.extensions_mut().insert(Auth::new(
            Access::full_ro("private ORAM recovery upload test"),
            None,
            None,
            AuthType::None,
            None,
        ));
        let mut payload = actix_web::dev::Payload::None;

        let result = PrivateOramRecoveryManageAuth::from_request(&request, &mut payload)
            .now_or_never()
            .expect("private ORAM recovery auth extractor is ready");
        assert!(result.is_err());
    }

    #[test]
    fn recovery_responses_are_not_cacheable() {
        let response = process_recovery_response(Ok(true), Instant::now());
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
    }
}
