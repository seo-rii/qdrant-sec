pub mod actix_telemetry;
pub mod api;
mod auth;
mod certificate_helpers;
mod forwarded;
pub mod helpers;
pub mod metrics_service;
pub mod web_ui;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use ::api::rest::models::{ApiResponse, ApiStatus, VersionInfo};
use actix_cors::Cors;
use actix_multipart::form::MultipartFormConfig;
use actix_multipart::form::tempfile::TempFileConfig;
use actix_web::dev::ServiceRequest;
use actix_web::http::KeepAlive;
use actix_web::middleware::{Compress, Condition, Logger, NormalizePath};
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, error, get, web};
use actix_web_extras::middleware::Condition as ConditionEx;
use api::facet_api::config_facet_api;
use collection::operations::validation;
use collection::operations::verification::new_unchecked_verification_pass;
use storage::dispatcher::Dispatcher;
use storage::rbac::{Access, Auth};

use crate::actix::api::audit_api::config_audit_api;
use crate::actix::api::cluster_api::config_cluster_api;
use crate::actix::api::collections_api::config_collections_api;
use crate::actix::api::count_api::count_points;
use crate::actix::api::debug_api::config_debugger_api;
use crate::actix::api::discover_api::config_discover_api;
use crate::actix::api::issues_api::config_issues_api;
use crate::actix::api::local_shard_api::config_local_shard_api;
use crate::actix::api::private_hnsw_api::config_private_hnsw_api;
#[cfg(target_os = "linux")]
use crate::actix::api::private_oram_mutation_api::config_private_oram_mutation_api;
use crate::actix::api::private_oram_recovery_api::config_private_oram_recovery_api;
use crate::actix::api::private_result_oram_api::config_private_result_oram_api;
use crate::actix::api::profiler_api::config_profiler_api;
use crate::actix::api::query_api::config_query_api;
use crate::actix::api::recommend_api::config_recommend_api;
use crate::actix::api::retrieve_api::{
    export_payload_points, get_point, get_points, scroll_points,
};
use crate::actix::api::search_api::config_search_api;
use crate::actix::api::service_api::config_service_api;
use crate::actix::api::shards_api::config_shards_api;
use crate::actix::api::snapshot_api::config_snapshots_api;
use crate::actix::api::update_api::config_update_api;
use crate::actix::auth::{AuthTransform, WhitelistItem};
use crate::actix::web_ui::{WEB_UI_PATH, web_ui_factory, web_ui_folder};
use crate::common::auth::AuthKeys;
use crate::common::debugger::DebuggerState;
use crate::common::health;
use crate::common::http_client::HttpClient;
use crate::common::private_oram_peer_identity::PrivateOramPeerRecoveryIdentity;
use crate::common::telemetry::TelemetryCollector;
use crate::settings::{Settings, max_web_workers};
use crate::tracing::LoggerHandle;

pub(crate) fn multipart_snapshot_upload_limit_bytes(settings: &Settings) -> usize {
    settings
        .service
        .max_snapshot_upload_size_mb
        .saturating_mul(1024 * 1024)
        .max(1)
}

#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok().json(VersionInfo::default())
}

const ACTIX_ACCESS_LOG_FORMAT: &str =
    r#"%a "%{qdrant_redacted_request}xi" %s %b "%{Referer}i" "%{User-Agent}i" %T"#;

fn access_log_request_line(req: &ServiceRequest) -> String {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or_else(|| req.path(), |value| value.as_str());
    format!(
        "{} {} {:?}",
        req.method(),
        redact_private_oram_access_path(path_and_query),
        req.version()
    )
}

pub(crate) fn redact_private_oram_access_path(path_and_query: &str) -> String {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, None), |(path, query)| (path, Some(query)));
    let private_oram_path = path_has_private_oram_marker(path);
    let redacted_path = redact_private_oram_path(path);

    match (private_oram_path, query) {
        (true, Some(_)) => format!("{redacted_path}?[redacted]"),
        (_, Some(query)) => format!("{redacted_path}?{query}"),
        (_, None) => redacted_path,
    }
}

fn redact_private_oram_path(path: &str) -> String {
    let session_redacted = redact_private_oram_session_path(path);
    if session_redacted != path {
        return session_redacted;
    }

    let segments = path.split('/').collect::<Vec<_>>();
    let endpoint_idx = match segments.as_slice() {
        ["", "collections", _, "private-oram", "recovery", action, ..]
            if is_private_oram_recovery_action(action) =>
        {
            Some(5)
        }
        ["", "collections", _, "private-oram", "recovery", ..] => Some(4),
        ["", "collections", _, "private-hnsw", _, "buckets", ..] => Some(5),
        ["", "collections", _, "private-hnsw", _, "manifest", ..] => Some(5),
        [
            "",
            "collections",
            _,
            "private-hnsw",
            _,
            "oram",
            "commit",
            ..,
        ] => Some(6),
        [
            "",
            "collections",
            _,
            "private-hnsw",
            _,
            "oram",
            "read_paths",
            ..,
        ] => Some(6),
        ["", "collections", _, "private-result-oram", "buckets", ..] => Some(4),
        ["", "collections", _, "private-result-oram", "manifest", ..] => Some(4),
        [
            "",
            "collections",
            _,
            "private-result-oram",
            "oram",
            "commit",
            ..,
        ] => Some(5),
        [
            "",
            "collections",
            _,
            "private-result-oram",
            "oram",
            "read_buckets",
            ..,
        ] => Some(5),
        _ => None,
    };

    let Some(endpoint_idx) = endpoint_idx else {
        return path.to_string();
    };
    if endpoint_idx + 1 >= segments.len() {
        return path.to_string();
    }

    let mut redacted = segments[..=endpoint_idx].to_vec();
    redacted.push("[redacted]");
    redacted.join("/")
}

fn redact_private_oram_session_path(path: &str) -> String {
    let segments = path.split('/').collect::<Vec<_>>();
    let session_idx = if segments.len() >= 6
        && segments.get(1) == Some(&"collections")
        && segments.get(3) == Some(&"private-hnsw")
        && segments.get(5) == Some(&"session")
    {
        Some(5)
    } else if segments.len() >= 5
        && segments.get(1) == Some(&"collections")
        && segments.get(3) == Some(&"private-result-oram")
        && segments.get(4) == Some(&"session")
    {
        Some(4)
    } else {
        None
    };

    let Some(session_idx) = session_idx else {
        return path.to_string();
    };
    if session_idx + 1 >= segments.len() {
        return path.to_string();
    }

    let mut redacted = segments[..=session_idx].to_vec();
    redacted.push("{session_id}");
    if segments.last() == Some(&"close") {
        redacted.push("close");
    } else {
        redacted.push("[redacted]");
    }
    redacted.join("/")
}

pub fn init(
    dispatcher: Arc<Dispatcher>,
    telemetry_collector: Arc<tokio::sync::Mutex<TelemetryCollector>>,
    health_checker: Option<Arc<health::HealthChecker>>,
    settings: Settings,
    logger_handle: LoggerHandle,
    private_oram_peer_identity: Option<Arc<PrivateOramPeerRecoveryIdentity>>,
) -> io::Result<()> {
    actix_web::rt::System::new().block_on(async {
        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();
        let auth = Auth::new_internal(Access::full("Service initialization"));
        let auth_keys =
            AuthKeys::try_create(&settings.service, dispatcher.toc(&auth, &pass).clone());
        let upload_dir = dispatcher
            .toc(&auth, &pass)
            .upload_dir()
            .map_err(|err| io::Error::other(format!("failed to resolve upload dir: {err}")))?;
        let dispatcher_data = web::Data::from(dispatcher);
        let actix_telemetry_collector = telemetry_collector
            .lock()
            .await
            .actix_telemetry_collector
            .clone();
        let debugger_state = web::Data::new(DebuggerState::from_settings(&settings));
        let telemetry_collector_data = web::Data::from(telemetry_collector);
        let logger_handle_data = web::Data::new(logger_handle);
        let http_client = web::Data::new(HttpClient::from_settings(&settings)?);
        let health_checker = web::Data::new(health_checker);
        let web_ui_available = web_ui_folder(&settings);
        let service_config = web::Data::new(settings.service.clone());
        let settings_data = web::Data::new(settings.clone());
        let private_oram_peer_identity_data =
            web::Data::new(private_oram_peer_identity.clone());
        let audit_config_data = web::Data::new(settings.audit.clone());
        let snapshot_upload_limit_bytes = multipart_snapshot_upload_limit_bytes(&settings);

        let mut api_key_whitelist = vec![
            WhitelistItem::exact("/"),
            WhitelistItem::exact("/healthz"),
            WhitelistItem::prefix("/readyz"),
            WhitelistItem::prefix("/livez"),
        ];
        if web_ui_available.is_some() {
            api_key_whitelist.push(WhitelistItem::prefix(WEB_UI_PATH));
        }

        let mut server = HttpServer::new(move || {
            let cors = Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header();
            let validate_path_config = actix_web_validator::PathConfig::default()
                .error_handler(|err, rec| validation_error_handler("path parameters", err, rec));
            let validate_query_config = actix_web_validator::QueryConfig::default()
                .error_handler(|err, rec| validation_error_handler("query parameters", err, rec));
            let validate_json_config = actix_web_validator::JsonConfig::default()
                .limit(settings.service.max_request_size_mb * 1024 * 1024)
                .error_handler(|err, rec| validation_error_handler("JSON body", err, rec));

            let app = App::new()
                .wrap(Compress::default()) // Reads the `Accept-Encoding` header to negotiate which compression codec to use.
                // api_key middleware
                // note: the last call to `wrap()` or `wrap_fn()` is executed first
                .wrap(ConditionEx::from_option(auth_keys.as_ref().map(
                    |auth_keys| AuthTransform::new(auth_keys.clone(), api_key_whitelist.clone()),
                )))
                // Normalize path
                .wrap(NormalizePath::trim())
                .wrap(Condition::new(settings.service.enable_cors, cors))
                .wrap(
                    // Set up logger, but avoid logging hot status endpoints
                    Logger::new(ACTIX_ACCESS_LOG_FORMAT)
                        .custom_request_replace(
                            "qdrant_redacted_request",
                            access_log_request_line,
                        )
                        .exclude("/")
                        .exclude("/metrics")
                        .exclude("/telemetry")
                        .exclude("/healthz")
                        .exclude("/readyz")
                        .exclude("/livez"),
                )
                .wrap(actix_telemetry::ActixTelemetryTransform::new(
                    actix_telemetry_collector.clone(),
                ))
                .app_data(dispatcher_data.clone())
                .app_data(telemetry_collector_data.clone())
                .app_data(logger_handle_data.clone())
                .app_data(http_client.clone())
                .app_data(debugger_state.clone())
                .app_data(health_checker.clone())
                .app_data(validate_path_config)
                .app_data(validate_query_config)
                .app_data(validate_json_config)
                .app_data(TempFileConfig::default().directory(&upload_dir))
                .app_data(
                    MultipartFormConfig::default()
                        .total_limit(snapshot_upload_limit_bytes),
                )
                .app_data(service_config.clone())
                .app_data(settings_data.clone())
                .app_data(private_oram_peer_identity_data.clone())
                .app_data(audit_config_data.clone())
                .service(index)
                .configure(config_collections_api)
                .configure(config_snapshots_api)
                .configure(config_update_api)
                .configure(config_cluster_api)
                .configure(config_service_api)
                .configure(config_search_api)
                .configure(config_recommend_api)
                .configure(config_discover_api)
                .configure(config_query_api)
                .configure(config_facet_api)
                .configure(config_private_hnsw_api);
            #[cfg(target_os = "linux")]
            let app = app.configure(config_private_oram_mutation_api);
            let mut app = app
                .configure(config_private_oram_recovery_api)
                .configure(config_private_result_oram_api)
                .configure(config_shards_api)
                .configure(config_issues_api)
                .configure(config_debugger_api)
                .configure(config_profiler_api)
                .configure(config_local_shard_api)
                .configure(config_audit_api)
                // Ordering of services is important for correct path pattern matching
                // See: <https://github.com/qdrant/qdrant/issues/3543>
                .service(export_payload_points)
                .service(scroll_points)
                .service(count_points)
                .service(get_point)
                .service(get_points);

            if let Some(static_folder) = web_ui_available.as_deref() {
                app = app.service(web_ui_factory(static_folder));
            }

            app
        })
        .keep_alive(KeepAlive::from(Duration::from_secs(
            settings.service.http_keep_alive_timeout_sec,
        )))
        .client_request_timeout(Duration::from_secs(
            settings.service.http_client_request_timeout_sec,
        ))
        .client_disconnect_timeout(Duration::from_secs(
            settings.service.http_client_disconnect_timeout_sec,
        ))
        .workers(max_web_workers(&settings));

        log::info!(
            "REST transport settings: keep_alive={}s, client_request_timeout={}s, client_disconnect_timeout={}s",
            settings.service.http_keep_alive_timeout_sec,
            settings.service.http_client_request_timeout_sec,
            settings.service.http_client_disconnect_timeout_sec,
        );

        let port = settings.service.http_port;
        let bind_addr = format!("{}:{}", settings.service.host, port);

        // With TLS enabled, bind with certificate helper and Rustls, or bind regularly
        server = if settings.service.enable_tls {
            log::info!(
                "TLS enabled for REST API (TTL: {})",
                settings
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.cert_ttl)
                    .map(|ttl| ttl.to_string())
                    .unwrap_or_else(|| "none".into()),
            );

            let config = certificate_helpers::actix_tls_server_config(&settings)
                .map_err(io::Error::other)?;
            server.bind_rustls_0_23(bind_addr, config)?
        } else {
            log::info!("TLS disabled for REST API");

            server.bind(bind_addr)?
        };

        log::info!("Qdrant HTTP listening on {port}");
        server.run().await
    })
}

fn validation_error_handler(
    name: &str,
    err: actix_web_validator::Error,
    req: &HttpRequest,
) -> error::Error {
    use actix_web_validator::error::DeserializeErrors;

    // Nicely describe deserialization and validation errors
    let msg = if let Some(private_oram_validation_message) =
        private_oram_validation_error_message(name, req.path(), &err)
    {
        private_oram_validation_message.to_string()
    } else {
        match &err {
            actix_web_validator::Error::Validate(errs) => {
                validation::label_errors(format!("Validation error in {name}"), errs)
            }
            actix_web_validator::Error::Deserialize(err) => {
                format!(
                    "Deserialize error in {name}: {}",
                    match err {
                        DeserializeErrors::DeserializeQuery(err) => err.to_string(),
                        DeserializeErrors::DeserializeJson(err) => err.to_string(),
                        DeserializeErrors::DeserializePath(err) => err.to_string(),
                    }
                )
            }
            actix_web_validator::Error::JsonPayloadError(
                actix_web::error::JsonPayloadError::Deserialize(err),
            ) => {
                format!("Format error in {name}: {err}",)
            }
            err => err.to_string(),
        }
    };

    // Build fitting response
    let response = match &err {
        actix_web_validator::Error::Validate(_) => HttpResponse::UnprocessableEntity(),
        _ => HttpResponse::BadRequest(),
    }
    .json(ApiResponse::<()> {
        result: None,
        status: ApiStatus::Error(msg),
        time: 0.0,
        usage: None,
    });
    error::InternalError::from_response(err, response).into()
}

fn private_oram_validation_error_message(
    name: &str,
    path: &str,
    err: &actix_web_validator::Error,
) -> Option<&'static str> {
    if !is_private_oram_request_path(path) {
        return None;
    }

    let should_sanitize = matches!(
        err,
        actix_web_validator::Error::Validate(_)
            | actix_web_validator::Error::Deserialize(_)
            | actix_web_validator::Error::JsonPayloadError(_)
    );
    if !should_sanitize {
        return None;
    }

    match name {
        "JSON body" => Some("Invalid JSON body for private ORAM request"),
        "path parameters" => Some("Invalid path parameters for private ORAM request"),
        _ => None,
    }
}

fn is_private_oram_request_path(path: &str) -> bool {
    path_has_private_oram_marker(path)
}

fn path_has_private_oram_marker(path: &str) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    matches!(
        segments.as_slice(),
        ["", "collections", _, "private-oram", "recovery", ..]
            | ["", "collections", _, "private-oram", "v2", "mutation", ..]
    ) || (segments.get(1) == Some(&"collections")
        && matches!(
            segments.get(3).copied(),
            Some("private-hnsw" | "private-result-oram")
        ))
}

fn is_private_oram_recovery_action(action: &str) -> bool {
    matches!(
        action,
        "begin" | "export-context" | "upload" | "status" | "verify" | "commit" | "abort"
    )
}

#[cfg(test)]
mod tests {
    use ::api::grpc::api_crate_version;
    use actix_web::{App, test as actix_test, web};
    use actix_web_validator::{Json, Path};
    use serde::Deserialize;
    use validator::Validate;

    use super::*;

    #[derive(Deserialize, Validate)]
    #[serde(deny_unknown_fields)]
    struct PrivateOramValidationTestBody {
        _known: String,
    }

    #[derive(Deserialize, Validate)]
    #[serde(deny_unknown_fields)]
    struct PrivateOramEnumValidationTestBody {
        _result_privacy: qdrant_sec::ResultPrivacyMode,
    }

    #[derive(Deserialize, Validate)]
    struct PrivateOramPathValidationTestPath {
        #[validate(length(max = 4))]
        _secret_path_segment: String,
    }

    async fn private_oram_validation_test_endpoint(
        _: Json<PrivateOramValidationTestBody>,
    ) -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    async fn private_oram_enum_validation_test_endpoint(
        _: Json<PrivateOramEnumValidationTestBody>,
    ) -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    async fn private_oram_path_validation_test_endpoint(
        _: Path<PrivateOramPathValidationTestPath>,
    ) -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    fn body_with_unknown_field(field_name: &str, value: &str) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        body.insert("_known".to_string(), serde_json::json!("ok"));
        body.insert(field_name.to_string(), serde_json::json!(value));
        serde_json::Value::Object(body)
    }

    #[test]
    fn test_version() {
        assert_eq!(
            api_crate_version(),
            env!("CARGO_PKG_VERSION"),
            "Qdrant and lib/api crate versions are not same"
        );
    }

    #[test]
    fn multipart_snapshot_upload_limit_is_finite_and_configurable() {
        let mut settings = Settings::new(None).unwrap();
        assert_eq!(
            multipart_snapshot_upload_limit_bytes(&settings),
            1024 * 1024 * 1024
        );

        settings.service.max_snapshot_upload_size_mb = 7;
        assert_eq!(
            multipart_snapshot_upload_limit_bytes(&settings),
            7 * 1024 * 1024
        );
        assert_ne!(multipart_snapshot_upload_limit_bytes(&settings), usize::MAX);
    }

    #[actix_web::test]
    async fn private_oram_json_validation_errors_do_not_reflect_unknown_field_names() {
        let validate_json_config = actix_web_validator::JsonConfig::default()
            .error_handler(|err, req| validation_error_handler("JSON body", err, req));
        let app = actix_test::init_service(
            App::new()
                .app_data(validate_json_config)
                .route(
                    "/collections/{collection_name}/private-hnsw/{vector_name}/session",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-hnsw/{vector_name}/manifest",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-hnsw/{vector_name}/buckets",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-result-oram/session",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-result-oram/manifest",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-result-oram/buckets",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-result-oram/oram/read_buckets",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-result-oram/oram/commit",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-oram/v2/mutation/open",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/ordinary/session",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/points/search",
                    web::post().to(private_oram_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/private-hnswish/{vector_name}/session",
                    web::post().to(private_oram_validation_test_endpoint),
                ),
        )
        .await;

        let sentinel = "qdrant-sec-private-oram-unknown-field-sentinel";
        let private_oram_unknown_field_sentinels = [
            sentinel,
            "payloadFetchToken",
            "payloadFetchTokens",
            "payload_fetch_token",
            "payload_fetch_tokens",
            "payload.fetch.token",
            "payload.fetch.tokens",
        ];
        for private_oram_path in [
            "/collections/docs/private-hnsw/text/session",
            "/collections/docs/private-hnsw/text/manifest",
            "/collections/docs/private-hnsw/text/buckets",
            "/collections/docs/private-hnsw/text/oram/read_paths",
            "/collections/docs/private-hnsw/text/oram/commit",
            "/collections/docs/private-result-oram/session",
            "/collections/docs/private-result-oram/manifest",
            "/collections/docs/private-result-oram/buckets",
            "/collections/docs/private-result-oram/oram/read_buckets",
            "/collections/docs/private-result-oram/oram/commit",
            "/collections/docs/private-oram/v2/mutation/open",
        ] {
            for field_sentinel in private_oram_unknown_field_sentinels {
                let private_oram_request = actix_test::TestRequest::post()
                    .uri(private_oram_path)
                    .set_json(body_with_unknown_field(field_sentinel, "must-not-reflect"))
                    .to_request();
                let private_oram_response =
                    actix_test::call_service(&app, private_oram_request).await;
                assert_eq!(
                    private_oram_response.status(),
                    actix_web::http::StatusCode::BAD_REQUEST
                );
                let private_oram_body = actix_test::read_body(private_oram_response).await;
                let private_oram_body = String::from_utf8_lossy(&private_oram_body);
                assert!(
                    private_oram_body.contains("Invalid JSON body for private ORAM request"),
                    "{private_oram_path}: {private_oram_body}"
                );
                assert!(
                    !private_oram_body.contains(field_sentinel),
                    "{private_oram_path}: {private_oram_body}"
                );
                assert!(
                    !private_oram_body.contains("unknown field"),
                    "{private_oram_path}: {private_oram_body}"
                );
            }
        }

        let malformed_body_sentinel = "qdrant-sec-private-oram-malformed-json-body-sentinel";
        let malformed_private_request = actix_test::TestRequest::post()
            .uri("/collections/docs/private-hnsw/text/session")
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .set_payload(format!(
                "{{\"_known\":\"ok\",\"bad\":\"{malformed_body_sentinel}\""
            ))
            .to_request();
        let malformed_private_response =
            actix_test::call_service(&app, malformed_private_request).await;
        assert_eq!(
            malformed_private_response.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        let malformed_private_body = actix_test::read_body(malformed_private_response).await;
        let malformed_private_body = String::from_utf8_lossy(&malformed_private_body);
        assert!(
            malformed_private_body.contains("Invalid JSON body for private ORAM request"),
            "{malformed_private_body}"
        );
        assert!(
            !malformed_private_body.contains(malformed_body_sentinel),
            "{malformed_private_body}"
        );

        let ordinary_request = actix_test::TestRequest::post()
            .uri("/collections/docs/ordinary/session")
            .set_json(body_with_unknown_field(
                sentinel,
                "ordinary-errors-still-render-field",
            ))
            .to_request();
        let ordinary_response = actix_test::call_service(&app, ordinary_request).await;
        assert_eq!(
            ordinary_response.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        let ordinary_body = actix_test::read_body(ordinary_response).await;
        let ordinary_body = String::from_utf8_lossy(&ordinary_body);
        assert!(ordinary_body.contains(sentinel), "{ordinary_body}");

        let lookalike_request = actix_test::TestRequest::post()
            .uri("/collections/docs/private-hnswish/text/session")
            .set_json(body_with_unknown_field(
                sentinel,
                "lookalike-errors-still-render-field",
            ))
            .to_request();
        let lookalike_response = actix_test::call_service(&app, lookalike_request).await;
        assert_eq!(
            lookalike_response.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        let lookalike_body = actix_test::read_body(lookalike_response).await;
        let lookalike_body = String::from_utf8_lossy(&lookalike_body);
        assert!(lookalike_body.contains(sentinel), "{lookalike_body}");

        for ordinary_collection_name in ["private-hnsw", "private-result-oram"] {
            let ordinary_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/{ordinary_collection_name}/points/search"
                ))
                .set_json(body_with_unknown_field(
                    sentinel,
                    "collection-name-marker-still-renders-field",
                ))
                .to_request();
            let ordinary_response = actix_test::call_service(&app, ordinary_request).await;
            assert_eq!(
                ordinary_response.status(),
                actix_web::http::StatusCode::BAD_REQUEST
            );
            let ordinary_body = actix_test::read_body(ordinary_response).await;
            let ordinary_body = String::from_utf8_lossy(&ordinary_body);
            assert!(ordinary_body.contains(sentinel), "{ordinary_body}");
        }
    }

    #[actix_web::test]
    async fn private_oram_json_validation_errors_do_not_reflect_unknown_enum_values() {
        let validate_json_config = actix_web_validator::JsonConfig::default()
            .error_handler(|err, req| validation_error_handler("JSON body", err, req));
        let app = actix_test::init_service(
            App::new()
                .app_data(validate_json_config)
                .route(
                    "/collections/{collection_name}/private-hnsw/{vector_name}/session",
                    web::post().to(private_oram_enum_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/ordinary/session",
                    web::post().to(private_oram_enum_validation_test_endpoint),
                ),
        )
        .await;

        let sentinel = "qdrant-sec-private-oram-result-privacy-sentinel";
        let private_request = actix_test::TestRequest::post()
            .uri("/collections/docs/private-hnsw/text/session")
            .set_json(serde_json::json!({ "_result_privacy": sentinel }))
            .to_request();
        let private_response = actix_test::call_service(&app, private_request).await;
        assert_eq!(
            private_response.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        let private_body = actix_test::read_body(private_response).await;
        let private_body = String::from_utf8_lossy(&private_body);
        assert!(
            private_body.contains("Invalid JSON body for private ORAM request"),
            "{private_body}"
        );
        assert!(!private_body.contains(sentinel), "{private_body}");
        assert!(!private_body.contains("unknown variant"), "{private_body}");

        let ordinary_request = actix_test::TestRequest::post()
            .uri("/collections/docs/ordinary/session")
            .set_json(serde_json::json!({ "_result_privacy": sentinel }))
            .to_request();
        let ordinary_response = actix_test::call_service(&app, ordinary_request).await;
        assert_eq!(
            ordinary_response.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        let ordinary_body = actix_test::read_body(ordinary_response).await;
        let ordinary_body = String::from_utf8_lossy(&ordinary_body);
        assert!(ordinary_body.contains(sentinel), "{ordinary_body}");
    }

    #[actix_web::test]
    async fn private_oram_path_validation_errors_do_not_reflect_path_values() {
        let validate_path_config = actix_web_validator::PathConfig::default()
            .error_handler(|err, req| validation_error_handler("path parameters", err, req));
        let app = actix_test::init_service(
            App::new()
                .app_data(validate_path_config)
                .route(
                    "/collections/{collection_name}/private-hnsw/{_secret_path_segment}/session",
                    web::post().to(private_oram_path_validation_test_endpoint),
                )
                .route(
                    "/collections/{collection_name}/ordinary/{_secret_path_segment}/session",
                    web::post().to(private_oram_path_validation_test_endpoint),
                ),
        )
        .await;

        let sentinel = "qdrant-sec-private-oram-path-parameter-sentinel";
        let private_request = actix_test::TestRequest::post()
            .uri(&format!(
                "/collections/docs/private-hnsw/{sentinel}/session"
            ))
            .to_request();
        let private_response = actix_test::call_service(&app, private_request).await;
        assert_eq!(
            private_response.status(),
            actix_web::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let private_body = actix_test::read_body(private_response).await;
        let private_body = String::from_utf8_lossy(&private_body);
        assert!(
            private_body.contains("Invalid path parameters for private ORAM request"),
            "{private_body}"
        );
        assert!(!private_body.contains(sentinel), "{private_body}");
        assert!(
            !private_body.contains("_secret_path_segment"),
            "{private_body}"
        );

        let ordinary_request = actix_test::TestRequest::post()
            .uri(&format!("/collections/docs/ordinary/{sentinel}/session"))
            .to_request();
        let ordinary_response = actix_test::call_service(&app, ordinary_request).await;
        assert_eq!(
            ordinary_response.status(),
            actix_web::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let ordinary_body = actix_test::read_body(ordinary_response).await;
        let ordinary_body = String::from_utf8_lossy(&ordinary_body);
        assert!(
            ordinary_body.contains("Validation error in path parameters"),
            "{ordinary_body}"
        );
    }

    #[test]
    fn private_oram_access_paths_redact_session_ids_and_queries() {
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-oram/v2/mutation/read?session_id=query-sentinel"
            ),
            "/collections/docs/private-oram/v2/mutation/read?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/session/session-id-sentinel/close"
            ),
            "/collections/docs/private-hnsw/text/session/{session_id}/close"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/session/bad/session-id-sentinel/close"
            ),
            "/collections/docs/private-hnsw/text/session/{session_id}/close"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/session/session-id-sentinel/read_paths?token=query-sentinel"
            ),
            "/collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/session/client-state-backup-sentinel?token=query-sentinel"
            ),
            "/collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/session/encryptedClientStateBackup-sentinel?token=query-sentinel"
            ),
            "/collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/session/clientStateCiphertext-sentinel?token=query-sentinel"
            ),
            "/collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextHash-sentinel?token=query-sentinel"
            ),
            "/collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted]"
        );
        for session_alias in [
            "clientStateBackup-sentinel",
            "clientStateBackups-sentinel",
            "clientStates-sentinel",
            "client_states-sentinel",
            "accessCount-sentinel",
            "accessCounts-sentinel",
            "access_count-sentinel",
            "access.count-sentinel",
            "access_counts-sentinel",
            "access.counts-sentinel",
            "accessVolume-sentinel",
            "accessVolumes-sentinel",
            "accessVolumeCount-sentinel",
            "accessVolumeCounts-sentinel",
            "accessVolumeLength-sentinel",
            "accessVolumeLengths-sentinel",
            "access_volume-sentinel",
            "access.volume-sentinel",
            "access_volumes-sentinel",
            "access.volumes-sentinel",
            "access_volume_len-sentinel",
            "access.volume.len-sentinel",
            "access_volume_count-sentinel",
            "access.volume.count-sentinel",
            "access_volume_counts-sentinel",
            "access.volume.counts-sentinel",
            "access_volume_length-sentinel",
            "access.volume.length-sentinel",
            "access_volume_lengths-sentinel",
            "access.volume.lengths-sentinel",
            "bucketCommitment-sentinel",
            "bucketCommitments-sentinel",
            "bucket_commitment-sentinel",
            "bucket.commitment-sentinel",
            "bucket_commitments-sentinel",
            "bucket.commitments-sentinel",
            "ciphertextSha256-sentinel",
            "ciphertextsSha256-sentinel",
            "ciphertext_sha256-sentinel",
            "ciphertexts_sha256-sentinel",
            "updatedBucketCommitment-sentinel",
            "updatedBucketCommitments-sentinel",
            "updated_bucket_commitment-sentinel",
            "updated.bucket.commitment-sentinel",
            "updated_bucket_commitments-sentinel",
            "updated.bucket.commitments-sentinel",
            "client_state_backup-sentinel",
            "clientStateSnapshot-sentinel",
            "clientStateSnapshots-sentinel",
            "client.state.snapshot-sentinel",
            "client_state_snapshot-sentinel",
            "client_state_snapshots-sentinel",
            "client.state.snapshots-sentinel",
            "clientStateCiphertextHashes-sentinel",
            "clientStateCiphertextSha256-sentinel",
            "clientStateCiphertextsSha256-sentinel",
            "client_state_ciphertext_hash.bin-sentinel",
            "client_state_ciphertext_hash.json-sentinel",
            "client_state_ciphertext_hashes-sentinel",
            "client_state_ciphertext_hashes.bin-sentinel",
            "client_state_ciphertext_hashes.json-sentinel",
            "client_state_ciphertext_sha256-sentinel",
            "client_state_ciphertext_sha256.bin-sentinel",
            "client_state_ciphertext_sha256.json-sentinel",
            "client_state_ciphertexts_sha256-sentinel",
            "client_state_ciphertexts_sha256.bin-sentinel",
            "client_state_ciphertexts_sha256.json-sentinel",
            "client_state_ciphertext-sentinel",
            "encryptedClientStateBackup-sentinel",
            "encryptedClientStateCiphertextHashes-sentinel",
            "encryptedClientStateCiphertextSha256-sentinel",
            "encryptedClientStateCiphertextsSha256-sentinel",
            "encryptedClientStateSnapshot-sentinel",
            "encryptedClientStateSnapshots-sentinel",
            "encrypted.client.state-sentinel",
            "encrypted.client.state.json-sentinel",
            "encrypted.client.state.snapshot-sentinel",
            "encrypted.client.state.snapshot.json-sentinel",
            "encrypted_client_state-sentinel",
            "encrypted_client_state.json-sentinel",
            "encrypted_client_state_snapshot-sentinel",
            "encrypted_client_state_snapshots-sentinel",
            "encrypted.client.state.snapshots-sentinel",
            "encrypted_client_state_ciphertext_hash.bin-sentinel",
            "encrypted_client_state_ciphertext_hash.json-sentinel",
            "encrypted_client_state_ciphertext_hashes-sentinel",
            "encrypted_client_state_ciphertext_hashes.bin-sentinel",
            "encrypted_client_state_ciphertext_hashes.json-sentinel",
            "encrypted_client_state_ciphertext_sha256-sentinel",
            "encrypted_client_state_ciphertext_sha256.bin-sentinel",
            "encrypted_client_state_ciphertext_sha256.json-sentinel",
            "encrypted_client_state_ciphertexts_sha256-sentinel",
            "encrypted_client_state_ciphertexts_sha256.bin-sentinel",
            "encrypted_client_state_ciphertexts_sha256.json-sentinel",
            "encrypted_client_state_ciphertext-sentinel",
            "oramPositionMapBackup-sentinel",
            "oramPositionMapBackups-sentinel",
            "oram_position_map_backup-sentinel",
            "oram_position_map_backups-sentinel",
            "positionMapBackup-sentinel",
            "positionMapBackups-sentinel",
            "position_map_backup-sentinel",
            "position_map_backups-sentinel",
            "stashBackup-sentinel",
            "stashBackups-sentinel",
            "stateCiphertext-sentinel",
            "stateCiphertextHashes-sentinel",
            "stateCiphertextSha256-sentinel",
            "stateCiphertextsSha256-sentinel",
            "state_ciphertext-sentinel",
            "state_ciphertext_hash.bin-sentinel",
            "state_ciphertext_hash.json-sentinel",
            "state_ciphertext_hashes-sentinel",
            "state_ciphertext_hashes.bin-sentinel",
            "state_ciphertext_hashes.json-sentinel",
            "state_ciphertext_sha256-sentinel",
            "state_ciphertext_sha256.bin-sentinel",
            "state_ciphertext_sha256.json-sentinel",
            "state_ciphertexts_sha256-sentinel",
            "state_ciphertexts_sha256.bin-sentinel",
            "state_ciphertexts_sha256.json-sentinel",
            "tokenMapBackup-sentinel",
            "tokenMapBackups-sentinel",
            "token.map.backup-sentinel",
            "token.map.backup.json-sentinel",
            "token.map.backups-sentinel",
            "token.map.backups.json-sentinel",
            "token_map_backup-sentinel",
            "token_map_backups-sentinel",
            "token.position.map-sentinel",
            "token.position.map.backup-sentinel",
            "token.position.map.backup.json-sentinel",
            "token.position.map.backups-sentinel",
            "token.position.map.backups.json-sentinel",
            "tokenPositionMapBackup-sentinel",
            "tokenPositionMapBackups-sentinel",
            "token_position_map_backup.json-sentinel",
            "token_position_map_backup-sentinel",
            "token_position_map_backups-sentinel",
        ] {
            assert_eq!(
                redact_private_oram_access_path(&format!(
                    "/collections/docs/private-hnsw/text/session/{session_alias}?token=query-sentinel"
                )),
                "/collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted]"
            );
        }
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/session/session-id-sentinel/close?token=query-sentinel"
            ),
            "/collections/docs/private-result-oram/session/{session_id}/close?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/session/bad/session-id-sentinel/close"
            ),
            "/collections/docs/private-result-oram/session/{session_id}/close"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/session/result-session-id-sentinel/read_buckets?bucket_ids=query-sentinel"
            ),
            "/collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/session/token-position-map-backup-sentinel?bucket_ids=query-sentinel"
            ),
            "/collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted]"
        );
        for session_alias in [
            "clientStateBackup-sentinel",
            "clientStateBackups-sentinel",
            "clientStates-sentinel",
            "client_states-sentinel",
            "accessCount-sentinel",
            "accessCounts-sentinel",
            "access_count-sentinel",
            "access.count-sentinel",
            "access_counts-sentinel",
            "access.counts-sentinel",
            "accessVolume-sentinel",
            "accessVolumes-sentinel",
            "accessVolumeCount-sentinel",
            "accessVolumeCounts-sentinel",
            "accessVolumeLength-sentinel",
            "accessVolumeLengths-sentinel",
            "access_volume-sentinel",
            "access.volume-sentinel",
            "access_volumes-sentinel",
            "access.volumes-sentinel",
            "access_volume_len-sentinel",
            "access.volume.len-sentinel",
            "access_volume_count-sentinel",
            "access.volume.count-sentinel",
            "access_volume_counts-sentinel",
            "access.volume.counts-sentinel",
            "access_volume_length-sentinel",
            "access.volume.length-sentinel",
            "access_volume_lengths-sentinel",
            "access.volume.lengths-sentinel",
            "bucketCommitment-sentinel",
            "bucketCommitments-sentinel",
            "bucket_commitment-sentinel",
            "bucket.commitment-sentinel",
            "bucket_commitments-sentinel",
            "bucket.commitments-sentinel",
            "ciphertextSha256-sentinel",
            "ciphertextsSha256-sentinel",
            "ciphertext_sha256-sentinel",
            "ciphertexts_sha256-sentinel",
            "updatedBucketCommitment-sentinel",
            "updatedBucketCommitments-sentinel",
            "updated_bucket_commitment-sentinel",
            "updated.bucket.commitment-sentinel",
            "updated_bucket_commitments-sentinel",
            "updated.bucket.commitments-sentinel",
            "client_state_backup-sentinel",
            "clientStateSnapshot-sentinel",
            "clientStateSnapshots-sentinel",
            "client.state.snapshot-sentinel",
            "client_state_snapshot-sentinel",
            "client_state_snapshots-sentinel",
            "client.state.snapshots-sentinel",
            "clientStateCiphertextHashes-sentinel",
            "clientStateCiphertextSha256-sentinel",
            "clientStateCiphertextsSha256-sentinel",
            "client_state_ciphertext_hash.bin-sentinel",
            "client_state_ciphertext_hash.json-sentinel",
            "client_state_ciphertext_hashes-sentinel",
            "client_state_ciphertext_hashes.bin-sentinel",
            "client_state_ciphertext_hashes.json-sentinel",
            "client_state_ciphertext_sha256-sentinel",
            "client_state_ciphertext_sha256.bin-sentinel",
            "client_state_ciphertext_sha256.json-sentinel",
            "client_state_ciphertexts_sha256-sentinel",
            "client_state_ciphertexts_sha256.bin-sentinel",
            "client_state_ciphertexts_sha256.json-sentinel",
            "encrypted.client.state-sentinel",
            "encrypted.client.state.json-sentinel",
            "encrypted.client.state.snapshot-sentinel",
            "encrypted.client.state.snapshot.json-sentinel",
            "encrypted_client_state.json-sentinel",
            "encryptedClientStateBackup-sentinel",
            "encryptedClientStateCiphertextHashes-sentinel",
            "encryptedClientStateCiphertextSha256-sentinel",
            "encryptedClientStateCiphertextsSha256-sentinel",
            "encryptedClientStateSnapshot-sentinel",
            "encryptedClientStateSnapshots-sentinel",
            "encrypted_client_state-sentinel",
            "encrypted_client_state_snapshot-sentinel",
            "encrypted_client_state_snapshots-sentinel",
            "encrypted.client.state.snapshots-sentinel",
            "encrypted_client_state_ciphertext_hash.bin-sentinel",
            "encrypted_client_state_ciphertext_hash.json-sentinel",
            "encrypted_client_state_ciphertext_hashes-sentinel",
            "encrypted_client_state_ciphertext_hashes.bin-sentinel",
            "encrypted_client_state_ciphertext_hashes.json-sentinel",
            "encrypted_client_state_ciphertext_sha256-sentinel",
            "encrypted_client_state_ciphertext_sha256.bin-sentinel",
            "encrypted_client_state_ciphertext_sha256.json-sentinel",
            "encrypted_client_state_ciphertexts_sha256-sentinel",
            "encrypted_client_state_ciphertexts_sha256.bin-sentinel",
            "encrypted_client_state_ciphertexts_sha256.json-sentinel",
            "client_state_ciphertext-sentinel",
            "oramPositionMapBackup-sentinel",
            "oramPositionMapBackups-sentinel",
            "oram_position_map_backup-sentinel",
            "oram_position_map_backups-sentinel",
            "positionMapBackup-sentinel",
            "positionMapBackups-sentinel",
            "position_map_backup-sentinel",
            "position_map_backups-sentinel",
            "stashBackup-sentinel",
            "stashBackups-sentinel",
            "stateCiphertext-sentinel",
            "stateCiphertextHashes-sentinel",
            "stateCiphertextSha256-sentinel",
            "stateCiphertextsSha256-sentinel",
            "state_ciphertext-sentinel",
            "state_ciphertext_hash.bin-sentinel",
            "state_ciphertext_hash-sentinel",
            "state_ciphertext_hash.json-sentinel",
            "state_ciphertext_hashes-sentinel",
            "state_ciphertext_hashes.bin-sentinel",
            "state_ciphertext_hashes.json-sentinel",
            "state_ciphertext_sha256-sentinel",
            "state_ciphertext_sha256.bin-sentinel",
            "state_ciphertext_sha256.json-sentinel",
            "state_ciphertexts_sha256-sentinel",
            "state_ciphertexts_sha256.bin-sentinel",
            "state_ciphertexts_sha256.json-sentinel",
            "tokenMapBackup-sentinel",
            "tokenMapBackups-sentinel",
            "token.map.backup-sentinel",
            "token.map.backup.json-sentinel",
            "token.map.backups-sentinel",
            "token.map.backups.json-sentinel",
            "token_map_backup-sentinel",
            "token_map_backups-sentinel",
            "token.position.map-sentinel",
            "token.position.map.backup-sentinel",
            "token.position.map.backup.json-sentinel",
            "token.position.map.backups-sentinel",
            "token.position.map.backups.json-sentinel",
            "payloadFetchToken-sentinel",
            "payloadFetchTokens-sentinel",
            "payload_fetch_token-sentinel",
            "payload_fetch_tokens-sentinel",
            "payload.fetch.token-sentinel",
            "payload.fetch.tokens-sentinel",
            "tokenPositionMapBackup-sentinel",
            "token_position_map_backup.json-sentinel",
            "token_position_map_backup-sentinel",
            "token_position_map_backups-sentinel",
        ] {
            assert_eq!(
                redact_private_oram_access_path(&format!(
                    "/collections/docs/private-result-oram/session/{session_alias}?bucket_ids=query-sentinel"
                )),
                "/collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted]"
            );
        }
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/session/tokenPositionMapBackups-sentinel?bucket_ids=query-sentinel"
            ),
            "/collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/session/stateCiphertext-sentinel?bucket_ids=query-sentinel"
            ),
            "/collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/session/stateCiphertextHash-sentinel?bucket_ids=query-sentinel"
            ),
            "/collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/oram/read_paths?leaf=query-sentinel"
            ),
            "/collections/docs/private-hnsw/text/oram/read_paths?[redacted]"
        );
        for query in [
            "proof_value=proof-value-query-sentinel",
            "proof.value=proof-value-dot-query-sentinel",
            "proofValue=proofValue-query-sentinel",
            "proof_values=proof-values-query-sentinel",
            "proof.values=proof-values-dot-query-sentinel",
            "access_count=access-count-query-sentinel",
            "access.count=access-count-dot-query-sentinel",
            "access_counts=access-counts-query-sentinel",
            "access.counts=access-counts-dot-query-sentinel",
            "accessCount=accessCount-query-sentinel",
            "accessCounts=accessCounts-query-sentinel",
            "access_volume=access-volume-query-sentinel",
            "access.volume=access-volume-dot-query-sentinel",
            "access_volumes=access-volumes-query-sentinel",
            "access.volumes=access-volumes-dot-query-sentinel",
            "accessVolume=accessVolume-query-sentinel",
            "accessVolumes=accessVolumes-query-sentinel",
            "access_volume_count=access-volume-count-query-sentinel",
            "access.volume.count=access-volume-count-dot-query-sentinel",
            "access_volume_counts=access-volume-counts-query-sentinel",
            "access.volume.counts=access-volume-counts-dot-query-sentinel",
            "accessVolumeCounts=accessVolumeCounts-query-sentinel",
            "access_volume_len=access-volume-len-query-sentinel",
            "access.volume.len=access-volume-len-dot-query-sentinel",
            "access_volume_length=access-volume-length-query-sentinel",
            "access.volume.length=access-volume-length-dot-query-sentinel",
            "access_volume_lengths=access-volume-lengths-query-sentinel",
            "access.volume.lengths=access-volume-lengths-dot-query-sentinel",
            "accessVolumeLength=accessVolumeLength-query-sentinel",
            "accessVolumeLengths=accessVolumeLengths-query-sentinel",
        ] {
            assert_eq!(
                redact_private_oram_access_path(&format!(
                    "/collections/docs/private-hnsw/text/oram/read_paths?{query}"
                )),
                "/collections/docs/private-hnsw/text/oram/read_paths?[redacted]"
            );
        }
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/buckets/bucket-id-sentinel"
            ),
            "/collections/docs/private-hnsw/text/buckets/[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/manifest/root-hash-sentinel"
            ),
            "/collections/docs/private-hnsw/text/manifest/[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/oram/read_paths/leaf-label-sentinel"
            ),
            "/collections/docs/private-hnsw/text/oram/read_paths/[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/oram/commit?old_root=root-sentinel"
            ),
            "/collections/docs/private-hnsw/text/oram/commit?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnsw/text/oram/commit/updated-bucket-sentinel"
            ),
            "/collections/docs/private-hnsw/text/oram/commit/[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/oram/read_buckets?bucket_ids=bucket-sentinel"
            ),
            "/collections/docs/private-result-oram/oram/read_buckets?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/oram/read_buckets?bucket_id=bucket-sentinel"
            ),
            "/collections/docs/private-result-oram/oram/read_buckets?[redacted]"
        );
        for query in [
            "proof_value=proof-value-query-sentinel",
            "proof.value=proof-value-dot-query-sentinel",
            "proofValue=proofValue-query-sentinel",
            "proof_values=proof-values-query-sentinel",
            "proof.values=proof-values-dot-query-sentinel",
            "access_count=access-count-query-sentinel",
            "access.count=access-count-dot-query-sentinel",
            "access_counts=access-counts-query-sentinel",
            "access.counts=access-counts-dot-query-sentinel",
            "accessCount=accessCount-query-sentinel",
            "accessCounts=accessCounts-query-sentinel",
            "access_volume=access-volume-query-sentinel",
            "access.volume=access-volume-dot-query-sentinel",
            "access_volumes=access-volumes-query-sentinel",
            "access.volumes=access-volumes-dot-query-sentinel",
            "accessVolume=accessVolume-query-sentinel",
            "accessVolumes=accessVolumes-query-sentinel",
            "access_volume_count=access-volume-count-query-sentinel",
            "access.volume.count=access-volume-count-dot-query-sentinel",
            "access_volume_counts=access-volume-counts-query-sentinel",
            "access.volume.counts=access-volume-counts-dot-query-sentinel",
            "accessVolumeCounts=accessVolumeCounts-query-sentinel",
            "access_volume_len=access-volume-len-query-sentinel",
            "access.volume.len=access-volume-len-dot-query-sentinel",
            "access_volume_length=access-volume-length-query-sentinel",
            "access.volume.length=access-volume-length-dot-query-sentinel",
            "access_volume_lengths=access-volume-lengths-query-sentinel",
            "access.volume.lengths=access-volume-lengths-dot-query-sentinel",
            "accessVolumeLength=accessVolumeLength-query-sentinel",
            "accessVolumeLengths=accessVolumeLengths-query-sentinel",
            "payload_fetch_token=payload-fetch-token-query-sentinel",
            "payload_fetch_tokens=payload-fetch-tokens-query-sentinel",
            "payloadFetchToken=payloadFetchToken-query-sentinel",
            "payloadFetchTokens=payloadFetchTokens-query-sentinel",
            "payload.fetch.token=payload-fetch-token-dot-query-sentinel",
            "payload.fetch.tokens=payload-fetch-tokens-dot-query-sentinel",
        ] {
            assert_eq!(
                redact_private_oram_access_path(&format!(
                    "/collections/docs/private-result-oram/oram/read_buckets?{query}"
                )),
                "/collections/docs/private-result-oram/oram/read_buckets?[redacted]"
            );
        }
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/buckets/result-bucket-id-sentinel"
            ),
            "/collections/docs/private-result-oram/buckets/[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/manifest/result-root-hash-sentinel"
            ),
            "/collections/docs/private-result-oram/manifest/[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/oram/read_buckets/result-bucket-id-sentinel"
            ),
            "/collections/docs/private-result-oram/oram/read_buckets/[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/oram/commit?updated_buckets=bucket-sentinel"
            ),
            "/collections/docs/private-result-oram/oram/commit?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/oram/commit?updated_bucket=bucket-sentinel"
            ),
            "/collections/docs/private-result-oram/oram/commit?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram/oram/commit/result-updated-bucket-sentinel"
            ),
            "/collections/docs/private-result-oram/oram/commit/[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path("/collections/docs/points/scroll?offset=7"),
            "/collections/docs/points/scroll?offset=7"
        );
        assert_eq!(
            redact_private_oram_access_path("/collections/docs/private-hnsw?leaf=query-sentinel"),
            "/collections/docs/private-hnsw?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oram?token=query-sentinel"
            ),
            "/collections/docs/private-result-oram?[redacted]"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/not-private-hnsw?leaf=query-sentinel"
            ),
            "/collections/docs/not-private-hnsw?leaf=query-sentinel"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-hnswish/text/oram/read_paths?leaf=query-sentinel"
            ),
            "/collections/docs/private-hnswish/text/oram/read_paths?leaf=query-sentinel"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-result-oramish?token=query-sentinel"
            ),
            "/collections/docs/private-result-oramish?token=query-sentinel"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/private-hnsw/points/search?leaf=query-sentinel"
            ),
            "/collections/private-hnsw/points/search?leaf=query-sentinel"
        );
        assert_eq!(
            redact_private_oram_access_path(
                "/collections/private-result-oram/points/search?token=query-sentinel"
            ),
            "/collections/private-result-oram/points/search?token=query-sentinel"
        );
    }

    #[test]
    fn private_oram_recovery_access_paths_redact_queries_and_unknown_suffixes() {
        for action in [
            "begin",
            "export-context",
            "upload",
            "status",
            "verify",
            "commit",
            "abort",
        ] {
            let endpoint = format!("/collections/docs/private-oram/recovery/{action}");
            assert_eq!(redact_private_oram_access_path(&endpoint), endpoint);
            assert_eq!(
                redact_private_oram_access_path(&format!(
                    "{endpoint}?operation_id=operation-token-sentinel"
                )),
                format!("{endpoint}?[redacted]")
            );
            assert_eq!(
                redact_private_oram_access_path(&format!(
                    "{endpoint}/operation-token-sentinel?chunk=chunk-sentinel"
                )),
                format!("{endpoint}/[redacted]?[redacted]")
            );
        }

        assert_eq!(
            redact_private_oram_access_path(
                "/collections/docs/private-oram/recovery/finalize?operation_id=operation-token-sentinel"
            ),
            "/collections/docs/private-oram/recovery/[redacted]?[redacted]"
        );

        for lookalike in [
            "/collections/docs/private-oramish/recovery/begin?operation_id=operation-token-sentinel",
            "/collections/docs/private-oram/recover/begin?operation_id=operation-token-sentinel",
            "/collections/private-oram/points/search?operation_id=operation-token-sentinel",
        ] {
            assert_eq!(redact_private_oram_access_path(lookalike), lookalike);
        }
    }

    #[test]
    fn private_oram_access_log_request_line_redacts_dynamic_values() {
        let cases = [
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/oram/read_paths/leaf-label-sentinel?leaf=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/oram/read_paths/[redacted]?[redacted] HTTP/1.1",
                ["leaf-label-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/result-session-id-sentinel/close?token=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/close?[redacted] HTTP/1.1",
                ["result-session-id-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/result-session-id-sentinel/read_buckets?bucket_ids=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["result-session-id-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/session/client-state-backup-sentinel/read_paths?token=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["client-state-backup-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/session/encryptedClientStateBackup-sentinel/read_paths?token=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["encryptedClientStateBackup-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/session/clientStateCiphertext-sentinel/read_paths?token=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["clientStateCiphertext-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/session/client_state_ciphertext-sentinel/read_paths?token=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["client_state_ciphertext-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextHash-sentinel/read_paths?token=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                [
                    "encryptedClientStateCiphertextHash-sentinel",
                    "query-sentinel",
                ],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_hash-sentinel/read_paths?token=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                [
                    "encrypted_client_state_ciphertext_hash-sentinel",
                    "query-sentinel",
                ],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/token-position-map-backup-sentinel/read_buckets?bucket_ids=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["token-position-map-backup-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/tokenPositionMapBackups-sentinel/read_buckets?bucket_ids=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["tokenPositionMapBackups-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/token_position_map_backups-sentinel/read_buckets?bucket_ids=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["token_position_map_backups-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/encrypted_client_state-sentinel/read_buckets?bucket_ids=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["encrypted_client_state-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/stateCiphertext-sentinel/read_buckets?bucket_ids=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["stateCiphertext-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/stateCiphertextHash-sentinel/read_buckets?bucket_ids=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["stateCiphertextHash-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/state_ciphertext_hash-sentinel/read_buckets?bucket_ids=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["state_ciphertext_hash-sentinel", "query-sentinel"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/oram/read_paths?proof_value=proof-value-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/oram/read_paths?[redacted] HTTP/1.1",
                ["proof-value-query-sentinel", "proof_value"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/oram/read_paths?accessVolume=accessVolume-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/oram/read_paths?[redacted] HTTP/1.1",
                ["accessVolume-query-sentinel", "accessVolume"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-hnsw/text/oram/read_paths?accessVolumes=accessVolumes-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-hnsw/text/oram/read_paths?[redacted] HTTP/1.1",
                ["accessVolumes-query-sentinel", "accessVolumes"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/oram/read_buckets?proof_values=proof-values-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/oram/read_buckets?[redacted] HTTP/1.1",
                ["proof-values-query-sentinel", "proof_values"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/oram/read_buckets?accessVolumeLength=accessVolumeLength-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/oram/read_buckets?[redacted] HTTP/1.1",
                ["accessVolumeLength-query-sentinel", "accessVolumeLength"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/oram/read_buckets?access_volumes=access-volumes-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/oram/read_buckets?[redacted] HTTP/1.1",
                ["access-volumes-query-sentinel", "access_volumes"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/oram/read_buckets?access.volumes=access-volumes-dot-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/oram/read_buckets?[redacted] HTTP/1.1",
                ["access-volumes-dot-query-sentinel", "access.volumes"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/oram/read_buckets?payloadFetchToken=payloadFetchToken-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/oram/read_buckets?[redacted] HTTP/1.1",
                ["payloadFetchToken-query-sentinel", "payloadFetchToken"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/oram/read_buckets?payload.fetch.token=payload-fetch-token-dot-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/oram/read_buckets?[redacted] HTTP/1.1",
                ["payload-fetch-token-dot-query-sentinel", "payload.fetch.token"],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/oram/read_buckets?payload.fetch.tokens=payload-fetch-tokens-dot-query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/oram/read_buckets?[redacted] HTTP/1.1",
                [
                    "payload-fetch-tokens-dot-query-sentinel",
                    "payload.fetch.tokens",
                ],
            ),
            (
                actix_test::TestRequest::post()
                    .uri(
                        "/collections/docs/private-result-oram/session/payload_fetch_token-sentinel/read_buckets?payload_fetch_tokens=query-sentinel",
                    )
                    .to_srv_request(),
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1",
                ["payload_fetch_token-sentinel", "query-sentinel"],
            ),
        ];

        for (request, expected, sentinels) in cases {
            let line = access_log_request_line(&request);
            assert_eq!(line, expected);
            for sentinel in sentinels {
                assert!(!line.contains(sentinel), "{line}");
            }
        }

        for sentinel in [
            "clientStateBackup-sentinel",
            "clientStateBackups-sentinel",
            "clientStates-sentinel",
            "client_states-sentinel",
            "client_state_backup-sentinel",
            "bucketCommitment-sentinel",
            "bucketCommitments-sentinel",
            "bucket_commitment-sentinel",
            "bucket.commitment-sentinel",
            "bucket_commitments-sentinel",
            "bucket.commitments-sentinel",
            "ciphertextSha256-sentinel",
            "ciphertextsSha256-sentinel",
            "ciphertext_sha256-sentinel",
            "ciphertexts_sha256-sentinel",
            "updatedBucketCommitment-sentinel",
            "updatedBucketCommitments-sentinel",
            "updated_bucket_commitment-sentinel",
            "updated.bucket.commitment-sentinel",
            "updated_bucket_commitments-sentinel",
            "updated.bucket.commitments-sentinel",
            "clientStateSnapshot-sentinel",
            "clientStateSnapshots-sentinel",
            "client.state.snapshot-sentinel",
            "client_state_snapshot-sentinel",
            "client_state_snapshots-sentinel",
            "client.state.snapshots-sentinel",
            "clientStateCiphertextHashes-sentinel",
            "clientStateCiphertextSha256-sentinel",
            "clientStateCiphertextsSha256-sentinel",
            "client_state_ciphertext_hash.bin-sentinel",
            "client_state_ciphertext_hash.json-sentinel",
            "client_state_ciphertext_hashes-sentinel",
            "client_state_ciphertext_hashes.bin-sentinel",
            "client_state_ciphertext_hashes.json-sentinel",
            "client_state_ciphertext_sha256-sentinel",
            "client_state_ciphertext_sha256.bin-sentinel",
            "client_state_ciphertext_sha256.json-sentinel",
            "client_state_ciphertexts_sha256-sentinel",
            "client_state_ciphertexts_sha256.bin-sentinel",
            "client_state_ciphertexts_sha256.json-sentinel",
            "client_state_ciphertext-sentinel",
            "encryptedClientStateBackup-sentinel",
            "encryptedClientStateCiphertextHashes-sentinel",
            "encryptedClientStateCiphertextSha256-sentinel",
            "encryptedClientStateCiphertextsSha256-sentinel",
            "encryptedClientStateSnapshot-sentinel",
            "encryptedClientStateSnapshots-sentinel",
            "encrypted.client.state-sentinel",
            "encrypted.client.state.json-sentinel",
            "encrypted.client.state.snapshot-sentinel",
            "encrypted.client.state.snapshot.json-sentinel",
            "encrypted_client_state_ciphertext_hashes-sentinel",
            "encrypted_client_state_ciphertext_hash.bin-sentinel",
            "encrypted_client_state_ciphertext_hash.json-sentinel",
            "encrypted_client_state_ciphertext_hashes.bin-sentinel",
            "encrypted_client_state_ciphertext_hashes.json-sentinel",
            "encrypted_client_state_ciphertext_sha256-sentinel",
            "encrypted_client_state_ciphertext_sha256.bin-sentinel",
            "encrypted_client_state_ciphertext_sha256.json-sentinel",
            "encrypted_client_state_ciphertexts_sha256-sentinel",
            "encrypted_client_state_ciphertexts_sha256.bin-sentinel",
            "encrypted_client_state_ciphertexts_sha256.json-sentinel",
            "encrypted_client_state-sentinel",
            "encrypted_client_state_snapshot-sentinel",
            "encrypted_client_state_snapshots-sentinel",
            "encrypted.client.state.snapshots-sentinel",
            "encrypted_client_state_ciphertext-sentinel",
            "oramPositionMapBackup-sentinel",
            "oramPositionMapBackups-sentinel",
            "oram_position_map_backup-sentinel",
            "oram_position_map_backups-sentinel",
            "positionMapBackup-sentinel",
            "positionMapBackups-sentinel",
            "position_map_backup-sentinel",
            "position_map_backups-sentinel",
            "stashBackup-sentinel",
            "stashBackup.json-sentinel",
            "stashBackups-sentinel",
            "stashBackups.json-sentinel",
            "stateCiphertext-sentinel",
            "stateCiphertextHashes-sentinel",
            "stateCiphertextSha256-sentinel",
            "stateCiphertextsSha256-sentinel",
            "state_ciphertext-sentinel",
            "state_ciphertext_hash.bin-sentinel",
            "state_ciphertext_hash.json-sentinel",
            "state_ciphertext_hashes-sentinel",
            "state_ciphertext_hashes.bin-sentinel",
            "state_ciphertext_hashes.json-sentinel",
            "state_ciphertext_sha256-sentinel",
            "state_ciphertext_sha256.bin-sentinel",
            "state_ciphertext_sha256.json-sentinel",
            "state_ciphertexts_sha256-sentinel",
            "state_ciphertexts_sha256.bin-sentinel",
            "state_ciphertexts_sha256.json-sentinel",
            "tokenMapBackup-sentinel",
            "tokenMapBackups-sentinel",
            "token.map.backup-sentinel",
            "token.map.backup.json-sentinel",
            "token.map.backups-sentinel",
            "token.map.backups.json-sentinel",
            "token_map_backup-sentinel",
            "token_map_backups-sentinel",
            "token.position.map-sentinel",
            "token.position.map.backup-sentinel",
            "token.position.map.backup.json-sentinel",
            "token.position.map.backups-sentinel",
            "token.position.map.backups.json-sentinel",
            "tokenPositionMapBackup-sentinel",
            "tokenPositionMapBackups-sentinel",
            "token_position_map_backup.json-sentinel",
            "token_position_map_backup-sentinel",
            "token_position_map_backups-sentinel",
        ] {
            let uri = format!(
                "/collections/docs/private-hnsw/text/session/{sentinel}/read_paths?token=query-sentinel"
            );
            let request = actix_test::TestRequest::post().uri(&uri).to_srv_request();
            let line = access_log_request_line(&request);
            assert_eq!(
                line,
                "POST /collections/docs/private-hnsw/text/session/{session_id}/[redacted]?[redacted] HTTP/1.1"
            );
            assert!(!line.contains(sentinel), "{line}");
            assert!(!line.contains("query-sentinel"), "{line}");
        }

        for sentinel in [
            "clientStateBackup-sentinel",
            "clientStateBackups-sentinel",
            "clientStates-sentinel",
            "client_states-sentinel",
            "client_state_backup-sentinel",
            "bucketCommitment-sentinel",
            "bucketCommitments-sentinel",
            "bucket_commitment-sentinel",
            "bucket.commitment-sentinel",
            "bucket_commitments-sentinel",
            "bucket.commitments-sentinel",
            "ciphertextSha256-sentinel",
            "ciphertextsSha256-sentinel",
            "ciphertext_sha256-sentinel",
            "ciphertexts_sha256-sentinel",
            "updatedBucketCommitment-sentinel",
            "updatedBucketCommitments-sentinel",
            "updated_bucket_commitment-sentinel",
            "updated.bucket.commitment-sentinel",
            "updated_bucket_commitments-sentinel",
            "updated.bucket.commitments-sentinel",
            "clientStateSnapshot-sentinel",
            "clientStateSnapshots-sentinel",
            "client.state.snapshot-sentinel",
            "client_state_snapshot-sentinel",
            "client_state_snapshots-sentinel",
            "client.state.snapshots-sentinel",
            "clientStateCiphertextHashes-sentinel",
            "clientStateCiphertextSha256-sentinel",
            "clientStateCiphertextsSha256-sentinel",
            "client_state_ciphertext_hash.bin-sentinel",
            "client_state_ciphertext_hash.json-sentinel",
            "client_state_ciphertext_hashes-sentinel",
            "client_state_ciphertext_hashes.bin-sentinel",
            "client_state_ciphertext_hashes.json-sentinel",
            "client_state_ciphertext_sha256-sentinel",
            "client_state_ciphertext_sha256.bin-sentinel",
            "client_state_ciphertext_sha256.json-sentinel",
            "client_state_ciphertexts_sha256-sentinel",
            "client_state_ciphertexts_sha256.bin-sentinel",
            "client_state_ciphertexts_sha256.json-sentinel",
            "encrypted.client.state-sentinel",
            "encrypted.client.state.json-sentinel",
            "encrypted.client.state.snapshot-sentinel",
            "encrypted.client.state.snapshot.json-sentinel",
            "encrypted_client_state.json-sentinel",
            "encryptedClientStateBackup-sentinel",
            "encryptedClientStateCiphertextHashes-sentinel",
            "encryptedClientStateCiphertextSha256-sentinel",
            "encryptedClientStateCiphertextsSha256-sentinel",
            "encryptedClientStateSnapshot-sentinel",
            "encryptedClientStateSnapshots-sentinel",
            "encrypted_client_state_snapshot-sentinel",
            "encrypted_client_state_snapshots-sentinel",
            "encrypted.client.state.snapshots-sentinel",
            "encrypted_client_state_ciphertext_hash.bin-sentinel",
            "encrypted_client_state_ciphertext_hash.json-sentinel",
            "encrypted_client_state_ciphertext_hashes-sentinel",
            "encrypted_client_state_ciphertext_hashes.bin-sentinel",
            "encrypted_client_state_ciphertext_hashes.json-sentinel",
            "encrypted_client_state_ciphertext_sha256-sentinel",
            "encrypted_client_state_ciphertext_sha256.bin-sentinel",
            "encrypted_client_state_ciphertext_sha256.json-sentinel",
            "encrypted_client_state_ciphertexts_sha256-sentinel",
            "encrypted_client_state_ciphertexts_sha256.bin-sentinel",
            "encrypted_client_state_ciphertexts_sha256.json-sentinel",
            "client_state_ciphertext-sentinel",
            "oramPositionMapBackup-sentinel",
            "oramPositionMapBackups-sentinel",
            "oram_position_map_backup-sentinel",
            "oram_position_map_backups-sentinel",
            "positionMapBackup-sentinel",
            "positionMapBackups-sentinel",
            "position_map_backup-sentinel",
            "position_map_backups-sentinel",
            "stashBackup-sentinel",
            "stashBackup.json-sentinel",
            "stashBackups-sentinel",
            "stashBackups.json-sentinel",
            "stateCiphertext-sentinel",
            "stateCiphertextHashes-sentinel",
            "stateCiphertextSha256-sentinel",
            "stateCiphertextsSha256-sentinel",
            "state_ciphertext-sentinel",
            "state_ciphertext_hash.bin-sentinel",
            "state_ciphertext_hash-sentinel",
            "state_ciphertext_hash.json-sentinel",
            "state_ciphertext_hashes-sentinel",
            "state_ciphertext_hashes.bin-sentinel",
            "state_ciphertext_hashes.json-sentinel",
            "state_ciphertext_sha256-sentinel",
            "state_ciphertext_sha256.bin-sentinel",
            "state_ciphertext_sha256.json-sentinel",
            "state_ciphertexts_sha256-sentinel",
            "state_ciphertexts_sha256.bin-sentinel",
            "state_ciphertexts_sha256.json-sentinel",
            "tokenMapBackup-sentinel",
            "tokenMapBackups-sentinel",
            "token.map.backup-sentinel",
            "token.map.backup.json-sentinel",
            "token.map.backups-sentinel",
            "token.map.backups.json-sentinel",
            "token_map_backup-sentinel",
            "token_map_backups-sentinel",
            "token.position.map-sentinel",
            "token.position.map.backup-sentinel",
            "token.position.map.backup.json-sentinel",
            "token.position.map.backups-sentinel",
            "token.position.map.backups.json-sentinel",
            "payloadFetchToken-sentinel",
            "payloadFetchTokens-sentinel",
            "payload_fetch_token-sentinel",
            "payload_fetch_tokens-sentinel",
            "payload.fetch.tokens-sentinel",
            "tokenPositionMapBackup-sentinel",
            "token_position_map_backup.json-sentinel",
            "token_position_map_backup-sentinel",
            "token_position_map_backups-sentinel",
        ] {
            let uri = format!(
                "/collections/docs/private-result-oram/session/{sentinel}/read_buckets?bucket_ids=query-sentinel"
            );
            let request = actix_test::TestRequest::post().uri(&uri).to_srv_request();
            let line = access_log_request_line(&request);
            assert_eq!(
                line,
                "POST /collections/docs/private-result-oram/session/{session_id}/[redacted]?[redacted] HTTP/1.1"
            );
            assert!(!line.contains(sentinel), "{line}");
            assert!(!line.contains("query-sentinel"), "{line}");
        }
    }
}
