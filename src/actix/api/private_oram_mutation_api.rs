use std::fmt::{self, Debug, Formatter};

use actix_web::{HttpResponse, web};
use actix_web_validator::{Json, Path};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Number, Value};
use storage::dispatcher::Dispatcher;
use tokio::time::Instant;
use validator::{Validate, ValidationErrors};

use super::CollectionPath;
use crate::actix::auth::ActixAuth;
use crate::actix::helpers::process_response;
use crate::common::private_hnsw::{
    PrivateHnswClientSignature, PrivateHnswReadPadding, PrivateHnswReadPathsResponse,
};
use crate::common::private_oram_mutation::run_private_oram_mutation_append_v2;
use crate::common::private_oram_mutation_session::{
    PrivateOramMutationAppendInputV2, PrivateOramMutationAppendJobPhaseV2,
    PrivateOramMutationEnrollInputV2, PrivateOramMutationEnrollmentTemplateInputV2,
    PrivateOramMutationOpenInputV2, close_private_oram_mutation_session_v2,
    do_enroll_private_oram_mutation_collection_v2, do_open_private_oram_mutation_session_v2,
    do_read_private_oram_mutation_hnsw_paths_v2, do_read_private_oram_mutation_result_buckets_v2,
    do_validate_private_oram_mutation_append_v2, private_oram_mutation_enrollment_template_v2,
    private_oram_mutation_session_status_v2,
};
use crate::common::private_oram_peer_identity::PrivateOramPeerRecoveryIdentity;
use crate::common::private_result_oram::PrivateResultOramReadBucketsResponse;
use crate::settings::Settings;

const PRIVATE_ORAM_MUTATION_SESSION_JSON_LIMIT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Deserialize, Validate)]
struct PrivateOramMutationPathV2 {
    #[validate(nested)]
    #[serde(flatten)]
    collection: CollectionPath,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PrivateOramMutationReadRequestV2 {
    Hnsw {
        session_id: String,
        paths: Vec<String>,
        padding: PrivateOramMutationHnswReadPaddingV2,
        client_signature: PrivateOramMutationHnswSignatureV2,
    },
    Result {
        session_id: String,
        bucket_ids: Vec<u64>,
        read_signature: qdrant_sec::PrivateResultOramSignature,
    },
}

impl Debug for PrivateOramMutationReadRequestV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hnsw { padding, .. } => formatter
                .debug_struct("PrivateOramMutationReadRequestV2::Hnsw")
                .field("session_id", &"[redacted]")
                .field("path_count", &"[redacted]")
                .field("padding", padding)
                .field("client_signature", &"[redacted]")
                .finish(),
            Self::Result { .. } => formatter
                .debug_struct("PrivateOramMutationReadRequestV2::Result")
                .field("session_id", &"[redacted]")
                .field("bucket_id_count", &"[redacted]")
                .field("read_signature", &"[redacted]")
                .finish(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationHnswReadPaddingV2 {
    requested_paths: u32,
    dummy_paths_included: bool,
}

impl Debug for PrivateOramMutationHnswReadPaddingV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationHnswReadPaddingV2")
            .field("requested_paths", &"[redacted]")
            .field("dummy_paths_included", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationHnswSignatureV2 {
    alg: String,
    key_id: String,
    sig: String,
}

impl Debug for PrivateOramMutationHnswSignatureV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationHnswSignatureV2")
            .field("alg", &self.alg)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
    }
}

impl From<PrivateOramMutationHnswReadPaddingV2> for PrivateHnswReadPadding {
    fn from(padding: PrivateOramMutationHnswReadPaddingV2) -> Self {
        Self {
            requested_paths: padding.requested_paths,
            dummy_paths_included: padding.dummy_paths_included,
        }
    }
}

impl From<PrivateOramMutationHnswSignatureV2> for PrivateHnswClientSignature {
    fn from(signature: PrivateOramMutationHnswSignatureV2) -> Self {
        Self {
            alg: signature.alg,
            key_id: signature.key_id,
            sig: signature.sig,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationSessionRequestV2 {
    session_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationAppendAcceptedV2 {
    accepted: bool,
    phase: PrivateOramMutationAppendJobPhaseV2,
}

impl Debug for PrivateOramMutationSessionRequestV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationSessionRequestV2")
            .field("session_id", &"[redacted]")
            .finish()
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "response", rename_all = "snake_case")]
enum PrivateOramMutationReadResponseV2 {
    Hnsw(PrivateHnswReadPathsResponse),
    Result(PrivateResultOramReadBucketsResponse),
}

impl Debug for PrivateOramMutationReadResponseV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hnsw(_) => formatter.write_str("PrivateOramMutationReadResponseV2::Hnsw"),
            Self::Result(_) => formatter.write_str("PrivateOramMutationReadResponseV2::Result"),
        }
    }
}

/// V2 REST alone uses canonical decimal strings for every u64-bearing field. The wrapped
/// request/response types contain only protocol DTOs and no arbitrary user payload objects.
struct PrivateOramMutationWireV2<T>(T);

impl<T> PrivateOramMutationWireV2<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Debug for PrivateOramMutationWireV2<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramMutationWireV2")
            .field(&"[redacted]")
            .finish()
    }
}

impl<T> Validate for PrivateOramMutationWireV2<T> {
    fn validate(&self) -> Result<(), ValidationErrors> {
        Ok(())
    }
}

impl<'de, T> Deserialize<'de> for PrivateOramMutationWireV2<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;
        decode_canonical_u64_fields(&mut value).map_err(D::Error::custom)?;
        serde_json::from_value(value)
            .map(Self)
            .map_err(D::Error::custom)
    }
}

impl<T> Serialize for PrivateOramMutationWireV2<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serde_json::to_value(&self.0).map_err(serde::ser::Error::custom)?;
        encode_canonical_u64_fields(&mut value).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}

async fn open_session(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateOramMutationPathV2>,
    request: Json<PrivateOramMutationWireV2<PrivateOramMutationOpenInputV2>>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let collection_name = path.into_inner().collection.collection_name;
    let request = request.into_inner().into_inner();
    let timing = Instant::now();
    let result = do_open_private_oram_mutation_session_v2(
        dispatcher.get_ref(),
        &auth,
        settings.get_ref(),
        &collection_name,
        request,
    )
    .await
    .map(PrivateOramMutationWireV2);
    process_response(result, timing, None)
}

async fn enrollment_template(
    dispatcher: web::Data<Dispatcher>,
    path: Path<PrivateOramMutationPathV2>,
    request: Json<PrivateOramMutationWireV2<PrivateOramMutationEnrollmentTemplateInputV2>>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let collection_name = path.into_inner().collection.collection_name;
    let request = request.into_inner().into_inner();
    let timing = Instant::now();
    let result = private_oram_mutation_enrollment_template_v2(
        dispatcher.get_ref(),
        &auth,
        &collection_name,
        request,
    )
    .await
    .map(PrivateOramMutationWireV2);
    process_response(result, timing, None)
}

async fn enroll(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    identity: web::Data<Option<std::sync::Arc<PrivateOramPeerRecoveryIdentity>>>,
    path: Path<PrivateOramMutationPathV2>,
    request: Json<PrivateOramMutationWireV2<PrivateOramMutationEnrollInputV2>>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let collection_name = path.into_inner().collection.collection_name;
    let request = request.into_inner().into_inner();
    let timing = Instant::now();
    let result = match identity.get_ref().as_deref() {
        Some(identity) => do_enroll_private_oram_mutation_collection_v2(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            identity,
            &collection_name,
            request,
        )
        .await
        .map(PrivateOramMutationWireV2),
        None => Err(
            storage::content_manager::errors::StorageError::service_error(
                "private ORAM mutation peer identity is unavailable",
            ),
        ),
    };
    process_response(result, timing, None)
}

async fn read(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateOramMutationPathV2>,
    request: Json<PrivateOramMutationWireV2<PrivateOramMutationReadRequestV2>>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let collection_name = path.into_inner().collection.collection_name;
    let request = request.into_inner().into_inner();
    let timing = Instant::now();
    let result = match request {
        PrivateOramMutationReadRequestV2::Hnsw {
            session_id,
            paths,
            padding,
            client_signature,
        } => do_read_private_oram_mutation_hnsw_paths_v2(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &collection_name,
            &session_id,
            paths,
            padding.into(),
            client_signature.into(),
        )
        .await
        .map(PrivateOramMutationReadResponseV2::Hnsw),
        PrivateOramMutationReadRequestV2::Result {
            session_id,
            bucket_ids,
            read_signature,
        } => do_read_private_oram_mutation_result_buckets_v2(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &collection_name,
            &session_id,
            bucket_ids,
            read_signature,
        )
        .await
        .map(PrivateOramMutationReadResponseV2::Result),
    }
    .map(PrivateOramMutationWireV2);
    process_response(result, timing, None)
}

async fn append(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    identity: web::Data<Option<std::sync::Arc<PrivateOramPeerRecoveryIdentity>>>,
    path: Path<PrivateOramMutationPathV2>,
    request: Json<PrivateOramMutationWireV2<PrivateOramMutationAppendInputV2>>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let collection_name = path.into_inner().collection.collection_name;
    let request = request.into_inner().into_inner();
    let timing = Instant::now();
    let result = async {
        let identity = identity.get_ref().as_ref().cloned().ok_or_else(|| {
            storage::content_manager::errors::StorageError::service_error(
                "private ORAM mutation peer identity is unavailable",
            )
        })?;
        let validated = do_validate_private_oram_mutation_append_v2(
            dispatcher.get_ref(),
            &auth,
            settings.get_ref(),
            &collection_name,
            request,
        )
        .await?;
        let detached = validated.detach_to_registry_job(dispatcher.get_ref())?;
        let dispatcher = dispatcher.into_inner();
        let settings = settings.into_inner();
        actix_web::rt::spawn(async move {
            if run_private_oram_mutation_append_v2(dispatcher, settings, identity, detached)
                .await
                .is_err()
            {
                log::warn!("private ORAM mutation append requires status inspection or recovery");
            }
        });
        Ok(PrivateOramMutationAppendAcceptedV2 {
            accepted: true,
            phase: PrivateOramMutationAppendJobPhaseV2::PrestagePending,
        })
    }
    .await
    .map(PrivateOramMutationWireV2);
    process_response(result, timing, None)
}

async fn status(
    path: Path<PrivateOramMutationPathV2>,
    request: Json<PrivateOramMutationWireV2<PrivateOramMutationSessionRequestV2>>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let collection_name = path.into_inner().collection.collection_name;
    let request = request.into_inner().into_inner();
    let timing = Instant::now();
    let result =
        private_oram_mutation_session_status_v2(&auth, &collection_name, &request.session_id)
            .map(PrivateOramMutationWireV2);
    process_response(result, timing, None)
}

async fn close(
    path: Path<PrivateOramMutationPathV2>,
    request: Json<PrivateOramMutationWireV2<PrivateOramMutationSessionRequestV2>>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let collection_name = path.into_inner().collection.collection_name;
    let request = request.into_inner().into_inner();
    let timing = Instant::now();
    let result =
        close_private_oram_mutation_session_v2(&auth, &collection_name, &request.session_id)
            .map(PrivateOramMutationWireV2);
    process_response(result, timing, None)
}

pub fn config_private_oram_mutation_api(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/collections/{collection_name}/private-oram/v2/mutation")
            .app_data(private_oram_mutation_json_config())
            .route("/enrollment-template", web::post().to(enrollment_template))
            .route("/enroll", web::post().to(enroll))
            .route("/open", web::post().to(open_session))
            .route("/read", web::post().to(read))
            .route("/append", web::post().to(append))
            .route("/status", web::post().to(status))
            .route("/close", web::post().to(close)),
    );
}

fn private_oram_mutation_json_config() -> actix_web_validator::JsonConfig {
    actix_web_validator::JsonConfig::default()
        .limit(PRIVATE_ORAM_MUTATION_SESSION_JSON_LIMIT_BYTES)
        .error_handler(|error, request| {
            crate::actix::validation_error_handler("JSON body", error, request)
        })
}

fn decode_canonical_u64_fields(value: &mut Value) -> Result<(), &'static str> {
    match value {
        Value::Array(values) => {
            for value in values {
                decode_canonical_u64_fields(value)?;
            }
        }
        Value::Object(fields) => {
            for (name, value) in fields {
                if is_u64_array_field(name) {
                    let Value::Array(values) = value else {
                        return Err("private ORAM V2 u64 list field is invalid");
                    };
                    for value in values {
                        let Value::String(encoded) = value else {
                            return Err("private ORAM V2 u64 list values must be decimal strings");
                        };
                        let parsed = parse_canonical_u64(encoded)?;
                        *value = Value::Number(Number::from(parsed));
                    }
                } else if is_u64_field(name) {
                    let Value::String(encoded) = value else {
                        return Err("private ORAM V2 u64 fields must be decimal strings");
                    };
                    let parsed = parse_canonical_u64(encoded)?;
                    *value = Value::Number(Number::from(parsed));
                } else {
                    decode_canonical_u64_fields(value)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn encode_canonical_u64_fields(value: &mut Value) -> Result<(), &'static str> {
    match value {
        Value::Array(values) => {
            for value in values {
                encode_canonical_u64_fields(value)?;
            }
        }
        Value::Object(fields) => {
            for (name, value) in fields {
                if is_u64_array_field(name) {
                    let Value::Array(values) = value else {
                        return Err("private ORAM V2 u64 list field is invalid");
                    };
                    for value in values {
                        let encoded = value
                            .as_u64()
                            .ok_or("private ORAM V2 u64 list value is invalid")?
                            .to_string();
                        *value = Value::String(encoded);
                    }
                } else if is_u64_field(name) {
                    let encoded = match value {
                        Value::Number(number) => number
                            .as_u64()
                            .ok_or("private ORAM V2 u64 field is invalid")?
                            .to_string(),
                        Value::String(encoded) => {
                            parse_canonical_u64(encoded)?;
                            encoded.clone()
                        }
                        _ => return Err("private ORAM V2 u64 field is invalid"),
                    };
                    *value = Value::String(encoded);
                } else {
                    encode_canonical_u64_fields(value)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_canonical_u64(encoded: &str) -> Result<u64, &'static str> {
    let value = encoded
        .parse::<u64>()
        .map_err(|_| "private ORAM V2 u64 field is invalid")?;
    if value.to_string() != encoded {
        return Err("private ORAM V2 u64 field is not canonical");
    }
    Ok(value)
}

fn is_u64_field(name: &str) -> bool {
    matches!(
        name,
        "bucket_count"
            | "bucket_id"
            | "created_at_unix"
            | "dummy_count"
            | "dummy_node_count"
            | "dummy_result_count"
            | "expires_at_unix"
            | "generation"
            | "index_epoch"
            | "initial_leaf"
            | "issued_at_unix"
            | "layout_generation"
            | "lease_expires_unix"
            | "level_mask"
            | "logical_capacity"
            | "logical_count"
            | "logical_node_count"
            | "logical_result_count"
            | "mutation_lease_generation"
            | "new_epoch"
            | "new_leaf"
            | "old_epoch"
            | "old_leaf"
            | "reserved_physical_slots"
            | "rk_epoch"
            | "signed_at_unix"
            | "state_sequence"
            | "writer_fence"
    )
}

fn is_u64_array_field(name: &str) -> bool {
    matches!(name, "bucket_ids")
}

#[cfg(test)]
mod tests {
    use actix_web::{App, HttpResponse, test as actix_test, web};
    use actix_web_validator::Json;
    use serde_json::json;

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct U64WireFixture {
        writer_fence: u64,
        bucket_ids: Vec<u64>,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SessionWireFixture {
        session_id: String,
    }

    async fn json_limit_probe(
        _: Json<PrivateOramMutationWireV2<SessionWireFixture>>,
    ) -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    #[test]
    fn v2_wire_round_trips_full_u64_range_as_decimal_strings() {
        for value in [(1u64 << 53) - 1, 1u64 << 53, u64::MAX] {
            let encoded = serde_json::to_value(PrivateOramMutationWireV2(U64WireFixture {
                writer_fence: value,
                bucket_ids: vec![value],
            }))
            .unwrap();
            assert_eq!(
                encoded,
                json!({ "writer_fence": value.to_string(), "bucket_ids": [value.to_string()] })
            );
            let decoded =
                serde_json::from_value::<PrivateOramMutationWireV2<U64WireFixture>>(encoded)
                    .unwrap();
            assert_eq!(decoded.into_inner().writer_fence, value);
        }
    }

    #[test]
    fn v2_wire_rejects_number_and_noncanonical_decimal_u64() {
        assert!(
            serde_json::from_value::<PrivateOramMutationWireV2<U64WireFixture>>(json!({
                "writer_fence": 9_007_199_254_740_992u64,
                "bucket_ids": ["1"]
            }))
            .is_err()
        );
        for encoded in ["01", "+1", "-1", "18446744073709551616"] {
            assert!(
                serde_json::from_value::<PrivateOramMutationWireV2<U64WireFixture>>(json!({
                    "writer_fence": encoded,
                    "bucket_ids": ["1"]
                }))
                .is_err()
            );
        }
        assert!(
            serde_json::from_value::<PrivateOramMutationWireV2<U64WireFixture>>(json!({
                "writer_fence": "1",
                "bucket_ids": [1]
            }))
            .is_err()
        );
    }

    #[actix_web::test]
    async fn v2_scope_enforces_hard_json_limit_without_reflecting_body() {
        let app = actix_test::init_service(
            App::new().service(
                web::scope("/collections/{collection_name}/private-oram/v2/mutation")
                    .app_data(private_oram_mutation_json_config())
                    .route("/probe", web::post().to(json_limit_probe)),
            ),
        )
        .await;

        let sentinel = "private-oram-v2-oversized-body-sentinel";
        let padding = "x".repeat(PRIVATE_ORAM_MUTATION_SESSION_JSON_LIMIT_BYTES);
        let payload = format!(r#"{{"session_id":"{sentinel}{padding}"}}"#);
        assert!(payload.len() > PRIVATE_ORAM_MUTATION_SESSION_JSON_LIMIT_BYTES);
        let request = actix_test::TestRequest::post()
            .uri("/collections/docs/private-oram/v2/mutation/probe")
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .set_payload(payload)
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let body = String::from_utf8_lossy(&actix_test::read_body(response).await).into_owned();
        assert!(
            body.contains("Invalid JSON body for private ORAM request"),
            "{body}"
        );
        assert!(!body.contains(sentinel), "{body}");
        assert!(
            !body.contains(
                PRIVATE_ORAM_MUTATION_SESSION_JSON_LIMIT_BYTES
                    .to_string()
                    .as_str()
            )
        );
    }
}
