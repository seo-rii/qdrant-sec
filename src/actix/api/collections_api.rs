use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path as FsPath;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actix_web::rt::time::Instant;
use actix_web::{HttpResponse, Responder, delete, get, patch, post, put, web};
use actix_web_validator::{Json, Path, Query};
use collection::config::{
    CollectionConfigInternal, CryptoMigrationCheckpoint, CryptoMigrationPlan, CryptoMigrationState,
    EncryptionSelector,
};
use collection::operations::cluster_ops::ClusterOperations;
use collection::operations::types::CollectionError;
use collection::operations::verification::new_unchecked_verification_pass;
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shard::operations::optimization::OptimizationsRequestOptions;
use storage::content_manager::collection_meta_ops::{
    ApplyCryptoMigrationPlan, ChangeAliasesOperation, CollectionMetaOperations, CreateCollection,
    CreateCollectionOperation, DeleteCollectionOperation, UpdateCollection,
    UpdateCollectionOperation,
};
use storage::content_manager::errors::StorageError;
use storage::dispatcher::Dispatcher;
use storage::rbac::AccessRequirements;
use validator::{Validate, ValidationError};

use super::CollectionPath;
use crate::actix::api::StrictCollectionPath;
use crate::actix::auth::ActixAuth;
use crate::actix::helpers::{self, process_response};
use crate::common::collections::*;
use crate::common::crypto::{
    validate_collection_crypto_runtime_with_crypto_id, validate_create_collection_crypto_runtime,
};
use crate::common::snapshots::begin_private_oram_collection_lifecycle_guard;
use crate::common::update::{
    do_decrypt_payloads_for_crypto_migration, do_reencrypt_stale_payloads_for_crypto_migration,
};
use crate::settings::Settings;

#[derive(Debug, Deserialize, Validate)]
pub struct WaitTimeout {
    #[validate(range(min = 1))]
    timeout: Option<u64>,
}

impl WaitTimeout {
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout.map(Duration::from_secs)
    }
}

#[get("/collections")]
async fn get_collections(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_list_collections(dispatcher.toc(&auth, &pass), &auth)).await
}

#[get("/aliases")]
async fn get_aliases(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_list_aliases(dispatcher.toc(&auth, &pass), &auth)).await
}

#[get("/collections/{collection_name}")]
async fn get_collection(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_get_collection(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection.collection_name,
        None,
    ))
    .await
}

#[get("/collections/{collection_name}/crypto/manifest")]
async fn get_collection_crypto_manifest(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let timing = Instant::now();
    let pass = new_unchecked_verification_pass();
    let collection_name = collection.collection_name.clone();

    let response = async {
        let collection_pass = auth.check_collection_access(
            &collection_name,
            AccessRequirements::new().manage(),
            "get_collection_crypto_manifest",
        )?;
        let collection = dispatcher
            .toc(&auth, &pass)
            .get_collection(&collection_pass)
            .await?;
        let config = collection.config_snapshot().await;
        build_collection_crypto_manifest_response(&collection_name, &config, settings.get_ref())
    };

    process_response(response.await, timing, None)
}

#[get("/collections/{collection_name}/exists")]
async fn get_collection_existence(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_collection_exists(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection.collection_name,
    ))
    .await
}

#[get("/collections/{collection_name}/aliases")]
async fn get_collection_aliases(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_list_collection_aliases(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection.collection_name,
    ))
    .await
}

#[put("/collections/{collection_name}")]
async fn create_collection(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<StrictCollectionPath>,
    operation: Json<CreateCollection>,
    settings: web::Data<Settings>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let timing = Instant::now();
    let collection_name = collection.collection_name.clone();
    let operation = operation.into_inner();
    let create_collection_op = CreateCollectionOperation::new(collection_name.clone(), operation);

    let Ok(create_collection_op) = create_collection_op else {
        return process_response(create_collection_op, timing, None);
    };

    // Authorize before the crypto runtime validation: it unwraps resource keys through external
    // key services and its errors name materials and other collections' crypto scopes.
    if let Err(err) =
        auth.check_global_access(AccessRequirements::new().manage(), "create_collection")
    {
        return process_response::<bool>(Err(err), timing, None);
    }

    if let Err(err) = validate_create_collection_crypto_runtime(
        settings.get_ref(),
        &collection_name,
        &create_collection_op.create_collection,
    ) {
        return process_response::<bool>(Err(err), timing, None);
    }

    let response = dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::CreateCollection(create_collection_op),
            auth,
            query.timeout(),
        )
        .await;
    process_response(response, timing, None)
}

#[patch("/collections/{collection_name}")]
async fn update_collection(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    operation: Json<UpdateCollection>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let name = collection.collection_name.clone();
    let response = async {
        let _private_oram_lifecycle_guard =
            begin_private_oram_collection_lifecycle_guard(dispatcher.get_ref(), &auth, &name)
                .await?;
        dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::UpdateCollection(UpdateCollectionOperation::new(
                    name,
                    operation.into_inner(),
                )),
                auth,
                query.timeout(),
            )
            .await
    }
    .await;
    process_response(response, timing, None)
}

#[post("/collections/{collection_name}/crypto/migration/plan")]
async fn apply_crypto_migration_plan(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    operation: Json<CryptoMigrationPlan>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let plan = operation.into_inner();
    let response = if let Err(err) = validate_standalone_crypto_migration_plan(&plan) {
        Err(StorageError::bad_input(format!(
            "crypto migration plan is invalid: {err}"
        )))
    } else {
        dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::ApplyCryptoMigration(ApplyCryptoMigrationPlan {
                    collection_name: collection.collection_name.clone(),
                    plan,
                }),
                auth,
                query.timeout(),
            )
            .await
    };
    process_response(response, timing, None)
}

fn validate_standalone_crypto_migration_plan(
    plan: &CryptoMigrationPlan,
) -> Result<(), ValidationError> {
    plan.validate_admin_plan()?;
    if plan.requires_verified_completion() {
        return Err(ValidationError::new(
            "crypto_migration_completion_requires_run_payloads",
        ));
    }

    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, Validate)]
pub struct RunPayloadCryptoMigration {
    pub active_rk_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_rk_id: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct RunPayloadCryptoMigrationResponse {
    pub checkpoints: Vec<CryptoMigrationCheckpoint>,
    pub completion_plan: CryptoMigrationPlan,
    pub completed: bool,
    pub dry_run: bool,
}

const PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE: &str = "payload_crypto_migration_last_run.json";
const PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
struct PayloadCryptoMigrationRunRecord {
    run_id: String,
    collection_name: String,
    stable_crypto_id: String,
    checkpoints_sha256_b64: String,
    completion_plan_sha256_b64: String,
    checkpoints: Vec<CryptoMigrationCheckpoint>,
    completion_plan: CryptoMigrationPlan,
    completed: bool,
    dry_run: bool,
}

fn payload_crypto_migration_run_record_digest_b64<T: Serialize>(
    label: &str,
    value: &T,
) -> Result<String, StorageError> {
    let bytes = serde_json::to_vec(value).map_err(|err| {
        StorageError::service_error(format!(
            "failed to serialize payload crypto migration {label} for digest: {err}",
        ))
    })?;
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(bytes)))
}

fn payload_crypto_migration_run_id(
    stable_crypto_id: &str,
    dry_run: bool,
    checkpoints_sha256_b64: &str,
    completion_plan_sha256_b64: &str,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"qdrant-sec/payload-crypto-migration-run/v1");
    hasher.update(stable_crypto_id.as_bytes());
    hasher.update([u8::from(dry_run)]);
    hasher.update(checkpoints_sha256_b64.as_bytes());
    hasher.update(completion_plan_sha256_b64.as_bytes());
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(now.to_be_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

#[derive(Debug, Serialize)]
pub struct CollectionCryptoManifestResponse {
    pub collection_name: String,
    pub stable_crypto_id: String,
    pub crypto_schema_version: u16,
    pub encryption_epoch: u64,
    pub migration_state: CryptoMigrationState,
    pub rules: Vec<CollectionCryptoManifestRule>,
    pub resource_keys: Vec<CollectionCryptoManifestResourceKey>,
}

#[derive(Debug, Serialize)]
pub struct CollectionCryptoManifestRule {
    pub rule_id: String,
    pub selector: String,
    pub instance: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_material: Option<String>,
    pub retired_materials: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_rk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_rk_epoch: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CollectionCryptoManifestResourceKey {
    pub rk_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub material_ref: Option<String>,
    pub epoch: u64,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_by: Option<String>,
    pub used_by_rules: Vec<String>,
}

#[derive(Debug)]
struct CollectionCryptoManifestResourceKeyBuilder {
    material_ref: Option<String>,
    epoch: u64,
    state: String,
    scope: Option<String>,
    wrapped_by: Option<String>,
    used_by_rules: Vec<String>,
}

fn selector_kind(selector: &EncryptionSelector) -> &'static str {
    match selector {
        EncryptionSelector::PayloadPaths { .. } => "payload_paths",
        EncryptionSelector::VectorNames { .. } => "vector_names",
        EncryptionSelector::MetadataKeys { .. } => "metadata_keys",
    }
}

fn option_string<'a>(options: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    options.get(key).and_then(serde_json::Value::as_str)
}

fn option_u64(options: &serde_json::Value, key: &str) -> Option<u64> {
    options.get(key).and_then(serde_json::Value::as_u64)
}

fn add_manifest_material_resource_key(
    material_ref: &str,
    rule_id: &str,
    settings: &Settings,
    resource_keys: &mut BTreeMap<String, CollectionCryptoManifestResourceKeyBuilder>,
) -> Result<(), StorageError> {
    let Some(material) = settings.crypto.materials.get(material_ref) else {
        return Err(StorageError::bad_request(format!(
            "crypto manifest material {material_ref} is referenced by rule {rule_id} but is missing from runtime settings",
        )));
    };
    let Some(epoch) = material.rk_epoch else {
        return Err(StorageError::bad_request(format!(
            "crypto manifest material {material_ref} is referenced by rule {rule_id} but is missing rk_epoch",
        )));
    };
    let state = material
        .state
        .clone()
        .unwrap_or_else(|| "active".to_string());
    let entry = resource_keys
        .entry(material_ref.to_string())
        .or_insert_with(|| CollectionCryptoManifestResourceKeyBuilder {
            material_ref: Some(material_ref.to_string()),
            epoch,
            state,
            scope: material.scope.clone(),
            wrapped_by: material.wrapped_by.clone(),
            used_by_rules: Vec::new(),
        });

    if entry.epoch != epoch || entry.state != material.state.as_deref().unwrap_or("active") {
        return Err(StorageError::bad_request(format!(
            "crypto manifest material {material_ref} has inconsistent RK metadata across rules",
        )));
    }
    if !entry
        .used_by_rules
        .iter()
        .any(|existing| existing == rule_id)
    {
        entry.used_by_rules.push(rule_id.to_string());
    }

    Ok(())
}

fn add_manifest_client_resource_key(
    rk_id: &str,
    epoch: u64,
    rule_id: &str,
    resource_keys: &mut BTreeMap<String, CollectionCryptoManifestResourceKeyBuilder>,
) -> Result<(), StorageError> {
    let entry = resource_keys.entry(rk_id.to_string()).or_insert_with(|| {
        CollectionCryptoManifestResourceKeyBuilder {
            material_ref: None,
            epoch,
            state: "active".to_string(),
            scope: Some("client-envelope".to_string()),
            wrapped_by: None,
            used_by_rules: Vec::new(),
        }
    });

    if entry.epoch != epoch || entry.state != "active" {
        return Err(StorageError::bad_request(format!(
            "crypto manifest client RK {rk_id} has inconsistent policy metadata across rules",
        )));
    }
    if !entry
        .used_by_rules
        .iter()
        .any(|existing| existing == rule_id)
    {
        entry.used_by_rules.push(rule_id.to_string());
    }

    Ok(())
}

fn build_collection_crypto_manifest_response(
    collection_name: &str,
    config: &CollectionConfigInternal,
    settings: &Settings,
) -> Result<CollectionCryptoManifestResponse, StorageError> {
    let encryption = config.params.effective_encryption().ok_or_else(|| {
        StorageError::bad_request(format!(
            "collection {collection_name} does not have encryption configured",
        ))
    })?;
    let stable_crypto_id = config.stable_crypto_id(collection_name)?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection_name,
        &stable_crypto_id,
        &config.params,
    )?;
    let mut rules = Vec::new();
    let mut resource_keys = BTreeMap::new();

    for rule in &encryption.rules {
        let instance = settings
            .crypto
            .instances
            .get(&rule.instance)
            .ok_or_else(|| {
                StorageError::bad_request(format!(
                    "collection {collection_name} references unknown crypto instance {}",
                    rule.instance
                ))
            })?;
        let active_material = instance.materials.get("sym_key").cloned();
        if let Some(material_ref) = active_material.as_deref() {
            add_manifest_material_resource_key(
                material_ref,
                &rule.id,
                settings,
                &mut resource_keys,
            )?;
        }

        let mut retired_materials = Vec::new();
        if let Some(retired) = instance.options.get("retired_materials") {
            let Some(retired) = retired.as_array() else {
                return Err(StorageError::bad_request(format!(
                    "collection {collection_name} crypto instance {} has malformed retired_materials",
                    rule.instance
                )));
            };
            for retired_entry in retired {
                let Some(material_ref) = retired_entry
                    .as_object()
                    .and_then(|entry| entry.get("material"))
                    .and_then(serde_json::Value::as_str)
                else {
                    return Err(StorageError::bad_request(format!(
                        "collection {collection_name} crypto instance {} has malformed retired_materials",
                        rule.instance
                    )));
                };
                add_manifest_material_resource_key(
                    material_ref,
                    &rule.id,
                    settings,
                    &mut resource_keys,
                )?;
                retired_materials.push(material_ref.to_string());
            }
        }

        let client_rk_id =
            option_string(&instance.options, "expected_rk_id").map(ToOwned::to_owned);
        let client_rk_epoch = match (
            option_u64(&instance.options, "min_rk_epoch"),
            option_u64(&instance.options, "max_rk_epoch"),
        ) {
            (Some(min), Some(max)) if min == max => Some(min),
            _ => None,
        };
        if let (Some(rk_id), Some(epoch)) = (client_rk_id.as_deref(), client_rk_epoch) {
            add_manifest_client_resource_key(rk_id, epoch, &rule.id, &mut resource_keys)?;
        }

        rules.push(CollectionCryptoManifestRule {
            rule_id: rule.id.clone(),
            selector: selector_kind(&rule.selector).to_string(),
            instance: rule.instance.clone(),
            provider: instance.provider.clone(),
            binding: rule.binding.clone(),
            active_material,
            retired_materials,
            client_rk_id,
            client_rk_epoch,
        });
    }

    Ok(CollectionCryptoManifestResponse {
        collection_name: collection_name.to_string(),
        stable_crypto_id,
        crypto_schema_version: encryption.crypto_schema_version,
        encryption_epoch: encryption.encryption_epoch,
        migration_state: encryption.migration_state,
        rules,
        resource_keys: resource_keys
            .into_iter()
            .map(|(rk_id, key)| CollectionCryptoManifestResourceKey {
                rk_id,
                material_ref: key.material_ref,
                epoch: key.epoch,
                state: key.state,
                scope: key.scope,
                wrapped_by: key.wrapped_by,
                used_by_rules: key.used_by_rules,
            })
            .collect(),
    })
}

fn payload_crypto_migration_completion_plan(
    migration_state: CryptoMigrationState,
    target_epoch: u64,
    request: RunPayloadCryptoMigration,
    checkpoints: Vec<CryptoMigrationCheckpoint>,
) -> Result<CryptoMigrationPlan, CollectionError> {
    validate_payload_crypto_migration_run_request(migration_state, &request)?;

    let retired_rk_id = if migration_state == CryptoMigrationState::Rotating {
        request.retired_rk_id
    } else {
        None
    };

    Ok(CryptoMigrationPlan {
        from: migration_state,
        to: payload_crypto_migration_completion_state(migration_state)?,
        target_epoch,
        active_rk_id: Some(request.active_rk_id),
        retired_rk_id,
        dry_run: request.dry_run,
        checkpoints,
    })
}

fn payload_crypto_migration_completion_state(
    migration_state: CryptoMigrationState,
) -> Result<CryptoMigrationState, CollectionError> {
    match migration_state {
        CryptoMigrationState::Encrypting | CryptoMigrationState::Rotating => {
            Ok(CryptoMigrationState::Active)
        }
        CryptoMigrationState::Decrypting => Ok(CryptoMigrationState::Disabled),
        CryptoMigrationState::Disabled | CryptoMigrationState::Active => {
            Err(CollectionError::bad_input(format!(
                "payload crypto migration run requires migration_state=encrypting, rotating, or decrypting; current state is {migration_state:?}",
            )))
        }
    }
}

fn validate_payload_crypto_migration_run_request(
    migration_state: CryptoMigrationState,
    request: &RunPayloadCryptoMigration,
) -> Result<(), CollectionError> {
    if request.active_rk_id.is_empty() {
        return Err(CollectionError::bad_input(
            "payload crypto migration run requires active_rk_id",
        ));
    }

    payload_crypto_migration_completion_state(migration_state)?;

    if migration_state == CryptoMigrationState::Rotating {
        if request.retired_rk_id.is_none() {
            return Err(CollectionError::bad_input(
                "payload crypto rotation run requires retired_rk_id for completion",
            ));
        }
    } else if request.retired_rk_id.is_some() {
        return Err(CollectionError::bad_input(
            "retired_rk_id is only valid while completing rotating payload crypto migration",
        ));
    }

    Ok(())
}

fn validate_payload_crypto_migration_run_request_for_config(
    migration_state: CryptoMigrationState,
    target_epoch: u64,
    request: &RunPayloadCryptoMigration,
    encryption: &collection::config::CollectionEncryptionConfig,
    settings: &Settings,
) -> Result<(), CollectionError> {
    validate_payload_crypto_migration_run_request(migration_state, request)?;
    let mut active_material_refs = BTreeSet::new();
    let mut retired_material_refs = BTreeSet::new();
    for rule in &encryption.rules {
        if !matches!(rule.selector, EncryptionSelector::PayloadPaths { .. }) {
            continue;
        }
        let Some(instance) = settings.crypto.instances.get(&rule.instance) else {
            return Err(CollectionError::bad_input(format!(
                "payload crypto migration rule {} references unknown crypto instance {}",
                rule.id, rule.instance,
            )));
        };
        if instance.provider != "payload/aes-256-gcm@v1" {
            continue;
        }
        let Some(active_material) = instance.materials.get("sym_key") else {
            return Err(CollectionError::bad_input(format!(
                "payload crypto migration rule {} instance {} must configure materials.sym_key",
                rule.id, rule.instance,
            )));
        };
        active_material_refs.insert(active_material.clone());

        if let Some(retired_materials) = instance.options.get("retired_materials") {
            let Some(retired_materials) = retired_materials.as_array() else {
                return Err(CollectionError::bad_input(format!(
                    "payload crypto migration rule {} instance {} has malformed retired_materials",
                    rule.id, rule.instance,
                )));
            };
            for retired_material in retired_materials {
                let Some(material_ref) = retired_material
                    .as_object()
                    .and_then(|entry| entry.get("material"))
                    .and_then(serde_json::Value::as_str)
                else {
                    return Err(CollectionError::bad_input(format!(
                        "payload crypto migration rule {} instance {} has malformed retired_materials",
                        rule.id, rule.instance,
                    )));
                };
                retired_material_refs.insert(material_ref.to_string());
            }
        }
    }
    if active_material_refs.len() > 1 {
        return Err(CollectionError::bad_input(
            "payload crypto migration run currently requires a single active server-side payload resource key",
        ));
    }
    if let Some(active_material_ref) = active_material_refs.iter().next()
        && active_material_ref != &request.active_rk_id
    {
        return Err(CollectionError::bad_input(format!(
            "payload crypto migration active_rk_id {} does not match runtime active material {}",
            request.active_rk_id, active_material_ref,
        )));
    }
    if migration_state == CryptoMigrationState::Rotating {
        let Some(retired_rk_id) = request.retired_rk_id.as_ref() else {
            return Err(CollectionError::bad_input(
                "payload crypto rotation run requires retired_rk_id for completion",
            ));
        };
        if !retired_material_refs.contains(retired_rk_id) {
            return Err(CollectionError::bad_input(format!(
                "payload crypto migration retired_rk_id {retired_rk_id} is not configured as a runtime retired material",
            )));
        }
    }

    let preflight_plan = CryptoMigrationPlan {
        from: migration_state,
        to: payload_crypto_migration_completion_state(migration_state)?,
        target_epoch,
        active_rk_id: Some(request.active_rk_id.clone()),
        retired_rk_id: if migration_state == CryptoMigrationState::Rotating {
            Some(request.retired_rk_id.clone().ok_or_else(|| {
                CollectionError::bad_input(
                    "payload crypto rotation run requires retired_rk_id for completion",
                )
            })?)
        } else {
            None
        },
        dry_run: false,
        checkpoints: vec![CryptoMigrationCheckpoint {
            shard_id: 0,
            total_points: 1,
            processed_points: 1,
            rewritten_points: 1,
            changed_points: 0,
            status: collection::config::CryptoMigrationCheckpointStatus::Verified,
        }],
    };
    preflight_plan
        .validate_admin_plan_for_config(encryption)
        .map_err(|err| {
            CollectionError::bad_input(format!(
                "payload crypto migration request is invalid for current config: {err}"
            ))
        })
}

fn persist_payload_crypto_migration_run_record(
    collection_path: &FsPath,
    record: &PayloadCryptoMigrationRunRecord,
) -> Result<(), StorageError> {
    validate_payload_crypto_migration_record_directory(collection_path)?;
    let record_path = collection_path.join(PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE);
    validate_payload_crypto_migration_record_target(&record_path)?;
    let temp_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_path = collection_path.join(format!(
        ".{PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE}.{}.{}.tmp",
        std::process::id(),
        temp_suffix,
    ));
    let bytes = serde_json::to_vec_pretty(record).map_err(|err| {
        StorageError::service_error(format!(
            "failed to serialize payload crypto migration run record: {err}"
        ))
    })?;
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .apply_private_payload_crypto_migration_record_open_options()
            .open(&temp_path)
            .map_err(|err| {
                StorageError::service_error(format!(
                    "failed to create payload crypto migration run record temp file: {err}"
                ))
            })?;
        file.write_all(&bytes).map_err(|err| {
            StorageError::service_error(format!(
                "failed to write payload crypto migration run record temp file: {err}"
            ))
        })?;
        file.sync_all().map_err(|err| {
            StorageError::service_error(format!(
                "failed to sync payload crypto migration run record temp file: {err}"
            ))
        })?;
    }
    fs::rename(&temp_path, &record_path).map_err(|err| {
        StorageError::service_error(format!(
            "failed to replace payload crypto migration run record: {err}"
        ))
    })?;
    set_private_payload_crypto_migration_record_permissions(&record_path)?;
    let mut parent_options = fs::OpenOptions::new();
    parent_options.read(true);
    #[cfg(unix)]
    parent_options
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW);
    if let Ok(parent) = parent_options.open(collection_path) {
        parent.sync_all().map_err(|err| {
            StorageError::service_error(format!(
                "failed to sync payload crypto migration run record parent directory: {err}"
            ))
        })?;
    }
    Ok(())
}

fn load_payload_crypto_migration_run_record(
    collection_path: &FsPath,
) -> Result<PayloadCryptoMigrationRunRecord, StorageError> {
    validate_payload_crypto_migration_record_directory(collection_path)?;
    let record_path = collection_path.join(PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE);
    validate_payload_crypto_migration_record_target(&record_path)?;
    let metadata = fs::metadata(&record_path).map_err(|err| {
        StorageError::service_error(format!(
            "failed to inspect payload crypto migration run record: {err}",
        ))
    })?;
    if metadata.len() > PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_MAX_BYTES {
        return Err(StorageError::service_error(format!(
            "payload crypto migration run record exceeds {} bytes",
            PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_MAX_BYTES,
        )));
    }

    let bytes = fs::read(&record_path).map_err(|err| {
        StorageError::service_error(format!(
            "failed to read payload crypto migration run record: {err}",
        ))
    })?;
    if bytes.len() as u64 > PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_MAX_BYTES {
        return Err(StorageError::service_error(format!(
            "payload crypto migration run record exceeds {} bytes after read",
            PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_MAX_BYTES,
        )));
    }

    serde_json::from_slice(&bytes).map_err(|err| {
        StorageError::service_error(format!(
            "failed to parse payload crypto migration run record: {err}",
        ))
    })
}

fn validate_payload_crypto_migration_pending_run_record(
    record: &PayloadCryptoMigrationRunRecord,
    expected_run_id: &str,
    expected_collection_name: &str,
    expected_stable_crypto_id: &str,
    expected_checkpoints_sha256_b64: &str,
    expected_completion_plan_sha256_b64: &str,
) -> Result<(), StorageError> {
    if record.completed {
        return Err(StorageError::service_error(
            "payload crypto migration completion requires a pending run record",
        ));
    }
    if record.dry_run {
        return Err(StorageError::service_error(
            "payload crypto migration completion cannot use a dry-run record",
        ));
    }
    if record.run_id != expected_run_id {
        return Err(StorageError::service_error(
            "payload crypto migration run record id does not match the planned completion",
        ));
    }
    if record.collection_name != expected_collection_name {
        return Err(StorageError::service_error(format!(
            "payload crypto migration run record collection {} does not match requested collection {}",
            record.collection_name, expected_collection_name,
        )));
    }
    if record.stable_crypto_id != expected_stable_crypto_id {
        return Err(StorageError::service_error(
            "payload crypto migration run record stable crypto id does not match current collection identity",
        ));
    }
    if record.checkpoints_sha256_b64 != expected_checkpoints_sha256_b64 {
        return Err(StorageError::service_error(
            "payload crypto migration run record checkpoint digest does not match the planned completion",
        ));
    }
    if record.completion_plan_sha256_b64 != expected_completion_plan_sha256_b64 {
        return Err(StorageError::service_error(
            "payload crypto migration run record completion plan digest does not match the planned completion",
        ));
    }

    let actual_checkpoints_sha256_b64 =
        payload_crypto_migration_run_record_digest_b64("checkpoints", &record.checkpoints)?;
    if actual_checkpoints_sha256_b64 != record.checkpoints_sha256_b64 {
        return Err(StorageError::service_error(
            "payload crypto migration run record checkpoint digest is inconsistent with persisted checkpoints",
        ));
    }

    let actual_completion_plan_sha256_b64 =
        payload_crypto_migration_run_record_digest_b64("completion plan", &record.completion_plan)?;
    if actual_completion_plan_sha256_b64 != record.completion_plan_sha256_b64 {
        return Err(StorageError::service_error(
            "payload crypto migration run record completion plan digest is inconsistent with persisted plan",
        ));
    }

    Ok(())
}

trait PayloadCryptoMigrationRecordOpenOptionsExt {
    fn apply_private_payload_crypto_migration_record_open_options(&mut self) -> &mut Self;
}

impl PayloadCryptoMigrationRecordOpenOptionsExt for fs::OpenOptions {
    fn apply_private_payload_crypto_migration_record_open_options(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            self.mode(0o600)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        }

        #[cfg(not(unix))]
        {
            self
        }
    }
}

fn validate_payload_crypto_migration_record_directory(
    collection_path: &FsPath,
) -> Result<(), StorageError> {
    #[cfg(unix)]
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    let mut directory = Some(collection_path);
    while let Some(path) = directory {
        let metadata = fs::symlink_metadata(path).map_err(|err| {
            StorageError::service_error(format!(
                "failed to inspect payload crypto migration run record directory: {err}",
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StorageError::service_error(
                "payload crypto migration run record directory must be a regular non-symlink directory",
            ));
        }

        #[cfg(unix)]
        {
            if metadata.uid() != 0 && metadata.uid() != effective_uid {
                return Err(StorageError::service_error(
                    "payload crypto migration run record directory must be owned by root or the Qdrant process user",
                ));
            }
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(StorageError::service_error(
                    "payload crypto migration run record directory must not be group/world-writable",
                ));
            }
        }

        directory = path.parent();
    }

    Ok(())
}

fn validate_payload_crypto_migration_record_target(
    record_path: &FsPath,
) -> Result<(), StorageError> {
    let Ok(metadata) = fs::symlink_metadata(record_path) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::service_error(
            "payload crypto migration run record target must be a regular non-symlink file",
        ));
    }

    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StorageError::service_error(
            "payload crypto migration run record target must not be group/world-accessible",
        ));
    }

    Ok(())
}

fn set_private_payload_crypto_migration_record_permissions(
    record_path: &FsPath,
) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(record_path)
            .map_err(|err| {
                StorageError::service_error(format!(
                    "failed to inspect payload crypto migration run record: {err}",
                ))
            })?
            .permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(record_path, permissions).map_err(|err| {
            StorageError::service_error(format!(
                "failed to restrict payload crypto migration run record permissions: {err}",
            ))
        })?;
    }

    Ok(())
}

#[post("/collections/{collection_name}/crypto/migration/run-payloads")]
async fn run_payloads_for_crypto_migration(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    operation: Json<RunPayloadCryptoMigration>,
    settings: web::Data<Settings>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let pass = new_unchecked_verification_pass();
    let collection_name = collection.collection_name.clone();

    let response = async {
        let collection_pass = auth.check_collection_access(
            &collection_name,
            AccessRequirements::new().manage(),
            "run_payloads_for_crypto_migration",
        )?;
        let collection = dispatcher
            .toc(&auth, &pass)
            .get_collection(&collection_pass)
            .await?;
        let config = collection.config_snapshot().await;
        let encryption = config.params.effective_encryption().ok_or_else(|| {
            CollectionError::bad_input(format!(
                "payload crypto migration for collection {collection_name} requires an encrypted collection",
            ))
        })?;
        let migration_state = encryption.migration_state;
        let target_epoch = encryption.encryption_epoch;
        let request = operation.into_inner();
        let dry_run = request.dry_run;

        validate_payload_crypto_migration_run_request_for_config(
            migration_state,
            target_epoch,
            &request,
            &encryption,
            settings.get_ref(),
        )
        .map_err(StorageError::from)?;

        let checkpoints = match migration_state {
            CryptoMigrationState::Encrypting | CryptoMigrationState::Rotating => {
                do_reencrypt_stale_payloads_for_crypto_migration(
                    dispatcher.toc(&auth, &pass),
                    &collection_name,
                    settings.get_ref(),
                    &auth,
                    dry_run,
                )
                .await?
            }
            CryptoMigrationState::Decrypting => {
                do_decrypt_payloads_for_crypto_migration(
                    dispatcher.toc(&auth, &pass),
                    &collection_name,
                    settings.get_ref(),
                    &auth,
                    dry_run,
                )
                .await?
            }
            CryptoMigrationState::Disabled | CryptoMigrationState::Active => {
                return Err(StorageError::bad_input(format!(
                    "payload crypto migration run for collection {collection_name} requires migration_state=encrypting, rotating, or decrypting; current state is {migration_state:?}",
                )));
            }
        };

        let completion_plan = payload_crypto_migration_completion_plan(
            migration_state,
            target_epoch,
            request,
            checkpoints,
        )
        .map_err(StorageError::from)?;
        let completed_plan_is_valid = if dry_run {
            let mut applyable_plan = completion_plan.clone();
            applyable_plan.dry_run = false;
            applyable_plan.validate_admin_plan_for_config(&encryption)
        } else {
            completion_plan.validate_admin_plan_for_config(&encryption)
        };
        completed_plan_is_valid.map_err(|err| {
            StorageError::bad_input(format!(
                "payload crypto migration completion plan is invalid: {err}",
            ))
        })?;
        let stable_crypto_id = config
            .stable_crypto_id(&collection_name)
            .map_err(StorageError::from)?;
        let checkpoints_sha256_b64 = payload_crypto_migration_run_record_digest_b64(
            "checkpoints",
            &completion_plan.checkpoints,
        )?;
        let completion_plan_sha256_b64 =
            payload_crypto_migration_run_record_digest_b64("completion plan", &completion_plan)?;
        let run_id = payload_crypto_migration_run_id(
            &stable_crypto_id,
            dry_run,
            &checkpoints_sha256_b64,
            &completion_plan_sha256_b64,
        );
        let mut run_record = PayloadCryptoMigrationRunRecord {
            run_id,
            collection_name: collection_name.clone(),
            stable_crypto_id,
            checkpoints_sha256_b64,
            completion_plan_sha256_b64,
            checkpoints: completion_plan.checkpoints.clone(),
            completion_plan: completion_plan.clone(),
            completed: false,
            dry_run,
        };

        let completed = if dry_run {
            persist_payload_crypto_migration_run_record(collection.path(), &run_record)?;
            false
        } else {
            persist_payload_crypto_migration_run_record(collection.path(), &run_record)?;
            let persisted_run_record =
                load_payload_crypto_migration_run_record(collection.path())?;
            validate_payload_crypto_migration_pending_run_record(
                &persisted_run_record,
                &run_record.run_id,
                &collection_name,
                &run_record.stable_crypto_id,
                &run_record.checkpoints_sha256_b64,
                &run_record.completion_plan_sha256_b64,
            )?;
            let completed = dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::ApplyCryptoMigration(ApplyCryptoMigrationPlan {
                        collection_name: collection_name.clone(),
                        plan: completion_plan.clone(),
                    }),
                    auth,
                    query.timeout(),
                )
                .await?;
            run_record.completed = completed;
            persist_payload_crypto_migration_run_record(collection.path(), &run_record)?;
            completed
        };

        Ok(RunPayloadCryptoMigrationResponse {
            checkpoints: completion_plan.checkpoints.clone(),
            completion_plan,
            completed,
            dry_run,
        })
    }
    .await;

    process_response(response, timing, None)
}

#[delete("/collections/{collection_name}")]
async fn delete_collection(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let response = async {
        let _private_oram_lifecycle_guard = begin_private_oram_collection_lifecycle_guard(
            dispatcher.get_ref(),
            &auth,
            &collection.collection_name,
        )
        .await?;
        dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::DeleteCollection(DeleteCollectionOperation(
                    collection.collection_name.clone(),
                )),
                auth,
                query.timeout(),
            )
            .await
    }
    .await;
    process_response(response, timing, None)
}

#[post("/collections/aliases")]
async fn update_aliases(
    dispatcher: web::Data<Dispatcher>,
    operation: Json<ChangeAliasesOperation>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let response = dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::ChangeAliases(operation.0),
            auth,
            query.timeout(),
        )
        .await;
    process_response(response, timing, None)
}

#[get("/collections/{collection_name}/cluster")]
async fn get_cluster_info(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_get_collection_cluster(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection.collection_name,
    ))
    .await
}

#[post("/collections/{collection_name}/cluster")]
async fn update_collection_cluster(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    collection: Path<CollectionPath>,
    operation: Json<ClusterOperations>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let wait_timeout = query.timeout();
    let response = do_update_collection_cluster(
        &dispatcher.into_inner(),
        settings.get_ref(),
        collection.collection_name.clone(),
        operation.0,
        auth,
        wait_timeout,
    )
    .await;
    process_response(response, timing, None)
}

#[derive(Deserialize, Clone, Validate)]
struct OptimizationsParam {
    with: Option<String>,
    completed_limit: Option<u64>,
}

const DEFAULT_OPTIMIZATIONS_COMPLETED_LIMIT: u64 = 16;

impl TryFrom<&OptimizationsParam> for OptimizationsRequestOptions {
    type Error = CollectionError;

    fn try_from(
        params: &OptimizationsParam,
    ) -> Result<OptimizationsRequestOptions, CollectionError> {
        let OptimizationsParam {
            with,
            completed_limit,
        } = params;
        let completed_limit =
            completed_limit.unwrap_or(DEFAULT_OPTIMIZATIONS_COMPLETED_LIMIT) as usize;
        let mut options = OptimizationsRequestOptions {
            queued: false,
            completed_limit: None,
            idle_segments: false,
        };
        for field in with.as_deref().unwrap_or("").split(',') {
            match field.trim() {
                "" => (),
                "queued" => options.queued = true,
                "completed" => options.completed_limit = Some(completed_limit),
                "idle_segments" => options.idle_segments = true,
                _ => Err(CollectionError::bad_input(format!(
                    "Unknown field in 'with' parameter: {field}"
                )))?,
            }
        }
        Ok(options)
    }
}

#[get("/collections/{collection_name}/optimizations")]
fn get_optimizations(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
    params: Query<OptimizationsParam>,
) -> impl Future<Output = HttpResponse> {
    helpers::time(async move {
        let options = OptimizationsRequestOptions::try_from(&params.into_inner())?;
        let pass = new_unchecked_verification_pass();
        let collection_pass = auth.check_collection_access(
            &collection.collection_name,
            AccessRequirements::new(),
            "get_optimizations",
        )?;
        Ok(dispatcher
            .toc(&auth, &pass)
            .get_collection(&collection_pass)
            .await?
            .optimizations(options)
            .await?)
    })
}

// Configure services
pub fn config_collections_api(cfg: &mut web::ServiceConfig) {
    // Ordering of services is important for correct path pattern matching
    // See: <https://github.com/qdrant/qdrant/issues/3543>
    cfg.service(update_aliases)
        .service(get_collections)
        .service(get_collection)
        .service(get_collection_crypto_manifest)
        .service(get_collection_existence)
        .service(create_collection)
        .service(update_collection)
        .service(apply_crypto_migration_plan)
        .service(run_payloads_for_crypto_migration)
        .service(delete_collection)
        .service(get_aliases)
        .service(get_collection_aliases)
        .service(get_cluster_info)
        .service(get_optimizations)
        .service(update_collection_cluster);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use actix_web::web::Query;
    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationCheckpointStatus,
        EncryptionRuleRef, EncryptionSelector, WalConfig,
    };
    use collection::optimizers_builder::OptimizersConfig;
    use segment::types::HnswConfig;
    use serde_json::{Value, json};
    use storage::rbac::{Access, Auth};
    use uuid::Uuid;

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
    use crate::settings::{CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings};

    #[test]
    fn timeout_is_deserialized() {
        let timeout: WaitTimeout = Query::from_query("").unwrap().0;
        assert!(timeout.timeout.is_none());
        let timeout: WaitTimeout = Query::from_query("timeout=10").unwrap().0;
        assert_eq!(timeout.timeout, Some(10))
    }

    #[actix_web::test]
    async fn legacy_partial_payload_migration_endpoints_are_not_registered() {
        let app =
            actix_web::test::init_service(actix_web::App::new().configure(config_collections_api))
                .await;

        for path in [
            "/collections/docs/crypto/migration/rewrite-payloads",
            "/collections/docs/crypto/migration/decrypt-payloads",
        ] {
            let request = actix_web::test::TestRequest::post().uri(path).to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(
                response.status(),
                actix_web::http::StatusCode::NOT_FOUND,
                "{path} must not remain as a partial migration mutation endpoint",
            );
        }
    }

    #[test]
    fn update_and_delete_collection_reject_private_oram_snapshot_window() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.get_ref()).await;

            let auth =
                Auth::new_internal(Access::full("private ORAM collection update route test"));
            let pass = new_unchecked_verification_pass();
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new().manage(),
                    "private_oram_update_route_test",
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
                    .configure(config_collections_api),
            )
            .await;
            let request = actix_web::test::TestRequest::patch()
                .uri("/collections/docs")
                .set_json(json!({
                    "metadata": {
                        "label": "updated"
                    }
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
                "private_oram_update_route_test",
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

            let request = actix_web::test::TestRequest::delete()
                .uri("/collections/docs")
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
                "private_oram_update_route_test",
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
    fn update_and_delete_collection_reject_private_result_oram_snapshot_window() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(dispatcher.get_ref()).await;

            let auth = Auth::new_internal(Access::full(
                "private result ORAM collection update route test",
            ));
            let pass = new_unchecked_verification_pass();
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new().manage(),
                    "private_result_oram_update_route_test",
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
                    .configure(config_collections_api),
            )
            .await;
            let request = actix_web::test::TestRequest::patch()
                .uri("/collections/docs")
                .set_json(json!({
                    "metadata": {
                        "label": "updated"
                    }
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
                "private_result_oram_update_route_test",
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

            let request = actix_web::test::TestRequest::delete()
                .uri("/collections/docs")
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
                "private_result_oram_update_route_test",
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
    fn update_and_delete_collection_reject_active_private_oram_session() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.get_ref()).await;

            let auth = Auth::new_internal(Access::full("private ORAM active session route test"));
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
                "tenant-a/sdk-active-session-route-test".to_string(),
                BASE_EPOCH,
                true,
                qdrant_sec::ResultPrivacyMode::IdsVisible,
            )
            .await
            .unwrap();

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .configure(config_collections_api),
            )
            .await;
            let request = actix_web::test::TestRequest::patch()
                .uri("/collections/docs")
                .set_json(json!({
                    "metadata": {
                        "label": "updated"
                    }
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
            assert!(!body.contains(&fixture.encrypted_build.root_hash), "{body}");
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/sdk-active-session-route-test",
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

            let request = actix_web::test::TestRequest::delete()
                .uri("/collections/docs")
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
            assert!(!body.contains(&fixture.encrypted_build.root_hash), "{body}");
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/sdk-active-session-route-test",
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
    fn update_and_delete_collection_reject_active_private_result_oram_session() {
        let _guard = route_e2e_guard();
        let hnsw_fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let result_fixture = PrivateResultOramRouteFixture::build();
        let settings = result_fixture.route_settings_with_private_hnsw(&hnsw_fixture);
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = web::Data::new(dispatcher);
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(dispatcher.get_ref()).await;

            let auth = Auth::new_internal(Access::full("private result ORAM active route test"));
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
                "tenant-a/result-sdk-active-route-test".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap();

            let app = actix_web::test::init_service(
                actix_web::App::new()
                    .app_data(dispatcher.clone())
                    .configure(config_collections_api),
            )
            .await;
            let request = actix_web::test::TestRequest::patch()
                .uri("/collections/docs")
                .set_json(json!({
                    "metadata": {
                        "label": "updated"
                    }
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
            assert!(!body.contains(&result_fixture.manifest.root_hash), "{body}");
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/result-sdk-active-route-test",
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

            let request = actix_web::test::TestRequest::delete()
                .uri("/collections/docs")
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
            assert!(!body.contains(&result_fixture.manifest.root_hash), "{body}");
            for forbidden in [
                COLLECTION_NAME,
                &session.session_id,
                "tenant-a/result-sdk-active-route-test",
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

    fn verified_checkpoint() -> CryptoMigrationCheckpoint {
        CryptoMigrationCheckpoint {
            shard_id: 0,
            total_points: 3,
            processed_points: 3,
            rewritten_points: 3,
            changed_points: 2,
            status: CryptoMigrationCheckpointStatus::Verified,
        }
    }

    fn payload_crypto_migration_run_test_record() -> PayloadCryptoMigrationRunRecord {
        let completion_plan = payload_crypto_migration_completion_plan(
            CryptoMigrationState::Rotating,
            4,
            RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: false,
            },
            vec![verified_checkpoint()],
        )
        .unwrap();

        let checkpoints_sha256_b64 = payload_crypto_migration_run_record_digest_b64(
            "checkpoints",
            &completion_plan.checkpoints,
        )
        .unwrap();
        let completion_plan_sha256_b64 =
            payload_crypto_migration_run_record_digest_b64("completion plan", &completion_plan)
                .unwrap();

        PayloadCryptoMigrationRunRecord {
            run_id: payload_crypto_migration_run_id(
                "12345678-90ab-cdef-1234-567890abcdef",
                false,
                &checkpoints_sha256_b64,
                &completion_plan_sha256_b64,
            ),
            collection_name: "docs".to_string(),
            stable_crypto_id: "12345678-90ab-cdef-1234-567890abcdef".to_string(),
            checkpoints_sha256_b64,
            completion_plan_sha256_b64,
            checkpoints: completion_plan.checkpoints.clone(),
            completion_plan,
            completed: true,
            dry_run: false,
        }
    }

    fn migration_config(state: CryptoMigrationState, epoch: u64) -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("rk/docs/4".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: epoch,
            migration_state: state,
            rules: vec![EncryptionRuleRef {
                id: "body_conf".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["body".to_string()],
                },
                instance: "docs_payload_v1".to_string(),
                binding: Some("payload-field/v1".to_string()),
            }],
        }
    }

    fn config_with_encryption(encryption: CollectionEncryptionConfig) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                encryption: Some(encryption),
                ..CollectionParams::empty()
            },
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig {
                deleted_threshold: 0.1,
                vacuum_min_vector_number: 1000,
                default_segment_number: 0,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: None,
                indexing_threshold: Some(100_000),
                flush_interval_sec: 60,
                max_optimization_threads: Some(0),
                prevent_unoptimized: None,
            },
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(Uuid::from_u128(0x1234567890abcdef1234567890abcdef)),
            metadata: None,
        }
    }

    fn crypto_settings_for_manifest() -> Settings {
        Settings {
            crypto: CryptoSettings {
                zero_trust_profile: None,
                ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
                ckks_scoring_source_batch_max:
                    crate::settings::default_ckks_scoring_source_batch_max(),
                ckks_query_nonce_replay_ttl_secs:
                    crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
                ckks_query_nonce_replay_cache_max_entries:
                    crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
                allow_inline_key_material: true,
                instances: HashMap::from([
                    (
                        "docs_payload_v1".to_string(),
                        CryptoInstanceConfig {
                            provider: "payload/aes-256-gcm@v1".to_string(),
                            materials: HashMap::from([(
                                "sym_key".to_string(),
                                "tenant-a/server-rk-v4".to_string(),
                            )]),
                            backend_ref: None,
                            options: json!({
                                "key_id": "tenant-a:docs",
                                "material_fingerprint_id": "tenant-a/server-rk-v4@fp",
                                "retired_materials": [{
                                    "material": "tenant-a/server-rk-v3",
                                    "material_fingerprint_id": "tenant-a/server-rk-v3@fp",
                                }],
                            }),
                        },
                    ),
                    (
                        "docs_client_v1".to_string(),
                        CryptoInstanceConfig {
                            provider: "payload/client-aead@v1".to_string(),
                            materials: HashMap::new(),
                            backend_ref: None,
                            options: json!({
                                "key_id": "tenant-a:docs",
                                "key_id_required": true,
                                "expected_rk_id": "tenant-a:docs",
                                "min_rk_epoch": 4,
                                "max_rk_epoch": 4,
                                "signature_public_keys": {
                                    "tenant-a/client-signing-v1": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
                                },
                            }),
                        },
                    ),
                ]),
                materials: HashMap::from([
                    (
                        "tenant-a/server-rk-v4".to_string(),
                        CryptoMaterialConfig {
                            kind: "symmetric_key_32".to_string(),
                            source: Some("inline".to_string()),
                            value_b64: Some(
                                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_string(),
                            ),
                            rk_epoch: Some(4),
                            state: Some("active".to_string()),
                            scope: Some(
                                "collection:12345678-90ab-cdef-1234-567890abcdef".to_string(),
                            ),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (
                        "tenant-a/server-rk-v3".to_string(),
                        CryptoMaterialConfig {
                            kind: "symmetric_key_32".to_string(),
                            source: Some("inline".to_string()),
                            value_b64: Some(
                                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_string(),
                            ),
                            rk_epoch: Some(3),
                            state: Some("retired".to_string()),
                            scope: Some(
                                "collection:12345678-90ab-cdef-1234-567890abcdef".to_string(),
                            ),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                ]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        }
    }

    fn manifest_encryption_config() -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:docs".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 4,
            migration_state: CryptoMigrationState::Active,
            rules: vec![
                EncryptionRuleRef {
                    id: "body_server".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                },
                EncryptionRuleRef {
                    id: "body_client".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["client_body".to_string()],
                    },
                    instance: "docs_client_v1".to_string(),
                    binding: Some("client-payload-envelope/v1".to_string()),
                },
            ],
        }
    }

    #[test]
    fn payload_crypto_migration_run_builds_completion_plan_for_rotation() {
        let plan = payload_crypto_migration_completion_plan(
            CryptoMigrationState::Rotating,
            4,
            RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: false,
            },
            vec![verified_checkpoint()],
        )
        .unwrap();

        assert_eq!(plan.from, CryptoMigrationState::Rotating);
        assert_eq!(plan.to, CryptoMigrationState::Active);
        assert_eq!(plan.target_epoch, 4);
        assert_eq!(plan.active_rk_id.as_deref(), Some("rk/docs/4"));
        assert_eq!(plan.retired_rk_id.as_deref(), Some("rk/docs/3"));
        plan.validate_admin_plan().unwrap();
    }

    #[test]
    fn payload_crypto_migration_dry_run_completion_plan_is_not_applyable() {
        let plan = payload_crypto_migration_completion_plan(
            CryptoMigrationState::Rotating,
            4,
            RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: true,
            },
            vec![verified_checkpoint()],
        )
        .unwrap();

        assert!(plan.dry_run);
        let err = plan
            .validate_admin_plan()
            .expect_err("dry-run completion plans must not be directly applyable");
        assert_eq!(
            err.code.as_ref(),
            "crypto_migration_completion_cannot_be_dry_run"
        );
    }

    #[test]
    fn standalone_crypto_migration_plan_rejects_completion_transitions() {
        let completion_plan = payload_crypto_migration_completion_plan(
            CryptoMigrationState::Rotating,
            4,
            RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: false,
            },
            vec![verified_checkpoint()],
        )
        .unwrap();
        completion_plan.validate_admin_plan().unwrap();

        let err = validate_standalone_crypto_migration_plan(&completion_plan)
            .expect_err("standalone endpoint must not close migration state");
        assert_eq!(
            err.code.as_ref(),
            "crypto_migration_completion_requires_run_payloads"
        );

        let start_plan = CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            checkpoints: Vec::new(),
            dry_run: false,
        };
        validate_standalone_crypto_migration_plan(&start_plan).unwrap();
    }

    #[test]
    fn payload_crypto_migration_run_rejects_invalid_rk_ids_for_state() {
        assert!(
            payload_crypto_migration_completion_plan(
                CryptoMigrationState::Rotating,
                4,
                RunPayloadCryptoMigration {
                    active_rk_id: "rk/docs/4".to_string(),
                    retired_rk_id: None,
                    dry_run: false,
                },
                vec![verified_checkpoint()],
            )
            .is_err()
        );

        assert!(
            payload_crypto_migration_completion_plan(
                CryptoMigrationState::Decrypting,
                3,
                RunPayloadCryptoMigration {
                    active_rk_id: "rk/docs/3".to_string(),
                    retired_rk_id: Some("rk/docs/2".to_string()),
                    dry_run: false,
                },
                vec![verified_checkpoint()],
            )
            .is_err()
        );

        assert!(
            payload_crypto_migration_completion_plan(
                CryptoMigrationState::Active,
                3,
                RunPayloadCryptoMigration {
                    active_rk_id: "rk/docs/3".to_string(),
                    retired_rk_id: None,
                    dry_run: false,
                },
                vec![verified_checkpoint()],
            )
            .is_err()
        );
    }

    #[test]
    fn payload_crypto_migration_run_preflights_request_before_rewrite() {
        let rotating = migration_config(CryptoMigrationState::Rotating, 4);
        let settings = crypto_settings_for_manifest();

        let missing_retired = validate_payload_crypto_migration_run_request_for_config(
            CryptoMigrationState::Rotating,
            4,
            &RunPayloadCryptoMigration {
                active_rk_id: "tenant-a/server-rk-v4".to_string(),
                retired_rk_id: None,
                dry_run: false,
            },
            &rotating,
            &settings,
        );
        assert!(
            missing_retired.is_err(),
            "rotation run must reject missing retired_rk_id before rewriting payloads",
        );

        let malformed_active_rk = validate_payload_crypto_migration_run_request_for_config(
            CryptoMigrationState::Rotating,
            4,
            &RunPayloadCryptoMigration {
                active_rk_id: "rk docs 4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: false,
            },
            &rotating,
            &settings,
        );
        assert!(
            malformed_active_rk.is_err(),
            "migration run must reject malformed active_rk_id before rewriting payloads",
        );

        let wrong_retired_rk = validate_payload_crypto_migration_run_request_for_config(
            CryptoMigrationState::Rotating,
            4,
            &RunPayloadCryptoMigration {
                active_rk_id: "tenant-a/server-rk-v4".to_string(),
                retired_rk_id: Some("tenant-a/server-rk-v2".to_string()),
                dry_run: false,
            },
            &rotating,
            &settings,
        );
        assert!(
            wrong_retired_rk.is_err(),
            "migration run must reject retired_rk_id that is not in runtime retired_materials",
        );

        validate_payload_crypto_migration_run_request_for_config(
            CryptoMigrationState::Rotating,
            4,
            &RunPayloadCryptoMigration {
                active_rk_id: "tenant-a/server-rk-v4".to_string(),
                retired_rk_id: Some("tenant-a/server-rk-v3".to_string()),
                dry_run: false,
            },
            &rotating,
            &settings,
        )
        .unwrap();
    }

    #[test]
    fn payload_crypto_migration_run_record_persists_completion_plan_for_resume() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let record = payload_crypto_migration_run_test_record();

        persist_payload_crypto_migration_run_record(dir.path(), &record).unwrap();
        let record_path = dir.path().join(PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE);

        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&record_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "payload migration run record must be private"
        );

        let persisted: Value =
            serde_json::from_slice(&std::fs::read(record_path).unwrap()).unwrap();
        assert_eq!(persisted["collection_name"], "docs");
        assert_eq!(
            persisted["stable_crypto_id"],
            "12345678-90ab-cdef-1234-567890abcdef"
        );
        assert_eq!(persisted["completed"], true);
        assert_eq!(persisted["dry_run"], false);
        assert_eq!(persisted["completion_plan"]["from"], "rotating");
        assert_eq!(persisted["completion_plan"]["to"], "active");
        assert_eq!(persisted["checkpoints"][0]["status"], "verified");
        assert!(persisted["run_id"].as_str().is_some_and(|run_id| {
            BASE64URL_NOPAD
                .decode(run_id.as_bytes())
                .is_ok_and(|bytes| bytes.len() == 32)
        }));
        assert_eq!(
            persisted["checkpoints_sha256_b64"],
            payload_crypto_migration_run_record_digest_b64("checkpoints", &record.checkpoints)
                .unwrap()
        );
        assert_eq!(
            persisted["completion_plan_sha256_b64"],
            payload_crypto_migration_run_record_digest_b64(
                "completion plan",
                &record.completion_plan,
            )
            .unwrap()
        );
    }

    #[test]
    fn payload_crypto_migration_run_record_commits_after_pending_record() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-commit-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let mut record = payload_crypto_migration_run_test_record();
        record.completed = false;

        persist_payload_crypto_migration_run_record(dir.path(), &record).unwrap();
        let record_path = dir.path().join(PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE);
        let pending: Value = serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        assert_eq!(pending["completed"], false);
        assert_eq!(pending["completion_plan"]["from"], "rotating");
        assert_eq!(pending["completion_plan"]["to"], "active");

        record.completed = true;
        persist_payload_crypto_migration_run_record(dir.path(), &record).unwrap();
        let committed: Value =
            serde_json::from_slice(&std::fs::read(record_path).unwrap()).unwrap();
        assert_eq!(committed["completed"], true);
        assert_eq!(committed["run_id"], pending["run_id"]);
        assert_eq!(
            committed["completion_plan_sha256_b64"],
            pending["completion_plan_sha256_b64"]
        );
        assert_eq!(
            committed["checkpoints_sha256_b64"],
            pending["checkpoints_sha256_b64"]
        );
        assert_eq!(committed["completion_plan"], pending["completion_plan"]);
        assert_eq!(committed["checkpoints"], pending["checkpoints"]);
    }

    #[test]
    fn payload_crypto_migration_pending_run_record_loads_and_validates_for_completion() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-validate-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let mut record = payload_crypto_migration_run_test_record();
        record.completed = false;

        persist_payload_crypto_migration_run_record(dir.path(), &record).unwrap();
        let loaded = load_payload_crypto_migration_run_record(dir.path()).unwrap();

        assert_eq!(loaded.run_id, record.run_id);
        validate_payload_crypto_migration_pending_run_record(
            &loaded,
            &record.run_id,
            &record.collection_name,
            &record.stable_crypto_id,
            &record.checkpoints_sha256_b64,
            &record.completion_plan_sha256_b64,
        )
        .expect("persisted pending run record must gate completion");
    }

    #[test]
    fn payload_crypto_migration_pending_run_record_rejects_committed_record_before_completion() {
        let record = payload_crypto_migration_run_test_record();

        let err = validate_payload_crypto_migration_pending_run_record(
            &record,
            &record.run_id,
            &record.collection_name,
            &record.stable_crypto_id,
            &record.checkpoints_sha256_b64,
            &record.completion_plan_sha256_b64,
        )
        .expect_err("completed record must not authorize a new completion apply");
        assert!(
            err.to_string().contains("pending run record"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn payload_crypto_migration_pending_run_record_rejects_tampered_checkpoint_digest() {
        let mut record = payload_crypto_migration_run_test_record();
        record.completed = false;
        record.checkpoints[0].processed_points = 1;

        let err = validate_payload_crypto_migration_pending_run_record(
            &record,
            &record.run_id,
            &record.collection_name,
            &record.stable_crypto_id,
            &record.checkpoints_sha256_b64,
            &record.completion_plan_sha256_b64,
        )
        .expect_err("tampered checkpoint body must not match persisted digest");
        assert!(
            err.to_string()
                .contains("checkpoint digest is inconsistent"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn payload_crypto_migration_pending_run_record_rejects_expected_plan_digest_mismatch() {
        let mut record = payload_crypto_migration_run_test_record();
        record.completed = false;
        let wrong_completion_plan_sha256_b64 = BASE64URL_NOPAD.encode(&[7; 32]);

        let err = validate_payload_crypto_migration_pending_run_record(
            &record,
            &record.run_id,
            &record.collection_name,
            &record.stable_crypto_id,
            &record.checkpoints_sha256_b64,
            &wrong_completion_plan_sha256_b64,
        )
        .expect_err("pending record must be bound to the exact completion plan digest");
        assert!(
            err.to_string()
                .contains("completion plan digest does not match"),
            "unexpected error: {err}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn payload_crypto_migration_run_record_rejects_symlink_target() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-symlink-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let target_path = dir.path().join("attacker-controlled-record.json");
        std::fs::write(&target_path, b"{}").unwrap();
        let record_path = dir.path().join(PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE);
        symlink(&target_path, &record_path).unwrap();

        let err = persist_payload_crypto_migration_run_record(
            dir.path(),
            &payload_crypto_migration_run_test_record(),
        )
        .expect_err("payload migration run record must reject symlink target");
        assert!(
            err.to_string().contains("non-symlink file"),
            "unexpected error: {err}",
        );
        assert_payload_crypto_migration_run_record_error_redacts_paths(&err);
    }

    #[cfg(unix)]
    #[test]
    fn payload_crypto_migration_run_record_rejects_writable_directory() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-dir-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let mut permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        permissions.set_mode(0o722);
        std::fs::set_permissions(dir.path(), permissions).unwrap();

        let err = persist_payload_crypto_migration_run_record(
            dir.path(),
            &payload_crypto_migration_run_test_record(),
        )
        .expect_err("payload migration run record must reject writable collection directory");
        assert!(
            err.to_string().contains("group/world-writable"),
            "unexpected error: {err}",
        );
        assert_payload_crypto_migration_run_record_error_redacts_paths(&err);
    }

    #[cfg(unix)]
    #[test]
    fn payload_crypto_migration_run_record_rejects_writable_ancestor_directory() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-ancestor-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let writable_ancestor = dir.path().join("writable-ancestor");
        let collection_dir = writable_ancestor.join("collection");
        std::fs::create_dir_all(&collection_dir).unwrap();
        let mut permissions = std::fs::metadata(&writable_ancestor).unwrap().permissions();
        permissions.set_mode(0o722);
        std::fs::set_permissions(&writable_ancestor, permissions).unwrap();

        let err = persist_payload_crypto_migration_run_record(
            &collection_dir,
            &payload_crypto_migration_run_test_record(),
        )
        .expect_err("payload migration run record must reject writable ancestor directory");
        assert!(
            err.to_string().contains("group/world-writable"),
            "unexpected error: {err}",
        );
        assert_payload_crypto_migration_run_record_error_redacts_paths(&err);
    }

    #[cfg(unix)]
    #[test]
    fn payload_crypto_migration_run_record_rejects_symlink_ancestor_directory() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-symlink-parent-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let real_parent = dir.path().join("real-parent");
        let symlink_parent = dir.path().join("symlink-parent");
        let collection_dir = symlink_parent.join("collection");
        std::fs::create_dir_all(real_parent.join("collection")).unwrap();
        symlink(&real_parent, &symlink_parent).unwrap();

        let err = persist_payload_crypto_migration_run_record(
            &collection_dir,
            &payload_crypto_migration_run_test_record(),
        )
        .expect_err("payload migration run record must reject symlink ancestor directory");
        assert!(
            err.to_string().contains("non-symlink directory"),
            "unexpected error: {err}",
        );
        assert_payload_crypto_migration_run_record_error_redacts_paths(&err);
    }

    fn assert_payload_crypto_migration_run_record_error_redacts_paths(err: &StorageError) {
        let rendered = err.to_string();
        for leaked in [
            "qdrant-sec-payload-migration-record",
            "attacker-controlled-record",
            "writable-ancestor",
            "real-parent",
            "symlink-parent",
            "collection",
            PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE,
        ] {
            assert!(
                !rendered.contains(leaked),
                "payload crypto migration run record error leaked path component {leaked}: {rendered}",
            );
        }
    }

    #[test]
    fn collection_crypto_manifest_reports_non_secret_runtime_key_manifest() {
        let settings = crypto_settings_for_manifest();
        let config = config_with_encryption(manifest_encryption_config());

        let manifest = build_collection_crypto_manifest_response("docs", &config, &settings)
            .expect("valid collection crypto runtime must build a manifest");

        assert_eq!(manifest.collection_name, "docs");
        assert_eq!(
            manifest.stable_crypto_id,
            "12345678-90ab-cdef-1234-567890abcdef"
        );
        assert_eq!(manifest.encryption_epoch, 4);
        assert_eq!(manifest.rules.len(), 2);
        assert_eq!(manifest.resource_keys.len(), 3);

        let active = manifest
            .resource_keys
            .iter()
            .find(|key| key.rk_id == "tenant-a/server-rk-v4")
            .unwrap();
        assert_eq!(
            active.material_ref.as_deref(),
            Some("tenant-a/server-rk-v4")
        );
        assert_eq!(active.epoch, 4);
        assert_eq!(active.state, "active");
        assert_eq!(
            active.scope.as_deref(),
            Some("collection:12345678-90ab-cdef-1234-567890abcdef")
        );
        assert_eq!(active.wrapped_by, None);
        assert_eq!(active.used_by_rules, vec!["body_server".to_string()]);

        let retired = manifest
            .resource_keys
            .iter()
            .find(|key| key.rk_id == "tenant-a/server-rk-v3")
            .unwrap();
        assert_eq!(retired.epoch, 3);
        assert_eq!(retired.state, "retired");

        let client = manifest
            .resource_keys
            .iter()
            .find(|key| key.rk_id == "tenant-a:docs")
            .unwrap();
        assert_eq!(client.material_ref, None);
        assert_eq!(client.epoch, 4);
        assert_eq!(client.scope.as_deref(), Some("client-envelope"));
        assert_eq!(client.used_by_rules, vec!["body_client".to_string()]);
    }

    #[test]
    fn collection_crypto_manifest_fails_closed_on_runtime_mismatch() {
        let mut settings = crypto_settings_for_manifest();
        settings
            .crypto
            .materials
            .get_mut("tenant-a/server-rk-v4")
            .unwrap()
            .rk_epoch = None;
        let config = config_with_encryption(manifest_encryption_config());

        let err = build_collection_crypto_manifest_response("docs", &config, &settings)
            .expect_err("manifest must not hide runtime RK metadata mismatch");

        let rendered = err.to_string();
        assert!(
            rendered.contains("payload crypto runtime validation failed"),
            "{rendered}",
        );
        assert!(!rendered.contains("server-side AEAD material"));
        assert!(!rendered.contains("missing rk_epoch"));
        assert!(!rendered.contains("tenant-a/server-rk-v4"));
    }
}
