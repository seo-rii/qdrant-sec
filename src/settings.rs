use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;
use std::{env, fmt, io};

use api::grpc::transport_channel_pool::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_GRPC_TIMEOUT, DEFAULT_POOL_SIZE,
};
use collection::operations::validation;
use collection::shards::shard::PeerId;
use common::flags::FeatureFlags;
use config::{Config, ConfigError, Environment, File, FileFormat, Source};
use qdrant_sec::PrivateOramActivationAuthorityPublicKeyV1;
use serde::Deserialize;
use storage::types::StorageConfig;
use validator::{Validate, ValidationError, ValidationErrors};

use crate::common::audit::AuditConfig;
use crate::common::debugger::DebuggerConfig;
use crate::common::inference::config::InferenceConfig;
use crate::tracing;

const MAX_PEER_ID: u64 = (1 << 53) - 1;

const DEFAULT_CONFIG: &str = include_str!("../config/config.yaml");

#[derive(Deserialize, Validate, Clone)]
pub struct ServiceConfig {
    #[validate(length(min = 1))]
    pub host: String,
    pub http_port: u16,
    pub grpc_port: Option<u16>, // None means that gRPC is disabled

    /// If specified, qdrant will serve a separate service for `/metrics` on this port.
    /// Separate port is not protected by API keys and dedicated for internal monitoring systems.
    /// This port should not be exposed to untrusted networks.
    #[serde(default)]
    pub metrics_port: Option<u16>,

    pub max_request_size_mb: usize,
    /// Maximum accepted multipart upload size in megabytes.
    ///
    /// Snapshot uploads are spooled to temp files by Actix before handler-level
    /// auth and crypto preflight run, so this must be finite.
    #[serde(default = "default_max_snapshot_upload_size_mb")]
    #[validate(range(min = 1))]
    pub max_snapshot_upload_size_mb: usize,
    pub max_workers: Option<usize>,
    /// Keep-alive timeout for incoming HTTP connections in seconds.
    #[serde(default = "default_http_keep_alive_timeout_sec")]
    #[validate(range(min = 1))]
    pub http_keep_alive_timeout_sec: u64,
    /// Timeout for reading HTTP request data from clients in seconds.
    #[serde(default = "default_http_client_request_timeout_sec")]
    #[validate(range(min = 1))]
    pub http_client_request_timeout_sec: u64,
    /// Timeout for client disconnect handling in seconds.
    #[serde(default = "default_http_client_disconnect_timeout_sec")]
    #[validate(range(min = 1))]
    pub http_client_disconnect_timeout_sec: u64,
    #[serde(default = "default_cors")]
    pub enable_cors: bool,
    #[serde(default)]
    pub enable_tls: bool,
    #[serde(default)]
    pub verify_https_client_certificate: bool,
    pub api_key: Option<String>,

    /// Same as `api_key`, can be used for rolling key rotation.
    pub alt_api_key: Option<String>,

    pub read_only_api_key: Option<String>,
    #[serde(default)]
    pub jwt_rbac: Option<bool>,

    #[serde(default)]
    pub hide_jwt_dashboard: Option<bool>,

    /// Directory where static files are served from.
    /// For example, the Web-UI should be placed here.
    #[serde(default)]
    pub static_content_dir: Option<String>,

    /// If serving of the static content is enabled.
    /// This includes the Web-UI. True by default.
    #[serde(default)]
    pub enable_static_content: Option<bool>,

    /// How much time is considered too long for a query to execute.
    pub slow_query_secs: Option<f32>,

    /// Whether to enable reporting of measured hardware utilization in API responses.
    #[serde(default)]
    pub hardware_reporting: Option<bool>,

    /// Global prefix for metrics.
    #[serde(default)]
    #[validate(custom(function = validate_metrics_prefix))]
    pub metrics_prefix: Option<String>,
}

impl fmt::Debug for ServiceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceConfig")
            .field("host", &self.host)
            .field("http_port", &self.http_port)
            .field("grpc_port", &self.grpc_port)
            .field("metrics_port", &self.metrics_port)
            .field("max_request_size_mb", &self.max_request_size_mb)
            .field(
                "max_snapshot_upload_size_mb",
                &self.max_snapshot_upload_size_mb,
            )
            .field("max_workers", &self.max_workers)
            .field(
                "http_keep_alive_timeout_sec",
                &self.http_keep_alive_timeout_sec,
            )
            .field(
                "http_client_request_timeout_sec",
                &self.http_client_request_timeout_sec,
            )
            .field(
                "http_client_disconnect_timeout_sec",
                &self.http_client_disconnect_timeout_sec,
            )
            .field("enable_cors", &self.enable_cors)
            .field("enable_tls", &self.enable_tls)
            .field(
                "verify_https_client_certificate",
                &self.verify_https_client_certificate,
            )
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .field(
                "alt_api_key",
                &self.alt_api_key.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "read_only_api_key",
                &self.read_only_api_key.as_ref().map(|_| "[redacted]"),
            )
            .field("jwt_rbac", &self.jwt_rbac)
            .field("hide_jwt_dashboard", &self.hide_jwt_dashboard)
            .field("static_content_dir", &self.static_content_dir)
            .field("enable_static_content", &self.enable_static_content)
            .field("slow_query_secs", &self.slow_query_secs)
            .field("hardware_reporting", &self.hardware_reporting)
            .field("metrics_prefix", &self.metrics_prefix)
            .finish()
    }
}

impl ServiceConfig {
    pub fn hardware_reporting(&self) -> bool {
        self.hardware_reporting.unwrap_or_default()
    }
}

#[derive(Debug, Deserialize, Clone, Default, Validate)]
pub struct ClusterConfig {
    pub enabled: bool, // disabled by default
    #[serde(default)]
    #[validate(range(min = 1, max = MAX_PEER_ID))]
    pub peer_id: Option<PeerId>,
    #[serde(default = "default_timeout_ms")]
    #[validate(range(min = 1))]
    pub grpc_timeout_ms: u64,
    #[serde(default = "default_connection_timeout_ms")]
    #[validate(range(min = 1))]
    pub connection_timeout_ms: u64,
    #[serde(default)]
    #[validate(nested)]
    pub p2p: P2pConfig,
    #[serde(default)]
    #[validate(nested)]
    pub consensus: ConsensusConfig,
    #[serde(default)]
    pub resharding_enabled: bool, // disabled by default
}

#[derive(Debug, Deserialize, Clone, Validate)]
pub struct P2pConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default = "default_connection_pool_size")]
    #[validate(range(min = 1))]
    pub connection_pool_size: usize,
    #[serde(default)]
    pub enable_tls: bool,
}

impl Default for P2pConfig {
    fn default() -> Self {
        P2pConfig {
            port: None,
            connection_pool_size: default_connection_pool_size(),
            enable_tls: false,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Validate)]
pub struct ConsensusConfig {
    #[serde(default = "default_max_message_queue_size")]
    pub max_message_queue_size: usize, // controls the back-pressure at the Raft level
    #[serde(default = "default_tick_period_ms")]
    #[validate(range(min = 1))]
    pub tick_period_ms: u64,
    #[serde(default = "default_bootstrap_timeout_sec")]
    #[validate(range(min = 1))]
    pub bootstrap_timeout_sec: u64,
    #[validate(range(min = 1))]
    #[serde(default = "default_message_timeout_tics")]
    pub message_timeout_ticks: u64,
    /// Compact WAL when it grows to enough applied entries
    #[serde(default = "default_compact_wal_entries")]
    pub compact_wal_entries: u64,
    /// Externally anchored opt-in for the irreversible private ORAM mutation V2 protocol.
    #[serde(default)]
    #[validate(nested)]
    pub private_oram_mutation_v2_activation: Option<PrivateOramMutationV2ActivationConfig>,
}

#[derive(Debug, Deserialize, Clone, Validate)]
pub struct PrivateOramMutationV2ActivationConfig {
    pub authority: PrivateOramActivationAuthorityPublicKeyV1,
    pub cluster_identity_digest: String,
    #[validate(range(min = 1, max = MAX_PEER_ID))]
    pub cluster_first_voter_peer_id: PeerId,
    /// Canonical JSON containing the administrator-signed cumulative peer pin registry.
    pub authority_bundle_path: PathBuf,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        ConsensusConfig {
            max_message_queue_size: default_max_message_queue_size(),
            tick_period_ms: default_tick_period_ms(),
            bootstrap_timeout_sec: default_bootstrap_timeout_sec(),
            message_timeout_ticks: default_message_timeout_tics(),
            compact_wal_entries: default_compact_wal_entries(),
            private_oram_mutation_v2_activation: None,
        }
    }
}

#[derive(Deserialize, Clone, Validate)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
    pub ca_cert: Option<String>,
    #[serde(default = "default_tls_cert_ttl")]
    #[validate(range(min = 1))]
    pub cert_ttl: Option<u64>,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("cert", &"[redacted]")
            .field("key", &"[redacted]")
            .field("ca_cert", &self.ca_cert.as_ref().map(|_| "[redacted]"))
            .field("cert_ttl", &self.cert_ttl)
            .finish()
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, Validate)]
pub struct GpuConfig {
    /// Enable GPU indexing.
    #[serde(default)]
    pub indexing: bool,
    /// Force half precision for `f32` values while indexing.
    /// `f16` conversion will take place only inside GPU memory and won't affect storage type.
    #[serde(default)]
    pub force_half_precision: bool,
    /// Used vulkan "groups" of GPU. In other words, how many parallel points can be indexed by GPU.
    /// Optimal value might depend on the GPU model.
    /// Proportional, but doesn't necessary equal to the physical number of warps.
    /// Do not change this value unless you know what you are doing.
    /// Default: 512
    #[serde(default)]
    #[validate(range(min = 1))]
    pub groups_count: Option<usize>,
    /// Filter for GPU devices by hardware name. Case insensitive.
    /// Comma-separated list of substrings to match against the gpu device name.
    /// Example: "nvidia"
    /// Default: "" - all devices are accepted.
    #[serde(default)]
    pub device_filter: String,
    /// List of explicit GPU devices to use.
    /// If host has multiple GPUs, this option allows to select specific devices
    /// by their index in the list of found devices.
    /// If `device_filter` is set, indexes are applied after filtering.
    /// By default, all devices are accepted.
    #[serde(default)]
    pub devices: Option<Vec<usize>>,
    /// How many parallel indexing processes are allowed to run.
    /// Default: 1
    #[serde(default)]
    pub parallel_indexes: Option<usize>,
    /// Allow to use integrated GPUs.
    /// Default: false
    #[serde(default)]
    pub allow_integrated: bool,
    /// Allow to use emulated GPUs like LLVMpipe. Useful for CI.
    /// Default: false
    #[serde(default)]
    pub allow_emulated: bool,
}

fn validate_crypto_runtime_identifier(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(ValidationError::new("invalid_crypto_runtime_identifier"));
    }

    Ok(())
}

fn validate_optional_crypto_runtime_identifier(
    value: &Option<String>,
) -> Result<(), ValidationError> {
    if let Some(value) = value {
        validate_crypto_runtime_identifier(value)?;
    }

    Ok(())
}

fn validate_crypto_material_bindings(
    bindings: &HashMap<String, String>,
) -> Result<(), ValidationError> {
    for (role, reference) in bindings {
        validate_crypto_runtime_identifier(role)?;
        validate_crypto_runtime_identifier(reference)?;
    }

    Ok(())
}

fn default_crypto_options() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
}

#[derive(Deserialize, Clone, Default, Validate)]
pub struct CryptoMaterialConfig {
    #[validate(custom(function = "validate_crypto_runtime_identifier"))]
    pub kind: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub fd: Option<i32>,
    #[serde(default)]
    pub value_b64: Option<String>,
    #[serde(default)]
    pub vault_field: Option<String>,
    #[serde(default)]
    pub expected_host: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    #[validate(custom(function = "validate_crypto_runtime_identifier"))]
    pub provider_key_version: Option<String>,
    #[serde(default)]
    #[validate(custom(function = "validate_crypto_runtime_identifier"))]
    pub provider_attestation_id: Option<String>,
    #[serde(default)]
    #[validate(custom(function = "validate_crypto_runtime_identifier"))]
    pub wrapped_by: Option<String>,
    #[serde(default)]
    pub wrap_algorithm: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub wrapped_key_b64: Option<String>,
    #[serde(default)]
    pub rk_epoch: Option<u64>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl fmt::Debug for CryptoMaterialConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source_configured = self.source.is_some();
        let env_configured = self.env.is_some();
        let path_configured = self.path.is_some();
        let fd_configured = self.fd.is_some();
        let vault_field_configured = self.vault_field.is_some();
        let expected_host_configured = self.expected_host.is_some();
        let provider_key_version_configured = self.provider_key_version.is_some();
        let provider_attestation_id_configured = self.provider_attestation_id.is_some();
        let wrapped_by_configured = self.wrapped_by.is_some();
        let scope_configured = self.scope.is_some();

        f.debug_struct("CryptoMaterialConfig")
            .field("kind", &self.kind)
            .field("source_configured", &source_configured)
            .field("env_configured", &env_configured)
            .field("path_configured", &path_configured)
            .field("fd_configured", &fd_configured)
            .field("value_b64", &self.value_b64.as_ref().map(|_| "[redacted]"))
            .field("vault_field_configured", &vault_field_configured)
            .field("expected_host_configured", &expected_host_configured)
            .field("timeout_ms", &self.timeout_ms)
            .field(
                "provider_key_version_configured",
                &provider_key_version_configured,
            )
            .field(
                "provider_attestation_id_configured",
                &provider_attestation_id_configured,
            )
            .field("wrapped_by_configured", &wrapped_by_configured)
            .field("wrap_algorithm", &self.wrap_algorithm)
            .field("nonce", &self.nonce.as_ref().map(|_| "[redacted]"))
            .field(
                "wrapped_key_b64",
                &self.wrapped_key_b64.as_ref().map(|_| "[redacted]"),
            )
            .field("rk_epoch", &self.rk_epoch)
            .field("state", &self.state)
            .field("scope_configured", &scope_configured)
            .finish()
    }
}

#[derive(Deserialize, Clone, Default, Validate)]
pub struct CryptoBackendConfig {
    #[validate(custom(function = "validate_crypto_runtime_identifier"))]
    pub kind: String,
    #[serde(default)]
    pub program: Option<String>,
    #[serde(default)]
    pub sha256_b64: Option<String>,
    #[serde(default)]
    pub signature_public_key_b64: Option<String>,
    #[serde(default)]
    pub signature_b64: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Largest bridge response line (and total stderr) accepted per worker, in bytes.
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
    /// Extra directories or files the `*_landlock_strict*` bridge sandbox kinds let the bridge
    /// read, as absolute normalized paths (for example an OpenFHE data directory). Never list
    /// the storage, snapshot, configuration or key material locations here.
    #[serde(default)]
    pub landlock_read_allow_roots: Vec<String>,
}

impl fmt::Debug for CryptoBackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoBackendConfig")
            .field("kind", &self.kind)
            .field("program", &self.program.as_ref().map(|_| "[redacted]"))
            .field(
                "sha256_b64",
                &self.sha256_b64.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "signature_public_key_b64",
                &self.signature_public_key_b64.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "signature_b64",
                &self.signature_b64.as_ref().map(|_| "[redacted]"),
            )
            .field("size", &self.size)
            .field("timeout_ms", &self.timeout_ms)
            .field("max_output_bytes", &self.max_output_bytes)
            .field(
                "landlock_read_allow_roots_count",
                &self.landlock_read_allow_roots.len(),
            )
            .finish()
    }
}

#[derive(Deserialize, Clone, Default)]
pub struct CryptoInstanceConfig {
    pub provider: String,
    #[serde(default)]
    pub materials: HashMap<String, String>,
    #[serde(default)]
    pub backend_ref: Option<String>,
    #[serde(default = "default_crypto_options")]
    pub options: serde_json::Value,
}

impl fmt::Debug for CryptoInstanceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let materials_count = self.materials.len();
        let backend_ref_configured = self.backend_ref.is_some();
        let options_shape = match &self.options {
            serde_json::Value::Null => "null".to_string(),
            serde_json::Value::Bool(_) => "bool".to_string(),
            serde_json::Value::Number(_) => "number".to_string(),
            serde_json::Value::String(_) => "string".to_string(),
            serde_json::Value::Array(items) => format!("array:{} items", items.len()),
            serde_json::Value::Object(fields) => format!("object:{} fields", fields.len()),
        };

        f.debug_struct("CryptoInstanceConfig")
            .field("provider", &self.provider)
            .field("materials_count", &materials_count)
            .field("backend_ref_configured", &backend_ref_configured)
            .field("options_shape", &options_shape)
            .finish()
    }
}

impl Validate for CryptoInstanceConfig {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        if let Err(error) = validate_crypto_runtime_identifier(&self.provider) {
            errors.add("provider", error);
        }
        if let Err(error) = validate_crypto_material_bindings(&self.materials) {
            errors.add("materials", error);
        }
        if let Err(error) = validate_optional_crypto_runtime_identifier(&self.backend_ref) {
            errors.add("backend_ref", error);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

const fn default_allow_inline_key_material() -> bool {
    false
}

pub(crate) const fn default_ckks_grouped_max_candidates() -> usize {
    4096
}

pub(crate) const fn default_ckks_scoring_source_batch_max() -> usize {
    32
}

pub(crate) const fn default_ckks_query_nonce_replay_ttl_secs() -> u64 {
    300
}

pub(crate) const fn default_ckks_query_nonce_replay_cache_max_entries() -> usize {
    100_000
}

pub const ZERO_TRUST_PROFILE_STRICT: &str = "strict";

#[derive(Debug, Deserialize, Clone, Validate)]
pub struct CryptoSettings {
    #[serde(default = "default_allow_inline_key_material")]
    pub allow_inline_key_material: bool,
    #[serde(default)]
    pub zero_trust_profile: Option<String>,
    #[serde(default = "default_ckks_grouped_max_candidates")]
    #[validate(range(min = 1))]
    pub ckks_grouped_max_candidates: usize,
    #[serde(default = "default_ckks_scoring_source_batch_max")]
    #[validate(range(min = 1))]
    pub ckks_scoring_source_batch_max: usize,
    #[serde(default = "default_ckks_query_nonce_replay_ttl_secs")]
    #[validate(range(min = 1))]
    pub ckks_query_nonce_replay_ttl_secs: u64,
    #[serde(default = "default_ckks_query_nonce_replay_cache_max_entries")]
    #[validate(range(min = 1))]
    pub ckks_query_nonce_replay_cache_max_entries: usize,
    #[serde(default)]
    #[validate(nested)]
    pub instances: HashMap<String, CryptoInstanceConfig>,
    #[serde(default)]
    #[validate(nested)]
    pub materials: HashMap<String, CryptoMaterialConfig>,
    #[serde(default)]
    #[validate(nested)]
    pub backends: HashMap<String, CryptoBackendConfig>,
}

impl Default for CryptoSettings {
    fn default() -> Self {
        Self {
            allow_inline_key_material: default_allow_inline_key_material(),
            zero_trust_profile: None,
            ckks_grouped_max_candidates: default_ckks_grouped_max_candidates(),
            ckks_scoring_source_batch_max: default_ckks_scoring_source_batch_max(),
            ckks_query_nonce_replay_ttl_secs: default_ckks_query_nonce_replay_ttl_secs(),
            ckks_query_nonce_replay_cache_max_entries:
                default_ckks_query_nonce_replay_cache_max_entries(),
            instances: HashMap::new(),
            materials: HashMap::new(),
            backends: HashMap::new(),
        }
    }
}

impl CryptoSettings {
    pub fn is_configured(&self) -> bool {
        !self.instances.is_empty() || !self.materials.is_empty() || !self.backends.is_empty()
    }
}

#[derive(Debug, Deserialize, Clone, Validate)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub logger: tracing::LoggerConfig,
    #[validate(nested)]
    pub storage: StorageConfig,
    #[validate(nested)]
    pub service: ServiceConfig,
    #[serde(default)]
    #[validate(nested)]
    pub cluster: ClusterConfig,
    #[serde(default = "default_telemetry_disabled")]
    pub telemetry_disabled: bool,
    #[validate(nested)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub debugger: DebuggerConfig,
    /// A list of messages for errors that happened during loading the configuration. We collect
    /// them and store them here while loading because then our logger is not configured yet.
    /// We therefore need to log these messages later, after the logger is ready.
    #[serde(default, skip)]
    pub load_errors: Vec<LogMsg>,
    #[serde(default)]
    pub inference: Option<InferenceConfig>,
    #[serde(default)]
    #[validate(nested)]
    pub gpu: Option<GpuConfig>,
    #[serde(default)]
    pub feature_flags: FeatureFlags,
    /// Audit logging configuration.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
    #[serde(default)]
    #[validate(nested)]
    pub crypto: CryptoSettings,
}

impl Settings {
    pub fn new(custom_config_path: Option<String>) -> Result<Self, ConfigError> {
        let mut load_errors = vec![];
        let config_exists = |path| File::with_name(path).collect().is_ok();

        // Check if custom config file exists, report error if not
        if let Some(path) = &custom_config_path
            && !config_exists(path)
        {
            load_errors.push(LogMsg::Error(format!(
                "Config file via --config-path is not found: {path}"
            )));
        }

        let env = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        let config_path_env = format!("config/{env}");

        // Report error if main or env config files exist, report warning if not
        // Check if main and env configuration file
        load_errors.extend(
            ["config/config", &config_path_env]
                .into_iter()
                .filter(|path| !config_exists(path))
                .map(|path| LogMsg::Warn(format!("Config file not found: {path}"))),
        );

        // Configuration builder: define different levels of configuration files
        let mut config = Config::builder()
            // Start with compile-time base config
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            // Merge main config: config/config
            .add_source(File::with_name("config/config").required(false))
            // Merge env config: config/{env}
            // Uses RUN_MODE, defaults to 'development'
            .add_source(File::with_name(&config_path_env).required(false))
            // Merge local config, not tracked in git: config/local
            .add_source(File::with_name("config/local").required(false));

        #[cfg(feature = "deb")]
        {
            // Read config, installed with deb package
            config = config.add_source(File::with_name("/etc/qdrant/config").required(false));
        }

        // Merge user provided config with --config-path
        if let Some(path) = custom_config_path {
            config = config.add_source(File::with_name(&path).required(false));
        }

        // Merge environment settings
        // E.g.: `QDRANT_DEBUG=1 ./target/app` would set `debug=true`
        config = config.add_source(Environment::with_prefix("QDRANT").separator("__"));

        // Build and merge config and deserialize into Settings, attach any load errors we had
        let mut settings: Settings = config.build()?.try_deserialize()?;
        settings.load_errors.extend(load_errors);
        Ok(settings)
    }

    pub fn tls(&self) -> io::Result<&TlsConfig> {
        self.tls
            .as_ref()
            .ok_or_else(Self::tls_config_is_undefined_error)
    }

    pub fn tls_config_is_undefined_error() -> io::Error {
        io::Error::other("TLS config is not defined in the Qdrant config file")
    }

    pub fn validate_and_warn(&self) {
        //
        // JWT RBAC
        //
        // Using HMAC-SHA256, recommended secret size is 32 bytes
        const JWT_RECOMMENDED_SECRET_LENGTH: usize = 256 / 8;

        let all_keys_are_empty = self
            .service
            .api_key
            .as_deref()
            .unwrap_or_default()
            .is_empty()
            && self
                .service
                .alt_api_key
                .as_deref()
                .unwrap_or_default()
                .is_empty();

        let min_length = [
            self.service.api_key.as_ref(),
            self.service.alt_api_key.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|key| key.len())
        .min()
        .unwrap_or_default();

        let any_api_key_is_short = min_length < JWT_RECOMMENDED_SECRET_LENGTH;

        // Log if JWT RBAC is enabled but no API key is set
        if self.service.jwt_rbac.unwrap_or_default() {
            if all_keys_are_empty {
                log::warn!("JWT RBAC configured but no API key set, JWT RBAC is not enabled")
            // Log if JWT RAC is enabled, API key is set but smaller than recommended size for JWT secret
            } else if any_api_key_is_short {
                log::warn!(
                    "It is highly recommended to use an API key of {JWT_RECOMMENDED_SECRET_LENGTH} bytes when JWT RBAC is enabled",
                )
            }
        }

        // Print any load error messages we had
        self.load_errors.iter().for_each(LogMsg::log);

        if let Err(ref errs) = self.validate() {
            validation::warn_validation_errors("Settings configuration file", errs);
        }
    }
}

/// Returns the number of maximum actix workers.
pub fn max_web_workers(settings: &Settings) -> usize {
    match settings.service.max_workers {
        Some(0) => {
            let num_cpu = common::cpu::get_num_cpus();
            std::cmp::max(1, num_cpu - 1)
        }
        Some(max_workers) => max_workers,
        None => settings.storage.performance.max_search_threads,
    }
}

#[derive(Clone, Debug)]
pub enum LogMsg {
    Warn(String),
    Error(String),
}

impl LogMsg {
    fn log(&self) {
        match self {
            Self::Warn(msg) => log::warn!("{msg}"),
            Self::Error(msg) => log::error!("{msg}"),
        }
    }
}

const fn default_telemetry_disabled() -> bool {
    false
}

const fn default_cors() -> bool {
    true
}

const fn default_http_keep_alive_timeout_sec() -> u64 {
    5
}

const fn default_http_client_request_timeout_sec() -> u64 {
    5
}

const fn default_max_snapshot_upload_size_mb() -> usize {
    1024
}

const fn default_http_client_disconnect_timeout_sec() -> u64 {
    5
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_GRPC_TIMEOUT.as_millis() as u64
}

const fn default_connection_timeout_ms() -> u64 {
    DEFAULT_CONNECT_TIMEOUT.as_millis() as u64
}

const fn default_tick_period_ms() -> u64 {
    100
}

// Should not be less than `DEFAULT_META_OP_WAIT` as bootstrapping perform sync. consensus meta operations.
const fn default_bootstrap_timeout_sec() -> u64 {
    15
}

const fn default_max_message_queue_size() -> usize {
    100
}

const fn default_connection_pool_size() -> usize {
    DEFAULT_POOL_SIZE
}

const fn default_message_timeout_tics() -> u64 {
    10
}

const fn default_compact_wal_entries() -> u64 {
    128
}

#[allow(clippy::unnecessary_wraps)] // Used as serde default
const fn default_tls_cert_ttl() -> Option<u64> {
    // Default one hour
    Some(3600)
}

/// Custom validation function for metrics prefixes.
fn validate_metrics_prefix(prefix: &str) -> Result<(), ValidationError> {
    // Prefix is not required
    if prefix.is_empty() {
        return Ok(());
    }

    // Only allow alphanumeric characters or '_'
    if !prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(
            ValidationError::new("invalid_metrics_prefix").with_message(Cow::Borrowed(
                "Metrics prefix must be of all alphanumeric characters, with an exception for '_'",
            )),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use fs_err as fs;
    use sealed_test::prelude::*;

    use super::*;

    /// Ensure we can successfully deserialize into [`Settings`] with just the default configuration.
    #[test]
    fn test_default_config() {
        let config = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .build()
            .expect("failed to build default config")
            .try_deserialize::<Settings>()
            .expect("failed to deserialize default config");

        assert_eq!(
            config.service.http_keep_alive_timeout_sec,
            default_http_keep_alive_timeout_sec()
        );
        assert_eq!(
            config.service.http_client_request_timeout_sec,
            default_http_client_request_timeout_sec()
        );
        assert_eq!(
            config.service.http_client_disconnect_timeout_sec,
            default_http_client_disconnect_timeout_sec()
        );
        assert!(!config.crypto.is_configured());

        config
            .validate()
            .expect("failed to validate default config");
    }

    #[test]
    fn service_config_debug_redacts_api_keys() {
        let mut config = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .build()
            .expect("failed to build default config")
            .try_deserialize::<Settings>()
            .expect("failed to deserialize default config");
        config.service.api_key = Some("qdrant-sec-api-key-sentinel".to_string());
        config.service.alt_api_key = Some("qdrant-sec-alt-api-key-sentinel".to_string());
        config.service.read_only_api_key = Some("qdrant-sec-read-only-key-sentinel".to_string());

        let service_debug = format!("{:?}", config.service);
        let settings_debug = format!("{config:?}");

        for rendered in [service_debug, settings_debug] {
            assert!(rendered.contains("[redacted]"));
            assert!(!rendered.contains("qdrant-sec-api-key-sentinel"));
            assert!(!rendered.contains("qdrant-sec-alt-api-key-sentinel"));
            assert!(!rendered.contains("qdrant-sec-read-only-key-sentinel"));
        }
    }

    #[test]
    fn tls_config_debug_redacts_key_paths() {
        let sentinel = "qdrant-sec-tls-debug-sentinel";
        let tls = TlsConfig {
            cert: format!("/tmp/{sentinel}/server.crt"),
            key: format!("/tmp/{sentinel}/server.key"),
            ca_cert: Some(format!("/tmp/{sentinel}/ca.crt")),
            cert_ttl: Some(3_600),
        };
        let mut settings = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .build()
            .expect("failed to build default config")
            .try_deserialize::<Settings>()
            .expect("failed to deserialize default config");
        settings.tls = Some(tls.clone());

        for rendered in [format!("{tls:?}"), format!("{settings:?}")] {
            assert!(rendered.contains("[redacted]"), "{rendered}");
            assert!(rendered.contains("cert_ttl"), "{rendered}");
            assert!(!rendered.contains("/tmp/"), "{rendered}");
            assert!(!rendered.contains("server.crt"), "{rendered}");
            assert!(!rendered.contains("server.key"), "{rendered}");
            assert!(!rendered.contains("ca.crt"), "{rendered}");
            assert!(!rendered.contains(sentinel), "{rendered}");
        }
    }

    #[test]
    fn crypto_backend_config_debug_redacts_program_and_pins() {
        let sentinel = "qdrant-sec-backend-debug-sentinel";
        let backend = CryptoBackendConfig {
            kind: "process_pool".to_string(),
            program: Some(format!("/tmp/{sentinel}/openfhe-bridge")),
            sha256_b64: Some(format!("sha256-{sentinel}")),
            signature_public_key_b64: Some(format!("public-key-{sentinel}")),
            signature_b64: Some(format!("signature-{sentinel}")),
            size: Some(2),
            timeout_ms: Some(5_000),
            max_output_bytes: None,
            landlock_read_allow_roots: Vec::new(),
        };
        let mut settings = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .build()
            .expect("failed to build default config")
            .try_deserialize::<Settings>()
            .expect("failed to deserialize default config");
        settings
            .crypto
            .backends
            .insert(format!("backend-{sentinel}"), backend.clone());

        for rendered in [format!("{backend:?}"), format!("{settings:?}")] {
            assert!(!rendered.contains("/tmp/"), "{rendered}");
            assert!(!rendered.contains("sha256-"), "{rendered}");
            assert!(!rendered.contains("public-key-"), "{rendered}");
            assert!(!rendered.contains("signature-"), "{rendered}");
            assert!(rendered.contains("[redacted]"), "{rendered}");
        }
    }

    #[test]
    fn crypto_material_config_debug_redacts_locators_and_material() {
        let sentinel = "qdrant-sec-material-debug-sentinel";
        let material = CryptoMaterialConfig {
            kind: "wrapped_symmetric_key_32".to_string(),
            source: Some(format!("source-{sentinel}")),
            env: Some(format!("ENV_{sentinel}")),
            path: Some(format!("/tmp/{sentinel}/material.key")),
            fd: Some(42),
            value_b64: Some(format!("value-{sentinel}")),
            vault_field: Some(format!("vault-field-{sentinel}")),
            expected_host: Some(format!("{sentinel}.example.com")),
            timeout_ms: Some(5_000),
            provider_key_version: Some(format!("provider-version-{sentinel}")),
            provider_attestation_id: Some(format!("provider-attestation-{sentinel}")),
            wrapped_by: Some(format!("wrapped-by-{sentinel}")),
            wrap_algorithm: Some("local_aes_gcm_siv".to_string()),
            nonce: Some(format!("nonce-{sentinel}")),
            wrapped_key_b64: Some(format!("wrapped-key-{sentinel}")),
            rk_epoch: Some(7),
            state: Some("active".to_string()),
            scope: Some(format!("scope-{sentinel}")),
        };
        let mut settings = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .build()
            .expect("failed to build default config")
            .try_deserialize::<Settings>()
            .expect("failed to deserialize default config");
        settings
            .crypto
            .materials
            .insert("docs_material".to_string(), material.clone());

        for rendered in [format!("{material:?}"), format!("{settings:?}")] {
            assert!(rendered.contains("wrapped_symmetric_key_32"), "{rendered}");
            assert!(rendered.contains("source_configured"), "{rendered}");
            assert!(rendered.contains("env_configured"), "{rendered}");
            assert!(rendered.contains("path_configured"), "{rendered}");
            assert!(rendered.contains("vault_field_configured"), "{rendered}");
            assert!(rendered.contains("expected_host_configured"), "{rendered}");
            assert!(rendered.contains("[redacted]"), "{rendered}");
            assert!(!rendered.contains("/tmp/"), "{rendered}");
            assert!(!rendered.contains("ENV_"), "{rendered}");
            assert!(!rendered.contains("source-"), "{rendered}");
            assert!(!rendered.contains("value-"), "{rendered}");
            assert!(!rendered.contains("vault-field-"), "{rendered}");
            assert!(!rendered.contains("provider-version-"), "{rendered}");
            assert!(!rendered.contains("provider-attestation-"), "{rendered}");
            assert!(!rendered.contains("wrapped-by-"), "{rendered}");
            assert!(!rendered.contains("nonce-"), "{rendered}");
            assert!(!rendered.contains("wrapped-key-"), "{rendered}");
            assert!(!rendered.contains("scope-"), "{rendered}");
            assert!(!rendered.contains(sentinel), "{rendered}");
        }
    }

    #[test]
    fn crypto_instance_config_debug_redacts_materials_backend_and_options() {
        let sentinel = "qdrant-sec-instance-debug-sentinel";
        let instance = CryptoInstanceConfig {
            provider: "vector/private-hnsw-oram@v1".to_string(),
            materials: HashMap::from([(
                "client_secret_material".to_string(),
                format!("material-ref-{sentinel}"),
            )]),
            backend_ref: Some(format!("backend-ref-{sentinel}")),
            options: serde_json::json!({
                "key_id": format!("tenant-a/{sentinel}"),
                "client_secret": format!("secret-option-{sentinel}"),
                "signature_public_keys": {
                    format!("signing-key-{sentinel}"): format!("public-key-{sentinel}")
                }
            }),
        };
        let mut settings = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .build()
            .expect("failed to build default config")
            .try_deserialize::<Settings>()
            .expect("failed to deserialize default config");
        settings
            .crypto
            .instances
            .insert("docs_private".to_string(), instance.clone());

        for rendered in [format!("{instance:?}"), format!("{settings:?}")] {
            assert!(
                rendered.contains("vector/private-hnsw-oram@v1"),
                "{rendered}"
            );
            assert!(rendered.contains("materials_count"), "{rendered}");
            assert!(rendered.contains("backend_ref_configured"), "{rendered}");
            assert!(rendered.contains("options_shape"), "{rendered}");
            assert!(!rendered.contains("client_secret_material"), "{rendered}");
            assert!(!rendered.contains("material-ref-"), "{rendered}");
            assert!(!rendered.contains("backend-ref-"), "{rendered}");
            assert!(!rendered.contains("client_secret"), "{rendered}");
            assert!(!rendered.contains("secret-option-"), "{rendered}");
            assert!(!rendered.contains("signature_public_keys"), "{rendered}");
            assert!(!rendered.contains("public-key-"), "{rendered}");
            assert!(!rendered.contains(sentinel), "{rendered}");
        }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "#[sealed_test] uses std::fs::copy"
    )]
    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test(files = ["config/config.yaml", "config/development.yaml"])]
    fn test_runtime_development_config() {
        unsafe { env::set_var("RUN_MODE", "development") };

        // `sealed_test` copies files into the same directory as the test runs in.
        // We need them in a subdirectory.
        fs::create_dir("config").expect("failed to create `config` subdirectory.");
        fs::copy("config.yaml", "config/config.yaml").expect("failed to copy `config.yaml`.");
        fs::copy("development.yaml", "config/development.yaml")
            .expect("failed to copy `development.yaml`.");

        // Read config
        let config = Settings::new(None).expect("failed to load development config at runtime");

        // Validate
        config
            .validate()
            .expect("failed to validate development config at runtime");
        assert!(config.load_errors.is_empty(), "must not have load errors")
    }

    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test]
    fn test_no_config_files() {
        let non_existing_config_path = "config/non_existing_config".to_string();

        // Read config
        let config = Settings::new(Some(non_existing_config_path))
            .expect("failed to load with non-existing runtime config");

        // Validate
        config
            .validate()
            .expect("failed to validate with non-existing runtime config");
        assert!(!config.load_errors.is_empty(), "must have load errors")
    }

    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test]
    fn test_custom_config() {
        let path = "config/custom.yaml";

        // Create custom config file
        {
            fs::create_dir("config").unwrap();
            let mut custom = fs::File::create(path).unwrap();
            write!(&mut custom, "service:\n    http_port: 9999").unwrap();
            custom.flush().unwrap();
        }

        // Load settings with custom config
        let config = Settings::new(Some(path.into())).unwrap();

        // Ensure our custom config is the most important
        assert_eq!(config.service.http_port, 9999);
        assert_eq!(
            config.service.http_keep_alive_timeout_sec,
            default_http_keep_alive_timeout_sec()
        );
        assert_eq!(
            config.service.http_client_request_timeout_sec,
            default_http_client_request_timeout_sec()
        );
        assert_eq!(
            config.service.http_client_disconnect_timeout_sec,
            default_http_client_disconnect_timeout_sec()
        );
        assert_eq!(
            config.service.max_snapshot_upload_size_mb,
            default_max_snapshot_upload_size_mb()
        );
        assert_eq!(
            config.crypto.ckks_grouped_max_candidates,
            default_ckks_grouped_max_candidates()
        );
        assert_eq!(
            config.crypto.ckks_scoring_source_batch_max,
            default_ckks_scoring_source_batch_max()
        );
        assert_eq!(
            config.crypto.ckks_query_nonce_replay_ttl_secs,
            default_ckks_query_nonce_replay_ttl_secs()
        );
        assert_eq!(
            config.crypto.ckks_query_nonce_replay_cache_max_entries,
            default_ckks_query_nonce_replay_cache_max_entries()
        );
        assert_eq!(config.crypto.zero_trust_profile, None);
    }

    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test]
    fn test_custom_http_transport_config() {
        let path = "config/custom_http_transport.yaml";

        {
            fs::create_dir("config").unwrap();
            let mut custom = fs::File::create(path).unwrap();
            write!(
                &mut custom,
                "service:\n    http_keep_alive_timeout_sec: 120\n    http_client_request_timeout_sec: 45\n    http_client_disconnect_timeout_sec: 60"
            )
            .unwrap();
            custom.flush().unwrap();
        }

        let config = Settings::new(Some(path.into())).unwrap();
        config
            .validate()
            .expect("custom HTTP transport timeouts must pass validation");

        assert_eq!(config.service.http_keep_alive_timeout_sec, 120);
        assert_eq!(config.service.http_client_request_timeout_sec, 45);
        assert_eq!(config.service.http_client_disconnect_timeout_sec, 60);
    }

    #[test]
    fn test_legacy_ckks_runtime_is_rejected() {
        let err = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .add_source(File::from_str(
                r#"
crypto:
  instances:
    docs_payload_v1:
      provider: payload/aes-256-gcm@v1
      materials:
        sym_key: tenant-a/payload-v1
  materials:
    tenant-a/payload-v1:
      kind: symmetric_key_32
      source: inline
      value_b64: AQID
ckks:
  enabled: true
"#,
                FileFormat::Yaml,
            ))
            .build()
            .expect("failed to build config")
            .try_deserialize::<Settings>()
            .expect_err("legacy ckks runtime settings must be rejected at parse time");
        assert!(err.to_string().contains("unknown field `ckks`"));
    }

    #[test]
    fn test_empty_legacy_ckks_runtime_section_is_rejected() {
        let err = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .add_source(File::from_str(
                r#"
ckks: {}
"#,
                FileFormat::Yaml,
            ))
            .build()
            .expect("failed to build config")
            .try_deserialize::<Settings>()
            .expect_err("legacy ckks runtime section presence must be rejected at parse time");
        assert!(err.to_string().contains("unknown field `ckks`"));
    }

    #[test]
    fn test_legacy_ckks_collection_runtime_is_rejected() {
        let secret = "legacy-secret-material-must-not-leak";
        let err = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .add_source(File::from_str(
                &format!(
                    r#"
ckks:
  collections:
    docs:
      master_key_b64: {secret}
"#
                ),
                FileFormat::Yaml,
            ))
            .build()
            .expect("failed to build config")
            .try_deserialize::<Settings>()
            .expect_err("legacy ckks collection runtime settings must be rejected at parse time");
        let err = err.to_string();
        assert!(err.contains("unknown field `ckks`"));
        assert!(
            !err.contains(secret),
            "legacy parse errors must not leak inline key material"
        );
    }

    #[test]
    fn test_inline_key_material_defaults_to_disabled() {
        assert!(!CryptoSettings::default().allow_inline_key_material);
    }

    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test]
    fn test_invalid_http_transport_config() {
        let path = "config/invalid_http_transport.yaml";

        {
            fs::create_dir("config").unwrap();
            let mut custom = fs::File::create(path).unwrap();
            write!(
                &mut custom,
                "service:\n    http_keep_alive_timeout_sec: 0\n    http_client_request_timeout_sec: 0\n    http_client_disconnect_timeout_sec: 0"
            )
            .unwrap();
            custom.flush().unwrap();
        }

        let config = Settings::new(Some(path.into())).unwrap();
        assert!(
            config.validate().is_err(),
            "zero timeout values must fail validation"
        );
    }
}
