use std::path::Path;

use chrono::{DateTime, SubsecRound, Utc};
use common::flags::FeatureFlags;
use common::types::{DetailsLevel, TelemetryDetail};
use schemars::JsonSchema;
use segment::common::anonymize::Anonymize;
use segment::types::HnswGlobalConfig;
use serde::Serialize;

use crate::common::crypto::crypto_runtime_capability_fingerprint;
use crate::settings::Settings;

pub struct AppBuildTelemetryCollector {
    pub startup: DateTime<Utc>,
}

impl AppBuildTelemetryCollector {
    pub fn new() -> Self {
        AppBuildTelemetryCollector {
            startup: Utc::now().round_subsecs(2),
        }
    }
}

#[derive(Serialize, Clone, Debug, JsonSchema, Anonymize)]
pub struct AppFeaturesTelemetry {
    pub debug: bool,
    pub service_debug_feature: bool,
    pub recovery_mode: bool,
    pub gpu: bool,
    pub rocksdb: bool,
    pub staging: bool,
}

#[derive(Serialize, Clone, Debug, JsonSchema, Anonymize)]
pub struct RunningEnvironmentTelemetry {
    #[anonymize(false)]
    distribution: Option<String>,
    #[anonymize(false)]
    distribution_version: Option<String>,
    is_docker: bool,
    #[anonymize(false)]
    cores: Option<usize>,
    ram_size: Option<usize>,
    disk_size: Option<usize>,
    #[anonymize(false)]
    cpu_flags: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_endian: Option<CpuEndian>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gpu_devices: Option<Vec<GpuDeviceTelemetry>>,
}

#[derive(Serialize, Clone, Debug, JsonSchema, Anonymize)]
pub struct AppBuildTelemetry {
    #[anonymize(false)]
    pub name: String,
    #[anonymize(false)]
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<AppFeaturesTelemetry>,
    #[anonymize(value = None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_features: Option<FeatureFlags>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hnsw_global_config: Option<HnswGlobalConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<RunningEnvironmentTelemetry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_rbac: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide_jwt_dashboard: Option<bool>,
    #[anonymize(value = None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_runtime_capability_fingerprint: Option<String>,
    pub startup: DateTime<Utc>,
}

impl AppBuildTelemetry {
    pub fn collect(
        detail: TelemetryDetail,
        collector: &AppBuildTelemetryCollector,
        settings: &Settings,
    ) -> Self {
        let fingerprint = Self::wants_crypto_runtime_capability_fingerprint(detail, settings)
            .then(|| crypto_runtime_capability_fingerprint(settings));
        Self::collect_with_crypto_fingerprint(detail, collector, settings, fingerprint)
    }

    /// Whether `collect` reports the crypto runtime capability fingerprint. Computing it may
    /// unwrap resource keys through external key services, so async callers compute it on the
    /// blocking pool and pass it to [`Self::collect_with_crypto_fingerprint`].
    pub fn wants_crypto_runtime_capability_fingerprint(
        detail: TelemetryDetail,
        settings: &Settings,
    ) -> bool {
        detail.level >= DetailsLevel::Level1 && settings.crypto.is_configured()
    }

    pub fn collect_with_crypto_fingerprint(
        detail: TelemetryDetail,
        collector: &AppBuildTelemetryCollector,
        settings: &Settings,
        crypto_runtime_capability_fingerprint: Option<String>,
    ) -> Self {
        AppBuildTelemetry {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            features: (detail.level >= DetailsLevel::Level1).then(|| AppFeaturesTelemetry {
                debug: cfg!(debug_assertions),
                service_debug_feature: cfg!(feature = "service_debug"),
                recovery_mode: settings.storage.recovery_mode.is_some(),
                gpu: cfg!(feature = "gpu"),
                rocksdb: cfg!(feature = "rocksdb"),
                staging: cfg!(feature = "staging"),
            }),
            runtime_features: (detail.level >= DetailsLevel::Level1)
                .then(common::flags::feature_flags),
            hnsw_global_config: (detail.level >= DetailsLevel::Level1)
                .then(|| settings.storage.hnsw_global_config.clone()),
            system: (detail.level >= DetailsLevel::Level1).then(get_system_data),
            jwt_rbac: settings.service.jwt_rbac,
            hide_jwt_dashboard: settings.service.hide_jwt_dashboard,
            crypto_runtime_capability_fingerprint: crypto_runtime_capability_fingerprint
                .filter(|_| Self::wants_crypto_runtime_capability_fingerprint(detail, settings)),
            startup: collector.startup,
        }
    }
}

fn get_system_data() -> RunningEnvironmentTelemetry {
    let distribution = if let Ok(release) = sys_info::linux_os_release() {
        release.id
    } else {
        sys_info::os_type().ok()
    };
    let distribution_version = if let Ok(release) = sys_info::linux_os_release() {
        release.version_id
    } else {
        sys_info::os_release().ok()
    };
    let mut cpu_flags = vec![];
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::arch::is_x86_feature_detected!("sse") {
            cpu_flags.push("sse");
        }
        if std::arch::is_x86_feature_detected!("sse2") {
            cpu_flags.push("sse2");
        }
        if std::arch::is_x86_feature_detected!("avx") {
            cpu_flags.push("avx");
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            cpu_flags.push("avx2");
        }
        if std::arch::is_x86_feature_detected!("fma") {
            cpu_flags.push("fma");
        }
        if std::arch::is_x86_feature_detected!("f16c") {
            cpu_flags.push("f16c");
        }
        if std::arch::is_x86_feature_detected!("avx512f") {
            cpu_flags.push("avx512f");
        }
        if std::arch::is_x86_feature_detected!("avx512vl") {
            cpu_flags.push("avx512vl");
        }
        if std::arch::is_x86_feature_detected!("avx512vpopcntdq") {
            cpu_flags.push("avx512vpopcntdq");
        }
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            cpu_flags.push("neon");
        }
        if std::arch::is_aarch64_feature_detected!("fp16") {
            cpu_flags.push("fp16");
        }
    }

    #[cfg(feature = "gpu")]
    let gpu_devices = segment::index::hnsw_index::gpu::GPU_DEVICES_MANAGER
        .read()
        .as_ref()
        .map(|gpu_devices_manager| {
            gpu_devices_manager
                .all_found_device_names()
                .iter()
                .map(|name| GpuDeviceTelemetry { name: name.clone() })
                .collect::<Vec<_>>()
        });

    #[cfg(not(feature = "gpu"))]
    let gpu_devices = None;

    RunningEnvironmentTelemetry {
        distribution,
        distribution_version,
        is_docker: cfg!(unix) && Path::new("/.dockerenv").exists(),
        cores: sys_info::cpu_num().ok().map(|x| x as usize),
        ram_size: sys_info::mem_info().ok().map(|x| x.total as usize),
        disk_size: sys_info::disk_info().ok().map(|x| x.total as usize),
        cpu_flags: cpu_flags.join(","),
        cpu_endian: Some(CpuEndian::current()),
        gpu_devices,
    }
}

#[derive(Serialize, Clone, Copy, Debug, JsonSchema, Anonymize)]
#[serde(rename_all = "snake_case")]
pub enum CpuEndian {
    Little,
    Big,
    Other,
}

impl CpuEndian {
    /// Get the current used byte order
    pub const fn current() -> Self {
        if cfg!(target_endian = "little") {
            CpuEndian::Little
        } else if cfg!(target_endian = "big") {
            CpuEndian::Big
        } else {
            CpuEndian::Other
        }
    }
}

#[derive(Serialize, Clone, Debug, JsonSchema, Anonymize)]
pub struct GpuDeviceTelemetry {
    #[anonymize(false)]
    pub name: String,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;
    use crate::settings::{CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings};

    #[test]
    fn app_telemetry_includes_crypto_runtime_capability_fingerprint() {
        let settings = Settings {
            crypto: CryptoSettings {
                zero_trust_profile: None,
                ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
                ckks_scoring_source_batch_max:
                    crate::settings::default_ckks_scoring_source_batch_max(),
                ckks_query_nonce_replay_ttl_secs:
                    crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
                ckks_query_nonce_replay_cache_max_entries:
                    crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "payload/aes-256-gcm@v1".to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            "tenant-a/payload-rk-v1".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/payload@v1",
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let collector = AppBuildTelemetryCollector::new();

        let telemetry = AppBuildTelemetry::collect(
            TelemetryDetail::new(DetailsLevel::Level1, false),
            &collector,
            &settings,
        );
        assert_eq!(
            telemetry.crypto_runtime_capability_fingerprint.as_deref(),
            Some(crypto_runtime_capability_fingerprint(&settings).as_str()),
        );

        let low_detail = AppBuildTelemetry::collect(
            TelemetryDetail::new(DetailsLevel::Level0, false),
            &collector,
            &settings,
        );
        assert!(low_detail.crypto_runtime_capability_fingerprint.is_none());

        let anonymized = telemetry.anonymize();
        assert!(anonymized.crypto_runtime_capability_fingerprint.is_none());
    }

    #[test]
    fn app_telemetry_does_not_serialize_crypto_key_material() {
        let inline_secret = "qdrant-sec-telemetry-inline-key-sentinel";
        let wrapped_secret = "qdrant-sec-telemetry-wrapped-key-sentinel";
        let signature_public_key = "qdrant-sec-telemetry-signature-public-key-sentinel";
        let private_hnsw_signature_public_key =
            "qdrant-sec-telemetry-private-hnsw-signature-public-key-sentinel";
        let private_hnsw_key_id = "qdrant-sec-telemetry-private-hnsw-key-id-sentinel";
        let private_hnsw_instance_id = "qdrant-sec-telemetry-private-hnsw-instance-id-sentinel";
        let private_hnsw_signing_key_id =
            "qdrant-sec-telemetry-private-hnsw-signing-key-id-sentinel";
        let private_result_signature_public_key =
            "qdrant-sec-telemetry-private-result-signature-public-key-sentinel";
        let private_result_key_id = "qdrant-sec-telemetry-private-result-key-id-sentinel";
        let private_result_instance_id = "qdrant-sec-telemetry-private-result-instance-id-sentinel";
        let private_result_signing_key_id =
            "qdrant-sec-telemetry-private-result-signing-key-id-sentinel";
        let mut settings = Settings {
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
                        "docs_payload_client_v1".to_string(),
                        CryptoInstanceConfig {
                            provider: "payload/client-aead@v1".to_string(),
                            materials: HashMap::new(),
                            backend_ref: None,
                            options: json!({
                                "key_id": "tenant-a/client-rk-v1",
                                "key_id_required": true,
                                "expected_rk_id": "tenant-a/client-rk-v1",
                                "min_rk_epoch": 3,
                                "max_rk_epoch": 3,
                                "signature_public_key_b64": signature_public_key,
                                "signature_key_id": "tenant-a/client-signing-v1",
                            }),
                        },
                    ),
                    (
                        private_hnsw_instance_id.to_string(),
                        CryptoInstanceConfig {
                            provider: "vector/private-hnsw-oram@v1".to_string(),
                            materials: HashMap::new(),
                            backend_ref: None,
                            options: json!({
                                "key_id": private_hnsw_key_id,
                                "expected_rk_id": private_hnsw_key_id,
                                "min_rk_epoch": 7,
                                "max_rk_epoch": 7,
                                "search_execution": "client_led",
                                "search_mode": "private_hnsw_oram",
                                "result_privacy": "ids_visible",
                                "distance": "cosine",
                                "dim": 1536,
                                "hnsw": {
                                    "m": 32,
                                    "ef_construction": 128,
                                    "max_layers": 16,
                                    "fixed_neighbor_slots": 64,
                                },
                                "oram": {
                                    "kind": "path_oram",
                                    "bucket_size": 4,
                                    "block_size_bytes": 8192,
                                    "tree_height": 24,
                                    "path_batch_size": 8,
                                },
                                "fixed_budget": {
                                    "enabled": true,
                                    "upper_layer_steps": 32,
                                    "base_layer_steps": 256,
                                    "paths_per_round": 8,
                                    "fixed_result_k": 10,
                                },
                                "integrity": {
                                    "manifest_signature_required": true,
                                    "commit_signature_required": true,
                                    "merkle_root_required": true,
                                },
                                "signature_public_keys": {
                                    "qdrant-sec-telemetry-private-hnsw-signing-key-id-sentinel": private_hnsw_signature_public_key,
                                },
                            }),
                        },
                    ),
                    (
                        private_result_instance_id.to_string(),
                        CryptoInstanceConfig {
                            provider: "payload/private-result-oram@v1".to_string(),
                            materials: HashMap::new(),
                            backend_ref: None,
                            options: json!({
                                "key_id": private_result_key_id,
                                "expected_rk_id": private_result_key_id,
                                "min_rk_epoch": 7,
                                "max_rk_epoch": 7,
                                "result_privacy": "private_payload_oram_required",
                                "oram": {
                                    "kind": "path_oram",
                                    "bucket_size": 4,
                                    "block_size_bytes": 8192,
                                    "tree_height": 24,
                                    "path_batch_size": 8,
                                },
                                "integrity": {
                                    "manifest_signature_required": true,
                                    "commit_signature_required": true,
                                    "merkle_root_required": true,
                                },
                                "signature_public_keys": {
                                    "qdrant-sec-telemetry-private-result-signing-key-id-sentinel": private_result_signature_public_key,
                                },
                            }),
                        },
                    ),
                ]),
                materials: HashMap::from([(
                    "tenant-a/payload-rk-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: "wrapped_symmetric_key_32".to_string(),
                        wrapped_by: Some("tenant-a/mk-v1".to_string()),
                        wrap_algorithm: Some("AES-256-GCM".to_string()),
                        nonce: Some("qdrant-sec-telemetry-nonce-sentinel".to_string()),
                        wrapped_key_b64: Some(wrapped_secret.to_string()),
                        value_b64: Some(inline_secret.to_string()),
                        rk_epoch: Some(3),
                        scope: Some("collection:docs".to_string()),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        };
        settings.crypto.allow_inline_key_material = true;
        let collector = AppBuildTelemetryCollector::new();

        let telemetry = AppBuildTelemetry::collect(
            TelemetryDetail::new(DetailsLevel::Level1, false),
            &collector,
            &settings,
        );
        let serialized = serde_json::to_string(&telemetry).unwrap();
        let anonymized = telemetry.anonymize();
        let anonymized_serialized = serde_json::to_string(&anonymized).unwrap();

        assert!(telemetry.crypto_runtime_capability_fingerprint.is_some());
        assert!(anonymized.crypto_runtime_capability_fingerprint.is_none());
        for sentinel in [
            inline_secret,
            wrapped_secret,
            signature_public_key,
            private_hnsw_instance_id,
            private_hnsw_signature_public_key,
            private_hnsw_key_id,
            private_hnsw_signing_key_id,
            private_result_instance_id,
            private_result_signature_public_key,
            private_result_key_id,
            private_result_signing_key_id,
        ] {
            assert!(
                !serialized.contains(sentinel),
                "app telemetry leaked crypto material sentinel {sentinel}",
            );
            assert!(
                !anonymized_serialized.contains(sentinel),
                "anonymized app telemetry leaked crypto material sentinel {sentinel}",
            );
        }
    }
}
