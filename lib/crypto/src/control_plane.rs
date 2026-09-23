use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::aead::{bounded_untrusted_text, validate_key_id};

pub const GENERIC_CIPHERTEXT_MARKER: &str = "$qdrant_ciphertext";
pub const PAYLOAD_AES_GCM_PROVIDER: &str = "payload/aes-256-gcm@v1";
pub const PAYLOAD_CLIENT_AEAD_PROVIDER: &str = "payload/client-aead@v1";
pub const PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER: &str = "payload/private-result-oram@v1";
pub const VECTOR_OPENFHE_CKKS_PROVIDER: &str = "vector/openfhe-ckks@v1";
pub const VECTOR_CLIENT_CKKS_PROVIDER: &str = "vector/client-ckks@v1";
pub const VECTOR_PRIVATE_HNSW_ORAM_PROVIDER: &str = "vector/private-hnsw-oram@v1";
pub const METADATA_AES_GCM_PROVIDER: &str = "metadata/aes-256-gcm@v1";
pub const METADATA_BLIND_INDEX_PROVIDER: &str = "metadata/blind-index-hmac@v1";
pub const PAYLOAD_FIELD_BINDING: &str = "payload-field/v1";
pub const CLIENT_PAYLOAD_ENVELOPE_BINDING: &str = "client-payload-envelope/v1";
pub const PRIVATE_RESULT_ORAM_BINDING: &str = "private-result-oram/v1";
pub const VECTOR_ENVELOPE_BINDING: &str = "vector-envelope/v1";
pub const PRIVATE_HNSW_ORAM_BINDING: &str = "private-hnsw-oram/v1";
pub const METADATA_VALUE_BINDING: &str = "metadata-value/v1";
pub const METADATA_EXACT_MATCH_TOKEN_BINDING: &str = "metadata-exact-match-token/v1";

#[derive(Error, PartialEq, Eq)]
pub enum ControlPlaneError {
    #[error("crypto identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("envelope key id is invalid: {0}")]
    InvalidEnvelopeKeyId(String),
    #[error("ciphertext envelope body must not be empty")]
    InvalidEnvelopeBody,
    #[error("ciphertext envelope version must be at least 1")]
    InvalidEnvelopeVersion,
    #[error("stored ciphertext envelope is malformed")]
    MalformedEnvelope,
}

impl Debug for ControlPlaneError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(_) => f
                .debug_tuple("InvalidIdentifier")
                .field(&"[redacted]")
                .finish(),
            Self::InvalidEnvelopeKeyId(_) => f
                .debug_tuple("InvalidEnvelopeKeyId")
                .field(&"[redacted]")
                .finish(),
            Self::InvalidEnvelopeBody => f.write_str("InvalidEnvelopeBody"),
            Self::InvalidEnvelopeVersion => f.write_str("InvalidEnvelopeVersion"),
            Self::MalformedEnvelope => f.write_str("MalformedEnvelope"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoCapability {
    PayloadValue,
    VectorCiphertext,
    MetadataValue,
    MetadataExactMatchToken,
}

impl CryptoCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PayloadValue => "payload_value",
            Self::VectorCiphertext => "vector_ciphertext",
            Self::MetadataValue => "metadata_value",
            Self::MetadataExactMatchToken => "metadata_exact_match_token",
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct CiphertextEnvelope {
    pub version: u16,
    pub capability: CryptoCapability,
    pub provider: String,
    pub instance_fingerprint: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub headers: Map<String, Value>,
    pub body: String,
}

impl fmt::Debug for CiphertextEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CiphertextEnvelope")
            .field("version", &self.version)
            .field("capability", &self.capability)
            .field("provider", &self.provider)
            .field("instance_fingerprint", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("binding", &self.binding)
            .field("header_count", &self.headers.len())
            .field("body_len", &"[redacted]")
            .finish()
    }
}

impl CiphertextEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u16,
        capability: CryptoCapability,
        provider: impl Into<String>,
        instance_fingerprint: impl Into<String>,
        key_id: impl Into<String>,
        binding: Option<String>,
        headers: Map<String, Value>,
        body: impl Into<String>,
    ) -> Result<Self, ControlPlaneError> {
        let provider = provider.into();
        let instance_fingerprint = instance_fingerprint.into();
        let key_id = key_id.into();
        let body = body.into();

        validate_envelope_fields(
            version,
            &provider,
            &instance_fingerprint,
            &key_id,
            binding.as_deref(),
            &body,
        )?;

        Ok(Self {
            version,
            capability,
            provider,
            instance_fingerprint,
            key_id,
            binding,
            headers,
            body,
        })
    }

    pub fn to_stored_value(&self) -> Value {
        let mut serialized = Map::from_iter([
            (
                "version".to_string(),
                Value::Number(serde_json::Number::from(self.version)),
            ),
            (
                "capability".to_string(),
                Value::String(self.capability.as_str().to_string()),
            ),
            ("provider".to_string(), Value::String(self.provider.clone())),
            (
                "instance_fingerprint".to_string(),
                Value::String(self.instance_fingerprint.clone()),
            ),
            ("key_id".to_string(), Value::String(self.key_id.clone())),
            ("body".to_string(), Value::String(self.body.clone())),
        ]);
        if let Some(binding) = &self.binding {
            serialized.insert("binding".to_string(), Value::String(binding.clone()));
        }
        if !self.headers.is_empty() {
            serialized.insert("headers".to_string(), Value::Object(self.headers.clone()));
        }

        Value::Object(Map::from_iter([(
            GENERIC_CIPHERTEXT_MARKER.to_string(),
            Value::Object(serialized),
        )]))
    }

    pub fn from_stored_value(value: &Value) -> Result<Option<Self>, ControlPlaneError> {
        let Value::Object(object) = value else {
            return Ok(None);
        };
        let Some(stored) = object.get(GENERIC_CIPHERTEXT_MARKER) else {
            return Ok(None);
        };
        if object.len() != 1 {
            return Err(ControlPlaneError::MalformedEnvelope);
        }

        let envelope: Self = serde_json::from_value(stored.clone())
            .map_err(|_| ControlPlaneError::MalformedEnvelope)?;
        validate_envelope_fields(
            envelope.version,
            &envelope.provider,
            &envelope.instance_fingerprint,
            &envelope.key_id,
            envelope.binding.as_deref(),
            &envelope.body,
        )?;

        Ok(Some(envelope))
    }
}

fn validate_envelope_fields(
    version: u16,
    provider: &str,
    instance_fingerprint: &str,
    key_id: &str,
    binding: Option<&str>,
    body: &str,
) -> Result<(), ControlPlaneError> {
    if version == 0 {
        return Err(ControlPlaneError::InvalidEnvelopeVersion);
    }
    validate_identifier(provider)?;
    validate_identifier(instance_fingerprint)?;
    validate_key_id(key_id)
        .map_err(|_| ControlPlaneError::InvalidEnvelopeKeyId(bounded_untrusted_text(key_id)))?;
    if let Some(binding) = binding {
        validate_identifier(binding)?;
    }
    if body.is_empty() {
        return Err(ControlPlaneError::InvalidEnvelopeBody);
    }

    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct CryptoRegistry {
    payload_provider_ids: BTreeSet<String>,
    vector_provider_ids: BTreeSet<String>,
    metadata_provider_ids: BTreeSet<String>,
}

impl CryptoRegistry {
    pub fn register_payload_provider(&mut self, provider_id: impl Into<String>) {
        self.payload_provider_ids.insert(provider_id.into());
    }

    pub fn register_vector_provider(&mut self, provider_id: impl Into<String>) {
        self.vector_provider_ids.insert(provider_id.into());
    }

    pub fn register_metadata_provider(&mut self, provider_id: impl Into<String>) {
        self.metadata_provider_ids.insert(provider_id.into());
    }

    pub fn payload_provider_ids(&self) -> impl Iterator<Item = &str> {
        self.payload_provider_ids.iter().map(String::as_str)
    }

    pub fn vector_provider_ids(&self) -> impl Iterator<Item = &str> {
        self.vector_provider_ids.iter().map(String::as_str)
    }

    pub fn metadata_provider_ids(&self) -> impl Iterator<Item = &str> {
        self.metadata_provider_ids.iter().map(String::as_str)
    }
}

pub trait CryptoSuite {
    fn register(&self, registry: &mut CryptoRegistry);
}

pub trait PayloadProviderFactory: Send + Sync {
    fn provider_id(&self) -> &'static str;
}

pub trait VectorProviderFactory: Send + Sync {
    fn provider_id(&self) -> &'static str;
}

pub trait MetadataProviderFactory: Send + Sync {
    fn provider_id(&self) -> &'static str;
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompiledPayloadRule {
    pub rule_id: String,
    pub instance: String,
    pub provider: String,
    pub binding: Option<String>,
}

impl fmt::Debug for CompiledPayloadRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledPayloadRule")
            .field("rule_id", &"[redacted]")
            .field("instance", &"[redacted]")
            .field("provider", &self.provider)
            .field("binding", &self.binding)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompiledVectorRule {
    pub rule_id: String,
    pub vector_name: String,
    pub instance: String,
    pub provider: String,
    pub binding: Option<String>,
}

impl fmt::Debug for CompiledVectorRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledVectorRule")
            .field("rule_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("instance", &"[redacted]")
            .field("provider", &self.provider)
            .field("binding", &self.binding)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompiledMetadataRule {
    pub rule_id: String,
    pub key: String,
    pub instance: String,
    pub provider: String,
    pub binding: Option<String>,
}

impl fmt::Debug for CompiledMetadataRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledMetadataRule")
            .field("rule_id", &"[redacted]")
            .field("key", &"[redacted]")
            .field("instance", &"[redacted]")
            .field("provider", &self.provider)
            .field("binding", &self.binding)
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct CompiledCollectionCryptoPlan {
    payload_rules: Vec<CompiledPayloadRule>,
    vector_rules: BTreeMap<String, CompiledVectorRule>,
    metadata_rules: Vec<CompiledMetadataRule>,
}

impl fmt::Debug for CompiledCollectionCryptoPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledCollectionCryptoPlan")
            .field("payload_rule_count", &"[redacted]")
            .field("vector_rule_count", &"[redacted]")
            .field("metadata_rule_count", &"[redacted]")
            .finish()
    }
}

impl CompiledCollectionCryptoPlan {
    pub fn add_payload_rule(&mut self, rule: CompiledPayloadRule) {
        self.payload_rules.push(rule);
    }

    pub fn add_vector_rule(&mut self, rule: CompiledVectorRule) {
        self.vector_rules.insert(rule.vector_name.clone(), rule);
    }

    pub fn add_metadata_rule(&mut self, rule: CompiledMetadataRule) {
        self.metadata_rules.push(rule);
    }

    pub fn payload_rules(&self) -> &[CompiledPayloadRule] {
        &self.payload_rules
    }

    pub fn vector_rule(&self, vector_name: &str) -> Option<&CompiledVectorRule> {
        self.vector_rules.get(vector_name)
    }

    pub fn metadata_rules(&self) -> &[CompiledMetadataRule] {
        &self.metadata_rules
    }
}

fn validate_identifier(value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty()
        || value.len() > 255
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(ControlPlaneError::InvalidIdentifier(
            bounded_untrusted_text(value),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BasicSuite;

    impl CryptoSuite for BasicSuite {
        fn register(&self, registry: &mut CryptoRegistry) {
            registry.register_payload_provider(PAYLOAD_AES_GCM_PROVIDER);
            registry.register_payload_provider(PAYLOAD_CLIENT_AEAD_PROVIDER);
            registry.register_payload_provider(PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER);
            registry.register_vector_provider(VECTOR_OPENFHE_CKKS_PROVIDER);
            registry.register_vector_provider(VECTOR_CLIENT_CKKS_PROVIDER);
            registry.register_vector_provider(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER);
            registry.register_metadata_provider(METADATA_AES_GCM_PROVIDER);
            registry.register_metadata_provider(METADATA_BLIND_INDEX_PROVIDER);
        }
    }

    #[test]
    fn ciphertext_envelope_round_trips_and_rejects_marker_bypass() {
        let envelope = CiphertextEnvelope::new(
            1,
            CryptoCapability::PayloadValue,
            PAYLOAD_AES_GCM_PROVIDER,
            "sha256:test",
            "tenant-a:payload:v1",
            Some(PAYLOAD_FIELD_BINDING.to_string()),
            Map::from_iter([("field".to_string(), Value::String("body".to_string()))]),
            "AQID",
        )
        .unwrap();

        let stored = envelope.to_stored_value();
        assert_eq!(
            CiphertextEnvelope::from_stored_value(&stored).unwrap(),
            Some(envelope.clone()),
        );

        let bypass = Value::Object(Map::from_iter([
            (
                GENERIC_CIPHERTEXT_MARKER.to_string(),
                serde_json::to_value(&envelope).unwrap(),
            ),
            (
                "plaintext".to_string(),
                Value::String("still here".to_string()),
            ),
        ]));
        assert_eq!(
            CiphertextEnvelope::from_stored_value(&bypass),
            Err(ControlPlaneError::MalformedEnvelope),
        );
    }

    #[test]
    fn ciphertext_envelope_distinguishes_provider_ids_from_key_ids() {
        assert!(
            CiphertextEnvelope::new(
                1,
                CryptoCapability::PayloadValue,
                PAYLOAD_AES_GCM_PROVIDER,
                "sha256:test",
                "tenant-a/payload@v1",
                Some(PAYLOAD_FIELD_BINDING.to_string()),
                Map::new(),
                "AQID",
            )
            .is_err_and(|err| matches!(err, ControlPlaneError::InvalidEnvelopeKeyId(_)))
        );

        assert!(
            CiphertextEnvelope::new(
                1,
                CryptoCapability::PayloadValue,
                PAYLOAD_AES_GCM_PROVIDER,
                "sha256:test",
                "tenant-a:payload-v1",
                Some(PAYLOAD_FIELD_BINDING.to_string()),
                Map::new(),
                "AQID",
            )
            .is_ok()
        );
    }

    #[test]
    fn control_plane_error_debug_redacts_identifier_values() {
        let sentinel = "control-plane-debug-sentinel";
        let errors = [
            ControlPlaneError::InvalidIdentifier(format!("provider {sentinel}")),
            ControlPlaneError::InvalidEnvelopeKeyId(format!("tenant-a/{sentinel}@v1")),
        ];

        for error in errors {
            let rendered = format!("{error:?}");
            assert!(!rendered.contains(sentinel), "{rendered}");
            assert!(rendered.contains("[redacted]"), "{rendered}");
        }
    }

    #[test]
    fn ciphertext_envelope_debug_redacts_body_and_identifiers() {
        let sentinel = "ciphertext-envelope-debug-sentinel";
        let envelope = CiphertextEnvelope::new(
            1,
            CryptoCapability::PayloadValue,
            PAYLOAD_AES_GCM_PROVIDER,
            format!("sha256:{sentinel}"),
            format!("tenant-a:{sentinel}"),
            Some(PAYLOAD_FIELD_BINDING.to_string()),
            Map::from_iter([(
                "field".to_string(),
                Value::String(format!("header-{sentinel}")),
            )]),
            format!("body-{sentinel}"),
        )
        .unwrap();
        let rendered = format!("{envelope:?}");

        assert!(rendered.contains("PayloadValue"), "{rendered}");
        assert!(rendered.contains("header_count"), "{rendered}");
        assert!(rendered.contains("body_len"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(!rendered.contains("sha256:"), "{rendered}");
        assert!(!rendered.contains("tenant-a:"), "{rendered}");
        assert!(!rendered.contains("header-"), "{rendered}");
        assert!(!rendered.contains("body-"), "{rendered}");
        assert!(!rendered.contains(sentinel), "{rendered}");
    }

    #[test]
    fn compiled_crypto_plan_debug_redacts_rule_selectors_and_instances() {
        let sentinel = "compiled-plan-debug-sentinel";
        let payload_rule = CompiledPayloadRule {
            rule_id: format!("payload-rule-{sentinel}"),
            instance: format!("payload-instance-{sentinel}"),
            provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
            binding: Some(PAYLOAD_FIELD_BINDING.to_string()),
        };
        let vector_rule = CompiledVectorRule {
            rule_id: format!("vector-rule-{sentinel}"),
            vector_name: format!("vector-name-{sentinel}"),
            instance: format!("vector-instance-{sentinel}"),
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
        };
        let metadata_rule = CompiledMetadataRule {
            rule_id: format!("metadata-rule-{sentinel}"),
            key: format!("metadata-key-{sentinel}"),
            instance: format!("metadata-instance-{sentinel}"),
            provider: METADATA_BLIND_INDEX_PROVIDER.to_string(),
            binding: Some(METADATA_EXACT_MATCH_TOKEN_BINDING.to_string()),
        };
        let mut plan = CompiledCollectionCryptoPlan::default();
        plan.add_payload_rule(payload_rule.clone());
        plan.add_vector_rule(vector_rule.clone());
        plan.add_metadata_rule(metadata_rule.clone());

        for rendered in [
            format!("{payload_rule:?}"),
            format!("{vector_rule:?}"),
            format!("{metadata_rule:?}"),
            format!("{plan:?}"),
        ] {
            assert!(rendered.contains("[redacted]"), "{rendered}");
            assert!(!rendered.contains("payload-rule-"), "{rendered}");
            assert!(!rendered.contains("payload-instance-"), "{rendered}");
            assert!(!rendered.contains("vector-rule-"), "{rendered}");
            assert!(!rendered.contains("vector-name-"), "{rendered}");
            assert!(!rendered.contains("vector-instance-"), "{rendered}");
            assert!(!rendered.contains("metadata-rule-"), "{rendered}");
            assert!(!rendered.contains("metadata-key-"), "{rendered}");
            assert!(!rendered.contains("metadata-instance-"), "{rendered}");
            assert!(!rendered.contains(sentinel), "{rendered}");
        }
    }

    #[test]
    fn ciphertext_envelope_validates_stored_fields_on_parse() {
        let envelope = CiphertextEnvelope::new(
            1,
            CryptoCapability::PayloadValue,
            PAYLOAD_AES_GCM_PROVIDER,
            "sha256:test",
            "tenant-a:payload-v1",
            Some(PAYLOAD_FIELD_BINDING.to_string()),
            Map::new(),
            "AQID",
        )
        .unwrap();

        let mut invalid_key_id = envelope.to_stored_value();
        invalid_key_id
            .as_object_mut()
            .unwrap()
            .get_mut(GENERIC_CIPHERTEXT_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "key_id".to_string(),
                Value::String("tenant-a/payload@v1".to_string()),
            );
        assert!(matches!(
            CiphertextEnvelope::from_stored_value(&invalid_key_id),
            Err(ControlPlaneError::InvalidEnvelopeKeyId(_))
        ));

        let mut invalid_provider = envelope.to_stored_value();
        invalid_provider
            .as_object_mut()
            .unwrap()
            .get_mut(GENERIC_CIPHERTEXT_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "provider".to_string(),
                Value::String("payload aes gcm".to_string()),
            );
        assert!(matches!(
            CiphertextEnvelope::from_stored_value(&invalid_provider),
            Err(ControlPlaneError::InvalidIdentifier(provider)) if provider == "payload aes gcm"
        ));

        let mut empty_body = envelope.to_stored_value();
        empty_body
            .as_object_mut()
            .unwrap()
            .get_mut(GENERIC_CIPHERTEXT_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("body".to_string(), Value::String(String::new()));
        assert!(matches!(
            CiphertextEnvelope::from_stored_value(&empty_body),
            Err(ControlPlaneError::InvalidEnvelopeBody)
        ));

        assert!(matches!(
            CiphertextEnvelope::new(
                1,
                CryptoCapability::PayloadValue,
                PAYLOAD_AES_GCM_PROVIDER,
                "sha256:test",
                "tenant-a:payload-v1",
                Some(PAYLOAD_FIELD_BINDING.to_string()),
                Map::new(),
                "",
            ),
            Err(ControlPlaneError::InvalidEnvelopeBody)
        ));

        let mut unknown_field = envelope.to_stored_value();
        unknown_field
            .as_object_mut()
            .unwrap()
            .get_mut(GENERIC_CIPHERTEXT_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected_header".to_string(), Value::Bool(true));
        assert_eq!(
            CiphertextEnvelope::from_stored_value(&unknown_field),
            Err(ControlPlaneError::MalformedEnvelope),
        );
    }

    #[test]
    fn registry_and_compiled_plan_track_capability_scoped_providers() {
        let mut registry = CryptoRegistry::default();
        BasicSuite.register(&mut registry);

        assert_eq!(
            registry.payload_provider_ids().collect::<Vec<_>>(),
            vec![
                PAYLOAD_AES_GCM_PROVIDER,
                PAYLOAD_CLIENT_AEAD_PROVIDER,
                PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
            ],
        );
        assert_eq!(
            registry.vector_provider_ids().collect::<Vec<_>>(),
            vec![
                VECTOR_CLIENT_CKKS_PROVIDER,
                VECTOR_OPENFHE_CKKS_PROVIDER,
                VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
            ],
        );
        assert_eq!(
            registry.metadata_provider_ids().collect::<Vec<_>>(),
            vec![METADATA_AES_GCM_PROVIDER, METADATA_BLIND_INDEX_PROVIDER],
        );

        let mut plan = CompiledCollectionCryptoPlan::default();
        plan.add_payload_rule(CompiledPayloadRule {
            rule_id: "body_conf".to_string(),
            instance: "docs_payload_v1".to_string(),
            provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
            binding: Some(PAYLOAD_FIELD_BINDING.to_string()),
        });
        plan.add_vector_rule(CompiledVectorRule {
            rule_id: "embedding_conf".to_string(),
            vector_name: "embedding".to_string(),
            instance: "docs_vector_v1".to_string(),
            provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
            binding: Some(VECTOR_ENVELOPE_BINDING.to_string()),
        });
        plan.add_metadata_rule(CompiledMetadataRule {
            rule_id: "tenant_conf".to_string(),
            key: "tenant_id".to_string(),
            instance: "docs_metadata_v1".to_string(),
            provider: METADATA_AES_GCM_PROVIDER.to_string(),
            binding: Some(METADATA_VALUE_BINDING.to_string()),
        });
        plan.add_metadata_rule(CompiledMetadataRule {
            rule_id: "body_blind_eq".to_string(),
            key: "body__blind_eq".to_string(),
            instance: "docs_body_blind_v1".to_string(),
            provider: METADATA_BLIND_INDEX_PROVIDER.to_string(),
            binding: Some(METADATA_EXACT_MATCH_TOKEN_BINDING.to_string()),
        });

        assert_eq!(plan.payload_rules().len(), 1);
        assert_eq!(
            plan.vector_rule("embedding")
                .map(|rule| rule.provider.as_str()),
            Some(VECTOR_OPENFHE_CKKS_PROVIDER),
        );
        assert_eq!(plan.metadata_rules().len(), 2);
    }
}
