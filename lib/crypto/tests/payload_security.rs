use data_encoding::BASE64URL_NOPAD;
use proptest::prelude::*;
use qdrant_sec::{
    AeadCipher, AeadKeyring, CLIENT_ENCRYPTED_PAYLOAD_MARKER, ClientPayloadNonceReplayKey,
    ClientPayloadSignatureVerification, ClientPayloadValidationContext, ENCRYPTED_PAYLOAD_MARKER,
    EncryptionError, ExistingPayloadMode, PAYLOAD_TEXT_ENVELOPE_KIND, PayloadEncryptionError,
    PayloadEncryptionPolicy, PayloadTextEncryptor, SecretKey, ServerPayloadValidationContext,
    client_payload_nonce_replay_key, client_payload_signature_key_id,
    client_payload_signature_message, is_client_encrypted_payload_value,
    is_encrypted_payload_value, validate_client_payload_value,
    validate_client_payload_value_after_runtime_verification,
    validate_client_payload_value_for_runtime,
    validate_server_payload_value_after_runtime_encryption, validate_server_payload_value_metadata,
};
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Map, Value, json};

fn encryptor() -> PayloadTextEncryptor {
    PayloadTextEncryptor::new_from_resource_key_with_material_fingerprint(
        "docs",
        "tenant-a:payload",
        &SecretKey::from_bytes([11u8; 32]),
        "tenant-a/payload@v1",
    )
    .unwrap()
}

#[test]
fn resource_key_constructor_derives_payload_text_subkey() {
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let encryptor = PayloadTextEncryptor::new_from_resource_key_with_material_fingerprint(
        "docs",
        "tenant-a:payload",
        &SecretKey::from_bytes([71u8; 32]),
        "tenant-a/payload@v1",
    )
    .unwrap();
    let mut payload = object(json!({ "body": "domain separated" }));

    encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();

    let wrong_resource_key = PayloadTextEncryptor::new_from_resource_key_with_material_fingerprint(
        "docs",
        "tenant-a:payload",
        &SecretKey::from_bytes([72u8; 32]),
        "tenant-a/payload@v1",
    )
    .unwrap();
    assert_eq!(
        wrong_resource_key.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
    );
}

#[test]
fn fingerprinted_keyring_does_not_fallback_after_active_open_failure() {
    let active = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        SecretKey::from_bytes([11u8; 32]),
        "tenant-a/payload@active",
    )
    .unwrap();
    let retired = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        SecretKey::from_bytes([12u8; 32]),
        "tenant-a/payload@retired",
    )
    .unwrap();
    let keyring = AeadKeyring::new(active).with_retired(retired);
    let context = qdrant_sec::EncryptionContext::payload_text("docs", "point-1", "body");
    let mut envelope = keyring.encrypt(b"secret", context).unwrap();
    let mut raw = BASE64URL_NOPAD
        .decode(envelope.ciphertext.as_bytes())
        .unwrap();
    raw[0] ^= 0x01;
    envelope.ciphertext = BASE64URL_NOPAD.encode(&raw);

    assert_eq!(
        keyring.decrypt(&envelope, context),
        Err(EncryptionError::OpenFailed),
    );
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(object) => object,
        _ => unreachable!("test fixture must be a JSON object"),
    }
}

#[test]
fn payload_encryption_error_debug_redacts_attacker_controlled_values() {
    let sentinel = "payload-debug-secret-sentinel";
    let errors = [
        PayloadEncryptionError::InvalidFieldPath(format!("bad.{sentinel}")),
        PayloadEncryptionError::MissingField(format!("missing.{sentinel}")),
        PayloadEncryptionError::ExpectedObjectParent(format!("parent.{sentinel}")),
        PayloadEncryptionError::ExpectedString {
            field: format!("field.{sentinel}"),
            found: "number",
        },
        PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: format!("envelope.{sentinel}"),
            found: "object",
        },
        PayloadEncryptionError::AlreadyEncrypted(format!("body.{sentinel}")),
        PayloadEncryptionError::MalformedEnvelope(format!("malformed.{sentinel}")),
        PayloadEncryptionError::UnsupportedEnvelopeKind(format!("kind.{sentinel}")),
        PayloadEncryptionError::UnsupportedClientAlgorithm(format!("algorithm.{sentinel}")),
        PayloadEncryptionError::ClientEnvelopeAadMismatch(format!("aad.{sentinel}")),
        PayloadEncryptionError::UnsupportedClientSignatureAlgorithm(format!("sig.{sentinel}")),
        PayloadEncryptionError::ClientCiphertextTooLarge(format!("client.{sentinel}")),
        PayloadEncryptionError::ServerCiphertextTooLarge(format!("server.{sentinel}")),
        PayloadEncryptionError::InvalidUtf8(format!("utf8.{sentinel}")),
        PayloadEncryptionError::Crypto(EncryptionError::UnsupportedAlgorithm(format!(
            "crypto.{sentinel}"
        ))),
    ];

    for error in errors {
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }
}

fn client_envelope(point_id: &str, field_path: &str) -> Value {
    json!({
        CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
            "version": 1,
            "kind": "payload_text",
            "algorithm": "AES-256-GCM",
            "key_id": "tenant-a/client-rk-2026-04",
            "rk_id": "tenant-a/client-rk-2026-04",
            "rk_epoch": 3,
            "kdf_domain": "qdrant-sec/client-payload-text/v1",
            "aad": {
                "collection_id": "docs",
                "point_id": point_id,
                "field_path": field_path,
                "schema_version": 1
            },
            "nonce": "AAAAAAAAAAAAAAAA",
            "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
        }
    })
}

fn signed_client_envelope(point_id: &str, field_path: &str) -> (Value, Vec<u8>) {
    let mut envelope = client_envelope(point_id, field_path);
    let signature = json!({
        "alg": "ed25519",
        "key_id": "tenant-a/client-signing-v1",
        "sig": ""
    });
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("signature".to_string(), signature);

    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let message = client_payload_signature_message(&envelope, field_path).unwrap();
    let signature = key_pair.sign(&message);
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("signature")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "sig".to_string(),
            Value::String(BASE64URL_NOPAD.encode(signature.as_ref())),
        );

    (envelope, key_pair.public_key().as_ref().to_vec())
}

#[test]
fn client_payload_envelope_validates_expected_aad_and_key_policy() {
    let envelope = client_envelope("point-1", "body");
    let context = ClientPayloadValidationContext {
        collection_id: "docs",
        point_id: "point-1",
        field_path: "body",
        expected_key_id: Some("tenant-a/client-rk-2026-04"),
        expected_rk_id: None,
        min_rk_epoch: None,
        max_rk_epoch: None,
        key_id_required: true,
        signature_required: false,
        signature_verification: None,
    };

    validate_client_payload_value(&envelope, context).unwrap();
    assert!(is_client_encrypted_payload_value(&envelope));
    assert!(!is_encrypted_payload_value(&envelope));

    let mut short_ciphertext = envelope.clone();
    short_ciphertext
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("ciphertext".to_string(), Value::String("AQID".to_string()));
    assert_eq!(
        validate_client_payload_value(&short_ciphertext, context),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );
}

#[test]
fn client_payload_signature_message_matches_sdk_test_vector() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../docs/qdrant-sec-client-payload-signature-test-vector.json"
    ))
    .expect("client payload signature test vector must be valid JSON");
    let get = |key: &str| {
        fixture
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("test vector must define string field {key}"))
    };
    let mut envelope = json!({
        CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
            "version": fixture.get("version").and_then(Value::as_u64).unwrap(),
            "kind": get("kind"),
            "algorithm": get("algorithm"),
            "key_id": get("key_id"),
            "rk_id": get("rk_id"),
            "rk_epoch": fixture.get("rk_epoch").and_then(Value::as_u64).unwrap(),
            "kdf_domain": get("kdf_domain"),
            "aad": {
                "collection_id": get("collection_id"),
                "point_id": get("point_id"),
                "field_path": get("field_path"),
                "schema_version": fixture.get("schema_version").and_then(Value::as_u64).unwrap(),
            },
            "nonce": get("nonce"),
            "ciphertext": get("ciphertext"),
            "signature": {
                "alg": get("signature_alg"),
                "key_id": get("signature_key_id"),
                "sig": BASE64URL_NOPAD.encode(&[0_u8; 64]),
            },
        },
    });
    let field_path = get("field_path");
    let message = client_payload_signature_message(&envelope, field_path).unwrap();

    assert_eq!(
        message.len() as u64,
        fixture
            .get("signature_message_len")
            .and_then(Value::as_u64)
            .unwrap(),
    );
    assert_eq!(
        BASE64URL_NOPAD.encode(&message),
        get("signature_message_b64"),
    );

    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("aad")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("field_path".to_string(), Value::String("other".to_string()));
    let changed_message = client_payload_signature_message(&envelope, "other").unwrap();
    assert_ne!(message, changed_message);
}

#[test]
fn client_blind_index_token_matches_sdk_test_vector() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../docs/qdrant-sec-client-blind-index-test-vector.json"
    ))
    .expect("client blind-index test vector must be valid JSON");
    let get = |key: &str| {
        fixture
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("test vector must define string field {key}"))
    };
    let normalized = get("plaintext").trim().to_lowercase();
    assert_eq!(normalized, get("normalized_plaintext"));

    let version = fixture["version"].as_u64().unwrap().to_string();
    let rk_epoch = fixture["rk_epoch"].as_u64().unwrap().to_string();
    let mut message = Vec::new();
    for field in [
        get("blind_index_domain").as_bytes(),
        version.as_bytes(),
        get("tenant_id").as_bytes(),
        get("collection_id").as_bytes(),
        get("field_path").as_bytes(),
        get("key_id").as_bytes(),
        get("rk_id").as_bytes(),
        rk_epoch.as_bytes(),
        normalized.as_bytes(),
    ] {
        message.extend_from_slice(&(field.len() as u32).to_be_bytes());
        message.extend_from_slice(field);
    }
    assert_eq!(
        message.len() as u64,
        fixture["token_message_len"].as_u64().unwrap()
    );
    assert_eq!(BASE64URL_NOPAD.encode(&message), get("token_message_b64"));

    let key_bytes = BASE64URL_NOPAD
        .decode(get("blind_index_key_b64").as_bytes())
        .unwrap();
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let token = hmac::sign(&key, &message);
    assert_eq!(BASE64URL_NOPAD.encode(token.as_ref()), get("token_b64"));

    let mut changed = message.clone();
    changed.extend_from_slice(b"!");
    assert_ne!(
        BASE64URL_NOPAD.encode(hmac::sign(&key, &changed).as_ref()),
        get("token_b64"),
    );
}

#[test]
fn client_payload_signature_message_binds_blind_index_manifest() {
    let token = BASE64URL_NOPAD.encode(&[13_u8; 32]);
    let mut envelope = client_envelope("point-1", "body");
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "blind_indexes".to_string(),
            json!([
                {
                    "field_path": "body__blind_eq",
                    "token": token,
                }
            ]),
        );
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "signature".to_string(),
            json!({
                "alg": "ed25519",
                "key_id": "tenant-a/client-signing-v1",
                "sig": BASE64URL_NOPAD.encode(&[0_u8; 64]),
            }),
        );

    let message = client_payload_signature_message(&envelope, "body").unwrap();
    let context = ClientPayloadValidationContext {
        collection_id: "docs",
        point_id: "point-1",
        field_path: "body",
        expected_key_id: Some("tenant-a/client-rk-2026-04"),
        expected_rk_id: Some("tenant-a/client-rk-2026-04"),
        min_rk_epoch: Some(3),
        max_rk_epoch: Some(3),
        key_id_required: true,
        signature_required: false,
        signature_verification: None,
    };
    validate_client_payload_value(&envelope, context).unwrap();

    let mut changed = envelope.clone();
    changed
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("blind_indexes")
        .unwrap()
        .as_array_mut()
        .unwrap()[0]
        .as_object_mut()
        .unwrap()
        .insert(
            "token".to_string(),
            Value::String(BASE64URL_NOPAD.encode(&[14_u8; 32])),
        );
    let changed_message = client_payload_signature_message(&changed, "body").unwrap();

    assert_ne!(message, changed_message);
}

#[test]
fn client_payload_runtime_verification_rejects_tampered_blind_index_manifest() {
    let token = BASE64URL_NOPAD.encode(&[13_u8; 32]);
    let mut envelope = client_envelope("point-1", "body");
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "blind_indexes".to_string(),
            json!([
                {
                    "field_path": "body__blind_eq",
                    "token": token,
                }
            ]),
        );
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "signature".to_string(),
            json!({
                "alg": "ed25519",
                "key_id": "tenant-a/client-signing-v1",
                "sig": "",
            }),
        );
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let message = client_payload_signature_message(&envelope, "body").unwrap();
    let signature = key_pair.sign(&message);
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("signature")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "sig".to_string(),
            Value::String(BASE64URL_NOPAD.encode(signature.as_ref())),
        );

    let verified = validate_client_payload_value_for_runtime(
        &envelope,
        ClientPayloadValidationContext {
            collection_id: "docs",
            point_id: "point-1",
            field_path: "body",
            expected_key_id: Some("tenant-a/client-rk-2026-04"),
            expected_rk_id: Some("tenant-a/client-rk-2026-04"),
            min_rk_epoch: Some(3),
            max_rk_epoch: Some(3),
            key_id_required: true,
            signature_required: true,
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a/client-signing-v1",
                public_key: key_pair.public_key().as_ref(),
            }),
        },
    )
    .unwrap();
    let mut tampered = envelope.clone();
    tampered
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("blind_indexes")
        .unwrap()
        .as_array_mut()
        .unwrap()[0]
        .as_object_mut()
        .unwrap()
        .insert(
            "token".to_string(),
            Value::String(BASE64URL_NOPAD.encode(&[14_u8; 32])),
        );

    assert_eq!(
        validate_client_payload_value_after_runtime_verification(
            &tampered,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: Some("tenant-a/client-rk-2026-04"),
                min_rk_epoch: Some(3),
                max_rk_epoch: Some(3),
                key_id_required: true,
                signature_required: true,
                signature_verification: None,
            },
            &verified,
        ),
        Err(PayloadEncryptionError::RuntimeEnvelopeProofMismatch),
    );
}

#[test]
fn payload_envelopes_reject_unknown_metadata_fields() {
    let context = ClientPayloadValidationContext {
        collection_id: "docs",
        point_id: "point-1",
        field_path: "body",
        expected_key_id: Some("tenant-a/client-rk-2026-04"),
        expected_rk_id: Some("tenant-a/client-rk-2026-04"),
        min_rk_epoch: Some(3),
        max_rk_epoch: Some(3),
        key_id_required: true,
        signature_required: false,
        signature_verification: None,
    };

    let mut extra_client_header = client_envelope("point-1", "body");
    extra_client_header
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unexpected_header".to_string(), json!(true));
    assert_eq!(
        validate_client_payload_value(&extra_client_header, context),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );

    let mut extra_client_aad = client_envelope("point-1", "body");
    extra_client_aad
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("aad")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unexpected_aad".to_string(), json!("not-signed"));
    assert_eq!(
        validate_client_payload_value(&extra_client_aad, context),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );

    let mut extra_client_signature = client_envelope("point-1", "body");
    extra_client_signature
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "signature".to_string(),
            json!({
                "alg": "ed25519",
                "key_id": "tenant-a/client-signing-v1",
                "sig": BASE64URL_NOPAD.encode(&[0u8; 64]),
                "unexpected_signature": "not-signed"
            }),
        );
    assert_eq!(
        validate_client_payload_value(&extra_client_signature, context),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );

    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut server_payload = object(json!({ "body": "secret" }));
    encryptor
        .encrypt_selected_fields("point-1", &mut server_payload, &policy)
        .unwrap();
    let mut server_outer_metadata = server_payload.clone();
    server_outer_metadata
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unexpected_header".to_string(), json!(true));
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut server_outer_metadata, &policy),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );

    server_payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unexpected_envelope".to_string(), json!(true));
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut server_payload, &policy),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );
}

#[test]
fn client_payload_envelope_rejects_aad_and_key_mismatch() {
    let envelope = client_envelope("point-1", "body");
    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-2",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: None,
                min_rk_epoch: None,
                max_rk_epoch: None,
                key_id_required: true,
                signature_required: false,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::ClientEnvelopeAadMismatch(
            "point_id".to_string()
        )),
    );
    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/other-rk"),
                expected_rk_id: None,
                min_rk_epoch: None,
                max_rk_epoch: None,
                key_id_required: true,
                signature_required: false,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::ClientKeyIdMismatch),
    );
}

#[test]
fn client_payload_envelope_rejects_invalid_key_identifiers() {
    let context = ClientPayloadValidationContext {
        collection_id: "docs",
        point_id: "point-1",
        field_path: "body",
        expected_key_id: None,
        expected_rk_id: None,
        min_rk_epoch: None,
        max_rk_epoch: None,
        key_id_required: true,
        signature_required: false,
        signature_verification: None,
    };

    let mut invalid_key_id = client_envelope("point-1", "body");
    invalid_key_id
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("key_id".to_string(), Value::String("not valid".to_string()));
    assert_eq!(
        validate_client_payload_value(&invalid_key_id, context),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidResourceKeyId,
        )),
    );
    assert_eq!(
        client_payload_nonce_replay_key(&invalid_key_id, "body"),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidResourceKeyId,
        )),
    );

    let mut invalid_rk_id = client_envelope("point-1", "body");
    invalid_rk_id
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("rk_id".to_string(), Value::String("not valid".to_string()));
    assert_eq!(
        validate_client_payload_value(&invalid_rk_id, context),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidResourceKeyId,
        )),
    );
    assert_eq!(
        client_payload_nonce_replay_key(&invalid_rk_id, "body"),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidResourceKeyId,
        )),
    );
}

#[test]
fn client_payload_envelope_requires_resource_key_metadata_and_kdf_domain() {
    for field in ["rk_id", "rk_epoch", "kdf_domain"] {
        let mut envelope = client_envelope("point-1", "body");
        envelope
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);

        assert_eq!(
            validate_client_payload_value(
                &envelope,
                ClientPayloadValidationContext {
                    collection_id: "docs",
                    point_id: "point-1",
                    field_path: "body",
                    expected_key_id: Some("tenant-a/client-rk-2026-04"),
                    expected_rk_id: None,
                    min_rk_epoch: None,
                    max_rk_epoch: None,
                    key_id_required: true,
                    signature_required: false,
                    signature_verification: None,
                },
            ),
            Err(PayloadEncryptionError::MalformedEnvelope(
                "body".to_string()
            )),
        );
    }

    let mut wrong_domain = client_envelope("point-1", "body");
    wrong_domain
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "kdf_domain".to_string(),
            Value::String("qdrant-sec/client-payload-text/v0".to_string()),
        );
    assert_eq!(
        validate_client_payload_value(
            &wrong_domain,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: None,
                min_rk_epoch: None,
                max_rk_epoch: None,
                key_id_required: true,
                signature_required: false,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );
}

#[test]
fn client_payload_envelope_enforces_resource_key_policy() {
    let envelope = client_envelope("point-1", "body");

    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: Some("tenant-a/other-rk"),
                min_rk_epoch: None,
                max_rk_epoch: None,
                key_id_required: true,
                signature_required: false,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::ClientResourceKeyIdMismatch),
    );
    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: Some("tenant-a/client-rk-2026-04"),
                min_rk_epoch: Some(4),
                max_rk_epoch: None,
                key_id_required: true,
                signature_required: false,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::ClientResourceKeyEpochMismatch),
    );
    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: Some("tenant-a/client-rk-2026-04"),
                min_rk_epoch: Some(3),
                max_rk_epoch: Some(3),
                key_id_required: true,
                signature_required: false,
                signature_verification: None,
            },
        ),
        Ok(()),
    );
}

#[test]
fn client_payload_nonce_replay_cache_key_validation_rejects_malformed_entries() {
    let key = client_payload_nonce_replay_key(&client_envelope("point-1", "body"), "body")
        .unwrap()
        .unwrap();
    let valid = key.cache_key_for_collection("crypto-collection-uuid");

    ClientPayloadNonceReplayKey::validate_cache_key_for_collection(&valid).unwrap();

    for malformed in [
        "",
        "not-a-cache-key",
        "\x1ftenant-a/client-rk-2026-04\x1ftenant-a/client-rk-2026-04\x1f3\x1fAAAAAAAAAAAAAAAA",
        "not valid\x1ftenant-a/client-rk-2026-04\x1ftenant-a/client-rk-2026-04\x1f3\x1fAAAAAAAAAAAAAAAA",
        "crypto-collection-uuid\x1fnot valid\x1ftenant-a/client-rk-2026-04\x1f3\x1fAAAAAAAAAAAAAAAA",
        "crypto-collection-uuid\x1ftenant-a/client-rk-2026-04\x1fnot valid\x1f3\x1fAAAAAAAAAAAAAAAA",
        "crypto-collection-uuid\x1ftenant-a/client-rk-2026-04\x1ftenant-a/client-rk-2026-04\x1fnot-an-epoch\x1fAAAAAAAAAAAAAAAA",
        "crypto-collection-uuid\x1ftenant-a/client-rk-2026-04\x1ftenant-a/client-rk-2026-04\x1f3\x1fnot-valid-base64!",
        "crypto-collection-uuid\x1ftenant-a/client-rk-2026-04\x1ftenant-a/client-rk-2026-04\x1f3\x1fAQID",
        "crypto-collection-uuid\x1ftenant-a/client-rk-2026-04\x1ftenant-a/client-rk-2026-04\x1f3\x1fAAAAAAAAAAAAAAAA\x1fextra",
    ] {
        assert_eq!(
            ClientPayloadNonceReplayKey::validate_cache_key_for_collection(malformed),
            Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey),
        );
    }
}

#[test]
fn client_payload_envelope_verifies_ed25519_signature() {
    let (envelope, public_key) = signed_client_envelope("point-1", "body");
    validate_client_payload_value(
        &envelope,
        ClientPayloadValidationContext {
            collection_id: "docs",
            point_id: "point-1",
            field_path: "body",
            expected_key_id: Some("tenant-a/client-rk-2026-04"),
            expected_rk_id: None,
            min_rk_epoch: None,
            max_rk_epoch: None,
            key_id_required: true,
            signature_required: true,
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a/client-signing-v1",
                public_key: &public_key,
            }),
        },
    )
    .unwrap();

    let mut tampered = envelope.clone();
    tampered
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "ciphertext".to_string(),
            Value::String("AQEBAQEBAQEBAQEBAQEBAQ".to_string()),
        );
    assert_eq!(
        validate_client_payload_value(
            &tampered,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: None,
                min_rk_epoch: None,
                max_rk_epoch: None,
                key_id_required: true,
                signature_required: true,
                signature_verification: Some(ClientPayloadSignatureVerification {
                    expected_key_id: "tenant-a/client-signing-v1",
                    public_key: &public_key,
                }),
            },
        ),
        Err(PayloadEncryptionError::InvalidClientSignature),
    );
}

#[test]
fn client_payload_envelope_requires_signature_when_verifier_is_configured() {
    let envelope = client_envelope("point-1", "body");
    let public_key = [7u8; 32];

    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: None,
                min_rk_epoch: None,
                max_rk_epoch: None,
                key_id_required: true,
                signature_required: true,
                signature_verification: Some(ClientPayloadSignatureVerification {
                    expected_key_id: "tenant-a/client-signing-v1",
                    public_key: &public_key,
                }),
            },
        ),
        Err(PayloadEncryptionError::MissingClientSignature),
    );
}

#[test]
fn client_payload_envelope_rejects_invalid_signature_key_id() {
    let mut envelope = client_envelope("point-1", "body");
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "signature".to_string(),
            json!({
                "alg": "ed25519",
                "key_id": "not valid",
                "sig": BASE64URL_NOPAD.encode(&[0u8; 64])
            }),
        );

    assert_eq!(
        client_payload_signature_key_id(&envelope, "body"),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidResourceKeyId,
        )),
    );
    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: None,
                min_rk_epoch: None,
                max_rk_epoch: None,
                key_id_required: true,
                signature_required: false,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidResourceKeyId,
        )),
    );
}

#[test]
fn post_runtime_client_payload_validation_requires_verified_proof_match() {
    let (envelope, public_key) = signed_client_envelope("point-1", "body");
    let verified = validate_client_payload_value_for_runtime(
        &envelope,
        ClientPayloadValidationContext {
            collection_id: "docs",
            point_id: "point-1",
            field_path: "body",
            expected_key_id: Some("tenant-a/client-rk-2026-04"),
            expected_rk_id: Some("tenant-a/client-rk-2026-04"),
            min_rk_epoch: Some(3),
            max_rk_epoch: Some(3),
            key_id_required: true,
            signature_required: true,
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a/client-signing-v1",
                public_key: &public_key,
            }),
        },
    )
    .unwrap();

    validate_client_payload_value_after_runtime_verification(
        &envelope,
        ClientPayloadValidationContext {
            collection_id: "docs",
            point_id: "point-1",
            field_path: "body",
            expected_key_id: Some("tenant-a/client-rk-2026-04"),
            expected_rk_id: Some("tenant-a/client-rk-2026-04"),
            min_rk_epoch: Some(3),
            max_rk_epoch: Some(3),
            key_id_required: true,
            signature_required: true,
            signature_verification: None,
        },
        &verified,
    )
    .unwrap();

    let mut different_ciphertext = envelope.clone();
    different_ciphertext
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "ciphertext".to_string(),
            Value::String("AQEBAQEBAQEBAQEBAQEBAQ".to_string()),
        );

    assert_eq!(
        validate_client_payload_value_after_runtime_verification(
            &different_ciphertext,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: Some("tenant-a/client-rk-2026-04"),
                min_rk_epoch: Some(3),
                max_rk_epoch: Some(3),
                key_id_required: true,
                signature_required: true,
                signature_verification: None,
            },
            &verified,
        ),
        Err(PayloadEncryptionError::RuntimeEnvelopeProofMismatch),
    );
}

#[test]
fn post_runtime_server_payload_validation_requires_verified_proof_match() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "secret" }));
    let (_, verified_keys) = encryptor
        .encrypt_selected_fields_for_runtime("point-1", &mut payload, &policy, "docs")
        .unwrap();
    let body = payload.get("body").unwrap();
    let context = ServerPayloadValidationContext {
        field_path: "body",
        expected_kind: Some(PAYLOAD_TEXT_ENVELOPE_KIND),
        key_id: Some("tenant-a:payload"),
        crypto_schema_version: 1,
        encryption_epoch: 0,
    };
    let verified = verified_keys.into_iter().next().unwrap();

    validate_server_payload_value_after_runtime_encryption(
        body, "docs", "point-1", context, &verified,
    )
    .unwrap();

    let mut different_ciphertext = body.clone();
    different_ciphertext
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "ciphertext".to_string(),
            Value::String("AQEBAQEBAQEBAQEBAQEBAQ".to_string()),
        );

    assert_eq!(
        validate_server_payload_value_after_runtime_encryption(
            &different_ciphertext,
            "docs",
            "point-1",
            context,
            &verified,
        ),
        Err(PayloadEncryptionError::RuntimeEnvelopeProofMismatch),
    );
}

#[test]
fn runtime_server_payload_proof_requires_encryptor_collection_identity() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "secret" }));

    assert_eq!(
        encryptor.encrypt_selected_fields_for_runtime(
            "point-1",
            &mut payload,
            &policy,
            "other-collection",
        ),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "collection_id".to_string(),
        )),
    );
}

#[test]
fn public_client_payload_validation_requires_signature_verifier_when_signature_is_required() {
    let mut envelope = client_envelope("point-1", "body");
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "signature".to_string(),
            json!({
                "alg": "ed25519",
                "key_id": "tenant-a/client-signing-v1",
                "sig": BASE64URL_NOPAD.encode(&[0u8; 64])
            }),
        );

    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: None,
                min_rk_epoch: None,
                max_rk_epoch: None,
                key_id_required: true,
                signature_required: true,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::InvalidClientSignature),
    );
}

#[test]
fn runtime_client_payload_proof_requires_signature_verifier() {
    let (envelope, _public_key) = signed_client_envelope("point-1", "body");

    assert_eq!(
        validate_client_payload_value_for_runtime(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: Some("tenant-a/client-rk-2026-04"),
                min_rk_epoch: Some(3),
                max_rk_epoch: Some(3),
                key_id_required: true,
                signature_required: true,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::InvalidClientSignature),
    );
}

#[test]
fn selected_body_field_is_encrypted_without_leaking_plaintext() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({
        "body": "classified body text",
        "title": "public title"
    }));

    assert_eq!(
        encryptor
            .encrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        1,
    );

    let body = payload.get("body").unwrap();
    assert!(is_encrypted_payload_value(body));

    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(serialized.contains(ENCRYPTED_PAYLOAD_MARKER));
    assert!(serialized.contains("\"schema_version\":1"));
    assert!(serialized.contains("\"encryption_epoch\":0"));
    assert!(serialized.contains("\"material_fingerprint\""));
    assert!(!serialized.contains("classified body text"));
    assert!(serialized.contains("public title"));

    assert_eq!(
        encryptor
            .decrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        1,
    );
    assert_eq!(payload.get("body"), Some(&json!("classified body text")));
}

#[test]
fn payload_decrypt_rejects_wrong_encryption_epoch() {
    let base_encryptor = encryptor();
    let next_epoch_encryptor = encryptor().with_encryption_epoch(1);
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "epoch scoped" }));

    base_encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();

    assert_eq!(
        next_epoch_encryptor.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::EncryptionEpochMismatch),
    );
}

#[test]
fn server_payload_metadata_validation_rejects_stale_or_wrong_key_markers() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "metadata checked" }));

    encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();
    let body = payload.get("body").unwrap();
    validate_server_payload_value_metadata(
        body,
        ServerPayloadValidationContext {
            field_path: "body",
            expected_kind: Some(PAYLOAD_TEXT_ENVELOPE_KIND),
            key_id: Some("tenant-a:payload"),
            crypto_schema_version: 1,
            encryption_epoch: 0,
        },
    )
    .unwrap();

    assert_eq!(
        validate_server_payload_value_metadata(
            body,
            ServerPayloadValidationContext {
                field_path: "body",
                expected_kind: Some(PAYLOAD_TEXT_ENVELOPE_KIND),
                key_id: Some("tenant-a:other"),
                crypto_schema_version: 1,
                encryption_epoch: 0,
            },
        ),
        Err(PayloadEncryptionError::Crypto(EncryptionError::KeyMismatch)),
    );
    assert_eq!(
        validate_server_payload_value_metadata(
            body,
            ServerPayloadValidationContext {
                field_path: "body",
                expected_kind: Some(PAYLOAD_TEXT_ENVELOPE_KIND),
                key_id: Some("tenant-a:payload"),
                crypto_schema_version: 1,
                encryption_epoch: 1,
            },
        ),
        Err(PayloadEncryptionError::EncryptionEpochMismatch),
    );
}

#[test]
fn server_payload_metadata_validation_rejects_invalid_envelope_headers() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut base_payload = object(json!({ "body": "metadata checked" }));

    encryptor
        .encrypt_selected_fields("point-1", &mut base_payload, &policy)
        .unwrap();

    let tampered_body = |field: &str, value: Value| {
        let mut payload = base_payload.clone();
        payload
            .get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut(ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("envelope")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(field.to_string(), value);
        payload.remove("body").unwrap()
    };
    let context = ServerPayloadValidationContext {
        field_path: "body",
        expected_kind: Some(PAYLOAD_TEXT_ENVELOPE_KIND),
        key_id: Some("tenant-a:payload"),
        crypto_schema_version: 1,
        encryption_epoch: 0,
    };

    assert_eq!(
        validate_server_payload_value_metadata(&tampered_body("version", json!(2)), context),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::UnsupportedVersion(2),
        )),
    );
    assert_eq!(
        validate_server_payload_value_metadata(
            &tampered_body("algorithm", json!("plaintext")),
            context
        ),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::UnsupportedAlgorithm("plaintext".to_string()),
        )),
    );
    assert_eq!(
        validate_server_payload_value_metadata(&tampered_body("nonce", json!("AQID")), context),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidNonceLength,
        )),
    );
    assert_eq!(
        validate_server_payload_value_metadata(
            &tampered_body("ciphertext", json!("AQID")),
            context
        ),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidCiphertextLength,
        )),
    );
    assert_eq!(
        validate_server_payload_value_metadata(
            &tampered_body("material_fingerprint", json!("not valid")),
            context,
        ),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidMaterialFingerprintId,
        )),
    );
    assert_eq!(
        validate_server_payload_value_metadata(
            &tampered_body("rk_id", json!("not valid")),
            context
        ),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidResourceKeyId,
        )),
    );
    assert_eq!(
        validate_server_payload_value_metadata(&tampered_body("rk_epoch", json!(3)), context),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidResourceKeyId,
        )),
    );
}

#[test]
fn payload_outer_metadata_tampering_fails_authentication() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "epoch scoped" }));

    encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();

    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("schema_version".to_string(), json!(2));
    // The schema version is checked before any decryption is attempted, so a foreign schema is
    // rejected without materializing plaintext; the AAD still binds it for the decrypt path.
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::UnsupportedSchemaVersion(2)),
    );

    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("schema_version".to_string(), json!(1));
    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("encryption_epoch".to_string(), json!(1));
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::EncryptionEpochMismatch),
    );

    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("encryption_epoch".to_string(), json!(0));
    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("material_fingerprint".to_string(), json!(""));
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::Crypto(
            EncryptionError::InvalidMaterialFingerprintId,
        )),
    );
}

#[test]
fn payload_decrypt_accepts_retired_key_but_new_writes_use_active_key() {
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let old_resource_key = SecretKey::from_bytes([11u8; 32]);
    let new_resource_key = SecretKey::from_bytes([12u8; 32]);
    let old_encryptor = PayloadTextEncryptor::new_from_resource_key_with_material_fingerprint(
        "docs",
        "tenant-a:payload-old",
        &old_resource_key,
        "tenant-a/payload-old@v1",
    )
    .unwrap();
    let mut old_payload = object(json!({ "body": "rotation protected" }));

    old_encryptor
        .encrypt_selected_fields("point-1", &mut old_payload, &policy)
        .unwrap();

    let rotated_encryptor = PayloadTextEncryptor::new_from_resource_key_with_material_fingerprint(
        "docs",
        "tenant-a:payload-new",
        &new_resource_key,
        "tenant-a/payload-new@v1",
    )
    .unwrap()
    .with_retired_resource_key(
        "tenant-a:payload-old",
        &old_resource_key,
        "tenant-a/payload-old@v1",
    )
    .unwrap();

    assert_eq!(
        rotated_encryptor
            .decrypt_selected_fields("point-1", &mut old_payload, &policy)
            .unwrap(),
        1,
    );
    assert_eq!(old_payload.get("body"), Some(&json!("rotation protected")));

    let mut new_payload = object(json!({ "body": "active key only" }));
    rotated_encryptor
        .encrypt_selected_fields("point-2", &mut new_payload, &policy)
        .unwrap();
    let serialized = serde_json::to_string(&new_payload).unwrap();

    assert!(serialized.contains("tenant-a:payload-new"));
    assert!(!serialized.contains("tenant-a:payload-old"));
}

#[test]
fn encrypted_payload_is_bound_to_point_and_field_path() {
    let encryptor = encryptor();
    let body_policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let summary_policy = PayloadEncryptionPolicy::new(["summary"]).unwrap();
    let mut payload = object(json!({ "body": "copy protection" }));

    encryptor
        .encrypt_selected_fields("point-1", &mut payload, &body_policy)
        .unwrap();
    assert_eq!(
        encryptor.decrypt_selected_fields("point-2", &mut payload, &body_policy),
        Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
    );

    let encrypted_body = payload.remove("body").unwrap();
    payload.insert("summary".to_string(), encrypted_body);
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut payload, &summary_policy),
        Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
    );
}

#[test]
fn encrypting_already_encrypted_payload_is_idempotent() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "one encryption only" }));

    assert_eq!(
        encryptor
            .encrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        1,
    );
    let once = serde_json::to_string(&payload).unwrap();
    assert_eq!(
        encryptor
            .encrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        0,
    );
    assert_eq!(serde_json::to_string(&payload).unwrap(), once);
}

#[test]
fn existing_payload_mode_can_fail_or_reencrypt_stale_envelopes() {
    let old_encryptor = encryptor();
    let new_encryptor = encryptor().with_encryption_epoch(1);
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "rotate this" }));

    old_encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();
    let mut fail_payload = payload.clone();
    assert_eq!(
        new_encryptor.encrypt_selected_fields_with_mode(
            "point-1",
            &mut fail_payload,
            &policy,
            ExistingPayloadMode::FailIfExisting,
        ),
        Err(PayloadEncryptionError::AlreadyEncrypted("body".to_string())),
    );

    assert_eq!(
        new_encryptor
            .encrypt_selected_fields_with_mode(
                "point-1",
                &mut payload,
                &policy,
                ExistingPayloadMode::ReencryptIfStale,
            )
            .unwrap(),
        1,
    );
    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(serialized.contains("\"encryption_epoch\":1"));
    assert!(!serialized.contains("rotate this"));

    assert_eq!(
        new_encryptor
            .decrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        1,
    );
    assert_eq!(payload.get("body"), Some(&json!("rotate this")));
}

#[test]
fn malformed_marker_does_not_bypass_encryption() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({
        "body": {
            "$qdrant_sec": {
                "kind": "payload_text"
            },
            "plaintext": "secret body"
        }
    }));

    assert!(!is_encrypted_payload_value(payload.get("body").unwrap()));
    assert_eq!(
        encryptor.encrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );

    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(serialized.contains("secret body"));
}

#[test]
fn nested_payload_paths_are_supported() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["document.body"]).unwrap();
    let mut payload = object(json!({
        "document": {
            "body": "nested secret",
            "author": "analyst"
        }
    }));

    encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();
    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(!serialized.contains("nested secret"));

    encryptor
        .decrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();
    assert_eq!(payload["document"]["body"], json!("nested secret"));
    assert_eq!(payload["document"]["author"], json!("analyst"));
}

#[test]
fn strict_missing_fields_and_non_strings_fail_closed() {
    let encryptor = encryptor();
    let strict = PayloadEncryptionPolicy::new(["body"])
        .unwrap()
        .with_strict_missing_fields(true);
    let mut missing_payload = Map::new();

    assert_eq!(
        encryptor.encrypt_selected_fields("point-1", &mut missing_payload, &strict),
        Err(PayloadEncryptionError::MissingField("body".to_string())),
    );

    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut numeric_payload = object(json!({ "body": 7 }));
    assert_eq!(
        encryptor.encrypt_selected_fields("point-1", &mut numeric_payload, &policy),
        Err(PayloadEncryptionError::ExpectedString {
            field: "body".to_string(),
            found: "number",
        }),
    );
}

#[test]
fn malformed_or_plaintext_values_do_not_decrypt() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut plaintext_payload = object(json!({ "body": "not encrypted" }));

    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut plaintext_payload, &policy),
        Err(PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: "body".to_string(),
            found: "string",
        }),
    );

    let mut malformed_payload = object(json!({
        "body": {
            "$qdrant_sec": {
                "kind": "payload_text"
            }
        }
    }));
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut malformed_payload, &policy),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );
}

#[test]
fn invalid_policies_are_rejected() {
    assert_eq!(
        PayloadEncryptionPolicy::new(Vec::<String>::new()),
        Err(PayloadEncryptionError::EmptyPolicy),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new([".body"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            ".body".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["body..text"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "body..text".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new([format!("{ENCRYPTED_PAYLOAD_MARKER}.body")]),
        Err(PayloadEncryptionError::InvalidFieldPath(format!(
            "{ENCRYPTED_PAYLOAD_MARKER}.body"
        ))),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new([format!("{CLIENT_ENCRYPTED_PAYLOAD_MARKER}.body")]),
        Err(PayloadEncryptionError::InvalidFieldPath(format!(
            "{CLIENT_ENCRYPTED_PAYLOAD_MARKER}.body"
        ))),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["$qdrant_ciphertext.body"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "$qdrant_ciphertext.body".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["items[].name"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "items[].name".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["items.*.name"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "items.*.name".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["items.0.name"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "items.0.name".to_string()
        )),
    );
}

proptest! {
    #[test]
    fn arbitrary_utf8_body_round_trips(body in "\\PC{0,512}") {
        let encryptor = encryptor();
        let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
        let mut payload = object(json!({ "body": body.clone() }));

        encryptor.encrypt_selected_fields("property-point", &mut payload, &policy).unwrap();
        encryptor.decrypt_selected_fields("property-point", &mut payload, &policy).unwrap();
        prop_assert_eq!(payload.get("body"), Some(&json!(body)));
    }
}

#[test]
fn reencrypt_if_stale_rewraps_envelopes_after_resource_key_rotation() {
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let old_key = SecretKey::from_bytes([11u8; 32]);
    let new_key = SecretKey::from_bytes([12u8; 32]);
    let old_encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
        "docs",
        "tenant-a:payload",
        &old_key,
        "tenant-a/payload@v1",
        "tenant-a/payload-rk",
        1,
    )
    .unwrap();
    // Same key_id, material fingerprint, schema version and encryption epoch: only the
    // resource key lineage (rk_epoch) moved forward.
    let new_encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
        "docs",
        "tenant-a:payload",
        &new_key,
        "tenant-a/payload@v1",
        "tenant-a/payload-rk",
        2,
    )
    .unwrap()
    .with_retired_resource_key_metadata(
        "tenant-a:payload",
        &old_key,
        "tenant-a/payload@v1",
        "tenant-a/payload-rk",
        1,
    )
    .unwrap();

    let mut payload = object(json!({ "body": "rotate this" }));
    old_encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();
    assert!(
        serde_json::to_string(&payload)
            .unwrap()
            .contains("\"rk_epoch\":1")
    );

    assert_eq!(
        new_encryptor
            .encrypt_selected_fields_with_mode(
                "point-1",
                &mut payload,
                &policy,
                ExistingPayloadMode::ReencryptIfStale,
            )
            .unwrap(),
        1,
        "an envelope on a retired resource key epoch must be re-wrapped",
    );
    let rewrapped = serde_json::to_string(&payload).unwrap();
    assert!(rewrapped.contains("\"rk_epoch\":2"));
    assert!(!rewrapped.contains("\"rk_epoch\":1"));
    assert!(!rewrapped.contains("rotate this"));

    assert_eq!(
        new_encryptor
            .encrypt_selected_fields_with_mode(
                "point-1",
                &mut payload,
                &policy,
                ExistingPayloadMode::ReencryptIfStale,
            )
            .unwrap(),
        0,
        "an envelope already on the active resource key epoch is fresh",
    );
    assert_eq!(
        new_encryptor
            .decrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        1,
    );
    assert_eq!(payload.get("body"), Some(&json!("rotate this")));
}
