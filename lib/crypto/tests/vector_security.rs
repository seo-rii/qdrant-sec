#[cfg(unix)]
use std::io::BufRead;
#[cfg(unix)]
use std::num::NonZeroUsize;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(unix)]
use std::thread::JoinHandle;
#[cfg(unix)]
use std::time::{Duration, Instant};

use data_encoding::BASE64URL_NOPAD;
#[cfg(unix)]
use fs_err as fs;
#[cfg(unix)]
use qdrant_sec::CommandOpenFheBackend;
use qdrant_sec::vector::CkksPlaintextQueryScoreBatchItem;
use qdrant_sec::{
    AeadCipher, CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
    CKKS_PUBLIC_MATERIAL_MAX_CRYPTO_CONTEXT_BYTES, CKKS_PUBLIC_MATERIAL_MAX_PUBLIC_KEY_BYTES,
    CkksBatchEncryptionInput, CkksEncryptedQueryScoreBatchInput, CkksEncryptedQueryScoreBatchItem,
    CkksEncryptedQueryScoreInput, CkksEncryptionInput, CkksError, CkksParameters,
    CkksPlaintextQueryScoreBatchInput, CkksPlaintextQueryScoreInput, CkksPublicMaterial,
    CkksQueryEncryptionInput, CkksVectorBackend, CkksVectorBatchItem, CkksVectorEncryptor,
    CkksVectorSidecarDeleteTarget, ClientCkksVectorSignatureVerification,
    ClientCkksVectorValidationContext, ENCRYPTED_CKKS_VECTOR_MARKER, EncryptedCkksVector,
    EncryptionContext, EncryptionError, SecretKey, VerifiedCkksVector,
    ckks_vector_sidecar_envelope_key, ckks_vector_verified_sidecar_delete_key,
    client_ckks_vector_signature_message, validate_client_ckks_vector_payload_value_for_runtime,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug)]
struct SealedTestBackend;

impl CkksVectorBackend for SealedTestBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        let cipher = AeadCipher::new_with_material_fingerprint(
            "test-vector",
            SecretKey::from_bytes([23u8; 32]),
            "test/vector@v1",
        )
        .unwrap();
        let plaintext = serde_json::to_vec(input.values)
            .map_err(|err| CkksError::Backend(format!("test serialization failed: {err}")))?;
        let envelope = cipher
            .encrypt(
                &plaintext,
                EncryptionContext::ckks_vector(input.collection, input.point_id, input.vector_name),
            )
            .map_err(|err| CkksError::Backend(format!("test sealing failed: {err}")))?;

        serde_json::to_vec(&envelope)
            .map_err(|err| CkksError::Backend(format!("test envelope failed: {err}")))
    }
}

#[derive(Clone, Copy, Debug)]
struct OversizedCiphertextBackend;

impl CkksVectorBackend for OversizedCiphertextBackend {
    fn encrypt(&self, _input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        Ok(vec![7_u8; 17 * 1024 * 1024])
    }
}

#[test]
fn ckks_public_material_rejects_oversized_context_and_public_key() {
    let oversized_context = vec![1u8; CKKS_PUBLIC_MATERIAL_MAX_CRYPTO_CONTEXT_BYTES + 1];
    assert!(matches!(
        CkksPublicMaterial::new(oversized_context, vec![1u8]),
        Err(CkksError::InvalidContext(message))
            if message.contains("crypto_context") && message.contains("at most")
    ));

    let oversized_public_key = vec![2u8; CKKS_PUBLIC_MATERIAL_MAX_PUBLIC_KEY_BYTES + 1];
    assert!(matches!(
        CkksPublicMaterial::new(vec![1u8], oversized_public_key),
        Err(CkksError::InvalidContext(message))
            if message.contains("public_key") && message.contains("at most")
    ));
}

#[derive(Clone, Debug)]
struct BatchTestBackend {
    single_calls: Arc<AtomicUsize>,
    batch_calls: Arc<AtomicUsize>,
}

impl BatchTestBackend {
    fn new() -> Self {
        Self {
            single_calls: Arc::new(AtomicUsize::new(0)),
            batch_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl CkksVectorBackend for BatchTestBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        self.single_calls.fetch_add(1, Ordering::Relaxed);
        Ok(format!("single:{}:{}", input.point_id, input.values.len()).into_bytes())
    }

    fn encrypt_batch(
        &self,
        input: CkksBatchEncryptionInput<'_>,
    ) -> Result<Vec<Vec<u8>>, CkksError> {
        self.batch_calls.fetch_add(1, Ordering::Relaxed);
        Ok(input
            .items
            .iter()
            .map(|item| format!("batch:{}:{}", item.point_id, item.values.len()).into_bytes())
            .collect())
    }
}

#[derive(Clone, Copy, Debug)]
struct ScoreTestBackend;

impl CkksVectorBackend for ScoreTestBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        Ok(format!("cipher:{}:{}", input.point_id, input.values.len()).into_bytes())
    }

    fn score_plaintext_query(
        &self,
        input: CkksPlaintextQueryScoreInput<'_>,
    ) -> Result<f64, CkksError> {
        assert_eq!(input.collection, "docs");
        assert_eq!(input.point_id, "point-1");
        assert_eq!(input.vector_name, "embedding");
        assert_eq!(input.distance, "dot");
        assert_eq!(input.query_values, &[0.5, 0.25]);
        assert_eq!(input.ciphertext, b"cipher:point-1:2");
        Ok(42.25)
    }
}

#[derive(Clone, Debug)]
struct BatchScoreTestBackend {
    single_calls: Arc<AtomicUsize>,
    batch_calls: Arc<AtomicUsize>,
}

impl BatchScoreTestBackend {
    fn new() -> Self {
        Self {
            single_calls: Arc::new(AtomicUsize::new(0)),
            batch_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl CkksVectorBackend for BatchScoreTestBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        Ok(format!("cipher:{}:{}", input.point_id, input.values.len()).into_bytes())
    }

    fn score_plaintext_query(
        &self,
        input: CkksPlaintextQueryScoreInput<'_>,
    ) -> Result<f64, CkksError> {
        self.single_calls.fetch_add(1, Ordering::Relaxed);
        Ok(match input.point_id {
            "point-1" => 10.0,
            "point-2" => 5.0,
            _ => 1.0,
        })
    }

    fn score_plaintext_query_batch(
        &self,
        input: CkksPlaintextQueryScoreBatchInput<'_>,
    ) -> Result<Vec<f64>, CkksError> {
        self.batch_calls.fetch_add(1, Ordering::Relaxed);
        assert_eq!(input.collection, "docs");
        assert_eq!(input.vector_name, "embedding");
        assert_eq!(input.distance, "dot");
        assert_eq!(input.query_values, &[0.5, 0.25]);
        Ok(input
            .items
            .iter()
            .map(|item| match item.point_id {
                "point-1" => {
                    assert_eq!(item.ciphertext, b"cipher:point-1:2");
                    10.0
                }
                "point-2" => {
                    assert_eq!(item.ciphertext, b"cipher:point-2:2");
                    5.0
                }
                _ => 1.0,
            })
            .collect())
    }
}

#[derive(Clone, Copy, Debug)]
struct MismatchedEncryptedScoreBatchBackend;

impl CkksVectorBackend for MismatchedEncryptedScoreBatchBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        Ok(format!("cipher:{}:{}", input.point_id, input.values.len()).into_bytes())
    }

    fn score_encrypted_query_batch(
        &self,
        input: CkksEncryptedQueryScoreBatchInput<'_>,
    ) -> Result<Vec<f64>, CkksError> {
        assert_eq!(input.collection, "docs");
        assert_eq!(input.vector_name, "embedding");
        assert_eq!(input.distance, "dot");
        Ok(vec![1.0])
    }
}

fn public_material() -> CkksPublicMaterial {
    CkksPublicMaterial::new(
        b"openfhe crypto context".to_vec(),
        b"openfhe public key".to_vec(),
    )
    .unwrap()
}

#[cfg(unix)]
fn test_bash_backend() -> CommandOpenFheBackend {
    let bash = ["/usr/bin/bash", "/bin/bash"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .expect("bash must be available for OpenFHE bridge protocol tests");
    let bash = fs::canonicalize(bash).expect("bash path must canonicalize");
    let digest = BASE64URL_NOPAD.encode(&Sha256::digest(
        fs::read(&bash).expect("bash executable must be readable"),
    ));

    CommandOpenFheBackend::new_checked_with_sha256_b64(bash, digest)
        .expect("bash bridge test backend must validate with a SHA-256 pin")
}

#[cfg(target_os = "linux")]
fn linux_landlock_write_deny_supported_for_test() -> bool {
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    let version = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_create_ruleset,
            std::ptr::null::<nix::libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    version >= 1
}

#[cfg(unix)]
fn create_test_fifo(path: &Path) {
    nix::unistd::mkfifo(
        path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("test FIFO must be created");
}

#[cfg(unix)]
fn collect_fifo_lines(path: PathBuf) -> (Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let collected = Arc::clone(&lines);
    let handle = std::thread::spawn(move || {
        let file = fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("test FIFO must open for reading");
        let reader = std::io::BufReader::new(file);
        for line in reader.lines() {
            collected
                .lock()
                .expect("test FIFO line lock must not be poisoned")
                .push(line.expect("test FIFO line must be readable"));
        }
    });

    (lines, handle)
}

#[cfg(unix)]
fn fifo_line_count(lines: &Arc<Mutex<Vec<String>>>, expected: &str) -> usize {
    lines
        .lock()
        .expect("test FIFO line lock must not be poisoned")
        .iter()
        .filter(|line| line.as_str() == expected)
        .count()
}

fn signed_client_ckks_vector_payload(
    key_pair: &Ed25519KeyPair,
    signature_key_id: &str,
) -> serde_json::Value {
    let ciphertext = b"client-side-ckks-ciphertext";
    let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(ciphertext).as_ref());
    let context_digest = public_material().digest_for(&CkksParameters::openfhe_default_128_bit());
    let mut value = json!({
        "$qdrant_sec_client_ckks_vector": {
            "version": 1,
            "scheme": "openfhe-ckks",
            "security_profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "collection_id": "collection-uuid",
            "point_id": "point-1",
            "vector_name": "embedding",
            "key_id": "tenant-a:docs",
            "rk_id": "tenant-a/vector-rk",
            "rk_epoch": 3,
            "context_digest": context_digest,
            "slots": 2,
            "ciphertext_sha256": ciphertext_sha256,
            "ciphertext": BASE64URL_NOPAD.encode(ciphertext),
            "signature": {
                "alg": "ed25519",
                "key_id": signature_key_id,
                "sig": ""
            }
        }
    });
    let message = client_ckks_vector_signature_message(&value).unwrap();
    let signature = key_pair.sign(&message);
    value["$qdrant_sec_client_ckks_vector"]["signature"]["sig"] =
        json!(BASE64URL_NOPAD.encode(signature.as_ref()));
    value
}

#[test]
fn client_ckks_vector_payload_validation_binds_signature_and_aad() {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();
    let value = signed_client_ckks_vector_payload(&key_pair, "tenant-a/signing-v1");

    let verified = validate_client_ckks_vector_payload_value_for_runtime(
        &value,
        ClientCkksVectorValidationContext {
            collection_id: "collection-uuid",
            point_id: "point-1",
            vector_name: "embedding",
            expected_key_id: "tenant-a:docs",
            expected_rk_id: "tenant-a/vector-rk",
            min_rk_epoch: 3,
            max_rk_epoch: 3,
            expected_context_digest: &public_material()
                .digest_for(&CkksParameters::openfhe_default_128_bit()),
            max_slots: CkksParameters::openfhe_default_128_bit().batch_size as usize,
            signature_verification: ClientCkksVectorSignatureVerification {
                expected_key_id: "tenant-a/signing-v1",
                public_key: &public_key,
            },
        },
    )
    .unwrap();
    assert!(
        verified
            .envelope_key()
            .matches_binding("collection-uuid", "point-1", "embedding")
    );

    let err = validate_client_ckks_vector_payload_value_for_runtime(
        &value,
        ClientCkksVectorValidationContext {
            collection_id: "collection-uuid",
            point_id: "point-2",
            vector_name: "embedding",
            expected_key_id: "tenant-a:docs",
            expected_rk_id: "tenant-a/vector-rk",
            min_rk_epoch: 3,
            max_rk_epoch: 3,
            expected_context_digest: &public_material()
                .digest_for(&CkksParameters::openfhe_default_128_bit()),
            max_slots: CkksParameters::openfhe_default_128_bit().batch_size as usize,
            signature_verification: ClientCkksVectorSignatureVerification {
                expected_key_id: "tenant-a/signing-v1",
                public_key: &public_key,
            },
        },
    )
    .unwrap_err();
    assert!(matches!(err, CkksError::MalformedEnvelope(message) if message.contains("point_id")));
}

#[test]
fn client_ckks_vector_signature_message_matches_sdk_test_vector() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../docs/qdrant-sec-client-ckks-vector-signature-test-vector.json"
    ))
    .unwrap();
    let get = |key: &str| fixture.get(key).and_then(Value::as_str).unwrap();
    let value = json!({
        "$qdrant_sec_client_ckks_vector": {
            "version": fixture["version"].as_u64().unwrap(),
            "scheme": get("scheme"),
            "security_profile": get("security_profile"),
            "collection_id": get("collection_id"),
            "point_id": get("point_id"),
            "vector_name": get("vector_name"),
            "key_id": get("key_id"),
            "rk_id": get("rk_id"),
            "rk_epoch": fixture["rk_epoch"].as_u64().unwrap(),
            "context_digest": get("context_digest"),
            "slots": fixture["slots"].as_u64().unwrap(),
            "ciphertext_sha256": get("ciphertext_sha256"),
            "ciphertext": get("ciphertext"),
            "signature": {
                "alg": get("signature_alg"),
                "key_id": get("signature_key_id"),
                "sig": BASE64URL_NOPAD.encode(&[0_u8; 64]),
            },
        },
    });

    let message = client_ckks_vector_signature_message(&value).unwrap();

    assert_eq!(
        message.len() as u64,
        fixture["signature_message_len"].as_u64().unwrap()
    );
    assert_eq!(
        BASE64URL_NOPAD.encode(&message),
        get("signature_message_b64")
    );

    let mut changed = value.clone();
    changed["$qdrant_sec_client_ckks_vector"]["vector_name"] = json!("other");
    assert_ne!(
        message,
        client_ckks_vector_signature_message(&changed).unwrap()
    );
}

#[test]
fn debug_redacts_ckks_plaintext_and_ciphertext_material() {
    let parameters = CkksParameters::openfhe_default_128_bit();
    let material = public_material();
    let values = [12345.625, -987.5];
    let second_values = [777.25, 888.5];
    let ciphertext = b"ckks-ciphertext-sentinel";
    let second_ciphertext = b"ckks-second-ciphertext-sentinel";
    let encrypted_query = b"ckks-encrypted-query-sentinel";
    let context_debug = format!("{material:?}");
    assert!(context_debug.contains("crypto_context_len"));
    assert!(context_debug.contains("public_key_len"));
    assert!(!context_debug.contains("openfhe crypto context"));
    assert!(!context_debug.contains("openfhe public key"));

    let encryption_debug = format!(
        "{:?}",
        CkksEncryptionInput {
            parameters: &parameters,
            public_material: &material,
            collection: "docs",
            point_id: "point-1",
            vector_name: "embedding",
            values: &values,
        }
    );
    assert!(encryption_debug.contains("values_len"));
    assert!(!encryption_debug.contains("12345.625"));
    assert!(!encryption_debug.contains("-987.5"));

    let batch_debug = format!(
        "{:?}",
        CkksBatchEncryptionInput {
            parameters: &parameters,
            public_material: &material,
            collection: "docs",
            vector_name: "embedding",
            items: &[
                CkksVectorBatchItem {
                    point_id: "point-1",
                    values: &values,
                },
                CkksVectorBatchItem {
                    point_id: "point-2",
                    values: &second_values,
                },
            ],
        }
    );
    assert!(batch_debug.contains("values_len"));
    assert!(!batch_debug.contains("777.25"));
    assert!(!batch_debug.contains("888.5"));

    let query_debug = format!(
        "{:?}",
        CkksQueryEncryptionInput {
            parameters: &parameters,
            public_material: &material,
            collection: "docs",
            vector_name: "embedding",
            values: &values,
        }
    );
    assert!(query_debug.contains("values_len"));
    assert!(!query_debug.contains("12345.625"));

    let plaintext_score_debug = format!(
        "{:?}",
        CkksPlaintextQueryScoreInput {
            parameters: &parameters,
            public_material: &material,
            collection: "docs",
            point_id: "point-1",
            vector_name: "embedding",
            distance: "dot",
            query_values: &values,
            ciphertext,
        }
    );
    assert!(plaintext_score_debug.contains("query_values_len"));
    assert!(plaintext_score_debug.contains("ciphertext_len"));
    assert!(!plaintext_score_debug.contains("12345.625"));
    assert!(!plaintext_score_debug.contains("ckks-ciphertext-sentinel"));

    let plaintext_score_batch_debug = format!(
        "{:?}",
        CkksPlaintextQueryScoreBatchInput {
            parameters: &parameters,
            public_material: &material,
            collection: "docs",
            vector_name: "embedding",
            distance: "dot",
            query_values: &values,
            items: &[
                CkksPlaintextQueryScoreBatchItem {
                    point_id: "point-1",
                    ciphertext,
                },
                CkksPlaintextQueryScoreBatchItem {
                    point_id: "point-2",
                    ciphertext: second_ciphertext,
                },
            ],
        }
    );
    assert!(plaintext_score_batch_debug.contains("ciphertext_len"));
    assert!(!plaintext_score_batch_debug.contains("ckks-second-ciphertext-sentinel"));

    let encrypted_score_debug = format!(
        "{:?}",
        CkksEncryptedQueryScoreInput {
            parameters: &parameters,
            public_material: &material,
            collection: "docs",
            point_id: "point-1",
            vector_name: "embedding",
            distance: "dot",
            encrypted_query,
            ciphertext,
        }
    );
    assert!(encrypted_score_debug.contains("encrypted_query_len"));
    assert!(encrypted_score_debug.contains("ciphertext_len"));
    assert!(!encrypted_score_debug.contains("ckks-encrypted-query-sentinel"));
    assert!(!encrypted_score_debug.contains("ckks-ciphertext-sentinel"));

    let encrypted_score_batch_debug = format!(
        "{:?}",
        CkksEncryptedQueryScoreBatchInput {
            parameters: &parameters,
            public_material: &material,
            collection: "docs",
            vector_name: "embedding",
            distance: "dot",
            encrypted_query,
            items: &[
                CkksEncryptedQueryScoreBatchItem {
                    point_id: "point-1",
                    ciphertext,
                },
                CkksEncryptedQueryScoreBatchItem {
                    point_id: "point-2",
                    ciphertext: second_ciphertext,
                },
            ],
        }
    );
    assert!(encrypted_score_batch_debug.contains("encrypted_query_len"));
    assert!(encrypted_score_batch_debug.contains("ciphertext_len"));
    assert!(!encrypted_score_batch_debug.contains("ckks-encrypted-query-sentinel"));
    assert!(!encrypted_score_batch_debug.contains("ckks-second-ciphertext-sentinel"));

    let verified_debug = format!(
        "{:?}",
        VerifiedCkksVector {
            crypto_schema_version: 1,
            encryption_epoch: 3,
            key_id: "tenant-a:ckks".to_string(),
            vector_name: "embedding".to_string(),
            slots: values.len(),
            context_digest: BASE64URL_NOPAD.encode(&[9_u8; 32]),
            ciphertext: BASE64URL_NOPAD.encode(ciphertext),
        }
    );
    assert!(verified_debug.contains("ciphertext_len"));
    assert!(!verified_debug.contains("tenant-a:ckks"));
    assert!(!verified_debug.contains(&BASE64URL_NOPAD.encode(&[9_u8; 32])));
    assert!(!verified_debug.contains(&BASE64URL_NOPAD.encode(ciphertext)));
}

#[test]
fn ckks_error_debug_redacts_attacker_controlled_values() {
    let sentinel = "ckks-error-debug-sentinel";
    let errors = [
        CkksError::InvalidContext(format!("context.{sentinel}")),
        CkksError::InvalidParameters(format!("params.{sentinel}")),
        CkksError::UnsupportedScheme(format!("scheme.{sentinel}")),
        CkksError::MalformedEnvelope(format!("envelope.{sentinel}")),
        CkksError::Backend(format!("backend.{sentinel}")),
        CkksError::Envelope(EncryptionError::UnsupportedAlgorithm(format!(
            "algorithm.{sentinel}"
        ))),
    ];

    for error in errors {
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }
}

fn test_ckks_encryptor<B: CkksVectorBackend>(
    key_id: impl Into<String>,
    vector_name: impl Into<String>,
    parameters: CkksParameters,
    resource_key: SecretKey,
    backend: B,
) -> Result<CkksVectorEncryptor<B>, CkksError> {
    CkksVectorEncryptor::new_from_resource_key_with_material_fingerprint(
        key_id,
        vector_name,
        parameters,
        &resource_key,
        "tenant-a/vector@v1",
        backend,
    )
}

fn encryptor() -> CkksVectorEncryptor<SealedTestBackend> {
    test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        SealedTestBackend,
    )
    .unwrap()
}

#[test]
fn encrypt_sidecar_payload_value_returns_runtime_verified_proof() {
    let encryptor = encryptor()
        .with_collection_identity("collection-uuid-1")
        .unwrap();
    let material = public_material();
    let (value, proof) = encryptor
        .encrypt_sidecar_payload_value("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();

    let envelope_key =
        ckks_vector_sidecar_envelope_key(&value, "collection-uuid-1", "point-1", "embedding")
            .unwrap()
            .unwrap();
    assert_eq!(proof.envelope_key(), &envelope_key);

    let wrong_point_key =
        ckks_vector_sidecar_envelope_key(&value, "collection-uuid-1", "point-2", "embedding")
            .unwrap()
            .unwrap();
    assert_ne!(proof.envelope_key(), &wrong_point_key);

    let mut tampered_value = value.clone();
    tampered_value
        .get_mut(ENCRYPTED_CKKS_VECTOR_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "ciphertext".to_string(),
            serde_json::Value::String(BASE64URL_NOPAD.encode(b"tampered-ckks-ciphertext")),
        );
    let tampered_key = ckks_vector_sidecar_envelope_key(
        &tampered_value,
        "collection-uuid-1",
        "point-1",
        "embedding",
    )
    .unwrap()
    .unwrap();
    assert_ne!(proof.envelope_key(), &tampered_key);
}

#[test]
fn ckks_vector_rejects_oversized_ciphertext_at_seal_and_proof_boundaries() {
    let oversized_encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        OversizedCiphertextBackend,
    )
    .unwrap();

    let err = oversized_encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap_err();
    assert!(
        matches!(err, CkksError::MalformedEnvelope(ref message) if message.contains("maximum size")),
        "{err:?}",
    );

    let (mut value, _) = encryptor()
        .with_collection_identity("collection-uuid-1")
        .unwrap()
        .encrypt_sidecar_payload_value("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    value
        .get_mut(ENCRYPTED_CKKS_VECTOR_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "ciphertext".to_string(),
            serde_json::Value::String(BASE64URL_NOPAD.encode(&vec![8_u8; 17 * 1024 * 1024])),
        );

    let err = ckks_vector_sidecar_envelope_key(&value, "collection-uuid-1", "point-1", "embedding")
        .unwrap_err();
    assert!(
        matches!(err, CkksError::MalformedEnvelope(ref message) if message.contains("maximum size")),
        "{err:?}",
    );
}

#[test]
fn ckks_vector_delete_target_rejects_oversized_digest_before_decode() {
    let oversized_digest = "A".repeat(44);
    assert!(matches!(
        ckks_vector_verified_sidecar_delete_key(
            "collection-uuid-1",
            "embedding",
            CkksVectorSidecarDeleteTarget::PointIds {
                digest_b64: oversized_digest,
            },
        ),
        Err(CkksError::InvalidDeleteTarget)
    ));
}

#[test]
fn ckks_vector_encrypt_batch_uses_backend_batch_and_binds_each_point() {
    let backend = BatchTestBackend::new();
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend.clone(),
    )
    .unwrap();
    let material = public_material();
    let first = [1.0, 2.0];
    let second = [3.0, 4.0, 5.0];
    let items = [
        CkksVectorBatchItem {
            point_id: "point-1",
            values: &first,
        },
        CkksVectorBatchItem {
            point_id: "point-2",
            values: &second,
        },
    ];

    let encrypted = encryptor.encrypt_batch("docs", &material, &items).unwrap();

    assert_eq!(backend.batch_calls.load(Ordering::Relaxed), 1);
    assert_eq!(backend.single_calls.load(Ordering::Relaxed), 0);
    assert_eq!(encrypted.len(), 2);
    assert_eq!(
        encryptor
            .open("docs", "point-1", &material, &encrypted[0])
            .unwrap()
            .slots,
        2,
    );
    assert_eq!(
        encryptor
            .open("docs", "point-2", &material, &encrypted[1])
            .unwrap()
            .slots,
        3,
    );
    assert!(matches!(
        encryptor.open("docs", "point-2", &material, &encrypted[0]),
        Err(CkksError::Envelope(_)),
    ));
}

#[test]
fn ckks_vector_plaintext_query_scoring_uses_verified_ciphertext() {
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        ScoreTestBackend,
    )
    .unwrap();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();

    let score = encryptor
        .score_plaintext_query(
            "docs",
            "point-1",
            &public_material(),
            &encrypted,
            "dot",
            &[0.5, 0.25],
        )
        .unwrap();

    assert_eq!(score, 42.25);
}

#[test]
fn ckks_vector_plaintext_query_batch_scoring_uses_backend_batch() {
    let backend = BatchScoreTestBackend::new();
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend.clone(),
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    let scores = encryptor
        .score_plaintext_query_batch(
            "docs",
            &public_material(),
            &[("point-1", &first), ("point-2", &second)],
            "dot",
            &[0.5, 0.25],
        )
        .unwrap();

    assert_eq!(scores, vec![10.0, 5.0]);
    assert_eq!(backend.batch_calls.load(Ordering::Relaxed), 1);
    assert_eq!(backend.single_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn ckks_vector_stored_query_batch_rejects_backend_score_count_mismatch() {
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        MismatchedEncryptedScoreBatchBackend,
    )
    .unwrap();
    let query = encryptor
        .encrypt("docs", "query-point", &public_material(), &[1.0, 2.0])
        .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[3.0, 4.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[5.0, 6.0])
        .unwrap();

    let err = encryptor
        .score_stored_query_batch(
            "docs",
            &public_material(),
            "query-point",
            &query,
            &[("point-1", &first), ("point-2", &second)],
            "dot",
        )
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("OpenFHE backend returned 1 scores for 2 encrypted vectors")
    ));
}

#[test]
fn ckks_vector_plaintext_query_scoring_rejects_dimension_mismatch() {
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        ScoreTestBackend,
    )
    .unwrap();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();

    let err = encryptor
        .score_plaintext_query(
            "docs",
            "point-1",
            &public_material(),
            &encrypted,
            "dot",
            &[0.5],
        )
        .unwrap_err();

    assert_eq!(
        err,
        CkksError::QueryDimensionMismatch {
            query_len: 1,
            slots: 2,
        }
    );
}

#[test]
fn ckks_vector_envelope_does_not_serialize_plain_embedding() {
    let material = public_material();
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &material, &[0.125, -42.5, 9.75])
        .unwrap();
    let verified = encryptor()
        .open("docs", "point-1", &material, &encrypted)
        .unwrap();

    assert_eq!(encrypted.scheme, "openfhe-ckks");
    assert_eq!(encrypted.envelope.key_id, "tenant-a:ckks");
    assert_eq!(verified.crypto_schema_version, 1);
    assert_eq!(verified.encryption_epoch, 0);
    assert_eq!(verified.key_id, "tenant-a:ckks");
    assert_eq!(verified.vector_name, "embedding");
    assert_eq!(verified.slots, 3);

    let serialized = serde_json::to_string(&encrypted).unwrap();
    assert!(!serialized.contains("0.125"));
    assert!(!serialized.contains("-42.5"));
    assert!(!serialized.contains("9.75"));
    assert!(!serialized.contains("\"vector_name\":\"embedding\""));

    let debug = format!("{encrypted:?}");
    assert!(debug.contains("EncryptedEnvelope"));
    assert!(!debug.contains(&encrypted.envelope.ciphertext));
}

#[test]
fn ckks_vector_envelope_rejects_unknown_metadata_fields() {
    let material = public_material();
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &material, &[0.125, -42.5, 9.75])
        .unwrap();

    let mut top_level = serde_json::to_value(&encrypted).unwrap();
    top_level
        .as_object_mut()
        .unwrap()
        .insert("unexpected_header".to_string(), json!(true));
    assert!(serde_json::from_value::<EncryptedCkksVector>(top_level).is_err());

    let mut envelope_header = serde_json::to_value(&encrypted).unwrap();
    envelope_header
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unexpected_envelope".to_string(), json!(true));
    assert!(serde_json::from_value::<EncryptedCkksVector>(envelope_header).is_err());
}

#[test]
fn context_digest_changes_with_public_material_and_parameters() {
    let base = public_material();
    let other_key =
        CkksPublicMaterial::new(b"openfhe crypto context".to_vec(), b"other key".to_vec()).unwrap();
    let default_params = CkksParameters::openfhe_default_128_bit();
    let base_digest = base.digest_for(&CkksParameters::openfhe_default_128_bit());

    assert_ne!(
        base_digest,
        other_key.digest_for(&CkksParameters::openfhe_default_128_bit()),
    );

    let mut changed_poly = default_params;
    changed_poly.poly_modulus_degree += 1;
    let mut changed_depth = default_params;
    changed_depth.multiplicative_depth += 1;
    let mut changed_scale = default_params;
    changed_scale.scaling_mod_size += 1;
    let mut changed_first = default_params;
    changed_first.first_mod_size += 1;
    let mut changed_batch = default_params;
    changed_batch.batch_size += 1;

    for changed_params in [
        changed_poly,
        changed_depth,
        changed_scale,
        changed_first,
        changed_batch,
    ] {
        assert_ne!(base_digest, base.digest_for(&changed_params));
    }
}

#[test]
fn open_rejects_encryption_epoch_mismatch() {
    let material = public_material();
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();
    let next_epoch_encryptor = encryptor().with_encryption_epoch(1);

    assert_eq!(
        next_epoch_encryptor.open("docs", "point-1", &material, &encrypted),
        Err(CkksError::EncryptionEpochMismatch),
    );
}

#[test]
fn vector_open_accepts_retired_metadata_key_but_new_writes_use_active_key() {
    let material = public_material();
    let old_encrypted = encryptor()
        .encrypt("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();
    let rotated_encryptor = test_ckks_encryptor(
        "tenant-a:ckks-v2",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([30u8; 32]),
        SealedTestBackend,
    )
    .unwrap()
    .with_retired_metadata_key_with_material_fingerprint(
        "tenant-a:ckks",
        &SecretKey::from_bytes([29u8; 32]),
        "tenant-a/vector@v1",
    )
    .unwrap();

    let verified = rotated_encryptor
        .open("docs", "point-1", &material, &old_encrypted)
        .unwrap();

    assert_eq!(verified.key_id, "tenant-a:ckks");

    let new_encrypted = rotated_encryptor
        .encrypt("docs", "point-2", &material, &[3.0, 4.0])
        .unwrap();
    let new_verified = rotated_encryptor
        .open("docs", "point-2", &material, &new_encrypted)
        .unwrap();

    assert_eq!(new_encrypted.envelope.key_id, "tenant-a:ckks-v2");
    assert_eq!(new_verified.key_id, "tenant-a:ckks-v2");
}

#[test]
fn ckks_vector_envelope_records_resource_key_metadata() {
    let material = public_material();
    let resource_key = SecretKey::from_bytes([29u8; 32]);
    let encryptor = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        &resource_key,
        "tenant-a/vector-rk@v3",
        "tenant-a/vector-rk-v3",
        3,
        SealedTestBackend,
    )
    .unwrap();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();

    assert_eq!(
        encrypted.envelope.material_fingerprint,
        "tenant-a/vector-rk@v3"
    );
    assert_eq!(encrypted.envelope.rk_id, "tenant-a/vector-rk-v3");
    assert_eq!(encrypted.envelope.rk_epoch, Some(3));
    assert_eq!(
        encryptor
            .open("docs", "point-1", &material, &encrypted)
            .unwrap()
            .key_id,
        "tenant-a:ckks",
    );

    let wrong_epoch = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        &resource_key,
        "tenant-a/vector-rk@v3",
        "tenant-a/vector-rk-v3",
        4,
        SealedTestBackend,
    )
    .unwrap();
    assert!(matches!(
        wrong_epoch.open("docs", "point-1", &material, &encrypted),
        Err(CkksError::Envelope(EncryptionError::KeyMismatch)),
    ));

    let rotated = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:ckks-v4",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        &SecretKey::from_bytes([30u8; 32]),
        "tenant-a/vector-rk@v4",
        "tenant-a/vector-rk-v4",
        4,
        SealedTestBackend,
    )
    .unwrap()
    .with_retired_metadata_resource_key(
        "tenant-a:ckks",
        &resource_key,
        "tenant-a/vector-rk@v3",
        "tenant-a/vector-rk-v3",
        3,
    )
    .unwrap();
    assert_eq!(
        rotated
            .open("docs", "point-1", &material, &encrypted)
            .unwrap()
            .key_id,
        "tenant-a:ckks",
    );
}

#[test]
fn open_rejects_context_digest_mismatch() {
    let material = public_material();
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();
    let other_material =
        CkksPublicMaterial::new(b"openfhe crypto context".to_vec(), b"other key".to_vec()).unwrap();

    assert!(matches!(
        encryptor().open("docs", "point-1", &other_material, &encrypted),
        Err(CkksError::MalformedEnvelope(message))
            if message.contains("context digest does not match")
    ));
}

#[test]
fn vector_validation_fails_closed_before_backend_call() {
    let encryptor = encryptor();
    let material = public_material();

    assert_eq!(
        encryptor.encrypt("docs", "point-1", &material, &[]),
        Err(CkksError::EmptyVector),
    );
    assert_eq!(
        encryptor.encrypt("docs", "point-1", &material, &[f64::NAN]),
        Err(CkksError::NonFiniteValue { index: 0 }),
    );

    let small_params = CkksParameters {
        batch_size: 1,
        ..CkksParameters::openfhe_default_128_bit()
    };
    let small_encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        small_params,
        SecretKey::from_bytes([29u8; 32]),
        SealedTestBackend,
    )
    .unwrap();
    assert_eq!(
        small_encryptor.encrypt("docs", "point-1", &material, &[1.0, 2.0]),
        Err(CkksError::VectorTooWide {
            len: 2,
            batch_size: 1,
        }),
    );
}

#[test]
fn ckks_parameter_validation_rejects_unsafe_shapes() {
    assert_eq!(
        CkksParameters::openfhe_default_128_bit().security_profile(),
        Some(CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50),
    );

    let mut params = CkksParameters::openfhe_default_128_bit();
    params.poly_modulus_degree = 12_288;
    assert!(matches!(
        params.validate(),
        Err(CkksError::InvalidParameters(_)),
    ));

    let mut params = CkksParameters::openfhe_default_128_bit();
    params.multiplicative_depth = 5;
    assert!(matches!(
        params.validate(),
        Err(CkksError::InvalidParameters(message)) if message.contains("allowlisted profile"),
    ));

    let mut params = CkksParameters::openfhe_default_128_bit();
    params.batch_size = params.poly_modulus_degree;
    assert!(matches!(
        params.validate(),
        Err(CkksError::InvalidParameters(_)),
    ));

    let mut params = CkksParameters::openfhe_default_128_bit();
    params.scaling_mod_size = 12;
    assert!(matches!(
        params.validate(),
        Err(CkksError::InvalidParameters(_)),
    ));
}

#[test]
fn constructor_rejects_invalid_identifiers_and_public_material() {
    assert_eq!(
        test_ckks_encryptor(
            "tenant/key",
            "embedding",
            CkksParameters::openfhe_default_128_bit(),
            SecretKey::from_bytes([29u8; 32]),
            SealedTestBackend,
        )
        .err(),
        Some(CkksError::InvalidKeyId),
    );
    assert_eq!(
        test_ckks_encryptor(
            "tenant-a:ckks",
            "bad\0name",
            CkksParameters::openfhe_default_128_bit(),
            SecretKey::from_bytes([29u8; 32]),
            SealedTestBackend,
        )
        .err(),
        Some(CkksError::InvalidVectorName),
    );
    assert!(matches!(
        CkksPublicMaterial::new(Vec::new(), b"pk".to_vec()),
        Err(CkksError::InvalidContext(_)),
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_checked_constructor_validates_bridge_path() {
    use std::os::unix::fs::PermissionsExt;

    assert!(matches!(
        CommandOpenFheBackend::new_checked("bash"),
        Err(CkksError::Backend(message)) if message.contains("absolute path")
    ));

    let dir = tempfile::Builder::new()
        .prefix("openfhe-checked")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let script_path = dir.path().join("checked-openfhe-bridge.sh");
    fs::write(&script_path, b"#!/bin/sh\n").unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    assert!(CommandOpenFheBackend::new_checked(&script_path).is_ok());
    let bridge_digest = Sha256::digest(fs::read(&script_path).unwrap());
    assert!(
        CommandOpenFheBackend::new_checked_with_sha256_b64(
            &script_path,
            BASE64URL_NOPAD.encode(&bridge_digest),
        )
        .is_ok()
    );
    assert!(matches!(
        CommandOpenFheBackend::new_checked_with_sha256_b64(
            &script_path,
            BASE64URL_NOPAD.encode(&[0u8; 32]),
        ),
        Err(CkksError::Backend(message)) if message.contains("sha256 pin does not match")
    ));
    assert!(matches!(
        CommandOpenFheBackend::new_checked_with_sha256_b64(
            &script_path,
            format!("{}!", "A".repeat(42)),
        ),
        Err(CkksError::Backend(message)) if message.contains("base64url-no-padding")
    ));

    let mut permissions = fs::metadata(dir.path()).unwrap().permissions();
    permissions.set_mode(0o777);
    fs::set_permissions(dir.path(), permissions).unwrap();
    assert!(matches!(
        CommandOpenFheBackend::new_checked(&script_path),
        Err(CkksError::Backend(message)) if message.contains("parent directory")
    ));
    let mut permissions = fs::metadata(dir.path()).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(dir.path(), permissions).unwrap();

    let symlink_path = dir.path().join("checked-openfhe-bridge-link.sh");
    std::os::unix::fs::symlink(&script_path, &symlink_path).unwrap();
    assert!(matches!(
        CommandOpenFheBackend::new_checked(&symlink_path),
        Err(CkksError::Backend(message)) if message.contains("non-symlink")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_revalidates_bridge_before_spawn() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::Builder::new()
        .prefix("openfhe-spawn-revalidate")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let script_path = dir.path().join("checked-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let bridge_digest = Sha256::digest(fs::read(&script_path).unwrap());
    let backend = CommandOpenFheBackend::new_checked_with_sha256_b64(
        &script_path,
        BASE64URL_NOPAD.encode(&bridge_digest),
    )
    .unwrap();

    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"cmVwbGFjZWQtY2lwaGVy"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(message) if message.contains("sha256 pin does not match"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn command_openfhe_backend_sets_no_new_privs_before_spawn() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::Builder::new()
        .prefix("openfhe-no-new-privs")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let script_path = dir.path().join("checked-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env python3
import ctypes
import signal
import os
import resource
import sys

with open("/proc/self/status", encoding="utf-8") as status:
    no_new_privs = next(
        (line.split()[1] for line in status if line.startswith("NoNewPrivs:")),
        None,
    )
if no_new_privs != "1":
    print("no_new_privs was not set", file=sys.stderr)
    raise SystemExit(17)

if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
    print("core dumps were not disabled", file=sys.stderr)
    raise SystemExit(19)

if resource.getrlimit(resource.RLIMIT_FSIZE) != (0, 0):
    print("regular file writes were not disabled", file=sys.stderr)
    raise SystemExit(23)

if os.getcwd() != "/":
    print(f"bridge inherited qdrant cwd: {os.getcwd()}", file=sys.stderr)
    raise SystemExit(24)

current_umask = os.umask(0o077)
os.umask(current_umask)
if current_umask != 0o077:
    print(f"bridge umask was not restricted: {oct(current_umask)}", file=sys.stderr)
    raise SystemExit(22)

value = ctypes.c_int(0)
if ctypes.CDLL(None).prctl(2, ctypes.byref(value), 0, 0, 0) != 0:
    raise SystemExit(2)
if value.value != signal.SIGKILL:
    print("parent death signal was not set to SIGKILL", file=sys.stderr)
    raise SystemExit(21)

for name in (
    "QDRANT",
    "QDRANT__SERVICE__API_KEY_FOR_TEST",
    "QDRANT_SERVICE_API_KEY_FOR_TEST",
    "QDRANT__CRYPTO__BRIDGE_ENV_SECRET_FOR_TEST",
    "QDRANT_CRYPTO_BRIDGE_ENV_SECRET_FOR_TEST",
    "QDRANT__CKKS__BRIDGE_ENV_SECRET_FOR_TEST",
    "QDRANT_CKKS_BRIDGE_ENV_SECRET_FOR_TEST",
    "TENANT_PAYLOAD_KEY_FOR_TEST",
    "OPENFHE_BRIDGE_UNTRUSTED_ENV_FOR_TEST",
):
    if os.environ.get(name):
        print(f"secret env leaked to bridge: {name}", file=sys.stderr)
        raise SystemExit(20)

sys.stdin.readline()
print('{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}', flush=True)
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    for name in [
        "QDRANT",
        "QDRANT__SERVICE__API_KEY_FOR_TEST",
        "QDRANT_SERVICE_API_KEY_FOR_TEST",
        "QDRANT__CRYPTO__BRIDGE_ENV_SECRET_FOR_TEST",
        "QDRANT_CRYPTO_BRIDGE_ENV_SECRET_FOR_TEST",
        "QDRANT__CKKS__BRIDGE_ENV_SECRET_FOR_TEST",
        "QDRANT_CKKS_BRIDGE_ENV_SECRET_FOR_TEST",
        "TENANT_PAYLOAD_KEY_FOR_TEST",
        "OPENFHE_BRIDGE_UNTRUSTED_ENV_FOR_TEST",
    ] {
        unsafe {
            std::env::set_var(name, "must-not-reach-bridge");
        }
    }
    let backend = CommandOpenFheBackend::new_checked(&script_path)
        .unwrap()
        .with_sensitive_env_names(["TENANT_PAYLOAD_KEY_FOR_TEST"]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let encrypted = encryptor.encrypt("docs", "point-1", &public_material(), &[1.0]);
    for name in [
        "QDRANT",
        "QDRANT__SERVICE__API_KEY_FOR_TEST",
        "QDRANT_SERVICE_API_KEY_FOR_TEST",
        "QDRANT__CRYPTO__BRIDGE_ENV_SECRET_FOR_TEST",
        "QDRANT_CRYPTO_BRIDGE_ENV_SECRET_FOR_TEST",
        "QDRANT__CKKS__BRIDGE_ENV_SECRET_FOR_TEST",
        "QDRANT_CKKS_BRIDGE_ENV_SECRET_FOR_TEST",
        "TENANT_PAYLOAD_KEY_FOR_TEST",
        "OPENFHE_BRIDGE_UNTRUSTED_ENV_FOR_TEST",
    ] {
        unsafe {
            std::env::remove_var(name);
        }
    }
    let encrypted = encrypted.unwrap();
    assert_eq!(encrypted.version, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn command_openfhe_backend_landlock_sandbox_denies_file_creation() {
    use std::os::unix::fs::PermissionsExt;

    if !linux_landlock_write_deny_supported_for_test() {
        eprintln!("skipping Landlock bridge sandbox test: kernel does not support Landlock");
        return;
    }

    let dir = tempfile::Builder::new()
        .prefix("openfhe-landlock")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let denied_path = dir.path().join("bridge-created-file");
    let script_path = dir.path().join("checked-openfhe-bridge.sh");
    fs::write(
        &script_path,
        format!(
            r#"#!/usr/bin/env python3
import os
import sys

try:
    open({denied_path:?}, "w", encoding="utf-8").close()
except OSError:
    pass
else:
    print("Landlock did not deny bridge file creation", file=sys.stderr)
    raise SystemExit(31)

sys.stdin.readline()
print('{{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}}', flush=True)
"#,
            denied_path = denied_path.to_string_lossy(),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_checked(&script_path)
        .unwrap()
        .with_linux_landlock_write_deny_sandbox();
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap();
    assert_eq!(encrypted.version, 1);
    assert!(
        !denied_path.exists(),
        "Landlock sandbox must prevent bridge-created files"
    );
}

/// Runs a python bridge under the strict Landlock sandbox that probes a secret file, a directory
/// listing and file creation inside the test directory. With `allow_test_dir` the directory is a
/// configured read root and the reads must succeed; otherwise every read must be denied. File
/// creation must always be denied.
#[cfg(target_os = "linux")]
fn run_landlock_strict_probe(allow_test_dir: bool) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::Builder::new()
        .prefix("openfhe-landlock-strict")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let secret_path = dir.path().join("storage-secret");
    fs::write(&secret_path, "resource-key-material").unwrap();
    let denied_path = dir.path().join("bridge-created-file");
    let script_path = dir.path().join("checked-openfhe-bridge.sh");
    fs::write(
        &script_path,
        format!(
            r#"#!/usr/bin/env python3
import os
import sys

expect_allowed = {expect_allowed}

def check(label, action):
    try:
        action()
    except PermissionError:
        if expect_allowed:
            print(label + " was denied although the directory is an allowed read root", file=sys.stderr)
            raise SystemExit(31)
    else:
        if not expect_allowed:
            print(label + " was not denied by the strict Landlock sandbox", file=sys.stderr)
            raise SystemExit(32)

check("secret read", lambda: open({secret_path:?}, "r", encoding="utf-8").read())
check("directory listing", lambda: os.listdir({dir_path:?}))
try:
    open({denied_path:?}, "w", encoding="utf-8").close()
except PermissionError:
    pass
else:
    print("file creation was not denied by the strict Landlock sandbox", file=sys.stderr)
    raise SystemExit(33)

sys.stdin.readline()
print('{{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}}', flush=True)
"#,
            expect_allowed = if allow_test_dir { "True" } else { "False" },
            secret_path = secret_path.to_string_lossy(),
            dir_path = dir.path().to_string_lossy(),
            denied_path = denied_path.to_string_lossy(),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let read_roots: Vec<PathBuf> = if allow_test_dir {
        vec![dir.path().to_path_buf()]
    } else {
        Vec::new()
    };
    let backend = CommandOpenFheBackend::new_checked(&script_path)
        .unwrap()
        .with_linux_landlock_read_allow_roots(read_roots)
        .unwrap()
        .with_linux_landlock_strict_sandbox();
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_or_else(|err| {
            panic!("strict Landlock bridge probe failed (allow_test_dir={allow_test_dir}): {err}")
        });
    assert_eq!(encrypted.version, 1);
    assert!(
        !denied_path.exists(),
        "strict Landlock sandbox must prevent bridge-created files"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn command_openfhe_backend_landlock_strict_sandbox_denies_reads_outside_the_allow_list() {
    if !linux_landlock_write_deny_supported_for_test() {
        eprintln!("skipping strict Landlock bridge sandbox test: kernel does not support Landlock");
        return;
    }
    run_landlock_strict_probe(false);
}

#[cfg(target_os = "linux")]
#[test]
fn command_openfhe_backend_landlock_strict_sandbox_allows_configured_read_roots() {
    if !linux_landlock_write_deny_supported_for_test() {
        eprintln!("skipping strict Landlock bridge sandbox test: kernel does not support Landlock");
        return;
    }
    run_landlock_strict_probe(true);
}

#[cfg(target_os = "linux")]
#[test]
fn command_openfhe_backend_landlock_strict_sandbox_fails_closed_for_missing_read_roots() {
    use std::os::unix::fs::PermissionsExt;

    if !linux_landlock_write_deny_supported_for_test() {
        eprintln!("skipping strict Landlock bridge sandbox test: kernel does not support Landlock");
        return;
    }

    let dir = tempfile::Builder::new()
        .prefix("openfhe-landlock-strict-missing")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let script_path = dir.path().join("checked-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env python3
import sys
sys.stdin.readline()
print('{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}', flush=True)
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_checked(&script_path)
        .unwrap()
        .with_linux_landlock_read_allow_roots([dir.path().join("missing-read-root")])
        .unwrap()
        .with_linux_landlock_strict_sandbox();
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .expect_err("a configured read root that does not exist must fail the spawn closed");
    assert!(
        err.to_string().contains("failed to start OpenFHE bridge"),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_uses_bridge_protocol() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("fake-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r request
case "$request" in
  *'"operation":"encrypt"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*'"context_id"'*) ;;
  *) exit 7 ;;
esac
printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();
    let single_batch_values = [5.0, 6.0];
    let single_batch = encryptor
        .encrypt_batch(
            "docs",
            &public_material(),
            &[CkksVectorBatchItem {
                point_id: "point-3",
                values: &single_batch_values,
            }],
        )
        .unwrap();

    assert_eq!(
        encryptor
            .open("docs", "point-1", &public_material(), &first)
            .unwrap()
            .ciphertext,
        BASE64URL_NOPAD.encode(b"openfhe-cipher"),
    );
    assert_eq!(
        encryptor
            .open("docs", "point-2", &public_material(), &second)
            .unwrap()
            .ciphertext,
        BASE64URL_NOPAD.encode(b"openfhe-cipher"),
    );
    assert_eq!(
        encryptor
            .open("docs", "point-3", &public_material(), &single_batch[0])
            .unwrap()
            .ciphertext,
        BASE64URL_NOPAD.encode(b"openfhe-cipher"),
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_reuses_registered_context_material() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("cached-context-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
count=0
while IFS= read -r request; do
  count=$((count + 1))
  case "$request" in
    *'"operation":"encrypt"'*'"scheme":"openfhe-ckks"'*'"context_id"'*) ;;
    *) exit 7 ;;
  esac
  if [[ "$count" -eq 1 ]]; then
    case "$request" in
      *'"parameters"'*'"crypto_context"'*'"public_key"'*) ;;
      *) exit 8 ;;
    esac
  elif [[ "$count" -eq 2 ]]; then
    case "$request" in
      *'"parameters"'*|*'"crypto_context"'*|*'"public_key"'*) exit 9 ;;
    esac
  else
    exit 10
  fi
  printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_reregisters_context_after_worker_restart() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("restarted-context-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r request
case "$request" in
  *'"operation":"encrypt"'*'"scheme":"openfhe-ckks"'*'"context_id"'*'"parameters"'*'"crypto_context"'*'"public_key"'*) ;;
  *) exit 8 ;;
esac

case "$request" in
  *'"point_id":"point-1"'*) printf 'not-json\n' ;;
  *'"point_id":"point-2"'*) printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n' ;;
  *) exit 9 ;;
esac
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap_err();
    encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_reuses_registered_context_for_score_and_query_requests() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir
        .path()
        .join("cached-context-score-query-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
count=0
while IFS= read -r request; do
  count=$((count + 1))
  case "$request" in
    *'"scheme":"openfhe-ckks"'*'"context_id"'*) ;;
    *) exit 7 ;;
  esac
  if [[ "$count" -eq 1 ]]; then
    case "$request" in
      *'"operation":"encrypt"'*'"parameters"'*'"crypto_context"'*'"public_key"'*) ;;
      *) exit 8 ;;
    esac
  else
    case "$request" in
      *'"parameters"'*|*'"crypto_context"'*|*'"public_key"'*) exit 9 ;;
    esac
  fi
  case "$count:$request" in
    1:*'"operation":"encrypt"'*|2:*'"operation":"encrypt"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    3:*'"operation":"score_plaintext_query"'*'"distance":"dot"'*'"query_values":[0.5,0.25]'*'"ciphertext":"b3BlbmZoZS1jaXBoZXI"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","score":12.5}\n'
      ;;
    4:*'"operation":"score_plaintext_query_batch"'*'"distance":"dot"'*'"items":[{"point_id":"point-1","ciphertext":"b3BlbmZoZS1jaXBoZXI"},{"point_id":"point-2","ciphertext":"b3BlbmZoZS1jaXBoZXI"}]'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[12.5,7.25]}\n'
      ;;
    5:*'"operation":"encrypt_query"'*'"values":[0.5,0.25]'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1xdWVyeQ"}\n'
      ;;
    6:*'"operation":"score_encrypted_query_batch"'*'"encrypted_query":"b3BlbmZoZS1xdWVyeQ"'*'"items":[{"point_id":"point-1","ciphertext":"b3BlbmZoZS1jaXBoZXI"},{"point_id":"point-2","ciphertext":"b3BlbmZoZS1jaXBoZXI"}]'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[9.5,4.25]}\n'
      ;;
    *) exit 10 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    let score = encryptor
        .score_plaintext_query(
            "docs",
            "point-1",
            &public_material(),
            &first,
            "dot",
            &[0.5, 0.25],
        )
        .unwrap();
    assert_eq!(score, 12.5);

    let scores = encryptor
        .score_plaintext_query_batch(
            "docs",
            &public_material(),
            &[("point-1", &first), ("point-2", &second)],
            "dot",
            &[0.5, 0.25],
        )
        .unwrap();
    assert_eq!(scores, vec![12.5, 7.25]);

    let encrypted_scores = encryptor
        .score_encrypted_query_batch(
            "docs",
            &public_material(),
            &[("point-1", &first), ("point-2", &second)],
            "dot",
            &[0.5, 0.25],
        )
        .unwrap();
    assert_eq!(encrypted_scores, vec![9.5, 4.25]);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_security_profile_mismatch() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("wrong-profile-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{"version":1,"security_profile":"ckks-unsafe-test-profile","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("security profile does not match expected")
                && message.contains(CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50)
                && !message.contains("ckks-unsafe-test-profile")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_missing_security_profile() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("missing-profile-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{"version":1,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("missing security profile")
                && message.contains(CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50)
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_weak_security_level_metadata() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("weak-level-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","security_level_bits":80,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("security level 80 bits")
                && message.contains("required 128 bits")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_invalid_noise_budget_metadata() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("bad-noise-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"score_plaintext_query"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","noise_budget_bits":-0.5,"score":12.5}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();

    let err = encryptor
        .score_plaintext_query(
            "docs",
            "point-1",
            &public_material(),
            &encrypted,
            "dot",
            &[0.5, 0.25],
        )
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("invalid noise budget")
                && message.contains("-0.5")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_batch_weak_security_level_metadata() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("weak-batch-level-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r request
case "$request" in
  *'"operation":"encrypt_batch"'*'"items"'*) ;;
  *) exit 7 ;;
esac
printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","security_level_bits":80,"ciphertexts":["YmF0Y2gtb25l","YmF0Y2gtdHdv"]}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = [1.0, 2.0];
    let second = [3.0, 4.0];
    let err = encryptor
        .encrypt_batch(
            "docs",
            &public_material(),
            &[
                CkksVectorBatchItem {
                    point_id: "point-1",
                    values: &first,
                },
                CkksVectorBatchItem {
                    point_id: "point-2",
                    values: &second,
                },
            ],
        )
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("security level 80 bits")
                && message.contains("required 128 bits")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_score_batch_invalid_noise_budget_metadata() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("bad-score-batch-noise-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"score_plaintext_query_batch"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","noise_budget_bits":-0.5,"scores":[12.5,7.25]}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    let err = encryptor
        .score_plaintext_query_batch(
            "docs",
            &public_material(),
            &[("point-1", &first), ("point-2", &second)],
            "dot",
            &[0.5, 0.25],
        )
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("invalid noise budget")
                && message.contains("-0.5")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_uses_plaintext_query_score_protocol() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("fake-openfhe-score-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"score_plaintext_query"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*'"distance":"dot"'*'"context_id"'*'"query_values":[0.5,0.25]'*'"ciphertext":"b3BlbmZoZS1jaXBoZXI"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","score":12.5}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();

    let score = encryptor
        .score_plaintext_query(
            "docs",
            "point-1",
            &public_material(),
            &encrypted,
            "dot",
            &[0.5, 0.25],
        )
        .unwrap();

    assert_eq!(score, 12.5);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_uses_plaintext_query_score_batch_protocol() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("fake-openfhe-score-batch-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"score_plaintext_query_batch"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*'"distance":"dot"'*'"context_id"'*'"query_values":[0.5,0.25]'*'"items":[{"point_id":"point-1","ciphertext":"b3BlbmZoZS1jaXBoZXI"},{"point_id":"point-2","ciphertext":"b3BlbmZoZS1jaXBoZXI"}]'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[12.5,7.25]}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    let scores = encryptor
        .score_plaintext_query_batch(
            "docs",
            &public_material(),
            &[("point-1", &first), ("point-2", &second)],
            "dot",
            &[0.5, 0.25],
        )
        .unwrap();

    assert_eq!(scores, vec![12.5, 7.25]);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_uses_encrypted_query_score_batch_protocol() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir
        .path()
        .join("fake-openfhe-encrypted-score-batch-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"encrypt_query"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*'"context_id"'*'"values":[0.5,0.25]'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1xdWVyeQ"}\n'
      ;;
    *'"operation":"score_encrypted_query_batch"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*'"distance":"dot"'*'"context_id"'*'"encrypted_query":"b3BlbmZoZS1xdWVyeQ"'*'"items":[{"point_id":"point-1","ciphertext":"b3BlbmZoZS1jaXBoZXI"},{"point_id":"point-2","ciphertext":"b3BlbmZoZS1jaXBoZXI"}]'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[12.5,7.25]}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    let scores = encryptor
        .score_encrypted_query_batch(
            "docs",
            &public_material(),
            &[("point-1", &first), ("point-2", &second)],
            "dot",
            &[0.5, 0.25],
        )
        .unwrap();

    assert_eq!(scores, vec![12.5, 7.25]);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_encrypted_query_score_batch_response_size_mismatch() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir
        .path()
        .join("bad-openfhe-encrypted-score-batch-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"encrypt_query"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1xdWVyeQ"}\n'
      ;;
    *'"operation":"score_encrypted_query_batch"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[12.5]}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    let err = encryptor
        .score_encrypted_query_batch(
            "docs",
            &public_material(),
            &[("point-1", &first), ("point-2", &second)],
            "dot",
            &[0.5, 0.25],
        )
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("returned 1 batch scores for 2 encrypted vectors")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_encrypted_query_score_batch_security_profile_mismatch() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir
        .path()
        .join("wrong-profile-openfhe-encrypted-score-batch-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"encrypt_query"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1xdWVyeQ"}\n'
      ;;
    *'"operation":"score_encrypted_query_batch"'*)
      printf '{"version":1,"security_profile":"ckks-unsafe-test-profile","scores":[12.5,7.25]}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    let err = encryptor
        .score_encrypted_query_batch(
            "docs",
            &public_material(),
            &[("point-1", &first), ("point-2", &second)],
            "dot",
            &[0.5, 0.25],
        )
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("security profile does not match expected")
                && !message.contains("ckks-unsafe-test-profile")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_scores_stored_ciphertext_as_query() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("fake-openfhe-stored-score-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"score_encrypted_query"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*'"distance":"dot"'*'"encrypted_query":"c3RvcmVkLXF1ZXJ5"'*'"ciphertext":"c3RvcmVkLWNhbmRpZGF0ZQ"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","score":8.5}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*'"point_id":"point-1"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"c3RvcmVkLXF1ZXJ5"}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*'"point_id":"point-2"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"c3RvcmVkLWNhbmRpZGF0ZQ"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let query = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let candidate = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    let scores = encryptor
        .score_stored_query_batch(
            "docs",
            &public_material(),
            "point-1",
            &query,
            &[("point-2", &candidate)],
            "dot",
        )
        .unwrap();

    assert_eq!(scores, vec![8.5]);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_score_batch_response_size_mismatch() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("bad-openfhe-score-batch-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"score_plaintext_query_batch"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[12.5]}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    let err = encryptor
        .score_plaintext_query_batch(
            "docs",
            &public_material(),
            &[("point-1", &first), ("point-2", &second)],
            "dot",
            &[0.5, 0.25],
        )
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("returned 1 batch scores for 2 encrypted vectors")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_passes_plaintext_query_distance_metric() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("fake-openfhe-cosine-score-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r request; do
  case "$request" in
    *'"operation":"score_plaintext_query"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*'"distance":"cosine"'*'"context_id"'*'"query_values":[0.5,0.25]'*'"ciphertext":"b3BlbmZoZS1jaXBoZXI"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","score":0.875}\n'
      ;;
    *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*)
      printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
      ;;
    *) exit 7 ;;
  esac
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();

    let score = encryptor
        .score_plaintext_query(
            "docs",
            "point-1",
            &public_material(),
            &encrypted,
            "cosine",
            &[0.5, 0.25],
        )
        .unwrap();

    assert_eq!(score, 0.875);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_uses_batch_bridge_protocol() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("fake-openfhe-batch-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r request
case "$request" in
  *'"operation":"encrypt_batch"'*'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*'"context_id"'*'"items"'*'"point_id":"point-1"'*'"point_id":"point-2"'*) ;;
  *) exit 7 ;;
esac
printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertexts":["YmF0Y2gtb25l","YmF0Y2gtdHdv"]}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = [1.0, 2.0];
    let second = [3.0, 4.0];
    let encrypted = encryptor
        .encrypt_batch(
            "docs",
            &public_material(),
            &[
                CkksVectorBatchItem {
                    point_id: "point-1",
                    values: &first,
                },
                CkksVectorBatchItem {
                    point_id: "point-2",
                    values: &second,
                },
            ],
        )
        .unwrap();

    assert_eq!(
        encryptor
            .open("docs", "point-1", &public_material(), &encrypted[0])
            .unwrap()
            .ciphertext,
        BASE64URL_NOPAD.encode(b"batch-one"),
    );
    assert_eq!(
        encryptor
            .open("docs", "point-2", &public_material(), &encrypted[1])
            .unwrap()
            .ciphertext,
        BASE64URL_NOPAD.encode(b"batch-two"),
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_batch_response_size_mismatch() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("bad-openfhe-batch-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r request
case "$request" in
  *'"items"'*) ;;
  *) exit 7 ;;
esac
printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertexts":["b25seS1vbmU"]}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = [1.0, 2.0];
    let second = [3.0, 4.0];
    let err = encryptor
        .encrypt_batch(
            "docs",
            &public_material(),
            &[
                CkksVectorBatchItem {
                    point_id: "point-1",
                    values: &first,
                },
                CkksVectorBatchItem {
                    point_id: "point-2",
                    values: &second,
                },
            ],
        )
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("returned 1 batch ciphertexts for 2 input vectors")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_times_out_and_kills_hung_bridge() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("hung-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
sleep 10
",
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend()
        .with_args([script_path.display().to_string()])
        .with_timeout(Duration::from_millis(50));
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(matches!(err, CkksError::Backend(message) if message.contains("timed out")));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_timeout_does_not_wait_for_stdout_holder() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("stdout-held-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
(sleep 2) &
sleep 10
",
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend()
        .with_args([script_path.display().to_string()])
        .with_timeout(Duration::from_millis(50));
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let started = Instant::now();
    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(matches!(err, CkksError::Backend(message) if message.contains("timed out")));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_bridge_exit_after_request() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("exit-after-request-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
exit 0
",
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(ref message) if message.contains("empty response")),
        "{err:?}",
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_oversized_bridge_output() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("noisy-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
for _ in {1..128}; do
  printf x
done
",
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend()
        .with_args([script_path.display().to_string()])
        .with_max_output_bytes(32);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(matches!(err, CkksError::Backend(message) if message.contains("stdout exceeded")));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_invalid_json_response() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("invalid-json-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf 'plaintext-embedding-secret-should-not-leak\n' >&2
printf '{not-json}\n'
",
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(matches!(
        err,
        CkksError::Backend(message)
            if message.contains("failed to parse OpenFHE bridge response")
                && !message.contains("plaintext-embedding-secret-should-not-leak")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_response_without_newline() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("no-newline-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{"version":1,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(message) if message.contains("empty response") || message.contains("disconnected"))
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_oversized_bridge_stderr() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("stderr-noisy-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -uo pipefail
IFS= read -r _request
for _ in {1..128}; do
  printf x >&2 || true
done
sleep 0.1
printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend()
        .with_args([script_path.display().to_string()])
        .with_max_output_bytes(64);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(ref message) if message.contains("stderr exceeded")),
        "unexpected bridge error: {err:?}",
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_stderr_cap_fails_before_timeout() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("stderr-infinite-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r"#!/usr/bin/env bash
set -uo pipefail
IFS= read -r _request
while true; do
  printf x >&2 || exit 0
done
",
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend()
        .with_args([script_path.display().to_string()])
        .with_timeout(Duration::from_secs(5))
        .with_max_output_bytes(64);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let started = Instant::now();
    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(ref message) if message.contains("stderr exceeded")),
        "unexpected bridge error: {err:?}",
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_reuses_worker_process_when_bridge_supports_streaming() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("loop-openfhe-bridge.sh");
    let count_fifo = dir.path().join("counts.fifo");
    create_test_fifo(&count_fifo);
    let (count_lines, count_reader) = collect_fifo_lines(count_fifo.clone());
    fs::write(
        &script_path,
        format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
count_fifo={}
exec 3>"$count_fifo"
printf 'start\n' >&3
while IFS= read -r request; do
  case "$request" in
    *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*) ;;
    *) exit 7 ;;
  esac
  printf 'request\n' >&3
  printf '{{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}}\n'
done
"#,
            count_fifo.display(),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend().with_args([script_path.display().to_string()]);
    let encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap();
    encryptor
        .encrypt("docs", "point-2", &public_material(), &[2.0])
        .unwrap();
    drop(encryptor);
    count_reader
        .join()
        .expect("test FIFO reader must finish after backend drop");

    assert_eq!(fifo_line_count(&count_lines, "start"), 1);
    assert_eq!(fifo_line_count(&count_lines, "request"), 2);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_uses_pool_size_for_concurrent_requests() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("pooled-openfhe-bridge.sh");
    let count_fifo = dir.path().join("pool-counts.fifo");
    create_test_fifo(&count_fifo);
    let (count_lines, count_reader) = collect_fifo_lines(count_fifo.clone());
    fs::write(
        &script_path,
        format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
	count_fifo={}
	exec 3>"$count_fifo"
	printf 'start\n' >&3
	while IFS= read -r _request; do
	  printf 'request\n' >&3
	  sleep 2
	  printf '{{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}}\n'
	done
"#,
            count_fifo.display(),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend()
        .with_args([script_path.display().to_string()])
        .with_pool_size(NonZeroUsize::new(2).unwrap());
    let encryptor = Arc::new(
        test_ckks_encryptor(
            "tenant-a:ckks",
            "embedding",
            CkksParameters::openfhe_default_128_bit(),
            SecretKey::from_bytes([29u8; 32]),
            backend,
        )
        .unwrap(),
    );

    let first_encryptor = Arc::clone(&encryptor);
    let first = std::thread::spawn(move || {
        first_encryptor
            .encrypt("docs", "point-1", &public_material(), &[1.0])
            .unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if fifo_line_count(&count_lines, "request") == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "first OpenFHE bridge request did not become busy before timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let second_encryptor = Arc::clone(&encryptor);
    let second = std::thread::spawn(move || {
        second_encryptor
            .encrypt("docs", "point-2", &public_material(), &[2.0])
            .unwrap();
    });
    first.join().unwrap();
    second.join().unwrap();
    drop(encryptor);
    count_reader
        .join()
        .expect("test FIFO reader must finish after backend drop");

    assert_eq!(fifo_line_count(&count_lines, "start"), 2);
    assert_eq!(fifo_line_count(&count_lines, "request"), 2);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_fails_fast_when_pool_is_busy() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("busy-pool-openfhe-bridge.sh");
    let count_fifo = dir.path().join("busy-pool-counts.fifo");
    create_test_fifo(&count_fifo);
    let (count_lines, count_reader) = collect_fifo_lines(count_fifo.clone());
    // The bridge holds the only worker longer than the reservation wait, so the second request
    // must give up with the pool-exhausted error instead of queueing behind it.
    fs::write(
        &script_path,
        format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
count_fifo={}
exec 3>"$count_fifo"
printf 'start\n' >&3
while IFS= read -r _request; do
  printf 'request\n' >&3
  sleep 7
  printf '{{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}}\n'
done
"#,
            count_fifo.display(),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend()
        .with_args([script_path.display().to_string()])
        .with_pool_size(NonZeroUsize::new(1).unwrap());
    let encryptor = Arc::new(
        test_ckks_encryptor(
            "tenant-a:ckks",
            "embedding",
            CkksParameters::openfhe_default_128_bit(),
            SecretKey::from_bytes([29u8; 32]),
            backend,
        )
        .unwrap(),
    );

    let first_encryptor = Arc::clone(&encryptor);
    let first = std::thread::spawn(move || {
        first_encryptor
            .encrypt("docs", "point-1", &public_material(), &[1.0])
            .unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if fifo_line_count(&count_lines, "request") == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "first OpenFHE bridge request did not become busy before timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let err = encryptor
        .encrypt("docs", "point-2", &public_material(), &[2.0])
        .expect_err("a busy full OpenFHE pool must fail once the reservation wait elapses");
    assert!(
        matches!(err, CkksError::Backend(ref message) if message.contains("worker pool is exhausted")),
        "unexpected busy pool error: {err:?}",
    );
    assert_eq!(fifo_line_count(&count_lines, "request"), 1);

    first.join().unwrap();
    drop(encryptor);
    count_reader
        .join()
        .expect("test FIFO reader must finish after backend drop");

    assert_eq!(fifo_line_count(&count_lines, "start"), 1);
    assert_eq!(fifo_line_count(&count_lines, "request"), 1);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_clones_reuse_worker_process() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("cloned-pool-openfhe-bridge.sh");
    let count_fifo = dir.path().join("cloned-pool-counts.fifo");
    create_test_fifo(&count_fifo);
    let (count_lines, count_reader) = collect_fifo_lines(count_fifo.clone());
    fs::write(
        &script_path,
        format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
count_fifo={}
exec 3>"$count_fifo"
printf 'start\n' >&3
while IFS= read -r _request; do
  printf 'request\n' >&3
  printf '{{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"b3BlbmZoZS1jaXBoZXI"}}\n'
done
"#,
            count_fifo.display(),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = test_bash_backend()
        .with_args([script_path.display().to_string()])
        .with_pool_size(NonZeroUsize::new(1).unwrap());
    let pool_owner = backend.clone();
    let first_encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend.clone(),
    )
    .unwrap();
    let second_encryptor = test_ckks_encryptor(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    first_encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap();
    second_encryptor
        .encrypt("docs", "point-2", &public_material(), &[2.0])
        .unwrap();
    drop(first_encryptor);
    drop(second_encryptor);
    drop(pool_owner);
    count_reader
        .join()
        .expect("test FIFO reader must finish after backend drop");

    assert_eq!(fifo_line_count(&count_lines, "start"), 1);
    assert_eq!(fifo_line_count(&count_lines, "request"), 2);
}

#[test]
fn encrypted_ckks_vector_has_stable_json_shape() {
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap();
    let value = serde_json::to_value(encrypted).unwrap();

    assert_eq!(value["version"], json!(1));
    assert_eq!(value["scheme"], json!("openfhe-ckks"));
    assert_eq!(value["envelope"]["key_id"], json!("tenant-a:ckks"));
    assert!(value["envelope"]["nonce"].as_str().unwrap().len() >= 16);
    assert!(value["envelope"]["ciphertext"].as_str().unwrap().len() >= 32);
}

#[test]
fn vector_metadata_tampering_fails_authentication() {
    let encryptor = encryptor();
    let mut encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0, 3.0])
        .unwrap();

    let mut raw = BASE64URL_NOPAD
        .decode(encrypted.envelope.ciphertext.as_bytes())
        .unwrap();
    raw[0] ^= 0x01;
    encrypted.envelope.ciphertext = BASE64URL_NOPAD.encode(&raw);

    assert!(matches!(
        encryptor.open("docs", "point-1", &public_material(), &encrypted),
        Err(CkksError::Envelope(_)),
    ));
}

#[test]
fn vector_header_tampering_fails_authentication() {
    let encryptor = encryptor();
    let mut encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    encrypted.envelope.material_fingerprint.clear();

    assert!(matches!(
        encryptor.open("docs", "point-1", &public_material(), &encrypted),
        Err(CkksError::Envelope(
            EncryptionError::InvalidMaterialFingerprintId
        )),
    ));
}

#[test]
fn vector_envelope_is_bound_to_collection_point_and_vector() {
    let encryptor = encryptor();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();

    assert!(matches!(
        encryptor.open("docs", "point-2", &public_material(), &encrypted),
        Err(CkksError::Envelope(_)),
    ));

    let other_vector = test_ckks_encryptor(
        "tenant-a:ckks",
        "other",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        SealedTestBackend,
    )
    .unwrap();
    assert!(matches!(
        other_vector.open("docs", "point-1", &public_material(), &encrypted),
        Err(CkksError::Envelope(_)),
    ));
}

#[test]
fn vector_envelope_can_bind_to_stable_collection_identity() {
    let material = public_material();
    let stable_identity = encryptor()
        .with_collection_identity("collection-uuid-123")
        .unwrap();
    let encrypted = stable_identity
        .encrypt("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();

    stable_identity
        .open("renamed-docs", "point-1", &material, &encrypted)
        .unwrap();

    assert!(matches!(
        encryptor().open("renamed-docs", "point-1", &material, &encrypted),
        Err(CkksError::Envelope(_)),
    ));
    assert!(matches!(
        encryptor().with_collection_identity(""),
        Err(CkksError::InvalidContext(_)),
    ));
}

#[test]
fn ckks_sidecar_markers_reject_sibling_keys() {
    let encryptor = encryptor()
        .with_collection_identity("collection-uuid-1")
        .unwrap();
    let material = public_material();
    let (value, _) = encryptor
        .encrypt_sidecar_payload_value("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();
    let mut with_sibling = value.clone();
    with_sibling
        .as_object_mut()
        .unwrap()
        .insert("plaintext".to_string(), json!([1.0, 2.0]));
    assert!(matches!(
        ckks_vector_sidecar_envelope_key(&with_sibling, "collection-uuid-1", "point-1", "embedding"),
        Err(CkksError::MalformedEnvelope(message)) if message.contains("only key")
    ));

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();
    let mut client_value = signed_client_ckks_vector_payload(&key_pair, "tenant-a/signing-v1");
    client_value
        .as_object_mut()
        .unwrap()
        .insert("plaintext".to_string(), json!("leaked"));
    let err = validate_client_ckks_vector_payload_value_for_runtime(
        &client_value,
        ClientCkksVectorValidationContext {
            collection_id: "collection-uuid",
            point_id: "point-1",
            vector_name: "embedding",
            expected_key_id: "tenant-a:docs",
            expected_rk_id: "tenant-a/vector-rk",
            min_rk_epoch: 3,
            max_rk_epoch: 3,
            expected_context_digest: &public_material()
                .digest_for(&CkksParameters::openfhe_default_128_bit()),
            max_slots: CkksParameters::openfhe_default_128_bit().batch_size as usize,
            signature_verification: ClientCkksVectorSignatureVerification {
                expected_key_id: "tenant-a/signing-v1",
                public_key: &public_key,
            },
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, CkksError::MalformedEnvelope(ref message) if message.contains("only key")),
        "unexpected error: {err:?}"
    );
}

#[test]
fn stored_sidecar_values_reverify_into_the_same_verified_key() {
    let encryptor = encryptor()
        .with_collection_identity("collection-uuid-1")
        .unwrap();
    let material = public_material();
    let (value, proof) = encryptor
        .encrypt_sidecar_payload_value("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();

    let reverified = encryptor
        .verify_stored_sidecar_payload_value("docs", "point-1", &material, &value)
        .unwrap()
        .expect("a stored server sidecar entry re-verifies");
    assert_eq!(reverified.envelope_key(), proof.envelope_key());

    // Another point's binding, a tampered ciphertext, and foreign values are refused.
    assert!(
        encryptor
            .verify_stored_sidecar_payload_value("docs", "point-2", &material, &value)
            .is_err()
    );
    let mut tampered = value.clone();
    tampered[ENCRYPTED_CKKS_VECTOR_MARKER]["envelope"]["ciphertext"] =
        json!(BASE64URL_NOPAD.encode(b"tampered-ckks-ciphertext"));
    assert!(
        encryptor
            .verify_stored_sidecar_payload_value("docs", "point-1", &material, &tampered)
            .is_err()
    );
    assert!(
        encryptor
            .verify_stored_sidecar_payload_value("docs", "point-1", &material, &json!("plain"))
            .unwrap()
            .is_none()
    );
}
