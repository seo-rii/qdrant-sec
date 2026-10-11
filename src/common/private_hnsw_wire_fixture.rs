use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use collection::config::{
    CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector,
};
use collection::operations::vector_params_builder::VectorParamsBuilder;
use collection::private_hnsw_oram_store::{PrivateHnswOramEpochState, PrivateHnswOramStore};
use collection::shards::channel_service::ChannelService;
use common::budget::ResourceBudget;
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND, PRIVATE_RESULT_ORAM_BINDING,
    PrivateHnswBucketAeadBaseContext, PrivateHnswBuildPoint, PrivateHnswClientCommitPlan,
    PrivateHnswClientError, PrivateHnswClientKeys, PrivateHnswCommitSignatureContext,
    PrivateHnswEncryptedIndexBuild, PrivateHnswEncryptedPathBatch, PrivateHnswManifestBuildContext,
    PrivateHnswOramBucket, PrivateHnswOramClientConfig, PrivateHnswOramManifest,
    PrivateHnswOramSignature, PrivateHnswParams, PrivateHnswPlaintextIndexBuild,
    PrivateHnswSearchParams, PrivateHnswSearchResult, PrivateResultOramBucket,
    PrivateResultOramBucketCommitmentContext, PrivateResultOramClientCommitBucketRef,
    PrivateResultOramCommitPlan, PrivateResultOramCommitSignatureContext,
    PrivateResultOramManifest, PrivateResultOramReadBucketsSignatureContext,
    PrivateResultOramSignature, ResultPrivacyMode, SecretKey,
    build_private_hnsw_oram_manifest_from_encrypted_index,
    build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points,
    encode_private_hnsw_oram_leaf_label, plan_private_hnsw_oram_commit_for_manifest,
    private_hnsw_oram_bucket_ids_for_leaf, private_result_oram_bucket_ciphertext_bytes,
    private_result_oram_bucket_commitment, private_result_oram_merkle_root_for_commitments,
    seal_private_hnsw_oram_plaintext_index, search_private_hnsw_oram_encrypted_verified,
    sign_private_hnsw_oram_commit, sign_private_hnsw_oram_manifest,
    sign_private_hnsw_oram_manifest_refresh, sign_private_hnsw_oram_read_paths,
    sign_private_hnsw_oram_read_paths_for_manifest_context, sign_private_result_oram_commit,
    sign_private_result_oram_manifest, sign_private_result_oram_read_buckets,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use sha2::{Digest, Sha256};
use storage::content_manager::collection_meta_ops::{
    CollectionMetaOperations, CreateCollection, CreateCollectionOperation,
};
use storage::content_manager::consensus::operation_sender::OperationSender;
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::Dispatcher;
use storage::rbac::{Access, Auth};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use uuid::Uuid;

use crate::settings::{CryptoInstanceConfig, CryptoSettings, Settings};

pub(crate) const COLLECTION_NAME: &str = "docs";
pub(crate) const COLLECTION_ID: &str = "12345678-90ab-cdef-1234-567890abcdef";
pub(crate) const VECTOR_NAME: &str = "text";
pub(crate) const KEY_ID: &str = "tenant-a/vector-private-rk";
pub(crate) const RESULT_SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v1";
pub(crate) const RK_EPOCH: u64 = 7;
pub(crate) const SIGNING_KEY_ID: &str = "tenant-a/private-hnsw-signing-v1";
pub(crate) const SESSION_ID: &str = "session-1";
pub(crate) const BASE_EPOCH: u64 = 42;
pub(crate) const NEXT_EPOCH: u64 = 43;
pub(crate) const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024;

pub(crate) struct PrivateHnswRouteWireFixture {
    _temp: TempDir,
    collection_id: &'static str,
    pub(crate) store: PrivateHnswOramStore,
    pub(crate) keys: PrivateHnswClientKeys,
    pub(crate) base_context: PrivateHnswBucketAeadBaseContext<'static>,
    pub(crate) config: PrivateHnswOramClientConfig,
    pub(crate) plaintext_build: PrivateHnswPlaintextIndexBuild,
    pub(crate) encrypted_build: PrivateHnswEncryptedIndexBuild,
    pub(crate) manifest: PrivateHnswOramManifest,
    pub(crate) manifest_signature: PrivateHnswOramSignature,
    pub(crate) leaf_commitments: Vec<String>,
    signing_key: Ed25519KeyPair,
}

pub(crate) struct PrivateHnswRouteWireSearchRun {
    pub(crate) result: PrivateHnswSearchResult,
    pub(crate) updated_buckets: Vec<PrivateHnswOramBucket>,
    pub(crate) commit_plan: PrivateHnswClientCommitPlan,
    pub(crate) commit_signature: PrivateHnswOramSignature,
}

pub(crate) struct PrivateResultOramRouteFixture {
    pub(crate) manifest: PrivateResultOramManifest,
    pub(crate) signature: PrivateResultOramSignature,
    pub(crate) buckets: Vec<PrivateResultOramBucket>,
    signing_key: Ed25519KeyPair,
}

impl PrivateResultOramRouteFixture {
    pub(crate) fn build() -> Self {
        Self::build_for_collection_id(COLLECTION_ID)
    }

    pub(crate) fn build_for_collection_id(collection_id: &str) -> Self {
        let signing_key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
        let oram = OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 1024,
            tree_height: 2,
            path_batch_size: 1,
        };
        let bucket_count = (1_u64 << (oram.tree_height + 1)) - 1;
        let mut manifest = PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: collection_id.to_string(),
            key_id: KEY_ID.to_string(),
            rk_id: KEY_ID.to_string(),
            rk_epoch: RK_EPOCH,
            oram: oram.clone(),
            index_epoch: BASE_EPOCH,
            root_hash: BASE64URL_NOPAD.encode(&[0; 32]),
            bucket_count,
            logical_result_count: 3,
            dummy_result_count: 1,
            owner_signing_key_id: RESULT_SIGNING_KEY_ID.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let buckets = (0..bucket_count)
            .map(|bucket_id| result_oram_bucket(bucket_id, &manifest))
            .collect::<Vec<_>>();
        let commitments = buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        manifest.root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let buckets = (0..bucket_count)
            .map(|bucket_id| result_oram_bucket(bucket_id, &manifest))
            .collect::<Vec<_>>();
        let signature = sign_private_result_oram_manifest(&signing_key, &manifest).unwrap();

        Self {
            manifest,
            signature,
            buckets,
            signing_key,
        }
    }

    pub(crate) fn read_signature(&self, bucket_ids: &[u64]) -> PrivateResultOramSignature {
        sign_private_result_oram_read_buckets(
            &self.signing_key,
            PrivateResultOramReadBucketsSignatureContext {
                collection_id: &self.manifest.collection_id,
                key_id: &self.manifest.key_id,
                rk_id: &self.manifest.rk_id,
                rk_epoch: self.manifest.rk_epoch,
                signing_key_id: RESULT_SIGNING_KEY_ID,
            },
            self.manifest.index_epoch,
            &self.manifest.root_hash,
            self.manifest.bucket_count,
            bucket_ids,
        )
        .unwrap()
    }

    pub(crate) fn commit_bucket(
        &self,
    ) -> (PrivateResultOramBucket, PrivateResultOramSignature, String) {
        let mut next_manifest = self.manifest.clone();
        next_manifest.index_epoch = NEXT_EPOCH;
        let updated_bucket = result_oram_bucket(0, &next_manifest);
        let mut commitments = self
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        commitments[0] = updated_bucket.bucket_commitment.clone();
        let new_root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let plan = PrivateResultOramCommitPlan {
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: self.manifest.root_hash.clone(),
            new_root_hash: new_root_hash.clone(),
            leaf_commitments: commitments,
            updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }],
        };
        let signature = sign_private_result_oram_commit(
            &self.signing_key,
            PrivateResultOramCommitSignatureContext {
                collection_id: &self.manifest.collection_id,
                key_id: &self.manifest.key_id,
                rk_id: &self.manifest.rk_id,
                rk_epoch: self.manifest.rk_epoch,
                signing_key_id: RESULT_SIGNING_KEY_ID,
            },
            &plan,
        )
        .unwrap();
        (updated_bucket, signature, new_root_hash)
    }

    pub(crate) fn route_settings_with_private_hnsw(
        &self,
        hnsw_fixture: &PrivateHnswRouteWireFixture,
    ) -> Settings {
        let mut settings = hnsw_fixture.route_settings();
        settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = json!("private_payload_oram_required");
        self.insert_runtime_instance(&mut settings);
        settings
    }

    fn insert_runtime_instance(&self, settings: &mut Settings) {
        settings.crypto.instances.insert(
            "docs_private_result_oram_v1".to_string(),
            CryptoInstanceConfig {
                provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                materials: HashMap::new(),
                backend_ref: None,
                options: json!({
                    "key_id": KEY_ID,
                    "expected_rk_id": KEY_ID,
                    "min_rk_epoch": RK_EPOCH,
                    "max_rk_epoch": RK_EPOCH,
                    "oram": {
                        "kind": "path_oram",
                        "bucket_size": self.manifest.oram.bucket_size,
                        "block_size_bytes": self.manifest.oram.block_size_bytes,
                        "tree_height": self.manifest.oram.tree_height,
                        "path_batch_size": self.manifest.oram.path_batch_size
                    },
                    "integrity": {
                        "manifest_signature_required": true,
                        "commit_signature_required": true,
                        "merkle_root_required": true
                    },
                    "signature_public_keys": {
                        RESULT_SIGNING_KEY_ID: self.signing_public_key_b64()
                    }
                }),
            },
        );
    }

    pub(crate) fn signing_public_key_b64(&self) -> String {
        BASE64URL_NOPAD.encode(self.signing_key.public_key().as_ref())
    }
}

fn result_oram_bucket(
    bucket_id: u64,
    manifest: &PrivateResultOramManifest,
) -> PrivateResultOramBucket {
    let expected_len = private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
    let mut fixed_ciphertext = vec![0; expected_len];
    for (offset, byte) in fixed_ciphertext.iter_mut().enumerate() {
        *byte = (bucket_id as u8).wrapping_add(manifest.index_epoch as u8) ^ (offset as u8);
    }
    let ciphertext = BASE64URL_NOPAD.encode(&fixed_ciphertext);
    let ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(&fixed_ciphertext));
    let bucket_commitment = private_result_oram_bucket_commitment(
        PrivateResultOramBucketCommitmentContext {
            collection_id: &manifest.collection_id,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            bucket_id,
            index_epoch: manifest.index_epoch,
        },
        &ciphertext_sha256,
    )
    .unwrap();

    PrivateResultOramBucket {
        version: 1,
        bucket_id,
        index_epoch: manifest.index_epoch,
        ciphertext,
        ciphertext_sha256,
        bucket_commitment,
    }
}

impl PrivateHnswRouteWireFixture {
    pub(crate) fn build_uploaded() -> Self {
        Self::build_uploaded_with_path_batch_size(1)
    }

    pub(crate) fn build_uploaded_with_path_batch_size(path_batch_size: u32) -> Self {
        Self::build_uploaded_for_collection_id_with_path_batch_size(COLLECTION_ID, path_batch_size)
    }

    pub(crate) fn build_uploaded_for_collection_id(collection_id: &'static str) -> Self {
        Self::build_uploaded_for_collection_id_with_path_batch_size(collection_id, 1)
    }

    /// Builds the fixture over caller-chosen points (three, like the default fixture), for
    /// leakage scans that need distinctive plaintext vectors and tokens.
    pub(crate) fn build_uploaded_with_points(points: Vec<PrivateHnswBuildPoint>) -> Self {
        Self::build_uploaded_for_collection_id_with_points(COLLECTION_ID, 1, points)
    }

    fn build_uploaded_for_collection_id_with_path_batch_size(
        collection_id: &'static str,
        path_batch_size: u32,
    ) -> Self {
        Self::build_uploaded_for_collection_id_with_points(
            collection_id,
            path_batch_size,
            Self::points(),
        )
    }

    fn build_uploaded_for_collection_id_with_points(
        collection_id: &'static str,
        path_batch_size: u32,
        points: Vec<PrivateHnswBuildPoint>,
    ) -> Self {
        let temp = TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), VECTOR_NAME).unwrap();
        let keys = PrivateHnswClientKeys::derive_from_resource_key_with_context(
            &SecretKey::from_bytes([13; 32]),
            collection_id,
            VECTOR_NAME,
            KEY_ID,
            RK_EPOCH,
        )
        .unwrap();
        let base_context = PrivateHnswBucketAeadBaseContext {
            collection_id,
            vector_name: VECTOR_NAME,
            key_id: KEY_ID,
            rk_id: KEY_ID,
            rk_epoch: RK_EPOCH,
        };
        let config = Self::config();
        let plaintext_build = build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
            config,
            DistanceKind::Euclid,
            2,
            1,
            2,
            &points,
            &[0, 1, 2],
        )
        .unwrap();
        let encrypted_build = seal_private_hnsw_oram_plaintext_index(
            &keys,
            base_context,
            BASE_EPOCH,
            &plaintext_build,
            config,
        )
        .unwrap();
        let manifest = build_private_hnsw_oram_manifest_from_encrypted_index(
            PrivateHnswManifestBuildContext {
                collection_id,
                vector_name: VECTOR_NAME,
                key_id: KEY_ID,
                rk_id: KEY_ID,
                rk_epoch: RK_EPOCH,
                dim: 2,
                distance: DistanceKind::Euclid,
                hnsw: PrivateHnswParams {
                    m: 2,
                    ef_construction: 4,
                    max_layers: 3,
                    fixed_neighbor_slots: config.fixed_neighbor_slots as u32,
                },
                oram: OramParams {
                    kind: OramKind::PathOram,
                    bucket_size: config.bucket_size as u32,
                    block_size_bytes: config.block_size_bytes as u32,
                    tree_height: config.tree_height,
                    path_batch_size,
                },
                fixed_budget: FixedBudgetParams {
                    enabled: true,
                    upper_layer_steps: 1,
                    base_layer_steps: 3,
                    paths_per_round: path_batch_size,
                    fixed_result_k: 1,
                },
                result_privacy: ResultPrivacyMode::IdsVisible,
                owner_signing_key_id: SIGNING_KEY_ID,
                created_at_unix: 1_770_000_000,
            },
            &encrypted_build,
        )
        .unwrap();
        let signing_key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let manifest_signature = sign_private_hnsw_oram_manifest(&signing_key, &manifest).unwrap();
        let leaf_commitments = encrypted_build
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        let leaf_commitment = leaf_commitments
            .first()
            .expect("private HNSW fixture must include a leaf commitment")
            .clone();
        debug_assert!(leaf_commitments.contains(&leaf_commitment));

        store
            .write_manifest(&manifest, &manifest_signature)
            .unwrap();
        store
            .write_initial_epoch(&PrivateHnswOramEpochState {
                index_epoch: encrypted_build.index_epoch,
                root_hash: encrypted_build.root_hash.clone(),
            })
            .unwrap();
        store
            .write_merkle_tree_from_commitments(
                encrypted_build.index_epoch,
                encrypted_build.root_hash.clone(),
                leaf_commitments.clone(),
            )
            .unwrap();
        for bucket in &encrypted_build.buckets {
            store
                .write_bucket(
                    bucket,
                    encrypted_build.index_epoch,
                    encrypted_build.bucket_count,
                    MAX_CIPHERTEXT_BYTES,
                )
                .unwrap();
        }

        Self {
            _temp: temp,
            collection_id,
            store,
            keys,
            base_context,
            config,
            plaintext_build,
            encrypted_build,
            manifest,
            manifest_signature,
            leaf_commitments,
            signing_key,
        }
    }

    pub(crate) fn with_result_privacy(mut self, result_privacy: ResultPrivacyMode) -> Self {
        self.manifest.result_privacy = result_privacy;
        self.manifest_signature = self.sign_manifest(&self.manifest);
        self
    }

    pub(crate) fn read_batch_for_leaf(
        &self,
        leaf: u64,
    ) -> (Vec<u64>, PrivateHnswEncryptedPathBatch) {
        let bucket_ids =
            private_hnsw_oram_bucket_ids_for_leaf(leaf, self.config.tree_height).unwrap();
        let buckets = bucket_ids
            .iter()
            .map(|bucket_id| {
                self.store
                    .read_bucket(
                        *bucket_id,
                        self.encrypted_build.index_epoch,
                        self.encrypted_build.bucket_count,
                        MAX_CIPHERTEXT_BYTES,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let proof = self
            .store
            .read_merkle_path_batch(
                &bucket_ids,
                self.encrypted_build.index_epoch,
                &self.encrypted_build.root_hash,
                self.encrypted_build.bucket_count,
            )
            .unwrap();

        (
            bucket_ids,
            PrivateHnswEncryptedPathBatch {
                index_epoch: self.encrypted_build.index_epoch,
                root_hash: self.encrypted_build.root_hash.clone(),
                bucket_count: self.encrypted_build.bucket_count,
                proof_value: serde_json::to_string(&proof).unwrap(),
                buckets,
            },
        )
    }

    pub(crate) fn entry_leaf_label(&self) -> String {
        encode_private_hnsw_oram_leaf_label(0, self.config.tree_height).unwrap()
    }

    pub(crate) fn proof_kind(&self) -> String {
        PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string()
    }

    pub(crate) fn client_signature(&self) -> PrivateHnswOramSignature {
        PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: SIGNING_KEY_ID.to_string(),
            sig: self.manifest_signature.sig.clone(),
        }
    }

    pub(crate) fn sign_read_paths(
        &self,
        paths: &[String],
        requested_paths: u32,
        dummy_paths_included: bool,
    ) -> PrivateHnswOramSignature {
        self.sign_read_paths_for_epoch(
            self.encrypted_build.index_epoch,
            &self.encrypted_build.root_hash,
            paths,
            requested_paths,
            dummy_paths_included,
        )
    }

    pub(crate) fn sign_read_paths_for_epoch(
        &self,
        index_epoch: u64,
        root_hash: &str,
        paths: &[String],
        requested_paths: u32,
        dummy_paths_included: bool,
    ) -> PrivateHnswOramSignature {
        if requested_paths == self.manifest.oram.path_batch_size && dummy_paths_included {
            if let Ok(signature) = sign_private_hnsw_oram_read_paths_for_manifest_context(
                &self.signing_key,
                &self.manifest,
                index_epoch,
                root_hash,
                paths,
            ) {
                return signature;
            }
        }
        sign_private_hnsw_oram_read_paths(
            &self.signing_key,
            PrivateHnswCommitSignatureContext {
                collection_id: self.collection_id,
                vector_name: VECTOR_NAME,
                key_id: KEY_ID,
                rk_id: KEY_ID,
                rk_epoch: RK_EPOCH,
                signing_key_id: SIGNING_KEY_ID,
            },
            index_epoch,
            root_hash,
            paths,
            requested_paths,
            dummy_paths_included,
        )
        .unwrap()
    }

    pub(crate) fn signing_public_key_b64(&self) -> String {
        BASE64URL_NOPAD.encode(self.signing_key.public_key().as_ref())
    }

    pub(crate) fn route_settings(&self) -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            zero_trust_profile: Some(crate::settings::ZERO_TRUST_PROFILE_STRICT.to_string()),
            instances: HashMap::from([(
                "docs_private_hnsw_v1".to_string(),
                CryptoInstanceConfig {
                    provider: qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: json!({
                        "key_id": KEY_ID,
                        "expected_rk_id": KEY_ID,
                        "min_rk_epoch": RK_EPOCH,
                        "max_rk_epoch": RK_EPOCH,
                        "search_execution": "client_led",
                        "search_mode": "private_hnsw_oram",
                        "result_privacy": "ids_visible",
                        "distance": "euclid",
                        "dim": 2,
                        "hnsw": {
                            "m": 2,
                            "ef_construction": 4,
                            "max_layers": 3,
                            "fixed_neighbor_slots": 4
                        },
                        "oram": {
                            "kind": "path_oram",
                            "bucket_size": 2,
                            "block_size_bytes": 4096,
                            "tree_height": 2,
                            "path_batch_size": self.manifest.oram.path_batch_size
                        },
                        "fixed_budget": {
                            "enabled": true,
                            "upper_layer_steps": 1,
                            "base_layer_steps": 3,
                            "paths_per_round": self.manifest.fixed_budget.paths_per_round,
                            "fixed_result_k": 1
                        },
                        "integrity": {
                            "manifest_signature_required": true,
                            "commit_signature_required": true,
                            "merkle_root_required": true
                        },
                        "signature_public_keys": {
                            SIGNING_KEY_ID: self.signing_public_key_b64()
                        }
                    }),
                },
            )]),
            ..CryptoSettings::default()
        };
        settings
    }

    pub(crate) fn route_settings_with_private_result_oram(&self) -> Settings {
        let mut settings = self.route_settings();
        settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = json!("private_payload_oram_required");
        PrivateResultOramRouteFixture::build().insert_runtime_instance(&mut settings);
        settings
    }

    pub(crate) fn sign_commit(
        &self,
        plan: &PrivateHnswClientCommitPlan,
    ) -> PrivateHnswOramSignature {
        sign_private_hnsw_oram_commit(
            &self.signing_key,
            PrivateHnswCommitSignatureContext {
                collection_id: self.collection_id,
                vector_name: VECTOR_NAME,
                key_id: KEY_ID,
                rk_id: KEY_ID,
                rk_epoch: RK_EPOCH,
                signing_key_id: SIGNING_KEY_ID,
            },
            plan,
        )
        .unwrap()
    }

    pub(crate) fn sign_manifest(
        &self,
        manifest: &PrivateHnswOramManifest,
    ) -> PrivateHnswOramSignature {
        sign_private_hnsw_oram_manifest(&self.signing_key, manifest).unwrap()
    }

    pub(crate) fn sign_manifest_refresh(
        &self,
        plan: &PrivateHnswClientCommitPlan,
    ) -> (PrivateHnswOramManifest, PrivateHnswOramSignature) {
        sign_private_hnsw_oram_manifest_refresh(&self.signing_key, &self.manifest, plan).unwrap()
    }

    pub(crate) fn run_single_search_collect_writeback(&self) -> PrivateHnswRouteWireSearchRun {
        let updated_by_bucket = RefCell::new(BTreeMap::new());
        let mut state = self.plaintext_build.state.clone();
        let mut remaps = [3].into_iter();
        let result = search_private_hnsw_oram_encrypted_verified(
            &self.keys,
            self.base_context,
            self.encrypted_build.index_epoch,
            &self.encrypted_build.root_hash,
            self.encrypted_build.bucket_count,
            NEXT_EPOCH,
            &mut state,
            self.config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: self.encrypted_build.entry_node_id,
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| Ok(self.read_batch_for_leaf(leaf).1),
            |writeback_buckets| {
                let mut updated = updated_by_bucket.borrow_mut();
                for bucket in writeback_buckets {
                    updated.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();
        let updated_buckets = updated_by_bucket
            .into_inner()
            .into_values()
            .collect::<Vec<_>>();
        let updated_bucket = updated_buckets
            .first()
            .expect("private HNSW fixture search must write back at least one bucket");
        debug_assert!(updated_bucket.bucket_id < self.encrypted_build.bucket_count);
        let commit_plan = plan_private_hnsw_oram_commit_for_manifest(
            &self.manifest,
            NEXT_EPOCH,
            &self.leaf_commitments,
            &updated_buckets,
        )
        .unwrap();
        let commit_signature = self.sign_commit(&commit_plan);

        PrivateHnswRouteWireSearchRun {
            result,
            updated_buckets,
            commit_plan,
            commit_signature,
        }
    }

    fn config() -> PrivateHnswOramClientConfig {
        PrivateHnswOramClientConfig {
            tree_height: 2,
            bucket_size: 2,
            block_size_bytes: 4096,
            fixed_neighbor_slots: 4,
        }
    }

    fn points() -> Vec<PrivateHnswBuildPoint> {
        vec![
            PrivateHnswBuildPoint {
                node_id: [1; 32],
                point_token: [11; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: [2; 32],
                point_token: [22; 32],
                vector: vec![2.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: [3; 32],
                point_token: [33; 32],
                vector: vec![0.0, 1.0],
                payload_fetch_token: None,
            },
        ]
    }
}

pub(crate) fn test_dispatcher() -> (TempDir, Dispatcher) {
    test_dispatcher_with_consensus_sender(false)
}

pub(crate) fn test_distributed_dispatcher() -> (TempDir, Dispatcher) {
    test_dispatcher_with_consensus_sender(true)
}

fn test_dispatcher_with_consensus_sender(distributed: bool) -> (TempDir, Dispatcher) {
    let temp = TempDir::new().unwrap();
    let mut storage_config = Settings::new(None).unwrap().storage;
    storage_config.storage_path = temp.path().join("storage");
    storage_config.snapshots_path = temp.path().join("snapshots");
    storage_config.temp_path = Some(temp.path().join("tmp"));
    let consensus_proposal_sender = distributed.then(|| {
        let (sender, _receiver) = std::sync::mpsc::channel();
        OperationSender::new(sender)
    });
    let toc = Arc::new(
        TableOfContent::new(
            &storage_config,
            Runtime::new().unwrap(),
            Runtime::new().unwrap(),
            Runtime::new().unwrap(),
            ResourceBudget::default(),
            ChannelService::new(6333, false, None, None),
            0,
            consensus_proposal_sender,
        )
        .unwrap(),
    );
    (temp, Dispatcher::new(toc))
}

pub(crate) fn route_e2e_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

pub(crate) async fn create_private_hnsw_collection(dispatcher: &Dispatcher) {
    create_private_hnsw_collection_with_result_oram_rule(dispatcher, VECTOR_NAME, false).await
}

pub(crate) async fn create_plain_collection(dispatcher: &Dispatcher, collection_name: &str) {
    dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::CreateCollection(
                CreateCollectionOperation::new(
                    collection_name.to_string(),
                    CreateCollection {
                        vectors: collection::operations::types::VectorsConfig::Multi(
                            BTreeMap::from([(
                                VECTOR_NAME.to_string(),
                                VectorParamsBuilder::new(2, segment::types::Distance::Euclid)
                                    .build(),
                            )]),
                        ),
                        sparse_vectors: None,
                        hnsw_config: None,
                        wal_config: None,
                        optimizers_config: None,
                        shard_number: Some(1),
                        on_disk_payload: None,
                        replication_factor: None,
                        write_consistency_factor: None,
                        quantization_config: None,
                        sharding_method: None,
                        encryption: None,
                        strict_mode_config: None,
                        uuid: Some(Uuid::from_u128(0xfeed_face_cafe_beef_dead_beef_0000_0001)),
                        metadata: None,
                    },
                )
                .unwrap(),
            ),
            Auth::new_internal(Access::full("private ORAM plain route test")),
            None,
        )
        .await
        .unwrap();
}

pub(crate) async fn create_private_hnsw_collection_with_private_result_oram(
    dispatcher: &Dispatcher,
) {
    create_private_hnsw_collection_with_result_oram_rule(dispatcher, VECTOR_NAME, true).await
}

async fn create_private_hnsw_collection_with_result_oram_rule(
    dispatcher: &Dispatcher,
    vector_name: &str,
    include_private_result_oram: bool,
) {
    let mut rules = vec![EncryptionRuleRef {
        id: "text_private_hnsw".to_string(),
        selector: EncryptionSelector::VectorNames {
            names: vec![vector_name.to_string()],
        },
        instance: "docs_private_hnsw_v1".to_string(),
        binding: Some(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING.to_string()),
    }];
    if include_private_result_oram {
        rules.push(EncryptionRuleRef {
            id: "payload_private_result_oram".to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec!["body".to_string()],
            },
            instance: "docs_private_result_oram_v1".to_string(),
            binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
        });
    }

    dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::CreateCollection(
                CreateCollectionOperation::new(
                    COLLECTION_NAME.to_string(),
                    CreateCollection {
                        vectors: collection::operations::types::VectorsConfig::Multi(
                            BTreeMap::from([(
                                vector_name.to_string(),
                                VectorParamsBuilder::new(2, segment::types::Distance::Euclid)
                                    .build(),
                            )]),
                        ),
                        sparse_vectors: None,
                        hnsw_config: None,
                        wal_config: None,
                        optimizers_config: None,
                        shard_number: Some(1),
                        on_disk_payload: None,
                        replication_factor: None,
                        write_consistency_factor: None,
                        quantization_config: None,
                        sharding_method: None,
                        encryption: Some(CollectionEncryptionConfig {
                            version: 1,
                            key_id: Some(KEY_ID.to_string()),
                            crypto_schema_version: 1,
                            encryption_epoch: RK_EPOCH,
                            migration_state: CryptoMigrationState::Active,
                            rules,
                        }),
                        strict_mode_config: None,
                        uuid: Some(Uuid::parse_str(COLLECTION_ID).unwrap()),
                        metadata: None,
                    },
                )
                .unwrap(),
            ),
            Auth::new_internal(Access::full("private HNSW route test")),
            None,
        )
        .await
        .unwrap();
}
