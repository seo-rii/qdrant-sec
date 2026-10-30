#![cfg(feature = "testing")]

//! Cross-crate recovery fixtures for development builds.
//!
//! This module can construct deterministic prepared and exact-new store images, but it does not
//! publish a canonical parent archive grant, archive an owner generation, or fabricate a clear
//! acknowledgement. Those archive-chain helpers remain inside this file's nested `cfg(test)`
//! module. Production binaries must use collection without the `testing` feature.

use std::path::Path;

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    PRIVATE_HNSW_ORAM_BINDING, PRIVATE_HNSW_ORAM_V2_BINDING,
    PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION, PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
    PRIVATE_ORAM_APPEND_OWNER_PREPARE_V1_VERSION, PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
    PRIVATE_ORAM_SIGNED_STATE_V2_VERSION, PRIVATE_RESULT_ORAM_BINDING,
    PRIVATE_RESULT_ORAM_V2_BINDING, PrivateHnswBucketAeadContext,
    PrivateHnswManifestValidationContext, PrivateHnswOramBucket, PrivateHnswOramManifest,
    PrivateHnswOramSignature, PrivateHnswOramUploadBundle, PrivateHnswParams,
    PrivateHnswSignatureVerification, PrivateHnswVectorEncoding, PrivateOramAppendBucketRefV1,
    PrivateOramAppendIndexWritebackV1, PrivateOramAppendMerklePatchLeafV1,
    PrivateOramAppendMerklePatchProofV1, PrivateOramAppendMerkleSiblingPositionV1,
    PrivateOramAppendMerkleSiblingV1, PrivateOramAppendMutationBundleV1,
    PrivateOramAppendMutationV1, PrivateOramAppendOwnerBucketBatchV1,
    PrivateOramAppendOwnerIndexPrepareV1, PrivateOramAppendOwnerPrepareV1,
    PrivateOramAppendReadTranscriptDigestInput, PrivateOramAppendReadWindowV1,
    PrivateOramAppendWritebackDigestInput, PrivateOramImmutableIndexParamsV2,
    PrivateOramImmutableIndexV2, PrivateOramImmutableManifestBundleV2,
    PrivateOramImmutableManifestV2, PrivateOramIndexCapacityV2, PrivateOramIndexKindV2,
    PrivateOramIndexStateV2, PrivateOramObservedReadTranscriptV1, PrivateOramPointOperationKindV1,
    PrivateOramSignatureVerification, PrivateOramSignedStateV2, PrivateResultOramBucket,
    PrivateResultOramBucketCommitmentContext, PrivateResultOramManifest,
    PrivateResultOramManifestValidationContext, PrivateResultOramSignature,
    PrivateResultOramSignatureVerification, PrivateResultOramUploadBundle, ResultPrivacyMode,
    VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER,
    encode_private_hnsw_oram_leaf_label, encode_private_result_oram_leaf_label,
    package_private_oram_append_mutation_v1, package_private_oram_immutable_manifest_v2,
    package_private_oram_signed_state_v2, private_hnsw_bucket_commitment,
    private_hnsw_oram_bucket_ciphertext_bytes, private_oram_append_read_transcript_v1,
    private_oram_append_writeback_v1_digest, private_oram_immutable_manifest_v2_digest,
    private_oram_no_server_point_record_v1_digest, private_oram_signed_state_v2_digest,
    private_result_oram_bucket_ciphertext_bytes, private_result_oram_bucket_commitment,
    sign_private_hnsw_oram_manifest, sign_private_result_oram_manifest,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

use crate::private_hnsw_oram_store::{
    MerkleSiblingPosition, PrivateHnswOramMerkleProof, PrivateHnswOramStore,
};
use crate::private_oram_owner_journal::{
    PrivateOramOwnerFinalBucketBatchV1, PrivateOramOwnerFinalBucketIndexV1, PrivateOramOwnerJournal,
};
use crate::private_oram_owner_store_adapter::PrivateOramOwnerRecoveryStorePairResourcesV1;
use crate::private_result_oram_store::PrivateResultOramStore;

pub const TEST_COLLECTION_ID: &str = "collection-uuid-1";
pub const TEST_HNSW_INDEX: &str = "text";
pub const TEST_RESULT_INDEX: &str = "private-payload";
pub const TEST_HNSW_KEY: &str = "tenant-a/vector-rk";
pub const TEST_RESULT_KEY: &str = "tenant-a/result-rk";
pub const TEST_OWNER_KEY: &str = "tenant-a/private-oram-owner-v2";

const MAX_CIPHERTEXT_BYTES: usize = 4096;
/// Prepared-index projection returned by the cross-crate recovery fixture.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateOramOwnerPreparedIndexTestEvidenceV1 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub owner_journal_descriptor_digest: String,
    pub prepared_journal_digest: String,
}

/// Real signed stores used to exercise the storage-to-collection recovery boundary.
#[doc(hidden)]
pub struct PrivateOramOwnerStorePairTestFixtureV1 {
    public_key: Vec<u8>,
    immutable_manifest: PrivateOramImmutableManifestBundleV2,
    mutation_bundle: PrivateOramAppendMutationBundleV1,
    hnsw_store: PrivateHnswOramStore,
    result_store: PrivateResultOramStore,
    owner_journal: PrivateOramOwnerJournal,
    hnsw_final: Vec<PrivateHnswOramBucket>,
    result_final: Vec<PrivateResultOramBucket>,
    read_transcripts: Vec<PrivateOramObservedReadTranscriptV1>,
}

impl PrivateOramOwnerStorePairTestFixtureV1 {
    pub fn new(collection_path: &Path, non_secret_test_owner_seed: [u8; 32]) -> Self {
        Self::new_with_writer_fence(collection_path, non_secret_test_owner_seed, 1)
    }

    pub fn new_with_writer_fence(
        collection_path: &Path,
        non_secret_test_owner_seed: [u8; 32],
        writer_fence: u64,
    ) -> Self {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&non_secret_test_owner_seed).unwrap();
        let hnsw_store = PrivateHnswOramStore::new(collection_path, TEST_HNSW_INDEX).unwrap();
        let result_store = PrivateResultOramStore::new(collection_path);
        let owner_journal = PrivateOramOwnerJournal::new(hnsw_store.root_path());

        let hnsw_params = PrivateHnswParams {
            m: 1,
            ef_construction: 4,
            max_layers: 2,
            fixed_neighbor_slots: 2,
        };
        let fixed_budget = FixedBudgetParams {
            enabled: true,
            upper_layer_steps: 2,
            base_layer_steps: 4,
            paths_per_round: 2,
            fixed_result_k: 1,
        };
        let mut hnsw_manifest = PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: TEST_COLLECTION_ID.to_string(),
            vector_name: TEST_HNSW_INDEX.to_string(),
            key_id: TEST_HNSW_KEY.to_string(),
            rk_id: TEST_HNSW_KEY.to_string(),
            rk_epoch: 7,
            dim: 2,
            distance: DistanceKind::Cosine,
            hnsw: hnsw_params.clone(),
            oram: oram(),
            fixed_budget: fixed_budget.clone(),
            index_epoch: 11,
            root_hash: digest(1),
            bucket_count: 3,
            logical_node_count: 2,
            dummy_node_count: 3,
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: TEST_OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let hnsw_buckets = (0..3)
            .map(|bucket_id| hnsw_bucket(&hnsw_manifest, bucket_id, 11, 10 + bucket_id as u8))
            .collect::<Vec<_>>();
        hnsw_manifest.root_hash = PrivateHnswOramStore::merkle_root_for_commitments(
            &hnsw_buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let hnsw_signature: PrivateHnswOramSignature =
            sign_private_hnsw_oram_manifest(&key_pair, &hnsw_manifest).unwrap();
        hnsw_store
            .write_initial_upload_bundle_with_signature(
                &PrivateHnswOramUploadBundle {
                    manifest: hnsw_manifest.clone(),
                    manifest_signature: hnsw_signature,
                    buckets: hnsw_buckets,
                },
                MAX_CIPHERTEXT_BYTES,
                PrivateHnswManifestValidationContext {
                    expected_collection_id: TEST_COLLECTION_ID,
                    expected_vector_name: TEST_HNSW_INDEX,
                    expected_key_id: TEST_HNSW_KEY,
                    expected_rk_id: TEST_HNSW_KEY,
                    min_rk_epoch: 7,
                    max_rk_epoch: 7,
                    expected_dim: 2,
                    expected_distance: DistanceKind::Cosine,
                    signature_verification: PrivateHnswSignatureVerification {
                        expected_key_id: TEST_OWNER_KEY,
                        public_key: key_pair.public_key().as_ref(),
                    },
                },
            )
            .unwrap();

        let mut result_manifest = PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: TEST_COLLECTION_ID.to_string(),
            key_id: TEST_RESULT_KEY.to_string(),
            rk_id: TEST_RESULT_KEY.to_string(),
            rk_epoch: 7,
            oram: oram(),
            index_epoch: 11,
            root_hash: digest(2),
            bucket_count: 3,
            logical_result_count: 2,
            dummy_result_count: 3,
            owner_signing_key_id: TEST_OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let result_buckets = (0..3)
            .map(|bucket_id| result_bucket(&result_manifest, bucket_id, 11, 20 + bucket_id as u8))
            .collect::<Vec<_>>();
        result_manifest.root_hash = PrivateResultOramStore::merkle_root_for_commitments(
            &result_buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let result_signature: PrivateResultOramSignature =
            sign_private_result_oram_manifest(&key_pair, &result_manifest).unwrap();
        result_store
            .write_initial_upload_bundle_with_signature(
                &PrivateResultOramUploadBundle {
                    manifest: result_manifest.clone(),
                    manifest_signature: result_signature,
                    buckets: result_buckets,
                },
                MAX_CIPHERTEXT_BYTES,
                PrivateResultOramManifestValidationContext {
                    expected_collection_id: TEST_COLLECTION_ID,
                    expected_key_id: TEST_RESULT_KEY,
                    expected_rk_id: TEST_RESULT_KEY,
                    min_rk_epoch: 7,
                    max_rk_epoch: 7,
                    signature_verification: PrivateResultOramSignatureVerification {
                        expected_key_id: TEST_OWNER_KEY,
                        public_key: key_pair.public_key().as_ref(),
                    },
                },
            )
            .unwrap();

        let immutable_manifest = PrivateOramImmutableManifestV2 {
            version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
            collection_id: TEST_COLLECTION_ID.to_string(),
            manifest_nonce: digest(3),
            indexes: vec![
                PrivateOramImmutableIndexV2 {
                    index_name: TEST_HNSW_INDEX.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Hnsw {
                        provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                        key_id: TEST_HNSW_KEY.to_string(),
                        rk_id: TEST_HNSW_KEY.to_string(),
                        rk_epoch: 7,
                        dim: 2,
                        vector_encoding: PrivateHnswVectorEncoding::F32Le,
                        distance: DistanceKind::Cosine,
                        hnsw: hnsw_params,
                        oram: oram(),
                        fixed_search_budget: fixed_budget,
                        max_neighbor_rewrites: 1,
                    },
                    capacity: capacity(),
                },
                PrivateOramImmutableIndexV2 {
                    index_name: TEST_RESULT_INDEX.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Result {
                        provider: qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
                        key_id: TEST_RESULT_KEY.to_string(),
                        rk_id: TEST_RESULT_KEY.to_string(),
                        rk_epoch: 7,
                        oram: oram(),
                    },
                    capacity: capacity(),
                },
            ],
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: TEST_OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let immutable_manifest =
            package_private_oram_immutable_manifest_v2(&key_pair, immutable_manifest).unwrap();

        let hnsw_final = (0..3)
            .map(|bucket_id| hnsw_bucket(&hnsw_manifest, bucket_id, 12, 30 + bucket_id as u8))
            .collect::<Vec<_>>();
        let result_final = (0..3)
            .map(|bucket_id| result_bucket(&result_manifest, bucket_id, 12, 40 + bucket_id as u8))
            .collect::<Vec<_>>();
        let hnsw_new_root = PrivateHnswOramStore::merkle_root_for_commitments(
            &hnsw_final
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let result_new_root = PrivateResultOramStore::merkle_root_for_commitments(
            &result_final
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let old_indexes = vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: TEST_HNSW_INDEX.to_string(),
                index_epoch: 11,
                root_hash: hnsw_manifest.root_hash.clone(),
                logical_count: 2,
                dummy_count: 3,
                last_writeback_digest: digest(50),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: TEST_RESULT_INDEX.to_string(),
                index_epoch: 11,
                root_hash: result_manifest.root_hash.clone(),
                logical_count: 2,
                dummy_count: 3,
                last_writeback_digest: digest(51),
            },
        ];
        let mut new_indexes = vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: TEST_HNSW_INDEX.to_string(),
                index_epoch: 12,
                root_hash: hnsw_new_root,
                logical_count: 3,
                dummy_count: 2,
                last_writeback_digest: digest(52),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: TEST_RESULT_INDEX.to_string(),
                index_epoch: 12,
                root_hash: result_new_root,
                logical_count: 3,
                dummy_count: 2,
                last_writeback_digest: digest(53),
            },
        ];
        let mutation_id = digest(56);
        let writer_lease_digest = digest(60);
        let old_state = package_private_oram_signed_state_v2(
            &key_pair,
            PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: TEST_COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                layout_digest: digest(57),
                state_sequence: 0,
                indexes: old_indexes,
                client_state_digest: digest(58),
                last_mutation_id: None,
                owner_signing_key_id: TEST_OWNER_KEY.to_string(),
                signed_at_unix: 1_770_000_100,
            },
        )
        .unwrap();
        let old_state_digest = private_oram_signed_state_v2_digest(&old_state.state).unwrap();
        let read_transcripts = [
            (PrivateOramIndexKindV2::Hnsw, TEST_HNSW_INDEX),
            (PrivateOramIndexKindV2::Result, TEST_RESULT_INDEX),
        ]
        .into_iter()
        .map(|(kind, index_name)| {
            read_transcript(
                kind,
                index_name,
                &manifest_digest,
                &mutation_id,
                &old_state_digest,
                &writer_lease_digest,
                writer_fence,
            )
        })
        .collect::<Vec<_>>();
        let writebacks = vec![
            PrivateOramAppendIndexWritebackV1 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: TEST_HNSW_INDEX.to_string(),
                read_path_count: 4,
                read_transcript_digest: read_transcripts[0].transcript_digest.clone(),
                updated_buckets: repeated_path_refs(
                    &hnsw_final.iter().map(hnsw_ref).collect::<Vec<_>>(),
                ),
            },
            PrivateOramAppendIndexWritebackV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: TEST_RESULT_INDEX.to_string(),
                read_path_count: 4,
                read_transcript_digest: read_transcripts[1].transcript_digest.clone(),
                updated_buckets: repeated_path_refs(
                    &result_final.iter().map(result_ref).collect::<Vec<_>>(),
                ),
            },
        ];
        for offset in 0..writebacks.len() {
            let old = &old_state.state.indexes[offset];
            let new = &new_indexes[offset];
            let writeback = &writebacks[offset];
            new_indexes[offset].last_writeback_digest =
                private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                    collection_id: TEST_COLLECTION_ID,
                    manifest_digest: &manifest_digest,
                    kind: writeback.kind,
                    index_name: &writeback.index_name,
                    old_epoch: old.index_epoch,
                    new_epoch: new.index_epoch,
                    old_root_hash: &old.root_hash,
                    new_root_hash: &new.root_hash,
                    read_path_count: writeback.read_path_count,
                    read_transcript_digest: &writeback.read_transcript_digest,
                    updated_buckets: &writeback.updated_buckets,
                })
                .unwrap();
        }
        let new_state = package_private_oram_signed_state_v2(
            &key_pair,
            PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: TEST_COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                layout_digest: digest(57),
                state_sequence: 1,
                indexes: new_indexes,
                client_state_digest: digest(59),
                last_mutation_id: Some(mutation_id.clone()),
                owner_signing_key_id: TEST_OWNER_KEY.to_string(),
                signed_at_unix: 1_770_000_130,
            },
        )
        .unwrap();
        let mutation_bundle = package_private_oram_append_mutation_v1(
            &key_pair,
            PrivateOramAppendMutationV1 {
                version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
                mutation_id: mutation_id.clone(),
                collection_id: TEST_COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                writer_lease_digest,
                writer_fence,
                issued_at_unix: 1_770_000_120,
                expires_at_unix: 1_770_000_180,
                old_state,
                new_state,
                point_operation_kind: PrivateOramPointOperationKindV1::NoServerPointRecord,
                point_operation_digest: private_oram_no_server_point_record_v1_digest(
                    TEST_COLLECTION_ID,
                    &manifest_digest,
                    &mutation_id,
                )
                .unwrap(),
                writebacks,
                owner_signing_key_id: TEST_OWNER_KEY.to_string(),
            },
        )
        .unwrap();

        Self {
            public_key: key_pair.public_key().as_ref().to_vec(),
            immutable_manifest,
            mutation_bundle,
            hnsw_store,
            result_store,
            owner_journal,
            hnsw_final,
            result_final,
            read_transcripts,
        }
    }

    pub fn mutation_bundle(&self) -> &PrivateOramAppendMutationBundleV1 {
        &self.mutation_bundle
    }

    pub fn immutable_manifest(&self) -> &PrivateOramImmutableManifestBundleV2 {
        &self.immutable_manifest
    }

    pub fn read_transcripts(&self) -> &[PrivateOramObservedReadTranscriptV1] {
        &self.read_transcripts
    }

    pub fn owner_prepare_bundle(&self) -> PrivateOramAppendOwnerPrepareV1 {
        let mutation = &self.mutation_bundle.mutation;
        let hnsw_old = &mutation.old_state.state.indexes[0];
        let result_old = &mutation.old_state.state.indexes[1];
        let (_, hnsw_proof) = self
            .hnsw_store
            .read_bucket_batch_with_proof(
                &[0, 1, 2],
                hnsw_old.index_epoch,
                &hnsw_old.root_hash,
                3,
                MAX_CIPHERTEXT_BYTES,
            )
            .unwrap();
        let (_, result_proof) = self
            .result_store
            .read_bucket_batch_with_proof(
                &[0, 1, 2],
                result_old.index_epoch,
                &result_old.root_hash,
                3,
                MAX_CIPHERTEXT_BYTES,
            )
            .unwrap();
        PrivateOramAppendOwnerPrepareV1 {
            version: PRIVATE_ORAM_APPEND_OWNER_PREPARE_V1_VERSION,
            mutation_bundle: self.mutation_bundle.clone(),
            indexes: vec![
                PrivateOramAppendOwnerIndexPrepareV1 {
                    index_name: TEST_HNSW_INDEX.to_string(),
                    ordered_encrypted_buckets: PrivateOramAppendOwnerBucketBatchV1::Hnsw(
                        repeated_hnsw_buckets(&self.hnsw_final),
                    ),
                    merkle_patch_proof: hnsw_patch_proof(&hnsw_proof),
                },
                PrivateOramAppendOwnerIndexPrepareV1 {
                    index_name: TEST_RESULT_INDEX.to_string(),
                    ordered_encrypted_buckets: PrivateOramAppendOwnerBucketBatchV1::Result(
                        repeated_result_buckets(&self.result_final),
                    ),
                    merkle_patch_proof: PrivateOramAppendMerklePatchProofV1::from(&result_proof),
                },
            ],
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn hnsw_store(&self) -> &PrivateHnswOramStore {
        &self.hnsw_store
    }

    pub fn result_store(&self) -> &PrivateResultOramStore {
        &self.result_store
    }

    pub fn owner_journal(&self) -> &PrivateOramOwnerJournal {
        &self.owner_journal
    }

    pub fn prepare_owner(
        &self,
        owner_peer_id: u64,
        parent_descriptor_digest: &str,
        parent_lease_acquired_record_digest: &str,
    ) -> Vec<PrivateOramOwnerPreparedIndexTestEvidenceV1> {
        let (_, token) = self
            .owner_journal
            .prepare_store_adapter_test_fixture_v1(
                &self.mutation_bundle,
                owner_peer_id,
                parent_descriptor_digest,
                parent_lease_acquired_record_digest,
                vec![
                    PrivateOramOwnerFinalBucketIndexV1 {
                        index_name: TEST_HNSW_INDEX.to_string(),
                        buckets: PrivateOramOwnerFinalBucketBatchV1::Hnsw(self.hnsw_final.clone()),
                    },
                    PrivateOramOwnerFinalBucketIndexV1 {
                        index_name: TEST_RESULT_INDEX.to_string(),
                        buckets: PrivateOramOwnerFinalBucketBatchV1::Result(
                            self.result_final.clone(),
                        ),
                    },
                ],
            )
            .unwrap();
        let owner_journal_descriptor_digest = token.journal_descriptor_digest().to_string();
        token
            .indexes()
            .iter()
            .map(|index| PrivateOramOwnerPreparedIndexTestEvidenceV1 {
                kind: index.kind(),
                index_name: index.index_name().to_string(),
                owner_journal_descriptor_digest: owner_journal_descriptor_digest.clone(),
                prepared_journal_digest: index.prepared_journal_digest().to_string(),
            })
            .collect()
    }

    pub fn install_hnsw_exact_new_for_recovery(&self) {
        let mutation = &self.mutation_bundle.mutation;
        self.hnsw_store
            .apply_owner_exact_new_test_fixture_v1(
                &mutation.old_state.state.indexes[0],
                &mutation.new_state.state.indexes[0],
                &self.hnsw_final,
                3,
                MAX_CIPHERTEXT_BYTES,
            )
            .unwrap();
    }

    pub fn install_result_exact_new_for_recovery(&self) {
        let mutation = &self.mutation_bundle.mutation;
        self.result_store
            .apply_owner_exact_new_test_fixture_v1(
                &mutation.old_state.state.indexes[1],
                &mutation.new_state.state.indexes[1],
                &self.result_final,
                3,
                MAX_CIPHERTEXT_BYTES,
            )
            .unwrap();
    }

    pub fn resources(&self) -> PrivateOramOwnerRecoveryStorePairResourcesV1<'_> {
        PrivateOramOwnerRecoveryStorePairResourcesV1 {
            owner_journal: &self.owner_journal,
            immutable_manifest: &self.immutable_manifest,
            mutation_bundle: &self.mutation_bundle,
            signature_verification: PrivateOramSignatureVerification {
                expected_key_id: TEST_OWNER_KEY,
                public_key: &self.public_key,
            },
            hnsw_store: &self.hnsw_store,
            hnsw_manifest_validation: PrivateHnswManifestValidationContext {
                expected_collection_id: TEST_COLLECTION_ID,
                expected_vector_name: TEST_HNSW_INDEX,
                expected_key_id: TEST_HNSW_KEY,
                expected_rk_id: TEST_HNSW_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 2,
                expected_distance: DistanceKind::Cosine,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: TEST_OWNER_KEY,
                    public_key: &self.public_key,
                },
            },
            hnsw_max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
            result_store: &self.result_store,
            result_manifest_validation: PrivateResultOramManifestValidationContext {
                expected_collection_id: TEST_COLLECTION_ID,
                expected_key_id: TEST_RESULT_KEY,
                expected_rk_id: TEST_RESULT_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                signature_verification: PrivateResultOramSignatureVerification {
                    expected_key_id: TEST_OWNER_KEY,
                    public_key: &self.public_key,
                },
            },
            result_max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
        }
    }
}

fn digest(marker: u8) -> String {
    BASE64URL_NOPAD.encode(&[marker; 32])
}

fn oram() -> OramParams {
    OramParams {
        kind: OramKind::PathOram,
        bucket_size: 2,
        block_size_bytes: 512,
        tree_height: 1,
        path_batch_size: 2,
    }
}

fn capacity() -> PrivateOramIndexCapacityV2 {
    PrivateOramIndexCapacityV2 {
        bucket_count: 3,
        logical_capacity: 5,
        reserved_physical_slots: 1,
        max_client_stash_blocks: 1,
        fixed_append_read_path_count: 4,
        fixed_append_write_bucket_count: 8,
    }
}

fn ciphertext(size: usize, marker: u8) -> (String, String) {
    let mut bytes = vec![marker; size];
    bytes[0] = 1;
    (
        BASE64URL_NOPAD.encode(&bytes),
        BASE64URL_NOPAD.encode(Sha256::digest(&bytes).as_ref()),
    )
}

fn hnsw_bucket(
    manifest: &PrivateHnswOramManifest,
    bucket_id: u64,
    epoch: u64,
    marker: u8,
) -> PrivateHnswOramBucket {
    let (ciphertext, ciphertext_sha256) = ciphertext(
        private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
        marker,
    );
    let bucket_commitment = private_hnsw_bucket_commitment(
        PrivateHnswBucketAeadContext {
            collection_id: &manifest.collection_id,
            vector_name: &manifest.vector_name,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            bucket_id,
            index_epoch: epoch,
        },
        &ciphertext_sha256,
    )
    .unwrap();
    PrivateHnswOramBucket {
        version: 1,
        bucket_id,
        index_epoch: epoch,
        ciphertext,
        ciphertext_sha256,
        bucket_commitment,
    }
}

fn result_bucket(
    manifest: &PrivateResultOramManifest,
    bucket_id: u64,
    epoch: u64,
    marker: u8,
) -> PrivateResultOramBucket {
    let (ciphertext, ciphertext_sha256) = ciphertext(
        private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
        marker,
    );
    let bucket_commitment = private_result_oram_bucket_commitment(
        PrivateResultOramBucketCommitmentContext {
            collection_id: &manifest.collection_id,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            bucket_id,
            index_epoch: epoch,
        },
        &ciphertext_sha256,
    )
    .unwrap();
    PrivateResultOramBucket {
        version: 1,
        bucket_id,
        index_epoch: epoch,
        ciphertext,
        ciphertext_sha256,
        bucket_commitment,
    }
}

fn hnsw_ref(bucket: &PrivateHnswOramBucket) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id: bucket.bucket_id,
        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        bucket_commitment: bucket.bucket_commitment.clone(),
    }
}

fn result_ref(bucket: &PrivateResultOramBucket) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id: bucket.bucket_id,
        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        bucket_commitment: bucket.bucket_commitment.clone(),
    }
}

fn hnsw_patch_proof(proof: &PrivateHnswOramMerkleProof) -> PrivateOramAppendMerklePatchProofV1 {
    PrivateOramAppendMerklePatchProofV1 {
        version: PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION,
        index_epoch: proof.index_epoch,
        old_root_hash: proof.root_hash.clone(),
        bucket_count: proof.bucket_count,
        leaves: proof
            .leaves
            .iter()
            .map(|leaf| PrivateOramAppendMerklePatchLeafV1 {
                bucket_id: leaf.bucket_id,
                old_commitment: leaf.leaf_hash.clone(),
                siblings: leaf
                    .siblings
                    .iter()
                    .map(|sibling| PrivateOramAppendMerkleSiblingV1 {
                        level: sibling.level,
                        position: match sibling.position {
                            MerkleSiblingPosition::Left => {
                                PrivateOramAppendMerkleSiblingPositionV1::Left
                            }
                            MerkleSiblingPosition::Right => {
                                PrivateOramAppendMerkleSiblingPositionV1::Right
                            }
                        },
                        hash: sibling.hash.clone(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn read_transcript(
    kind: PrivateOramIndexKindV2,
    index_name: &str,
    manifest_digest: &str,
    mutation_id: &str,
    old_state_digest: &str,
    writer_lease_digest: &str,
    writer_fence: u64,
) -> PrivateOramObservedReadTranscriptV1 {
    let labels = [0_u64, 1, 0, 1]
        .into_iter()
        .map(|leaf| match kind {
            PrivateOramIndexKindV2::Hnsw => encode_private_hnsw_oram_leaf_label(leaf, 1).unwrap(),
            PrivateOramIndexKindV2::Result => {
                encode_private_result_oram_leaf_label(leaf, 1).unwrap()
            }
        })
        .collect::<Vec<_>>();
    let windows = labels
        .chunks(2)
        .enumerate()
        .map(|(sequence, paths)| PrivateOramAppendReadWindowV1 {
            sequence: sequence.try_into().unwrap(),
            paths: paths.to_vec(),
        })
        .collect::<Vec<_>>();
    private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
        collection_id: TEST_COLLECTION_ID,
        manifest_digest,
        mutation_id,
        old_state_digest,
        writer_lease_digest,
        writer_fence,
        paths_per_window: 2,
        tree_height: 1,
        kind,
        index_name,
        windows: &windows,
    })
    .unwrap()
}

fn repeated_path_refs(
    final_refs: &[PrivateOramAppendBucketRefV1],
) -> Vec<PrivateOramAppendBucketRefV1> {
    [0, 1, 0, 2, 0, 1, 0, 2]
        .into_iter()
        .map(|index| final_refs[index].clone())
        .collect()
}

fn repeated_hnsw_buckets(final_buckets: &[PrivateHnswOramBucket]) -> Vec<PrivateHnswOramBucket> {
    [0, 1, 0, 2, 0, 1, 0, 2]
        .into_iter()
        .map(|index| final_buckets[index].clone())
        .collect()
}

fn repeated_result_buckets(
    final_buckets: &[PrivateResultOramBucket],
) -> Vec<PrivateResultOramBucket> {
    [0, 1, 0, 2, 0, 1, 0, 2]
        .into_iter()
        .map(|index| final_buckets[index].clone())
        .collect()
}

#[cfg(test)]
mod prestage_tests {
    use std::fs;
    use std::sync::mpsc;
    use std::time::Duration;

    use qdrant_sec::{
        PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
        PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
        PrivateOramAppendOwnerPrestageValidationContextV2, PrivateOramCleanupRaftLocatorV1,
        PrivateOramOwnerCleanupAttemptContextV1, PrivateOramOwnerCleanupAuthorityContextV1,
        PrivateOramOwnerCleanupAuthorizationV1, PrivateOramOwnerCleanupNegativeOutcomeKindV1,
        PrivateOramOwnerCleanupOutcomeContextV1, PrivateOramOwnerCleanupPolicyV1,
        PrivateOramOwnerCleanupTargetV1, PrivateOramOwnerLifecycleStateV1,
        PrivateOramOwnerPrestagePackageV2, PrivateOramOwnerReservationPrepareChallengeV1,
        VerifiedPrivateOramOwnerCleanupAuthorizationV1, VerifiedPrivateOramOwnerPrestageRequestV2,
        encode_private_oram_owner_prestage_package_v2, private_oram_append_mutation_v1_digest,
        private_oram_owner_cleanup_authorization_v1,
        private_oram_owner_cleanup_authorization_verification_context_v1,
        private_oram_owner_cleanup_signer_v1, private_oram_owner_prestage_read_observations_v2,
        private_oram_owner_prestage_request_digest_v2, private_oram_owner_prestage_request_v2,
        private_oram_owner_prestage_roster_digest_v2, private_oram_peer_recovery_public_key_v1,
        sign_private_oram_owner_cleanup_authorization_v1,
        sign_private_oram_owner_cleanup_receipt_v1, sign_private_oram_owner_prestage_request_v2,
        validate_private_oram_append_owner_prepare_from_verified_prestage_v2,
        validate_private_oram_owner_prestage_request_signature_v2,
        validate_signed_private_oram_owner_cleanup_authorization_v1,
    };

    use super::*;
    use crate::private_oram_owner_journal::{
        PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_FILE_V1, PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2,
        PRIVATE_ORAM_PARENT_JOURNAL_LOCK_FILE_V2, PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_FILE_V2,
        PrivateOramDurableOwnerFinalizedTokenV1, PrivateOramOwnerAcknowledgedArchiveExpectationV2,
        PrivateOramOwnerArchivedGenerationV1, PrivateOramOwnerCommittedArchiveGrantIndexV1,
        PrivateOramOwnerCommittedArchiveGrantV1, PrivateOramOwnerCompactedArchiveHistoryV1,
        PrivateOramOwnerNewGenerationReadinessExpectationV2,
        encode_private_oram_owner_committed_archive_grant_v1,
        set_fail_owner_archive_after_canonical_rename_v1,
        set_fail_owner_archive_after_record_publish_v1,
    };
    use crate::{
        PrivateOramOwnerCleanupRepairStateV2, PrivateOramOwnerJournalError,
        PrivateOramOwnerLocalIntentStateV2, PrivateOramOwnerPrepareParentV2,
        PrivateOramOwnerPrepareRequirementV2, PrivateOramOwnerPrestagePlanV2,
        PrivateOramOwnerPrestageReceiptV2, PrivateOramOwnerPrestageStoreV2,
        PrivateOramOwnerReservationResolutionKindV1, PrivateOramOwnerReservationResolutionV1,
    };

    struct PrestageMaterial {
        package: PrivateOramOwnerPrestagePackageV2,
        package_bytes: Vec<u8>,
        verified_request: VerifiedPrivateOramOwnerPrestageRequestV2,
        validated_prepare: qdrant_sec::PrivateOramValidatedOwnerPrepareV1,
        plan: PrivateOramOwnerPrestagePlanV2,
        parent: PrivateOramOwnerPrepareParentV2,
    }

    struct CommittedArchiveFixtureV1 {
        generation: u64,
        terminal_bytes: Vec<u8>,
        grant_bytes: Vec<u8>,
    }

    trait ArchiveCommittedGenerationForTestV1 {
        fn archive_committed_generation_v1(
            &self,
            fixture: CommittedArchiveFixtureV1,
        ) -> Result<PrivateOramOwnerArchivedGenerationV1, PrivateOramOwnerJournalError>;
    }

    impl ArchiveCommittedGenerationForTestV1 for PrivateOramOwnerPrestageStoreV2 {
        fn archive_committed_generation_v1(
            &self,
            fixture: CommittedArchiveFixtureV1,
        ) -> Result<PrivateOramOwnerArchivedGenerationV1, PrivateOramOwnerJournalError> {
            install_canonical_parent_fixture(self, &fixture, true);
            self.archive_committed_generation_from_canonical_parent_v1(fixture.generation)
        }
    }

    fn canonical_parent_completed_path(
        store: &PrivateOramOwnerPrestageStoreV2,
        generation: u64,
    ) -> std::path::PathBuf {
        let hnsw_root = store
            .root_path()
            .parent()
            .and_then(Path::parent)
            .expect("prestage root must be below the HNSW root");
        let collection_root = hnsw_root
            .parent()
            .and_then(Path::parent)
            .expect("HNSW root must be below the collection root");
        collection_root
            .join(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2)
            .join(format!("completed-v2-{generation:020}"))
    }

    fn install_canonical_parent_fixture(
        store: &PrivateOramOwnerPrestageStoreV2,
        fixture: &CommittedArchiveFixtureV1,
        include_grant: bool,
    ) {
        let completed = canonical_parent_completed_path(store, fixture.generation);
        let parent_root = completed.parent().unwrap();
        create_private_fixture_directory(parent_root);
        write_private_fixture_file(
            &parent_root.join(PRIVATE_ORAM_PARENT_JOURNAL_LOCK_FILE_V2),
            &[],
        );
        create_private_fixture_directory(&parent_root.join("temp"));
        create_private_fixture_directory(&completed);
        create_private_fixture_directory(&completed.join("temp"));
        let state_records = completed.join("state_records");
        create_private_fixture_directory(&state_records);
        for sequence in 1..=7 {
            write_private_fixture_file(&state_records.join(format!("{sequence:020}.json")), b"{}");
        }
        for file_name in [
            "descriptor.json",
            "immutable_manifest.json",
            "state.json",
            "format.json",
            "cleanup_complete_v2.json",
        ] {
            write_private_fixture_file(&completed.join(file_name), b"{}");
        }
        write_private_fixture_file(
            &completed.join(PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_FILE_V2),
            &fixture.terminal_bytes,
        );
        if include_grant {
            write_private_fixture_file(
                &completed.join(PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_FILE_V1),
                &fixture.grant_bytes,
            );
        }
        fs::File::open(&completed).unwrap().sync_all().unwrap();
        fs::File::open(parent_root).unwrap().sync_all().unwrap();
    }

    fn create_private_fixture_directory(path: &Path) {
        if !path.exists() {
            fs::create_dir(path).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn write_private_fixture_file(path: &Path, bytes: &[u8]) {
        if path.exists() {
            assert_eq!(fs::read(path).unwrap(), bytes);
        } else {
            fs::write(path, bytes).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::File::open(path).unwrap().sync_all().unwrap();
    }

    fn committed_archive_input(
        receipt: &PrivateOramOwnerPrestageReceiptV2,
        terminal: &PrivateOramDurableOwnerFinalizedTokenV1,
        marker: u8,
    ) -> CommittedArchiveFixtureV1 {
        let indexes = terminal
            .indexes()
            .iter()
            .map(|index| {
                PrivateOramOwnerCommittedArchiveGrantIndexV1::try_new(
                    index.kind(),
                    index.index_name().to_string(),
                    index.prepared_journal_digest().to_string(),
                    index.finalized_state_digest().to_string(),
                )
                .unwrap()
            })
            .collect();
        let terminal_bytes = serde_json::to_vec(&(2_u16, marker)).unwrap();
        let grant = PrivateOramOwnerCommittedArchiveGrantV1::try_new(
            terminal_bytes.len() as u64,
            BASE64URL_NOPAD.encode(&Sha256::digest(&terminal_bytes)),
            TEST_HNSW_INDEX.to_string(),
            receipt.clone(),
            digest(marker),
            digest(marker.wrapping_add(1)),
            digest(marker.wrapping_add(2)),
            digest(marker.wrapping_add(3)),
            terminal.terminal_record_digest().to_string(),
            terminal.consensus_authority_record_digest().to_string(),
            terminal.reconciliation_authority_digest().to_string(),
            digest(marker.wrapping_add(4)),
            indexes,
        )
        .unwrap();
        CommittedArchiveFixtureV1 {
            generation: receipt.lease_generation(),
            terminal_bytes,
            grant_bytes: encode_private_oram_owner_committed_archive_grant_v1(&grant).unwrap(),
        }
    }

    fn readiness_expectation(
        store: &PrivateOramOwnerPrestageStoreV2,
        archives: &[(&PrivateOramOwnerPrestageReceiptV2, u8)],
        aggregate_marker: u8,
    ) -> PrivateOramOwnerNewGenerationReadinessExpectationV2 {
        let (first_receipt, _) = archives
            .first()
            .expect("readiness fixture requires at least one acknowledged archive");
        let owner_store_incarnation_digest = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap()
            .owner_store_incarnation_digest()
            .to_string();
        let acknowledged_archives = archives
            .iter()
            .map(|(receipt, marker)| {
                PrivateOramOwnerAcknowledgedArchiveExpectationV2::try_new(
                    receipt.lease_generation(),
                    receipt.owner_peer_id(),
                    digest(*marker),
                    digest(marker.wrapping_add(2)),
                    digest(marker.wrapping_add(3)),
                )
                .unwrap()
            })
            .collect();
        PrivateOramOwnerNewGenerationReadinessExpectationV2::try_new(
            TEST_COLLECTION_ID.to_string(),
            owner_store_incarnation_digest,
            digest(aggregate_marker),
            acknowledged_archives,
        )
        .unwrap()
    }

    #[test]
    fn owner_snapshot_authority_digest_known_answer_binds_acknowledged_chain() {
        let expectation = PrivateOramOwnerNewGenerationReadinessExpectationV2::try_new(
            TEST_COLLECTION_ID.to_string(),
            digest(201),
            digest(202),
            vec![
                PrivateOramOwnerAcknowledgedArchiveExpectationV2::try_new(
                    7,
                    11,
                    digest(203),
                    digest(204),
                    digest(205),
                )
                .unwrap(),
                PrivateOramOwnerAcknowledgedArchiveExpectationV2::try_new(
                    9,
                    13,
                    digest(206),
                    digest(207),
                    digest(208),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let authority_digest = expectation.snapshot_authority_digest_v2().unwrap();
        assert_eq!(
            authority_digest,
            "NrHV8oWtPLdMmZzgUa8YyeEI2m_fd40nkGhAoJ5JaoA"
        );

        let changed = PrivateOramOwnerNewGenerationReadinessExpectationV2::try_new(
            TEST_COLLECTION_ID.to_string(),
            digest(201),
            digest(202),
            vec![
                PrivateOramOwnerAcknowledgedArchiveExpectationV2::try_new(
                    7,
                    11,
                    digest(203),
                    digest(204),
                    digest(205),
                )
                .unwrap(),
                PrivateOramOwnerAcknowledgedArchiveExpectationV2::try_new(
                    9,
                    13,
                    digest(206),
                    digest(207),
                    digest(209),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert_ne!(
            changed.snapshot_authority_digest_v2().unwrap(),
            authority_digest
        );
    }

    fn install_adopt_and_finalize(
        fixture: &PrivateOramOwnerStorePairTestFixtureV1,
        store: &PrivateOramOwnerPrestageStoreV2,
        material: &PrestageMaterial,
    ) -> (
        PrivateOramOwnerPrestageReceiptV2,
        PrivateOramDurableOwnerFinalizedTokenV1,
    ) {
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        store
            .adopt_for_parent_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            )
            .unwrap();
        let terminal = fixture
            .owner_journal()
            .finalize_store_adapter_test_fixture_v1(&digest(201), &digest(202), 203)
            .unwrap();
        (receipt, terminal)
    }

    fn requirements(
        fixture: &PrivateOramOwnerStorePairTestFixtureV1,
    ) -> Vec<PrivateOramOwnerPrepareRequirementV2> {
        let mutation = &fixture.mutation_bundle().mutation;
        mutation
            .old_state
            .state
            .indexes
            .iter()
            .zip(&mutation.new_state.state.indexes)
            .map(|(old, new)| PrivateOramOwnerPrepareRequirementV2 {
                kind: old.kind,
                index_name: old.index_name.clone(),
                old_epoch: old.index_epoch,
                new_epoch: new.index_epoch,
                old_root_hash: old.root_hash.clone(),
                new_root_hash: new.root_hash.clone(),
                writeback_digest: new.last_writeback_digest.clone(),
            })
            .collect()
    }

    fn material(
        fixture: &PrivateOramOwnerStorePairTestFixtureV1,
        peer_key_pair: &Ed25519KeyPair,
        marker: u8,
        lease_generation: u64,
    ) -> PrestageMaterial {
        let owner_prepare = fixture.owner_prepare_bundle();
        let mutation = &owner_prepare.mutation_bundle.mutation;
        let parent_descriptor_digest = digest(marker);
        let parent_lease_acquired_record_digest = digest(marker.wrapping_add(1));
        let owner_peer_ids = vec![11];
        let package = PrivateOramOwnerPrestagePackageV2 {
            version: PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
            collection_name: "docs".to_string(),
            collection_id: mutation.collection_id.clone(),
            mutation_id: mutation.mutation_id.clone(),
            mutation_digest: private_oram_append_mutation_v1_digest(mutation).unwrap(),
            transition_digest: digest(marker.wrapping_add(2)),
            base_record_digest: digest(marker.wrapping_add(3)),
            expected_aggregate_digest: digest(marker.wrapping_add(4)),
            lease_generation,
            writer_fence: mutation.writer_fence,
            coordinator_peer_id: 11,
            owner_peer_id: 11,
            vector_name: TEST_HNSW_INDEX.to_string(),
            owner_signing_key_id: TEST_OWNER_KEY.to_string(),
            activation_registry_generation: 7,
            activation_manifest_digest: digest(marker.wrapping_add(5)),
            parent_descriptor_digest: parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.clone(),
            owner_peer_ids: owner_peer_ids.clone(),
            owner_roster_digest: private_oram_owner_prestage_roster_digest_v2(&owner_peer_ids)
                .unwrap(),
            immutable_manifest: fixture.immutable_manifest().clone(),
            owner_prepare,
            durable_read_observations: private_oram_owner_prestage_read_observations_v2(
                fixture.read_transcripts(),
            )
            .unwrap(),
            staged_insert_frame_b64: None,
        };
        let mutation = &package.owner_prepare.mutation_bundle.mutation;
        let package_bytes = encode_private_oram_owner_prestage_package_v2(&package).unwrap();
        let request = private_oram_owner_prestage_request_v2(
            BASE64URL_NOPAD.encode(&[marker; 16]),
            &package,
            &package_bytes,
        )
        .unwrap();
        let request_signature =
            sign_private_oram_owner_prestage_request_v2(peer_key_pair, 3, &request).unwrap();
        let peer_public_key = private_oram_peer_recovery_public_key_v1(peer_key_pair, 3).unwrap();
        let verified_request = validate_private_oram_owner_prestage_request_signature_v2(
            &peer_public_key,
            &request,
            &package_bytes,
            &request_signature,
        )
        .unwrap();
        let old_state = &package
            .owner_prepare
            .mutation_bundle
            .mutation
            .old_state
            .state;
        let old_state_digest = private_oram_signed_state_v2_digest(old_state).unwrap();
        let validated_prepare =
            validate_private_oram_append_owner_prepare_from_verified_prestage_v2(
                &package.immutable_manifest,
                &package.owner_prepare,
                &package.durable_read_observations,
                &verified_request,
                PrivateOramAppendOwnerPrestageValidationContextV2 {
                    expected_collection_id: &mutation.collection_id,
                    expected_manifest_digest: &mutation.manifest_digest,
                    expected_owner_signing_key_id: &mutation.owner_signing_key_id,
                    expected_layout_generation: old_state.layout_generation,
                    expected_layout_digest: &old_state.layout_digest,
                    expected_writer_lease_digest: &mutation.writer_lease_digest,
                    expected_writer_fence: mutation.writer_fence,
                    expected_state_sequence: old_state.state_sequence,
                    expected_old_state_digest: &old_state_digest,
                    expected_visible_point_record: None,
                    now_unix: mutation.new_state.state.signed_at_unix,
                    max_mutation_ttl_secs: 300,
                    public_key: fixture.public_key(),
                },
            )
            .unwrap_or_else(|error| match error {
                qdrant_sec::PrivateOramAppendOwnerPrepareError::Mutation(
                    qdrant_sec::PrivateOramMutationError::InvalidMutationField(field),
                ) => panic!("invalid mutation field: {field}"),
                qdrant_sec::PrivateOramAppendOwnerPrepareError::Mutation(
                    qdrant_sec::PrivateOramMutationError::MutationContextMismatch(field),
                ) => panic!("mutation context mismatch: {field}"),
                qdrant_sec::PrivateOramAppendOwnerPrepareError::Mutation(
                    qdrant_sec::PrivateOramMutationError::InvalidStateField(field),
                ) => panic!("invalid state field: {field}"),
                qdrant_sec::PrivateOramAppendOwnerPrepareError::Mutation(
                    qdrant_sec::PrivateOramMutationError::InvalidStateTransition(field),
                ) => panic!("invalid state transition: {field}"),
                error => panic!("owner prepare validation failed: {error}"),
            });
        let requirements = requirements(fixture);
        let plan = PrivateOramOwnerPrestagePlanV2::try_new(
            parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest.clone(),
            11,
            requirements.clone(),
        )
        .unwrap();
        let parent = PrivateOramOwnerPrepareParentV2::try_new(
            parent_descriptor_digest,
            parent_lease_acquired_record_digest,
            11,
            requirements,
        )
        .unwrap();
        PrestageMaterial {
            package,
            package_bytes,
            verified_request,
            validated_prepare,
            plan,
            parent,
        }
    }

    fn reservation_challenge(
        material: &PrestageMaterial,
        lifecycle: &PrivateOramOwnerLifecycleStateV1,
    ) -> PrivateOramOwnerReservationPrepareChallengeV1 {
        let request = material.verified_request.request();
        PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: digest(201),
            raft_group_id_digest: digest(202),
            collection_id: request.collection_id.clone(),
            collection_lifetime_id_digest: digest(203),
            collection_incarnation_digest: digest(204),
            activation_anchor_digest: digest(205),
            capability_epoch: 7,
            protocol_capability_digest: digest(206),
            membership_epoch: 9,
            reservation_intent_digest: digest(207),
            checkpoint_context_digest: digest(208),
            committed_challenge_digest: digest(209),
            challenge_applied_term: 5,
            challenge_applied_index: 13,
            attempt_id: digest(210),
            challenge_nonce: BASE64URL_NOPAD.encode(&[211; 16]),
            expected_checkpoint_record_digest: digest(212),
            expected_checkpoint_sequence: 1,
            expected_owner_target_digest: digest(213),
            reserved_terminal_intent_key: request.intent_key.clone(),
            owner_index: 0,
            owner_count: 1,
            owner_enrollment_id: digest(214),
            owner_peer_id: request.owner_peer_id,
            owner_store_incarnation_digest: lifecycle.owner_store_incarnation_digest.clone(),
            authority_registry_digest: digest(215),
            owner_registry_digest: digest(216),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn cleanup_authorization(
        material: &PrestageMaterial,
        receipt: Option<&PrivateOramOwnerPrestageReceiptV2>,
        intent_marker_digest: Option<&str>,
        expected_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
        authority_key: &Ed25519KeyPair,
        owner_key: &Ed25519KeyPair,
        outcome_kind: PrivateOramOwnerCleanupNegativeOutcomeKindV1,
        synthetic_prestage_binding: bool,
    ) -> VerifiedPrivateOramOwnerCleanupAuthorizationV1 {
        let request = material.verified_request.request();
        let prestaged = receipt.is_some() || synthetic_prestage_binding;
        let owner_signer = private_oram_owner_cleanup_signer_v1(owner_key, 3).unwrap();
        let mut authorization = PrivateOramOwnerCleanupAuthorizationV1 {
            version: 0,
            protocol: String::new(),
            authority: PrivateOramOwnerCleanupAuthorityContextV1 {
                consensus_history_id_digest: digest(180),
                raft_group_id_digest: digest(181),
                collection_id: request.collection_id.clone(),
                collection_lifetime_id_digest: digest(182),
                collection_incarnation_digest: digest(183),
                activation_anchor_digest: digest(184),
                activation_registry_generation: request.activation_registry_generation,
                activation_manifest_digest: request.activation_manifest_digest.clone(),
                owner_roster_digest: request.owner_roster_digest.clone(),
            },
            attempt: PrivateOramOwnerCleanupAttemptContextV1 {
                attempt_id: digest(185),
                attempt_sequence: 1,
                mutation_id: request.mutation_id.clone(),
                mutation_digest: request.mutation_digest.clone(),
                expected_aggregate_digest: request.expected_aggregate_digest.clone(),
                reservation_digest: digest(186),
                reservation_applied: PrivateOramCleanupRaftLocatorV1 { term: 7, index: 10 },
                lease_generation: request.lease_generation,
                writer_fence: request.writer_fence,
            },
            outcome: PrivateOramOwnerCleanupOutcomeContextV1 {
                kind: outcome_kind.clone(),
                outcome_key: digest(187),
                outcome_digest: digest(188),
                negative_record_digest: digest(189),
                outcome_applied: PrivateOramCleanupRaftLocatorV1 { term: 7, index: 11 },
            },
            target: PrivateOramOwnerCleanupTargetV1 {
                owner_index: 0,
                owner_peer_id: request.owner_peer_id,
                owner_signer,
                expected_lifecycle_state,
                intent_key: request.intent_key.clone(),
                intent_identity_digest: String::new(),
                package_sha256: request.package_sha256.clone(),
                package_len: request.package_len,
                owner_request_digest: private_oram_owner_prestage_request_digest_v2(request)
                    .unwrap(),
                prestage_receipt_digest: receipt
                    .map(|receipt| receipt.receipt_digest().to_string())
                    .or_else(|| synthetic_prestage_binding.then(|| digest(190))),
                intent_marker_digest: intent_marker_digest
                    .map(ToOwned::to_owned)
                    .or_else(|| synthetic_prestage_binding.then(|| digest(191))),
                parent_descriptor_digest: request.parent_descriptor_digest.clone(),
                parent_lease_acquired_record_digest: request
                    .parent_lease_acquired_record_digest
                    .clone(),
                owner_journal_descriptor_digest: receipt
                    .map(|receipt| receipt.owner_journal_descriptor_digest().to_string())
                    .or_else(|| synthetic_prestage_binding.then(|| digest(192))),
                target_digest: String::new(),
            },
            policy: if matches!(
                outcome_kind,
                PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected
            ) {
                PrivateOramOwnerCleanupPolicyV1::RequireMatchingIntentQuarantine
            } else {
                PrivateOramOwnerCleanupPolicyV1::TombstoneAbsentOrQuarantineIntent
            },
            cleanup_operation_id: String::new(),
            authorization_digest: String::new(),
        };
        assert_eq!(
            prestaged,
            authorization.target.prestage_receipt_digest.is_some()
        );
        authorization = private_oram_owner_cleanup_authorization_v1(authorization).unwrap();
        let authority_signer = private_oram_owner_cleanup_signer_v1(authority_key, 7).unwrap();
        let signed =
            sign_private_oram_owner_cleanup_authorization_v1(authority_key, 7, &authorization)
                .unwrap();
        let verification_context =
            private_oram_owner_cleanup_authorization_verification_context_v1(
                authorization.clone(),
                authority_signer,
                authorization.target.owner_signer.clone(),
                authorization.target.expected_lifecycle_state.clone(),
                digest(193),
                digest(194),
                digest(195),
            )
            .unwrap();
        validate_signed_private_oram_owner_cleanup_authorization_v1(&signed, &verification_context)
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn consensus_prepared_genesis_enrollment_is_durable_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [36; 32]);
        let incarnation = digest(217);
        let conflicting_incarnation = digest(218);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());

        assert_eq!(
            store.require_enrollment_v2(&incarnation),
            Err(PrivateOramOwnerJournalError::NotEnrolled)
        );
        assert!(!store.root_path().exists());

        store.install_genesis_enrollment_v2(&incarnation).unwrap();
        store.require_enrollment_v2(&incarnation).unwrap();
        store
            .require_ready_for_new_generation_v2(
                &PrivateOramOwnerNewGenerationReadinessExpectationV2::try_new(
                    TEST_COLLECTION_ID.to_string(),
                    incarnation.clone(),
                    digest(219),
                    Vec::new(),
                )
                .unwrap(),
            )
            .unwrap();
        store.install_genesis_enrollment_v2(&incarnation).unwrap();

        let reopened = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        reopened.require_enrollment_v2(&incarnation).unwrap();
        assert_eq!(
            reopened.install_genesis_enrollment_v2(&conflicting_incarnation),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        assert_eq!(
            reopened.require_enrollment_v2(&conflicting_incarnation),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn active_reservation_fence_blocks_owner_state_mutations() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let authority_key = Ed25519KeyPair::from_seed_unchecked(&[111; 32]).unwrap();
        let first = material(&fixture, &owner_key, 117, 2);
        let second = material(&fixture, &owner_key, 118, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let first_receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        let first_status = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap();
        let lifecycle = first_status.lifecycle_state().clone();
        let challenge = reservation_challenge(&second, &lifecycle);
        let _fence = store
            .prepare_reservation_fence_v1(&challenge, &lifecycle)
            .unwrap();

        assert_eq!(
            store.install_v2(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            ),
            Err(PrivateOramOwnerJournalError::ConcurrentMutation)
        );
        assert_eq!(
            store.adopt_for_parent_v2(
                first_receipt.intent_key(),
                first_receipt.package_sha256(),
                &first.parent,
            ),
            Err(PrivateOramOwnerJournalError::ConcurrentMutation)
        );
        let authorization = cleanup_authorization(
            &first,
            Some(&first_receipt),
            first_status.marker_digest(),
            lifecycle,
            &authority_key,
            &owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
            false,
        );
        assert_eq!(
            store.cleanup_with_authorization_v2(&authorization, |_| {
                panic!("an active reservation fence must reject before signing cleanup")
            }),
            Err(PrivateOramOwnerJournalError::ConcurrentMutation)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finalized_reservation_fence_hands_off_only_to_the_reserved_intent() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let first = material(&fixture, &owner_key, 217, 2);
        let second = material(&fixture, &owner_key, 218, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let first_receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        let lifecycle = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap()
            .lifecycle_state()
            .clone();
        let challenge = reservation_challenge(&second, &lifecycle);
        let resolution = PrivateOramOwnerReservationResolutionV1 {
            kind: PrivateOramOwnerReservationResolutionKindV1::Finalized,
            committed_challenge_digest: challenge.committed_challenge_digest.clone(),
            reservation_intent_digest: challenge.reservation_intent_digest.clone(),
            attempt_id: challenge.attempt_id.clone(),
            challenge_applied_term: challenge.challenge_applied_term,
            challenge_applied_index: challenge.challenge_applied_index,
            resolution_applied_term: 5,
            resolution_applied_index: 14,
            finalized_reservation_digest: Some(digest(219)),
        };
        assert_eq!(
            store.install_v3_reserved(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            ),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        assert_eq!(
            store.resolve_reservation_fence_v1(&resolution),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        store
            .prepare_reservation_fence_v1(&challenge, &lifecycle)
            .unwrap();
        store.resolve_reservation_fence_v1(&resolution).unwrap();
        assert_eq!(
            store.confirm_installed_reservation_resolution_v1(&resolution),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        drop(store);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());

        let second_receipt = store
            .install_v3_reserved(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            )
            .unwrap();
        assert_eq!(
            store
                .install_v3_reserved(
                    &second.verified_request,
                    &second.package,
                    &second.package_bytes,
                    &second.validated_prepare,
                    &second.plan,
                )
                .unwrap(),
            second_receipt
        );
        store.resolve_reservation_fence_v1(&resolution).unwrap();
        let installed = store
            .confirm_installed_reservation_resolution_v1(&resolution)
            .unwrap();
        assert_eq!(
            installed
                .durable_resolution()
                .reserved_terminal_intent_key(),
            second_receipt.intent_key()
        );
        assert_eq!(
            installed.installed_prestage_receipt_digest(),
            second_receipt.receipt_digest()
        );
        assert_eq!(
            installed.installed_package_sha256(),
            second_receipt.package_sha256()
        );
        drop(store);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        assert_eq!(
            store
                .confirm_installed_reservation_resolution_v1(&resolution)
                .unwrap(),
            installed
        );
        store
            .adopt_for_parent_v2(
                second_receipt.intent_key(),
                second_receipt.package_sha256(),
                &second.parent,
            )
            .unwrap();
        drop(store);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let recovered = store
            .confirm_installed_reservation_resolution_v1(&resolution)
            .unwrap();
        assert_eq!(
            recovered.durable_resolution(),
            installed.durable_resolution()
        );
        assert_eq!(
            recovered.installed_prestage_receipt_digest(),
            installed.installed_prestage_receipt_digest()
        );
        assert_eq!(
            recovered.installed_package_sha256(),
            installed.installed_package_sha256()
        );
        assert_ne!(
            recovered.installed_intent_marker_digest(),
            installed.installed_intent_marker_digest()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cancelled_reservation_fence_releases_after_durable_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let first = material(&fixture, &owner_key, 220, 2);
        let second = material(&fixture, &owner_key, 221, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let first_receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        let lifecycle = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap()
            .lifecycle_state()
            .clone();
        let challenge = reservation_challenge(&second, &lifecycle);
        store
            .prepare_reservation_fence_v1(&challenge, &lifecycle)
            .unwrap();
        let resolution = PrivateOramOwnerReservationResolutionV1 {
            kind: PrivateOramOwnerReservationResolutionKindV1::Cancelled,
            committed_challenge_digest: challenge.committed_challenge_digest.clone(),
            reservation_intent_digest: challenge.reservation_intent_digest.clone(),
            attempt_id: challenge.attempt_id.clone(),
            challenge_applied_term: challenge.challenge_applied_term,
            challenge_applied_index: challenge.challenge_applied_index,
            resolution_applied_term: 6,
            resolution_applied_index: 15,
            finalized_reservation_digest: None,
        };
        store.resolve_reservation_fence_v1(&resolution).unwrap();
        assert_eq!(
            store.confirm_installed_reservation_resolution_v1(&resolution),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        drop(store);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        store.resolve_reservation_fence_v1(&resolution).unwrap();

        let mut next_challenge = challenge.clone();
        next_challenge.committed_challenge_digest = digest(222);
        next_challenge.challenge_nonce = BASE64URL_NOPAD.encode(&[223; 16]);
        next_challenge.attempt_id = digest(224);
        next_challenge.reservation_intent_digest = digest(225);
        store
            .prepare_reservation_fence_v1(&next_challenge, &lifecycle)
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cancelled_reservation_without_fence_records_absence_and_replays() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let first = material(&fixture, &owner_key, 239, 2);
        let second = material(&fixture, &owner_key, 240, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let first_receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        let lifecycle = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap()
            .lifecycle_state()
            .clone();
        let challenge = reservation_challenge(&second, &lifecycle);
        let resolution = PrivateOramOwnerReservationResolutionV1 {
            kind: PrivateOramOwnerReservationResolutionKindV1::Cancelled,
            committed_challenge_digest: challenge.committed_challenge_digest.clone(),
            reservation_intent_digest: challenge.reservation_intent_digest.clone(),
            attempt_id: challenge.attempt_id.clone(),
            challenge_applied_term: challenge.challenge_applied_term,
            challenge_applied_index: challenge.challenge_applied_index,
            resolution_applied_term: 9,
            resolution_applied_index: 18,
            finalized_reservation_digest: None,
        };
        let absent = store
            .resolve_reservation_fence_or_record_absent_cancellation_v1(
                &resolution,
                &challenge,
                &lifecycle,
            )
            .unwrap();
        assert_eq!(
            store.prepare_reservation_fence_v1(&challenge, &lifecycle),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        drop(store);

        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        assert_eq!(
            store
                .resolve_reservation_fence_or_record_absent_cancellation_v1(
                    &resolution,
                    &challenge,
                    &lifecycle,
                )
                .unwrap(),
            absent
        );
        let mut next_challenge = challenge.clone();
        next_challenge.committed_challenge_digest = digest(241);
        next_challenge.challenge_nonce = BASE64URL_NOPAD.encode(&[242; 16]);
        next_challenge.attempt_id = digest(243);
        next_challenge.reservation_intent_digest = digest(244);
        store
            .prepare_reservation_fence_v1(&next_challenge, &lifecycle)
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finalized_uninstalled_reservation_requires_durable_abort_release_marker() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let first = material(&fixture, &owner_key, 226, 2);
        let second = material(&fixture, &owner_key, 227, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let first_receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        let lifecycle = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap()
            .lifecycle_state()
            .clone();
        let challenge = reservation_challenge(&second, &lifecycle);
        let resolution = PrivateOramOwnerReservationResolutionV1 {
            kind: PrivateOramOwnerReservationResolutionKindV1::Finalized,
            committed_challenge_digest: challenge.committed_challenge_digest.clone(),
            reservation_intent_digest: challenge.reservation_intent_digest.clone(),
            attempt_id: challenge.attempt_id.clone(),
            challenge_applied_term: challenge.challenge_applied_term,
            challenge_applied_index: challenge.challenge_applied_index,
            resolution_applied_term: 7,
            resolution_applied_index: 16,
            finalized_reservation_digest: Some(digest(228)),
        };
        let abort_authority = digest(229);
        assert_eq!(
            store.release_finalized_reservation_after_abort_v1(&resolution, &abort_authority,),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        store
            .prepare_reservation_fence_v1(&challenge, &lifecycle)
            .unwrap();
        store.resolve_reservation_fence_v1(&resolution).unwrap();
        let released = store
            .release_finalized_reservation_after_abort_v1(&resolution, &abort_authority)
            .unwrap();
        assert_eq!(released.abort_release_authority_digest(), abort_authority);
        assert_eq!(
            released.durable_resolution().owner_store_binding_digest(),
            challenge.expected_checkpoint_record_digest
        );
        assert_eq!(
            store.install_v3_reserved(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            ),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        drop(store);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        assert_eq!(
            store
                .release_finalized_reservation_after_abort_v1(&resolution, &abort_authority)
                .unwrap(),
            released
        );
        assert_eq!(
            store.release_finalized_reservation_after_abort_v1(&resolution, &digest(230)),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        let mut next_challenge = challenge.clone();
        next_challenge.committed_challenge_digest = digest(231);
        next_challenge.challenge_nonce = BASE64URL_NOPAD.encode(&[232; 16]);
        next_challenge.attempt_id = digest(233);
        next_challenge.reservation_intent_digest = digest(234);
        store
            .prepare_reservation_fence_v1(&next_challenge, &lifecycle)
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finalized_abort_release_rejects_durable_intent_before_fence_consumption() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let first = material(&fixture, &owner_key, 235, 2);
        let second = material(&fixture, &owner_key, 236, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let first_receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        let lifecycle = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap()
            .lifecycle_state()
            .clone();
        let challenge = reservation_challenge(&second, &lifecycle);
        let resolution = PrivateOramOwnerReservationResolutionV1 {
            kind: PrivateOramOwnerReservationResolutionKindV1::Finalized,
            committed_challenge_digest: challenge.committed_challenge_digest.clone(),
            reservation_intent_digest: challenge.reservation_intent_digest.clone(),
            attempt_id: challenge.attempt_id.clone(),
            challenge_applied_term: challenge.challenge_applied_term,
            challenge_applied_index: challenge.challenge_applied_index,
            resolution_applied_term: 8,
            resolution_applied_index: 17,
            finalized_reservation_digest: Some(digest(237)),
        };
        store
            .prepare_reservation_fence_v1(&challenge, &lifecycle)
            .unwrap();
        store.resolve_reservation_fence_v1(&resolution).unwrap();
        store
            .install_v3_reserved_leave_fence_for_test_v1(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            )
            .unwrap();

        assert_eq!(
            store.release_finalized_reservation_after_abort_v1(&resolution, &digest(238)),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        store
            .install_v3_reserved(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            )
            .unwrap();
        assert!(
            store
                .confirm_installed_reservation_resolution_v1(&resolution)
                .is_ok()
        );
        assert_eq!(
            store.release_finalized_reservation_after_abort_v1(&resolution, &digest(238)),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finalized_install_rejects_durable_abort_marker_before_fence_consumption() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let first = material(&fixture, &owner_key, 245, 2);
        let second = material(&fixture, &owner_key, 246, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let first_receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        let lifecycle = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap()
            .lifecycle_state()
            .clone();
        let challenge = reservation_challenge(&second, &lifecycle);
        let resolution = PrivateOramOwnerReservationResolutionV1 {
            kind: PrivateOramOwnerReservationResolutionKindV1::Finalized,
            committed_challenge_digest: challenge.committed_challenge_digest.clone(),
            reservation_intent_digest: challenge.reservation_intent_digest.clone(),
            attempt_id: challenge.attempt_id.clone(),
            challenge_applied_term: challenge.challenge_applied_term,
            challenge_applied_index: challenge.challenge_applied_index,
            resolution_applied_term: 10,
            resolution_applied_index: 19,
            finalized_reservation_digest: Some(digest(247)),
        };
        let abort_authority = digest(248);
        store
            .prepare_reservation_fence_v1(&challenge, &lifecycle)
            .unwrap();
        store.resolve_reservation_fence_v1(&resolution).unwrap();
        let released = store
            .release_finalized_reservation_after_abort_leave_fence_for_test_v1(
                &resolution,
                &abort_authority,
            )
            .unwrap();

        assert_eq!(
            store.install_v3_reserved(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            ),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        assert_eq!(
            store
                .inspect_lifecycle_v2(second.verified_request.request().intent_key.as_str())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::Absent
        );
        assert_eq!(
            store
                .release_finalized_reservation_after_abort_v1(&resolution, &abort_authority)
                .unwrap(),
            released
        );
        assert_eq!(
            store.install_v3_reserved(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            ),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_signed_cleanup_quarantines_replays_and_fences_stale_root() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let authority_key = Ed25519KeyPair::from_seed_unchecked(&[111; 32]).unwrap();
        let first = material(&fixture, &owner_key, 121, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        let before = store.inspect_lifecycle_v2(receipt.intent_key()).unwrap();
        let genesis = before.lifecycle_state().clone();
        let authorization = cleanup_authorization(
            &first,
            Some(&receipt),
            before.marker_digest(),
            genesis.clone(),
            &authority_key,
            &owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
            false,
        );
        let signed = store
            .cleanup_with_authorization_v2(&authorization, |unsigned| {
                sign_private_oram_owner_cleanup_receipt_v1(&owner_key, 3, unsigned).map_err(|_| {
                    crate::PrivateOramOwnerJournalError::InvalidInput("test_cleanup_signer")
                })
            })
            .unwrap();
        assert_eq!(signed.receipt().previous_lifecycle_state, genesis);
        assert_eq!(signed.receipt().new_lifecycle_state.generation, 1);
        assert_eq!(
            signed.repair_state(),
            PrivateOramOwnerCleanupRepairStateV2::Complete
        );
        let status = store.inspect_lifecycle_v2(receipt.intent_key()).unwrap();
        assert_eq!(
            status.state(),
            PrivateOramOwnerLocalIntentStateV2::Quarantined
        );
        assert_eq!(
            status.lifecycle_state(),
            &signed.receipt().new_lifecycle_state
        );
        assert!(
            store
                .root_path()
                .join("quarantine")
                .join(receipt.intent_key())
                .exists()
        );
        let replay = store
            .cleanup_with_authorization_v2(&authorization, |_| {
                panic!("exact terminal replay must not request another owner signature")
            })
            .unwrap();
        assert_eq!(replay, signed);

        let second = material(&fixture, &owner_key, 122, 3);
        let second_receipt = store
            .install_v2(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            )
            .unwrap();
        let second_status = store
            .inspect_lifecycle_v2(second_receipt.intent_key())
            .unwrap();
        let stale = cleanup_authorization(
            &second,
            Some(&second_receipt),
            second_status.marker_digest(),
            genesis,
            &authority_key,
            &owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
            false,
        );
        assert!(
            store
                .cleanup_with_authorization_v2(&stale, |_| {
                    panic!("a stale lifecycle root must fail before owner signing")
                })
                .is_err()
        );
        assert_eq!(
            store
                .inspect_lifecycle_v2(second_receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::Intent
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_signed_absent_cleanup_tombstones_and_rejects_admission_absence() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [38; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[92; 32]).unwrap();
        let authority_key = Ed25519KeyPair::from_seed_unchecked(&[112; 32]).unwrap();
        let first = material(&fixture, &owner_key, 123, 2);
        let first_key = first.verified_request.request().intent_key.clone();
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let absent = store.inspect_lifecycle_v2(&first_key).unwrap();
        let authorization = cleanup_authorization(
            &first,
            None,
            None,
            absent.lifecycle_state().clone(),
            &authority_key,
            &owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::PrestageAborted,
            false,
        );
        let signed = store
            .cleanup_with_authorization_v2(&authorization, |unsigned| {
                sign_private_oram_owner_cleanup_receipt_v1(&owner_key, 3, unsigned).map_err(|_| {
                    crate::PrivateOramOwnerJournalError::InvalidInput("test_cleanup_signer")
                })
            })
            .unwrap();
        assert_eq!(
            signed.receipt().terminal_state,
            qdrant_sec::PrivateOramOwnerCleanupTerminalStateV1::TombstonedAbsent
        );
        assert_eq!(
            store.inspect_lifecycle_v2(&first_key).unwrap().state(),
            PrivateOramOwnerLocalIntentStateV2::TombstonedAbsent
        );
        assert!(
            store
                .install_v2(
                    &first.verified_request,
                    &first.package,
                    &first.package_bytes,
                    &first.validated_prepare,
                    &first.plan,
                )
                .is_err()
        );

        let second = material(&fixture, &owner_key, 124, 3);
        let second_key = second.verified_request.request().intent_key.clone();
        let second_absent = store.inspect_lifecycle_v2(&second_key).unwrap();
        let invalid_admission_cleanup = cleanup_authorization(
            &second,
            None,
            None,
            second_absent.lifecycle_state().clone(),
            &authority_key,
            &owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
            true,
        );
        assert!(
            store
                .cleanup_with_authorization_v2(&invalid_admission_cleanup, |_| {
                    panic!("admission rejection of an absent intent must fail before signing")
                })
                .is_err()
        );
        assert_eq!(
            store.inspect_lifecycle_v2(&second_key).unwrap().state(),
            PrivateOramOwnerLocalIntentStateV2::Absent
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_signed_cleanup_chain_gap_blocks_ordinary_open() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [42; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[97; 32]).unwrap();
        let authority_key = Ed25519KeyPair::from_seed_unchecked(&[117; 32]).unwrap();
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());

        let first = material(&fixture, &owner_key, 128, 2);
        let first_key = first.verified_request.request().intent_key.clone();
        let first_status = store.inspect_lifecycle_v2(&first_key).unwrap();
        let first_authorization = cleanup_authorization(
            &first,
            None,
            None,
            first_status.lifecycle_state().clone(),
            &authority_key,
            &owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::PrestageAborted,
            false,
        );
        store
            .cleanup_with_authorization_v2(&first_authorization, |unsigned| {
                sign_private_oram_owner_cleanup_receipt_v1(&owner_key, 3, unsigned)
                    .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("test_cleanup_signer"))
            })
            .unwrap();

        let second = material(&fixture, &owner_key, 129, 3);
        let second_key = second.verified_request.request().intent_key.clone();
        let second_status = store.inspect_lifecycle_v2(&second_key).unwrap();
        let second_authorization = cleanup_authorization(
            &second,
            None,
            None,
            second_status.lifecycle_state().clone(),
            &authority_key,
            &owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::PrestageAborted,
            false,
        );
        store
            .cleanup_with_authorization_v2(&second_authorization, |unsigned| {
                sign_private_oram_owner_cleanup_receipt_v1(&owner_key, 3, unsigned)
                    .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("test_cleanup_signer"))
            })
            .unwrap();

        fs::remove_dir_all(store.root_path().join("terminals").join(&first_key)).unwrap();
        assert!(matches!(
            store.inspect_lifecycle_v2(&second_key),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_signed_cleanup_cannot_cross_adoption_pending() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [39; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[93; 32]).unwrap();
        let authority_key = Ed25519KeyPair::from_seed_unchecked(&[113; 32]).unwrap();
        let material = material(&fixture, &owner_key, 125, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        let intent = store.inspect_lifecycle_v2(receipt.intent_key()).unwrap();
        let authorization = cleanup_authorization(
            &material,
            Some(&receipt),
            intent.marker_digest(),
            intent.lifecycle_state().clone(),
            &authority_key,
            &owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
            false,
        );
        store
            .leave_adoption_pending_for_test_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            )
            .unwrap();
        assert!(
            store
                .cleanup_with_authorization_v2(&authorization, |_| {
                    panic!("adoption-pending state must fail before owner signing")
                })
                .is_err()
        );
        let pending = store.inspect_lifecycle_v2(receipt.intent_key()).unwrap();
        assert_eq!(
            pending.state(),
            PrivateOramOwnerLocalIntentStateV2::AdoptionPending
        );
        assert_eq!(pending.lifecycle_state().generation, 0);
        assert!(
            !store
                .root_path()
                .join("terminals")
                .join(receipt.intent_key())
                .exists()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_signed_cleanup_recovers_terminal_before_superblock_crash() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [40; 32]);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[94; 32]).unwrap();
        let authority_key = Ed25519KeyPair::from_seed_unchecked(&[114; 32]).unwrap();
        let material = material(&fixture, &owner_key, 126, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        let intent = store.inspect_lifecycle_v2(receipt.intent_key()).unwrap();
        let authorization = cleanup_authorization(
            &material,
            Some(&receipt),
            intent.marker_digest(),
            intent.lifecycle_state().clone(),
            &authority_key,
            &owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
            false,
        );
        let signed = store
            .leave_cleanup_after_terminal_for_test_v2(&authorization, |unsigned| {
                sign_private_oram_owner_cleanup_receipt_v1(&owner_key, 3, unsigned).map_err(|_| {
                    crate::PrivateOramOwnerJournalError::InvalidInput("test_cleanup_signer")
                })
            })
            .unwrap();
        let superblock_path = store.root_path().join("superblock.json");
        let before: serde_json::Value =
            serde_json::from_slice(&fs::read(&superblock_path).unwrap()).unwrap();
        assert_eq!(before["lifecycle_generation"], 0);
        assert!(
            store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .exists()
        );

        let reopened = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        assert!(matches!(
            reopened.inspect_lifecycle_v2(receipt.intent_key()),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        ));
        let still_before: serde_json::Value =
            serde_json::from_slice(&fs::read(&superblock_path).unwrap()).unwrap();
        assert_eq!(still_before["lifecycle_generation"], 0);
        let replay = reopened
            .cleanup_with_authorization_v2(&authorization, |_| {
                panic!("recovery replay must use the durable signed receipt")
            })
            .unwrap();
        assert_eq!(replay.signed_receipt(), &signed);
        assert_eq!(
            replay.repair_state(),
            PrivateOramOwnerCleanupRepairStateV2::Complete
        );
        let recovered = reopened.inspect_lifecycle_v2(receipt.intent_key()).unwrap();
        assert_eq!(
            recovered.state(),
            PrivateOramOwnerLocalIntentStateV2::Quarantined
        );
        assert_eq!(
            recovered.lifecycle_state(),
            &signed.receipt.new_lifecycle_state
        );
        assert!(
            !reopened
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .exists()
        );
        assert!(
            reopened
                .root_path()
                .join("quarantine")
                .join(receipt.intent_key())
                .exists()
        );
        let after: serde_json::Value =
            serde_json::from_slice(&fs::read(superblock_path).unwrap()).unwrap();
        assert_eq!(after["lifecycle_generation"], 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_self_signed_terminal_cannot_advance_or_relocate_payload() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [41; 32]);
        let legitimate_owner_key = Ed25519KeyPair::from_seed_unchecked(&[95; 32]).unwrap();
        let legitimate_authority_key = Ed25519KeyPair::from_seed_unchecked(&[115; 32]).unwrap();
        let attacker_owner_key = Ed25519KeyPair::from_seed_unchecked(&[96; 32]).unwrap();
        let attacker_authority_key = Ed25519KeyPair::from_seed_unchecked(&[116; 32]).unwrap();
        let material = material(&fixture, &legitimate_owner_key, 127, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        let intent = store.inspect_lifecycle_v2(receipt.intent_key()).unwrap();
        let legitimate_authorization = cleanup_authorization(
            &material,
            Some(&receipt),
            intent.marker_digest(),
            intent.lifecycle_state().clone(),
            &legitimate_authority_key,
            &legitimate_owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
            false,
        );
        let attacker_authorization = cleanup_authorization(
            &material,
            Some(&receipt),
            intent.marker_digest(),
            intent.lifecycle_state().clone(),
            &attacker_authority_key,
            &attacker_owner_key,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
            false,
        );
        store
            .leave_cleanup_after_terminal_for_test_v2(&attacker_authorization, |unsigned| {
                sign_private_oram_owner_cleanup_receipt_v1(&attacker_owner_key, 3, unsigned)
                    .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("test_cleanup_signer"))
            })
            .unwrap();

        let reopened = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        assert!(matches!(
            reopened.inspect_lifecycle_v2(receipt.intent_key()),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        ));
        assert!(matches!(
            reopened.cleanup_with_authorization_v2(&legitimate_authorization, |_| {
                panic!("a conflicting self-signed terminal must fail before signing")
            }),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        ));
        let superblock: serde_json::Value = serde_json::from_slice(
            &fs::read(reopened.root_path().join("superblock.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(superblock["lifecycle_generation"], 0);
        assert!(
            reopened
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .exists()
        );
        assert!(
            !reopened
                .root_path()
                .join("quarantine")
                .join(receipt.intent_key())
                .exists()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_store_replays_coexists_and_adopts_exact_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let first = material(&fixture, &peer_key_pair, 70, 2);
        let second = material(&fixture, &peer_key_pair, 90, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());

        let first_receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        let replayed = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        assert_eq!(replayed, first_receipt);
        let intent_status = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap();
        assert_eq!(
            intent_status.state(),
            PrivateOramOwnerLocalIntentStateV2::Intent
        );
        assert!(intent_status.marker_digest().is_some());
        assert_eq!(
            store.inspect_v2(first_receipt.intent_key()).unwrap(),
            Some(first_receipt.clone())
        );

        let second_receipt = store
            .install_v2(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            )
            .unwrap();
        assert_ne!(first_receipt.intent_key(), second_receipt.intent_key());
        assert_eq!(
            fs::read_dir(store.root_path().join("intents"))
                .unwrap()
                .count(),
            2
        );

        assert!(
            store
                .adopt_for_parent_v2(first_receipt.intent_key(), &digest(250), &first.parent,)
                .is_err()
        );
        let adopted = store
            .adopt_for_parent_v2(
                first_receipt.intent_key(),
                first_receipt.package_sha256(),
                &first.parent,
            )
            .unwrap();
        assert_eq!(adopted.owner_peer_id(), 11);
        let adopted_status = store
            .inspect_lifecycle_v2(first_receipt.intent_key())
            .unwrap();
        assert_eq!(
            adopted_status.state(),
            PrivateOramOwnerLocalIntentStateV2::Adopted
        );
        assert_eq!(
            adopted_status.owner_store_incarnation_digest(),
            intent_status.owner_store_incarnation_digest()
        );
        assert_eq!(
            adopted.journal_descriptor_digest(),
            first_receipt.owner_journal_descriptor_digest()
        );
        let replayed_adoption = store
            .adopt_for_parent_v2(
                first_receipt.intent_key(),
                first_receipt.package_sha256(),
                &first.parent,
            )
            .unwrap();
        assert_eq!(
            replayed_adoption.journal_descriptor_digest(),
            adopted.journal_descriptor_digest()
        );

        let rendered = format!("{store:?} {first_receipt:?} {adopted:?}");
        assert!(!rendered.contains(TEST_COLLECTION_ID));
        assert!(!rendered.contains(&first.package.mutation_id));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_terminal_quarantine_is_immutable_and_moves_payload() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[93; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 130, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        let authority = digest(251);
        let terminal_only = store
            .leave_quarantine_before_payload_move_for_test_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &authority,
            )
            .unwrap();
        assert_eq!(
            terminal_only.state(),
            PrivateOramOwnerLocalIntentStateV2::Quarantined
        );
        assert!(
            store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .exists()
        );
        assert!(
            store
                .root_path()
                .join("terminals")
                .join(receipt.intent_key())
                .join("record.json")
                .exists()
        );
        assert_eq!(
            store
                .inspect_lifecycle_v2(receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::Quarantined
        );
        let quarantined = store
            .quarantine_intent_for_test_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &authority,
            )
            .unwrap();
        assert_eq!(quarantined, terminal_only);
        assert!(
            !store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .exists()
        );
        assert!(
            store
                .root_path()
                .join("quarantine")
                .join(receipt.intent_key())
                .exists()
        );
        assert!(
            store
                .install_v2(
                    &material.verified_request,
                    &material.package,
                    &material.package_bytes,
                    &material.validated_prepare,
                    &material.plan,
                )
                .is_err()
        );
        assert!(
            store
                .adopt_for_parent_v2(
                    receipt.intent_key(),
                    receipt.package_sha256(),
                    &material.parent,
                )
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_adoption_pending_rolls_forward_after_restart_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[94; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 150, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        store
            .leave_adoption_pending_for_test_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            )
            .unwrap();
        assert_eq!(
            store
                .inspect_lifecycle_v2(receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::AdoptionPending
        );
        assert!(
            PrivateOramOwnerJournal::new(fixture.hnsw_store().root_path())
                .inspect_structural()
                .unwrap()
                .is_none()
        );

        let reopened = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        reopened
            .adopt_for_parent_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            )
            .unwrap();
        assert_eq!(
            reopened
                .inspect_lifecycle_v2(receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::Adopted
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_pending_after_canonical_is_irrevocable_and_rolls_forward() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[99; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 160, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        store
            .leave_adoption_after_canonical_for_test_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            )
            .unwrap();
        assert_eq!(
            store
                .inspect_lifecycle_v2(receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::AdoptionPending
        );
        assert!(
            PrivateOramOwnerJournal::new(fixture.hnsw_store().root_path())
                .inspect_structural()
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .quarantine_intent_for_test_v2(
                    receipt.intent_key(),
                    receipt.package_sha256(),
                    &digest(253),
                )
                .is_err()
        );
        assert!(
            !store
                .root_path()
                .join("terminals")
                .join(receipt.intent_key())
                .exists()
        );

        let reopened = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        reopened
            .adopt_for_parent_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            )
            .unwrap();
        assert_eq!(
            reopened
                .inspect_lifecycle_v2(receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::Adopted
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_canonical_lock_contention_does_not_publish_pending() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[100; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 180, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        let canonical = PrivateOramOwnerJournal::new(fixture.hnsw_store().root_path());
        canonical
            .prepare_for_parent_v2(&material.validated_prepare, &material.parent)
            .unwrap();
        canonical
            .with_exclusive_root_lock_test_v1(|| {
                assert!(
                    store
                        .adopt_for_parent_v2(
                            receipt.intent_key(),
                            receipt.package_sha256(),
                            &material.parent,
                        )
                        .is_err()
                );
            })
            .unwrap();
        assert_eq!(
            store
                .inspect_lifecycle_v2(receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::Intent
        );

        store
            .adopt_for_parent_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            )
            .unwrap();
        assert_eq!(
            store
                .inspect_lifecycle_v2(receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::Adopted
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_parent_lock_blocks_replacement_root_operations() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[102; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 200, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        let detached = store.root_path().with_extension("detached-test");
        store
            .with_exclusive_lifecycle_root_lock_for_test_v2(|| {
                fs::rename(store.root_path(), &detached).unwrap();
                fs::create_dir(store.root_path()).unwrap();
                fs::set_permissions(store.root_path(), fs::Permissions::from_mode(0o700)).unwrap();
                assert_eq!(
                    store
                        .inspect_lifecycle_v2(receipt.intent_key())
                        .unwrap_err(),
                    crate::PrivateOramOwnerJournalError::ConcurrentMutation
                );
                fs::remove_dir(store.root_path()).unwrap();
                fs::rename(&detached, store.root_path()).unwrap();
            })
            .unwrap();
        assert_eq!(
            store
                .inspect_lifecycle_v2(receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::Intent
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_conflicting_canonical_adoption_quarantines_intent() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[95; 32]).unwrap();
        let first = material(&fixture, &peer_key_pair, 170, 2);
        let second = material(&fixture, &peer_key_pair, 190, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &first.verified_request,
                &first.package,
                &first.package_bytes,
                &first.validated_prepare,
                &first.plan,
            )
            .unwrap();
        PrivateOramOwnerJournal::new(fixture.hnsw_store().root_path())
            .prepare_for_parent_v2(&second.validated_prepare, &second.parent)
            .unwrap();

        assert!(
            store
                .adopt_for_parent_v2(
                    receipt.intent_key(),
                    receipt.package_sha256(),
                    &first.parent,
                )
                .is_err()
        );
        assert_eq!(
            store
                .inspect_lifecycle_v2(receipt.intent_key())
                .unwrap()
                .state(),
            PrivateOramOwnerLocalIntentStateV2::Quarantined
        );
        assert!(
            store
                .root_path()
                .join("quarantine")
                .join(receipt.intent_key())
                .exists()
        );
        assert!(
            !store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .exists()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_store_fails_closed_after_superblock_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[96; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 210, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        fs::write(store.root_path().join("superblock.json"), b"{}").unwrap();

        assert!(store.inspect_v2(receipt.intent_key()).is_err());
        assert!(store.inspect_lifecycle_v2(receipt.intent_key()).is_err());
        assert!(
            store
                .install_v2(
                    &material.verified_request,
                    &material.package,
                    &material.package_bytes,
                    &material.validated_prepare,
                    &material.plan,
                )
                .is_err()
        );
        assert!(
            store
                .adopt_for_parent_v2(
                    receipt.intent_key(),
                    receipt.package_sha256(),
                    &material.parent,
                )
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_store_fails_closed_after_adoption_marker_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[97; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 230, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        store
            .leave_adoption_pending_for_test_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            )
            .unwrap();
        fs::write(
            store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .join("adoption-pending.json"),
            b"{}",
        )
        .unwrap();

        assert!(store.inspect_lifecycle_v2(receipt.intent_key()).is_err());
        assert!(
            store
                .adopt_for_parent_v2(
                    receipt.intent_key(),
                    receipt.package_sha256(),
                    &material.parent,
                )
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_store_fails_closed_after_terminal_marker_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[98; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 250, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        let authority = digest(252);
        store
            .leave_quarantine_before_payload_move_for_test_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &authority,
            )
            .unwrap();
        fs::write(
            store
                .root_path()
                .join("terminals")
                .join(receipt.intent_key())
                .join("record.json"),
            b"{}",
        )
        .unwrap();

        assert!(store.inspect_v2(receipt.intent_key()).is_err());
        assert!(store.inspect_lifecycle_v2(receipt.intent_key()).is_err());
        assert!(
            store
                .quarantine_intent_for_test_v2(
                    receipt.intent_key(),
                    receipt.package_sha256(),
                    &authority,
                )
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_terminal_rejects_wrong_or_missing_payload_location() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[101; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 220, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        store
            .quarantine_intent_for_test_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &digest(254),
            )
            .unwrap();
        let quarantine = store
            .root_path()
            .join("quarantine")
            .join(receipt.intent_key());
        let retired = store.root_path().join("retired").join(receipt.intent_key());
        fs::rename(&quarantine, &retired).unwrap();
        assert!(store.inspect_lifecycle_v2(receipt.intent_key()).is_err());
        fs::rename(&retired, &quarantine).unwrap();
        fs::remove_dir_all(&quarantine).unwrap();
        assert!(store.inspect_lifecycle_v2(receipt.intent_key()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prestage_store_fails_closed_after_installed_body_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [37; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[92; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 110, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let receipt = store
            .install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            )
            .unwrap();
        let receipt_path = store
            .root_path()
            .join("intents")
            .join(receipt.intent_key())
            .join("receipt.json");
        fs::write(&receipt_path, b"{}").unwrap();

        assert!(store.inspect_v2(receipt.intent_key()).is_err());
        assert!(
            store
                .install_v2(
                    &material.verified_request,
                    &material.package,
                    &material.package_bytes,
                    &material.validated_prepare,
                    &material.plan,
                )
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_parent_grant_is_required_before_child_archive() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [51; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[111; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 181, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let parent = committed_archive_input(&receipt, &terminal, 231);
        install_canonical_parent_fixture(&store, &parent, false);

        assert!(matches!(
            store.archive_committed_generation_from_canonical_parent_v1(parent.generation),
            Err(PrivateOramOwnerJournalError::Corrupt)
        ));
        assert!(fixture.owner_journal().root_path().join("active").is_dir());
        assert!(
            store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .is_dir()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_parent_grant_binds_exact_terminal_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [52; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[112; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 182, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let mut parent = committed_archive_input(&receipt, &terminal, 232);
        parent.terminal_bytes.push(b' ');
        install_canonical_parent_fixture(&store, &parent, true);

        assert!(matches!(
            store.archive_committed_generation_from_canonical_parent_v1(parent.generation),
            Err(PrivateOramOwnerJournalError::Corrupt)
        ));
        assert!(fixture.owner_journal().root_path().join("active").is_dir());
        assert!(
            store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .is_dir()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_parent_grant_rejects_relative_storage_root_without_child_mutation() {
        let cwd = std::env::current_dir().unwrap();
        let temp = tempfile::tempdir_in(&cwd).unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [54; 32]);
        let absolute_store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[114; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 184, 2);
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &absolute_store, &material);
        let parent = committed_archive_input(&receipt, &terminal, 234);
        install_canonical_parent_fixture(&absolute_store, &parent, true);
        let relative_hnsw_root = fixture.hnsw_store().root_path().strip_prefix(&cwd).unwrap();
        let relative_store = PrivateOramOwnerPrestageStoreV2::new(relative_hnsw_root);

        assert!(matches!(
            relative_store.archive_committed_generation_from_canonical_parent_v1(parent.generation),
            Err(PrivateOramOwnerJournalError::Corrupt)
        ));
        assert!(fixture.owner_journal().root_path().join("active").is_dir());
        assert!(
            absolute_store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .is_dir()
        );

        let pinned_store =
            PrivateOramOwnerPrestageStoreV2::try_new_pinned_absolute_v2(relative_hnsw_root)
                .unwrap();
        assert!(pinned_store.root_path().is_absolute());
        let archived = pinned_store
            .archive_committed_generation_from_canonical_parent_v1(parent.generation)
            .unwrap();
        assert_eq!(archived.generation(), parent.generation);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_parent_grant_rejects_cross_incarnation_replay_without_child_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let source_fixture = PrivateOramOwnerStorePairTestFixtureV1::new(
            &temp.path().join("source-collection"),
            [55; 32],
        );
        let replay_fixture = PrivateOramOwnerStorePairTestFixtureV1::new(
            &temp.path().join("replay-collection"),
            [55; 32],
        );
        let source_store =
            PrivateOramOwnerPrestageStoreV2::new(source_fixture.hnsw_store().root_path());
        let replay_store =
            PrivateOramOwnerPrestageStoreV2::new(replay_fixture.hnsw_store().root_path());
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[115; 32]).unwrap();
        let material = material(&source_fixture, &peer_key_pair, 185, 2);
        let (source_receipt, source_terminal) =
            install_adopt_and_finalize(&source_fixture, &source_store, &material);
        let (replay_receipt, _) =
            install_adopt_and_finalize(&replay_fixture, &replay_store, &material);
        assert_ne!(
            source_receipt.owner_store_incarnation_digest(),
            replay_receipt.owner_store_incarnation_digest()
        );
        let parent = committed_archive_input(&source_receipt, &source_terminal, 235);
        install_canonical_parent_fixture(&replay_store, &parent, true);

        assert!(matches!(
            replay_store.archive_committed_generation_from_canonical_parent_v1(parent.generation),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        ));
        assert!(
            replay_fixture
                .owner_journal()
                .root_path()
                .join("active")
                .is_dir()
        );
        assert!(
            replay_store
                .root_path()
                .join("intents")
                .join(replay_receipt.intent_key())
                .is_dir()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_readiness_requires_retained_canonical_parent_grant() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [53; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[113; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 183, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let readiness = readiness_expectation(&store, &[(&receipt, 233)], 243);
        store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 233))
            .unwrap();
        store
            .require_ready_for_new_generation_v2(&readiness)
            .unwrap();

        let completed = canonical_parent_completed_path(&store, receipt.lease_generation());
        fs::remove_file(completed.join(PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_FILE_V1)).unwrap();
        fs::File::open(&completed).unwrap().sync_all().unwrap();

        assert_eq!(
            store.require_ready_for_new_generation_v2(&readiness),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_snapshot_guard_rejects_unexpected_owner_and_parent_entries() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [54; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[114; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 184, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let readiness = readiness_expectation(&store, &[(&receipt, 234)], 244);
        store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 234))
            .unwrap();

        store.acquire_snapshot_guard_v2(&readiness).unwrap();
        fs::write(
            store.root_path().join("unexpected.snapshot-entry"),
            b"unexpected",
        )
        .unwrap();
        assert!(store.acquire_snapshot_guard_v2(&readiness).is_err());
        fs::remove_file(store.root_path().join("unexpected.snapshot-entry")).unwrap();

        let completed = canonical_parent_completed_path(&store, receipt.lease_generation());
        fs::write(completed.join("unexpected.snapshot-entry"), b"unexpected").unwrap();
        assert!(store.acquire_snapshot_guard_v2(&readiness).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_snapshot_guard_rejects_archive_pending_consensus_ack() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [55; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[115; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 185, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let owner_store_incarnation_digest = store
            .inspect_lifecycle_v2(receipt.intent_key())
            .unwrap()
            .owner_store_incarnation_digest()
            .to_string();
        store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 235))
            .unwrap();
        let pending_ack = PrivateOramOwnerNewGenerationReadinessExpectationV2::try_new(
            TEST_COLLECTION_ID.to_string(),
            owner_store_incarnation_digest,
            digest(245),
            Vec::new(),
        )
        .unwrap();

        assert!(store.acquire_snapshot_guard_v2(&pending_ack).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_snapshot_guard_fences_concurrent_archive_publication() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [56; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[116; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 186, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let readiness = readiness_expectation(&store, &[(&receipt, 236)], 246);
        store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 236))
            .unwrap();

        let guard = store.acquire_snapshot_guard_v2(&readiness).unwrap();
        let replay_store = store.clone();
        let replay = committed_archive_input(&receipt, &terminal, 236);
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            done_tx
                .send(replay_store.archive_committed_generation_v1(replay))
                .unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let early = done_rx.recv_timeout(Duration::from_millis(150));
        drop(guard);

        match early {
            Ok(Ok(_)) => panic!("archive publication succeeded while snapshot guard was held"),
            Ok(Err(PrivateOramOwnerJournalError::ConcurrentMutation)) => {
                store
                    .archive_committed_generation_v1(committed_archive_input(
                        &receipt, &terminal, 236,
                    ))
                    .unwrap();
            }
            Ok(Err(error)) => panic!("unexpected archive error while snapshot was held: {error}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                done_rx
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .unwrap();
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("archive worker disconnected before reporting an outcome")
            }
        }
        worker.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn committed_owner_archive_replays_and_fences_stale_install() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [41; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[102; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 171, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let readiness = readiness_expectation(&store, &[(&receipt, 211)], 221);
        assert_eq!(
            store.require_ready_for_new_generation_v2(&readiness),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );

        let archived = store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 211))
            .unwrap();
        let replayed = store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 211))
            .unwrap();

        assert_eq!(archived.generation(), 2);
        assert_eq!(archived.owner_peer_id(), 11);
        assert_eq!(archived.collection_id(), TEST_COLLECTION_ID);
        assert_eq!(
            archived.parent_archive_record_digest(),
            replayed.parent_archive_record_digest()
        );
        assert_eq!(
            archived.owner_archive_record_digest(),
            replayed.owner_archive_record_digest()
        );
        assert_eq!(
            archived.retired_prestage_receipt_digest(),
            receipt.receipt_digest()
        );
        assert!(
            !store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .exists()
        );
        assert!(
            store
                .root_path()
                .join("retired")
                .join(receipt.intent_key())
                .exists()
        );
        assert!(
            fixture
                .owner_journal()
                .root_path()
                .join("completed-v2-00000000000000000002")
                .join("owner-terminal-archive-v1.json")
                .is_file()
        );
        assert_eq!(
            store.adopt_for_parent_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            ),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        assert_eq!(
            store.install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            ),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        assert!(
            fixture
                .owner_journal()
                .inspect_structural()
                .unwrap()
                .is_none()
        );
        store
            .require_ready_for_new_generation_v2(&readiness)
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_readiness_rejects_missing_completed_and_retired_pair() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [45; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[106; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 176, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let readiness = readiness_expectation(&store, &[(&receipt, 215)], 225);
        store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 215))
            .unwrap();
        store
            .require_ready_for_new_generation_v2(&readiness)
            .unwrap();

        fs::remove_dir_all(
            fixture
                .owner_journal()
                .root_path()
                .join("completed-v2-00000000000000000002"),
        )
        .unwrap();
        fs::remove_dir_all(store.root_path().join("retired").join(receipt.intent_key())).unwrap();

        assert_eq!(
            store.require_ready_for_new_generation_v2(&readiness),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        assert!(!fixture.owner_journal().root_path().join("active").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_readiness_rejects_missing_older_pair_when_newer_pair_matches() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [46; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[107; 32]).unwrap();
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());

        let first = material(&fixture, &peer_key_pair, 177, 2);
        let (first_receipt, first_terminal) = install_adopt_and_finalize(&fixture, &store, &first);
        store
            .archive_committed_generation_v1(committed_archive_input(
                &first_receipt,
                &first_terminal,
                216,
            ))
            .unwrap();

        let second = material(&fixture, &peer_key_pair, 178, 3);
        let (second_receipt, second_terminal) =
            install_adopt_and_finalize(&fixture, &store, &second);
        store
            .archive_committed_generation_v1(committed_archive_input(
                &second_receipt,
                &second_terminal,
                217,
            ))
            .unwrap();
        let readiness = readiness_expectation(
            &store,
            &[(&first_receipt, 216), (&second_receipt, 217)],
            226,
        );
        store
            .require_ready_for_new_generation_v2(&readiness)
            .unwrap();

        fs::remove_dir_all(
            fixture
                .owner_journal()
                .root_path()
                .join("completed-v2-00000000000000000002"),
        )
        .unwrap();
        fs::remove_dir_all(
            store
                .root_path()
                .join("retired")
                .join(first_receipt.intent_key()),
        )
        .unwrap();

        assert_eq!(
            store.require_ready_for_new_generation_v2(&readiness),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        assert!(
            fixture
                .owner_journal()
                .root_path()
                .join("completed-v2-00000000000000000003")
                .is_dir()
        );
        assert!(
            store
                .root_path()
                .join("retired")
                .join(second_receipt.intent_key())
                .is_dir()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn committed_owner_archive_repairs_missing_record() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [42; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[103; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 172, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let readiness = readiness_expectation(&store, &[(&receipt, 212)], 222);

        set_fail_owner_archive_after_canonical_rename_v1(true);
        let failed = store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 212));
        set_fail_owner_archive_after_canonical_rename_v1(false);
        assert!(matches!(
            failed,
            Err(PrivateOramOwnerJournalError::Indeterminate)
        ));
        let completed = fixture
            .owner_journal()
            .root_path()
            .join("completed-v2-00000000000000000002");
        assert!(completed.is_dir());
        assert!(!completed.join("owner-terminal-archive-v1.json").exists());
        assert!(!fixture.owner_journal().root_path().join("active").exists());
        assert_eq!(
            store.require_ready_for_new_generation_v2(&readiness),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        assert_eq!(
            store.adopt_for_parent_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            ),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );

        store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 212))
            .unwrap();
        assert!(completed.join("owner-terminal-archive-v1.json").is_file());
        assert!(
            store
                .root_path()
                .join("retired")
                .join(receipt.intent_key())
                .is_dir()
        );
        store
            .require_ready_for_new_generation_v2(&readiness)
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn committed_owner_archive_record_fences_unretired_adopted_intent() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [43; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[104; 32]).unwrap();
        let material = material(&fixture, &peer_key_pair, 173, 2);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
        let readiness = readiness_expectation(&store, &[(&receipt, 213)], 223);

        set_fail_owner_archive_after_record_publish_v1(true);
        let failed = store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 213));
        set_fail_owner_archive_after_record_publish_v1(false);
        assert!(matches!(
            failed,
            Err(PrivateOramOwnerJournalError::Indeterminate)
        ));
        assert!(
            store
                .root_path()
                .join("intents")
                .join(receipt.intent_key())
                .is_dir()
        );
        assert!(
            fixture
                .owner_journal()
                .root_path()
                .join("completed-v2-00000000000000000002")
                .join("owner-terminal-archive-v1.json")
                .is_file()
        );
        assert_eq!(
            store.require_ready_for_new_generation_v2(&readiness),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        assert_eq!(
            store.adopt_for_parent_v2(
                receipt.intent_key(),
                receipt.package_sha256(),
                &material.parent,
            ),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        assert_eq!(
            store.install_v2(
                &material.verified_request,
                &material.package,
                &material.package_bytes,
                &material.validated_prepare,
                &material.plan,
            ),
            Err(PrivateOramOwnerJournalError::InvalidTransition)
        );
        assert!(!fixture.owner_journal().root_path().join("active").exists());

        store
            .archive_committed_generation_v1(committed_archive_input(&receipt, &terminal, 213))
            .unwrap();
        assert!(
            store
                .root_path()
                .join("retired")
                .join(receipt.intent_key())
                .is_dir()
        );
        store
            .require_ready_for_new_generation_v2(&readiness)
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compacted_owner_archive_history_survives_reopen_and_snapshot_but_rejects_pair_rollback() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [56; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[116; 32]).unwrap();
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let mut receipts = Vec::new();
        for (generation, marker) in [(2, 186), (3, 187)] {
            let material = material(&fixture, &peer_key_pair, marker, generation);
            let (receipt, terminal) = install_adopt_and_finalize(&fixture, &store, &material);
            store
                .archive_committed_generation_v1(committed_archive_input(
                    &receipt, &terminal, marker,
                ))
                .unwrap();
            receipts.push((receipt, marker));
        }
        let full =
            readiness_expectation(&store, &[(&receipts[0].0, 186), (&receipts[1].0, 187)], 245);
        let history = PrivateOramOwnerCompactedArchiveHistoryV1::append(
            None,
            &full.acknowledged_archives()[0],
        )
        .unwrap();
        let make_expectation = |history| {
            PrivateOramOwnerNewGenerationReadinessExpectationV2::try_new_with_compacted_history(
                TEST_COLLECTION_ID.to_string(),
                store
                    .inspect_lifecycle_v2(receipts[0].0.intent_key())
                    .unwrap()
                    .owner_store_incarnation_digest()
                    .to_string(),
                digest(245),
                full.acknowledged_archives()[1..].to_vec(),
                history,
            )
            .unwrap()
        };
        let compacted = make_expectation(Some(history.clone()));
        let reopened = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        reopened
            .require_ready_for_new_generation_v2(&compacted)
            .unwrap();
        reopened
            .acquire_snapshot_guard_v2(&compacted)
            .unwrap()
            .validate_held_v2()
            .unwrap();
        assert_ne!(
            full.snapshot_authority_digest_v2().unwrap(),
            compacted.snapshot_authority_digest_v2().unwrap()
        );

        // Dropping the old expectation without a consensus commitment cannot authorize a suffix.
        assert_eq!(
            reopened.require_ready_for_new_generation_v2(&make_expectation(None)),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        for (field, value) in [
            ("history_digest", serde_json::json!(digest(250))),
            ("archive_count", serde_json::json!(2)),
            ("through_generation", serde_json::json!(1)),
        ] {
            let mut encoded = serde_json::to_value(&history).unwrap();
            encoded[field] = value;
            let altered: PrivateOramOwnerCompactedArchiveHistoryV1 =
                serde_json::from_value(encoded).unwrap();
            let bad = make_expectation(Some(altered));
            assert_ne!(
                compacted.snapshot_authority_digest_v2().unwrap(),
                bad.snapshot_authority_digest_v2().unwrap()
            );
            assert_eq!(
                reopened.require_ready_for_new_generation_v2(&bad),
                Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
            );
        }

        // Remove the same old generation from all three locally consistent histories. The
        // committed prefix still requires it, even though the retained suffix is intact.
        fs::remove_dir_all(
            fixture
                .owner_journal()
                .root_path()
                .join("completed-v2-00000000000000000002"),
        )
        .unwrap();
        fs::remove_dir_all(
            store
                .root_path()
                .join("retired")
                .join(receipts[0].0.intent_key()),
        )
        .unwrap();
        fs::remove_dir_all(canonical_parent_completed_path(&store, 2)).unwrap();
        assert_eq!(
            reopened.require_ready_for_new_generation_v2(&compacted),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        assert!(reopened.acquire_snapshot_guard_v2(&compacted).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn completed_generation_allows_next_generation_active() {
        let temp = tempfile::tempdir().unwrap();
        let collection_path = temp.path().join("collection");
        let fixture = PrivateOramOwnerStorePairTestFixtureV1::new(&collection_path, [44; 32]);
        let peer_key_pair = Ed25519KeyPair::from_seed_unchecked(&[105; 32]).unwrap();
        let first = material(&fixture, &peer_key_pair, 174, 2);
        let second = material(&fixture, &peer_key_pair, 175, 3);
        let store = PrivateOramOwnerPrestageStoreV2::new(fixture.hnsw_store().root_path());
        let (first_receipt, first_terminal) = install_adopt_and_finalize(&fixture, &store, &first);
        let readiness = readiness_expectation(&store, &[(&first_receipt, 214)], 224);
        store
            .archive_committed_generation_v1(committed_archive_input(
                &first_receipt,
                &first_terminal,
                214,
            ))
            .unwrap();
        store
            .require_ready_for_new_generation_v2(&readiness)
            .unwrap();

        let second_receipt = store
            .install_v2(
                &second.verified_request,
                &second.package,
                &second.package_bytes,
                &second.validated_prepare,
                &second.plan,
            )
            .unwrap();
        store
            .adopt_for_parent_v2(
                second_receipt.intent_key(),
                second_receipt.package_sha256(),
                &second.parent,
            )
            .unwrap();
        assert_eq!(
            store.require_ready_for_new_generation_v2(&readiness),
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        );
        let active = fixture
            .owner_journal()
            .inspect_structural()
            .unwrap()
            .unwrap();
        assert_eq!(
            active.descriptor.descriptor_digest,
            second_receipt.owner_journal_descriptor_digest()
        );
        assert!(
            fixture
                .owner_journal()
                .root_path()
                .join("completed-v2-00000000000000000002")
                .is_dir()
        );
        assert!(matches!(
            store.archive_committed_generation_v1(committed_archive_input(
                &first_receipt,
                &first_terminal,
                214,
            )),
            Err(PrivateOramOwnerJournalError::ConcurrentMutation)
        ));
        let active_after = fixture
            .owner_journal()
            .inspect_structural()
            .unwrap()
            .unwrap();
        assert_eq!(active_after, active);
    }
}
