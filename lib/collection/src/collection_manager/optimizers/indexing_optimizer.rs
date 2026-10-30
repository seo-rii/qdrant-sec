/// Looks for the segments, which require to be indexed.
///
/// If segment is too large, but still does not have indexes - it is time to create some indexes.
/// The process of index creation is slow and CPU-bounded, so it is convenient to perform
/// index building in a same way as segment re-creation.
pub use shard::optimizers::indexing_optimizer::IndexingOptimizer;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;

    use common::counter::hardware_counter::HardwareCounterCell;
    use data_encoding::BASE64URL_NOPAD;
    use fs_err as fs;
    use itertools::Itertools;
    use rand::rng;
    use segment::data_types::vectors::DEFAULT_VECTOR_NAME;
    use segment::entry::ReadSegmentEntry;
    use segment::entry::entry_point::SegmentEntry;
    use segment::fixtures::index_fixtures::random_vector;
    use segment::id_tracker::IdTracker;
    use segment::index::hnsw_index::ckks_ciphertext_graph::{
        CKKS_VECTOR_SIDECAR_MARKER, CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD,
    };
    use segment::index::{VectorIndex, VectorIndexEnum};
    use segment::json_path::JsonPath;
    use segment::payload_json;
    use segment::segment::Segment;
    use segment::segment_constructor::load_segment;
    use segment::segment_constructor::simple_segment_constructor::{VECTOR1_NAME, VECTOR2_NAME};
    use segment::types::{
        Distance, HnswConfig, HnswGlobalConfig, Indexes, Payload, PayloadSchemaType,
        QuantizationConfig, SegmentType, VectorNameBuf,
    };
    use shard::operations::optimization::OptimizerThresholds;
    use shard::optimizers::segment_optimizer::SegmentOptimizer;
    use shard::segment_holder::SegmentId;
    use shard::segment_holder::locked::LockedSegmentHolder;
    use shard::update::{process_field_index_operation, process_point_operation};
    use tempfile::Builder;

    use super::*;
    use crate::collection_manager::fixtures::{random_multi_vec_segment, random_segment};
    use crate::collection_manager::holders::segment_holder::SegmentHolder;
    use crate::collection_manager::optimizers::config_mismatch_optimizer::ConfigMismatchOptimizer;
    use crate::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector,
    };
    use crate::operations::point_ops::{
        BatchPersisted, BatchVectorStructPersisted, PointInsertOperationsInternal, PointOperations,
    };
    use crate::operations::types::{VectorParams, VectorsConfig};
    use crate::operations::vector_params_builder::VectorParamsBuilder;
    use crate::operations::{CreateIndex, FieldIndexOperations};
    use crate::optimizers_builder::build_segment_optimizer_config;

    #[allow(clippy::too_many_arguments)]
    fn new_indexing_optimizer(
        default_segments_number: usize,
        thresholds_config: OptimizerThresholds,
        segments_path: PathBuf,
        collection_temp_dir: PathBuf,
        collection_params: CollectionParams,
        hnsw_config: HnswConfig,
        hnsw_global_config: HnswGlobalConfig,
        quantization_config: Option<QuantizationConfig>,
    ) -> IndexingOptimizer {
        let segment_config =
            build_segment_optimizer_config(&collection_params, &hnsw_config, &quantization_config);
        shard::optimizers::indexing_optimizer::IndexingOptimizer::new(
            default_segments_number,
            thresholds_config,
            segments_path,
            collection_temp_dir,
            segment_config,
            hnsw_global_config,
        )
    }

    fn new_config_mismatch_optimizer(
        thresholds_config: OptimizerThresholds,
        segments_path: PathBuf,
        collection_temp_dir: PathBuf,
        collection_params: CollectionParams,
        hnsw_config: HnswConfig,
        hnsw_global_config: HnswGlobalConfig,
        quantization_config: Option<QuantizationConfig>,
    ) -> ConfigMismatchOptimizer {
        let segment_config =
            build_segment_optimizer_config(&collection_params, &hnsw_config, &quantization_config);
        shard::optimizers::config_mismatch_optimizer::ConfigMismatchOptimizer::new(
            thresholds_config,
            segments_path,
            collection_temp_dir,
            segment_config,
            hnsw_config,
            hnsw_global_config,
        )
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn normalize(segments: Vec<Vec<SegmentId>>) -> Vec<Vec<SegmentId>> {
        segments
            .into_iter()
            .map(|group| group.into_iter().sorted().collect_vec())
            .collect()
    }

    fn attach_ckks_vector_sidecars(segment: &mut Segment, vector_name: &str, opnum: u64) {
        let point_ids = segment
            .id_tracker
            .borrow()
            .point_mappings()
            .iter_external()
            .collect_vec();
        let hw_counter = HardwareCounterCell::new();
        for (idx, point_id) in point_ids.into_iter().enumerate() {
            let ciphertext = BASE64URL_NOPAD.encode(format!("ciphertext-{idx:04}-pad").as_bytes());
            let payload = Payload(
                serde_json::from_value(serde_json::json!({
                    CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD: {
                        vector_name: {
                            CKKS_VECTOR_SIDECAR_MARKER: {
                                "version": 1,
                                "scheme": "openfhe-ckks",
                                "envelope": {
                                    "version": 1,
                                    "algorithm": "AES-256-GCM",
                                    "key_id": "tenant-a:docs",
                                    "material_fingerprint": "tenant-a/vector@v1",
                                    "rk_id": "tenant-a/vector-rk@v1",
                                    "rk_epoch": 1,
                                    "nonce": "AAAAAAAAAAAAAAAA",
                                    "ciphertext": ciphertext
                                }
                            }
                        }
                    }
                }))
                .unwrap(),
            );
            segment
                .set_payload(opnum, point_id, &payload, &None, &hw_counter)
                .unwrap();
        }
    }

    #[test]
    fn test_multi_vector_optimization() {
        init();
        let mut holder = SegmentHolder::default();

        let dim1 = 128;
        let dim2 = 256;

        let segments_dir = Builder::new().prefix("segments_dir").tempdir().unwrap();
        let segments_temp_dir = Builder::new()
            .prefix("segments_temp_dir")
            .tempdir()
            .unwrap();
        let mut opnum = 101..1000000;

        let large_segment =
            random_multi_vec_segment(segments_dir.path(), opnum.next().unwrap(), 200, dim1, dim2);

        let segment_config = large_segment.segment_config.clone();

        let large_segment_id = holder.add_new(large_segment);

        let vectors_config: BTreeMap<VectorNameBuf, VectorParams> = segment_config
            .vector_data
            .iter()
            .map(|(name, params)| {
                (
                    name.to_owned(),
                    VectorParamsBuilder::new(params.size as u64, params.distance).build(),
                )
            })
            .collect();

        let mut index_optimizer = new_indexing_optimizer(
            2,
            OptimizerThresholds {
                max_segment_size_kb: 300,
                memmap_threshold_kb: 1000,
                indexing_threshold_kb: 1000,
                deferred_internal_id: None,
            },
            segments_dir.path().to_owned(),
            segments_temp_dir.path().to_owned(),
            CollectionParams {
                vectors: VectorsConfig::Multi(vectors_config),
                ..CollectionParams::empty()
            },
            Default::default(),
            HnswGlobalConfig::default(),
            Default::default(),
        );
        let locked_holder = LockedSegmentHolder::new(holder);

        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        assert!(suggested_to_optimize.is_empty());

        index_optimizer
            .threshold_config_mut_for_test()
            .memmap_threshold_kb = 1000;
        index_optimizer
            .threshold_config_mut_for_test()
            .indexing_threshold_kb = 50;

        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        let suggested_to_optimize = suggested_to_optimize.into_iter().exactly_one().unwrap();
        assert!(suggested_to_optimize.contains(&large_segment_id));

        index_optimizer.optimize_for_test(locked_holder.clone(), suggested_to_optimize);

        let infos = locked_holder
            .read()
            .iter()
            .map(|(_sid, segment)| segment.get().read().info())
            .collect_vec();
        let configs = locked_holder
            .read()
            .iter()
            .map(|(_sid, segment)| segment.get().read().config().clone())
            .collect_vec();

        assert_eq!(infos.len(), 2);
        assert_eq!(configs.len(), 2);

        let total_points: usize = infos.iter().map(|info| info.num_points).sum();
        let total_vectors: usize = infos.iter().map(|info| info.num_vectors).sum();
        assert_eq!(total_points, 200);
        assert_eq!(total_vectors, 400);

        for config in configs {
            assert_eq!(config.vector_data.len(), 2);
            assert_eq!(config.vector_data.get(VECTOR1_NAME).unwrap().size, dim1);
            assert_eq!(config.vector_data.get(VECTOR2_NAME).unwrap().size, dim2);
        }
    }

    #[test]
    fn test_indexing_optimizer() {
        init();

        let mut rng = rng();
        let mut holder = SegmentHolder::default();

        let payload_field: JsonPath = "number".parse().unwrap();

        let dim = 256;

        let segments_dir = Builder::new().prefix("segments_dir").tempdir().unwrap();
        let segments_temp_dir = Builder::new()
            .prefix("segments_temp_dir")
            .tempdir()
            .unwrap();
        let mut opnum = 101..1000000;

        let small_segment = random_segment(segments_dir.path(), opnum.next().unwrap(), 25, dim);
        let middle_low_segment =
            random_segment(segments_dir.path(), opnum.next().unwrap(), 90, dim);
        let middle_segment = random_segment(segments_dir.path(), opnum.next().unwrap(), 100, dim);
        let large_segment = random_segment(segments_dir.path(), opnum.next().unwrap(), 200, dim);

        let segment_config = small_segment.segment_config.clone();

        let small_segment_id = holder.add_new(small_segment);
        let middle_low_segment_id = holder.add_new(middle_low_segment);
        let middle_segment_id = holder.add_new(middle_segment);
        let large_segment_id = holder.add_new(large_segment);

        let mut index_optimizer = new_indexing_optimizer(
            2,
            OptimizerThresholds {
                max_segment_size_kb: 300,
                memmap_threshold_kb: 1000,
                indexing_threshold_kb: 1000,
                deferred_internal_id: None,
            },
            segments_dir.path().to_owned(),
            segments_temp_dir.path().to_owned(),
            CollectionParams {
                vectors: VectorsConfig::Single(
                    VectorParamsBuilder::new(
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].size as u64,
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].distance,
                    )
                    .build(),
                ),
                ..CollectionParams::empty()
            },
            Default::default(),
            HnswGlobalConfig::default(),
            Default::default(),
        );

        let locked_holder = LockedSegmentHolder::new(holder);

        // ---- check condition for MMap optimization
        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        assert!(suggested_to_optimize.is_empty());

        index_optimizer
            .threshold_config_mut_for_test()
            .memmap_threshold_kb = 1000;
        index_optimizer
            .threshold_config_mut_for_test()
            .indexing_threshold_kb = 50;

        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        assert_eq!(
            normalize(suggested_to_optimize),
            normalize(vec![
                vec![large_segment_id, middle_low_segment_id],
                vec![middle_segment_id],
            ]),
        );

        index_optimizer
            .threshold_config_mut_for_test()
            .memmap_threshold_kb = 1000;
        index_optimizer
            .threshold_config_mut_for_test()
            .indexing_threshold_kb = 1000;

        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        assert!(suggested_to_optimize.is_empty());

        index_optimizer
            .threshold_config_mut_for_test()
            .memmap_threshold_kb = 50;
        index_optimizer
            .threshold_config_mut_for_test()
            .indexing_threshold_kb = 1000;

        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        assert_eq!(
            normalize(suggested_to_optimize),
            normalize(vec![
                vec![large_segment_id, middle_low_segment_id],
                vec![middle_segment_id],
            ]),
        );

        index_optimizer
            .threshold_config_mut_for_test()
            .memmap_threshold_kb = 150;
        index_optimizer
            .threshold_config_mut_for_test()
            .indexing_threshold_kb = 50;

        // ----- CREATE AN INDEXED FIELD ------
        let hw_counter = HardwareCounterCell::new();

        process_field_index_operation(
            &locked_holder.read(),
            opnum.next().unwrap(),
            &FieldIndexOperations::CreateIndex(CreateIndex {
                field_name: payload_field.clone(),
                field_schema: Some(PayloadSchemaType::Integer.into()),
            }),
            &hw_counter,
        )
        .unwrap();

        // ------ Plain -> Mmap & Indexed payload
        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        assert_eq!(
            normalize(suggested_to_optimize.clone()),
            normalize(vec![
                vec![large_segment_id, middle_low_segment_id],
                vec![middle_segment_id],
            ]),
        );
        index_optimizer.optimize_for_test(locked_holder.clone(), suggested_to_optimize[0].clone());

        // ------ Plain -> Indexed payload
        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        assert_eq!(suggested_to_optimize.clone(), vec![vec![middle_segment_id]]);
        index_optimizer.optimize_for_test(locked_holder.clone(), suggested_to_optimize[0].clone());

        // ------- Keep smallest segment without changes
        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        assert!(suggested_to_optimize.is_empty());

        assert_eq!(
            locked_holder.read().len(),
            3,
            "Testing no new segments were created"
        );

        let infos = locked_holder
            .read()
            .iter()
            .map(|(_sid, segment)| segment.get().read().info())
            .collect_vec();
        let configs = locked_holder
            .read()
            .iter()
            .map(|(_sid, segment)| segment.get().read().config().clone())
            .collect_vec();

        let indexed_count = infos
            .iter()
            .filter(|info| info.segment_type == SegmentType::Indexed)
            .count();
        assert_eq!(
            indexed_count, 2,
            "Testing that 2 segments are actually indexed"
        );

        let on_disk_count = configs
            .iter()
            .filter(|config| config.is_any_on_disk())
            .count();
        assert_eq!(
            on_disk_count, 1,
            "Testing that only largest segment is not Mmap"
        );

        let segment_dirs = fs::read_dir(segments_dir.path()).unwrap().collect_vec();
        assert_eq!(
            segment_dirs.len(),
            locked_holder.read().len(),
            "Testing that new segments are persisted and old data is removed"
        );

        for info in &infos {
            assert!(
                info.index_schema.contains_key(&payload_field),
                "Testing that payload is not lost"
            );
            assert_eq!(
                info.index_schema[&payload_field].data_type,
                PayloadSchemaType::Integer,
                "Testing that payload type is not lost"
            );
        }

        let point_payload = payload_json! {"number": 10000i64};

        let batch = BatchPersisted {
            ids: vec![501.into(), 502.into(), 503.into()],
            vectors: BatchVectorStructPersisted::Single(vec![
                random_vector(&mut rng, dim),
                random_vector(&mut rng, dim),
                random_vector(&mut rng, dim),
            ]),
            payloads: Some(vec![
                Some(point_payload.clone()),
                Some(point_payload.clone()),
                Some(point_payload),
            ]),
        };

        let insert_point_ops =
            PointOperations::UpsertPoints(PointInsertOperationsInternal::from(batch));

        let smallest_size = infos
            .iter()
            .min_by_key(|info| info.num_vectors)
            .unwrap()
            .num_vectors;

        let hw_counter = HardwareCounterCell::new();

        process_point_operation(
            &locked_holder.read(),
            opnum.next().unwrap(),
            insert_point_ops,
            &hw_counter,
        )
        .unwrap();

        let new_infos = locked_holder
            .read()
            .iter()
            .map(|(_sid, segment)| segment.get().read().info())
            .collect_vec();
        let new_smallest_size = new_infos
            .iter()
            .min_by_key(|info| info.num_vectors)
            .unwrap()
            .num_vectors;

        assert_eq!(
            new_smallest_size,
            smallest_size + 3,
            "Testing that new data is added to an appendable segment only"
        );

        // ---- New appendable segment should be created if none left

        // Index even the smallest segment
        index_optimizer
            .threshold_config_mut_for_test()
            .indexing_threshold_kb = 20;
        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
        let suggested_to_optimize = suggested_to_optimize.into_iter().exactly_one().unwrap();
        assert!(suggested_to_optimize.contains(&small_segment_id));
        index_optimizer.optimize_for_test(locked_holder.clone(), suggested_to_optimize);

        let new_infos2 = locked_holder
            .read()
            .iter()
            .map(|(_sid, segment)| segment.get().read().info())
            .collect_vec();

        let mut has_empty = false;
        for info in new_infos2 {
            has_empty |= info.num_vectors == 0;
        }

        assert!(
            has_empty,
            "Testing that new segment is created if none left"
        );

        let batch = BatchPersisted {
            ids: vec![601.into(), 602.into(), 603.into()],
            vectors: BatchVectorStructPersisted::Single(vec![
                random_vector(&mut rng, dim),
                random_vector(&mut rng, dim),
                random_vector(&mut rng, dim),
            ]),
            payloads: None,
        };

        let insert_point_ops =
            PointOperations::UpsertPoints(PointInsertOperationsInternal::from(batch));

        process_point_operation(
            &locked_holder.read(),
            opnum.next().unwrap(),
            insert_point_ops,
            &hw_counter,
        )
        .unwrap();
    }

    #[test]
    fn encrypted_vector_sidecar_triggers_ckks_indexing_optimizer() {
        init();

        let mut holder = SegmentHolder::default();
        let dim = 256;

        let segments_dir = Builder::new().prefix("segments_dir").tempdir().unwrap();
        let segments_temp_dir = Builder::new()
            .prefix("segments_temp_dir")
            .tempdir()
            .unwrap();

        let mut segment = random_segment(segments_dir.path(), 101, 200, dim);
        attach_ckks_vector_sidecars(&mut segment, DEFAULT_VECTOR_NAME, 102);
        let segment_config = segment.segment_config.clone();
        holder.add_new(segment);

        let index_optimizer = new_indexing_optimizer(
            2,
            OptimizerThresholds {
                max_segment_size_kb: 300,
                memmap_threshold_kb: 1,
                indexing_threshold_kb: 1,
                deferred_internal_id: None,
            },
            segments_dir.path().to_owned(),
            segments_temp_dir.path().to_owned(),
            CollectionParams {
                vectors: VectorsConfig::Single(
                    VectorParamsBuilder::new(
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].size as u64,
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].distance,
                    )
                    .build(),
                ),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a:docs".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 3,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "default_vector_conf".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![DEFAULT_VECTOR_NAME.to_string()],
                        },
                        instance: "docs_vector_v1".to_string(),
                        binding: Some("vector-envelope/v1".to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            Default::default(),
            HnswGlobalConfig::default(),
            Default::default(),
        );

        let locked_holder = LockedSegmentHolder::new(holder);
        let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);

        assert!(!suggested_to_optimize.is_empty());
    }

    #[test]
    fn encrypted_vector_does_not_trigger_plaintext_config_mismatch_optimizer() {
        init();

        let mut holder = SegmentHolder::default();
        let dim = 256;

        let segments_dir = Builder::new().prefix("segments_dir").tempdir().unwrap();
        let segments_temp_dir = Builder::new()
            .prefix("segments_temp_dir")
            .tempdir()
            .unwrap();

        let segment = random_segment(segments_dir.path(), 101, 200, dim);
        let segment_config = segment.segment_config.clone();
        holder.add_new(segment);

        let config_mismatch_optimizer = new_config_mismatch_optimizer(
            OptimizerThresholds {
                max_segment_size_kb: 300,
                memmap_threshold_kb: 1,
                indexing_threshold_kb: 1,
                deferred_internal_id: None,
            },
            segments_dir.path().to_owned(),
            segments_temp_dir.path().to_owned(),
            CollectionParams {
                vectors: VectorsConfig::Single(
                    VectorParamsBuilder::new(
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].size as u64,
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].distance,
                    )
                    .with_on_disk(true)
                    .build(),
                ),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a:docs".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 3,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "default_vector_conf".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![DEFAULT_VECTOR_NAME.to_string()],
                        },
                        instance: "docs_vector_v1".to_string(),
                        binding: Some("vector-envelope/v1".to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            HnswConfig {
                m: 32,
                ef_construct: 200,
                full_scan_threshold: 1,
                max_indexing_threads: 0,
                on_disk: Some(true),
                payload_m: None,
                inline_storage: None,
            },
            HnswGlobalConfig::default(),
            None,
        );

        let locked_holder = LockedSegmentHolder::new(holder);
        let suggested_to_optimize =
            config_mismatch_optimizer.plan_optimizations_for_test(&locked_holder);

        assert!(
            suggested_to_optimize.is_empty(),
            "encrypted vectors must not be planned for plaintext config-mismatch rebuilds",
        );
    }

    #[test]
    fn encrypted_vector_forced_optimization_preserves_plain_storage_config() {
        init();

        let mut holder = SegmentHolder::default();
        let dim = 256;

        // Graph files require real directory ancestors, including the platform temp root.
        let temp_root = std::env::temp_dir().canonicalize().unwrap();
        let segments_dir = Builder::new()
            .prefix("segments_dir")
            .tempdir_in(&temp_root)
            .unwrap();
        let segments_temp_dir = Builder::new()
            .prefix("segments_temp_dir")
            .tempdir_in(&temp_root)
            .unwrap();

        let mut segment = random_segment(segments_dir.path(), 101, 200, dim);
        attach_ckks_vector_sidecars(&mut segment, DEFAULT_VECTOR_NAME, 102);
        let segment_config = segment.segment_config.clone();
        let segment_id = holder.add_new(segment);

        let index_optimizer = new_indexing_optimizer(
            2,
            OptimizerThresholds {
                max_segment_size_kb: 300,
                memmap_threshold_kb: 1,
                indexing_threshold_kb: 1,
                deferred_internal_id: None,
            },
            segments_dir.path().to_owned(),
            segments_temp_dir.path().to_owned(),
            CollectionParams {
                vectors: VectorsConfig::Single(
                    VectorParamsBuilder::new(
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].size as u64,
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].distance,
                    )
                    .with_on_disk(true)
                    .build(),
                ),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a:docs".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 3,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "default_vector_conf".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![DEFAULT_VECTOR_NAME.to_string()],
                        },
                        instance: "docs_vector_v1".to_string(),
                        binding: Some("vector-envelope/v1".to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            Default::default(),
            HnswGlobalConfig::default(),
            Default::default(),
        );

        let locked_holder = LockedSegmentHolder::new(holder);
        index_optimizer.optimize_for_test(locked_holder.clone(), vec![segment_id]);

        let configs = locked_holder
            .read()
            .iter_original()
            .filter_map(|(_, segment)| {
                let segment = segment.read();
                (segment.total_point_count() > 0).then(|| segment.config().clone())
            })
            .collect_vec();

        assert!(
            configs.iter().any(|config| {
                let vector_data = &config.vector_data[DEFAULT_VECTOR_NAME];
                matches!(
                    vector_data.index,
                    Indexes::CkksCiphertextHnsw {
                        ref vector_name,
                        ..
                    } if vector_name == DEFAULT_VECTOR_NAME
                ) && !vector_data.storage_type.is_on_disk()
                    && vector_data.quantization_config.is_none()
            }),
            "forced optimization must assign CKKS ciphertext HNSW without plaintext mmap or quantization",
        );

        assert!(
            locked_holder.read().iter_original().any(|(_, segment)| {
                let segment = segment.read();
                let Some(vector_data) = segment.vector_data.get(DEFAULT_VECTOR_NAME) else {
                    return false;
                };
                let vector_index = vector_data.vector_index.borrow();
                matches!(&*vector_index, VectorIndexEnum::CkksCiphertextHnsw(_))
                    && vector_index.immutable_files().iter().any(|path| {
                        path.file_name()
                            .is_some_and(|file_name| file_name == "ckks_ciphertext_hnsw_graph.json")
                    })
            }),
            "optimized encrypted vector segment must persist a CKKS ciphertext graph artifact",
        );

        let (optimized_segment_id, optimized_path, optimized_uuid) = {
            let holder = locked_holder.read();
            holder
                .iter_original()
                .find_map(|(segment_id, segment)| {
                    let segment = segment.read();
                    let vector_data = segment.vector_data.get(DEFAULT_VECTOR_NAME)?;
                    let vector_index = vector_data.vector_index.borrow();
                    matches!(&*vector_index, VectorIndexEnum::CkksCiphertextHnsw(_))
                        .then(|| (segment_id, segment.segment_path.clone(), segment.uuid))
                })
                .expect("optimized CKKS ciphertext segment must exist")
        };

        assert!(
            index_optimizer
                .plan_optimizations_for_test(&locked_holder)
                .is_empty(),
            "CKKS ciphertext index optimization must not repeat once the segment has a ciphertext graph artifact",
        );

        let removed_segments = locked_holder.write().remove(&[optimized_segment_id]);
        drop(removed_segments);

        let stopped = AtomicBool::new(false);
        let reopened_segment =
            load_segment(&optimized_path, optimized_uuid, None, &stopped).unwrap();
        let reopened_vector_index = reopened_segment.vector_data[DEFAULT_VECTOR_NAME]
            .vector_index
            .borrow();
        assert!(
            matches!(
                &*reopened_vector_index,
                VectorIndexEnum::CkksCiphertextHnsw(index)
                    if index.indexed_vector_count() > 0
                        && index.immutable_files().iter().any(|path| {
                            path.file_name().is_some_and(|file_name| {
                                file_name == "ckks_ciphertext_hnsw_graph.json"
                            })
                        })
            ),
            "reloaded optimized segment must reopen the persisted CKKS ciphertext graph artifact",
        );
    }

    /// Test that indexing optimizer maintain expected number of during the optimization duty
    #[test]
    fn test_indexing_optimizer_with_number_of_segments() {
        init();

        let mut holder = SegmentHolder::default();

        let dim = 256;

        let segments_dir = Builder::new().prefix("segments_dir").tempdir().unwrap();
        let segments_temp_dir = Builder::new()
            .prefix("segments_temp_dir")
            .tempdir()
            .unwrap();
        let mut opnum = 101..1000000;

        let segments = vec![
            random_segment(segments_dir.path(), opnum.next().unwrap(), 100, dim),
            random_segment(segments_dir.path(), opnum.next().unwrap(), 100, dim),
            random_segment(segments_dir.path(), opnum.next().unwrap(), 100, dim),
            random_segment(segments_dir.path(), opnum.next().unwrap(), 100, dim),
        ];

        let number_of_segments = segments.len();
        let segment_config = segments[0].segment_config.clone();

        let _segment_ids: Vec<SegmentId> = segments
            .into_iter()
            .map(|segment| holder.add_new(segment))
            .collect();

        let locked_holder = LockedSegmentHolder::new(holder);

        let index_optimizer = new_indexing_optimizer(
            number_of_segments, // Keep the same number of segments
            OptimizerThresholds {
                max_segment_size_kb: 1000,
                memmap_threshold_kb: 1000,
                indexing_threshold_kb: 10, // Always optimize
                deferred_internal_id: None,
            },
            segments_dir.path().to_owned(),
            segments_temp_dir.path().to_owned(),
            CollectionParams {
                vectors: VectorsConfig::Single(
                    VectorParamsBuilder::new(
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].size as u64,
                        segment_config.vector_data[DEFAULT_VECTOR_NAME].distance,
                    )
                    .build(),
                ),
                ..CollectionParams::empty()
            },
            Default::default(),
            HnswGlobalConfig::default(),
            Default::default(),
        );

        // Index until all segments are indexed
        let mut numer_of_optimizations = 0;
        loop {
            let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
            if suggested_to_optimize.is_empty() {
                break;
            }
            log::debug!("suggested_to_optimize = {suggested_to_optimize:#?}");
            let suggested_to_optimize = suggested_to_optimize.into_iter().next().unwrap();

            index_optimizer.optimize_for_test(locked_holder.clone(), suggested_to_optimize);
            numer_of_optimizations += 1;
            assert!(numer_of_optimizations <= number_of_segments);
            let number_of_segments = locked_holder.read().len();
            log::debug!(
                "numer_of_optimizations = {numer_of_optimizations}, number_of_segments = {number_of_segments}"
            );
        }

        // Ensure that the total number of segments did not change
        assert_eq!(locked_holder.read().len(), number_of_segments);
    }

    /// This tests things are as we expect when we define both `on_disk: false` and `memmap_threshold`
    ///
    /// Before this PR (<https://github.com/qdrant/qdrant/pull/3167>) such configuration would create an infinite optimization loop.
    ///
    /// It tests whether:
    /// - the on_disk flag is preferred over memmap_threshold
    /// - the index optimizer and config mismatch optimizer don't conflict with this preference
    /// - there is no infinite optiization loop with the above configuration
    ///
    /// In short, this is what happens in this test:
    /// - create randomized segment as base with `on_disk: false` and `memmap_threshold`
    /// - test that indexing optimizer and config mismatch optimizer dont trigger
    /// - test that current storage is in memory
    /// - change `on_disk: None`
    /// - test that indexing optimizer now wants to optimize for `memmap_threshold`
    /// - optimize with indexing optimizer to put storage on disk
    /// - test that config mismatch optimizer doesn't try to revert on disk storage
    #[test]
    fn test_on_disk_memmap_threshold_conflict() {
        // Collection configuration
        let (point_count, dim) = (1000, 10);
        let thresholds_config = OptimizerThresholds {
            max_segment_size_kb: usize::MAX,
            memmap_threshold_kb: 10,
            indexing_threshold_kb: usize::MAX,
            deferred_internal_id: None,
        };
        let mut collection_params = CollectionParams {
            vectors: VectorsConfig::Single(
                VectorParamsBuilder::new(dim as u64, Distance::Dot)
                    .with_on_disk(false)
                    .build(),
            ),
            ..CollectionParams::empty()
        };

        // Base segment
        let temp_dir = Builder::new().prefix("segment_temp_dir").tempdir().unwrap();
        let dir = Builder::new().prefix("segment_dir").tempdir().unwrap();
        let mut holder = SegmentHolder::default();

        let segment = random_segment(dir.path(), 100, point_count, dim as usize);

        let segment_id = holder.add_new(segment);
        let locked_holder = LockedSegmentHolder::new(holder);

        let hnsw_config = HnswConfig {
            m: 16,
            ef_construct: 100,
            full_scan_threshold: 10,
            max_indexing_threads: 0,
            on_disk: None,
            payload_m: None,
            inline_storage: None,
        };

        {
            // Optimizers used in test
            let index_optimizer = new_indexing_optimizer(
                2,
                thresholds_config,
                dir.path().to_owned(),
                temp_dir.path().to_owned(),
                collection_params.clone(),
                hnsw_config,
                HnswGlobalConfig::default(),
                Default::default(),
            );
            let config_mismatch_optimizer = new_config_mismatch_optimizer(
                thresholds_config,
                dir.path().to_owned(),
                temp_dir.path().to_owned(),
                collection_params.clone(),
                hnsw_config,
                HnswGlobalConfig::default(),
                Default::default(),
            );

            // Index optimizer should not optimize and put storage back in memory, nothing changed
            let suggested_to_optimize = index_optimizer.plan_optimizations_for_test(&locked_holder);
            assert_eq!(
                suggested_to_optimize.len(),
                0,
                "index optimizer should not run for index nor mmap"
            );

            // Config mismatch optimizer should not try to change the current state
            let suggested_to_optimize =
                config_mismatch_optimizer.plan_optimizations_for_test(&locked_holder);
            assert_eq!(
                suggested_to_optimize.len(),
                0,
                "config mismatch optimizer should not change anything"
            );

            // Ensure segment is not on disk
            locked_holder
                .read()
                .iter_original()
                .map(|(_, segment)| segment.read())
                .filter(|segment| segment.total_point_count() > 0)
                .for_each(|segment| {
                    assert!(
                        !segment.config().vector_data[DEFAULT_VECTOR_NAME]
                            .storage_type
                            .is_on_disk(),
                        "segment must not be on disk with mmap",
                    );
                });
        }

        // Remove explicit on_disk flag and go back to default
        collection_params
            .vectors
            .get_params_mut(DEFAULT_VECTOR_NAME)
            .unwrap()
            .on_disk
            .take();

        // Optimizers used in test
        let index_optimizer = new_indexing_optimizer(
            2,
            thresholds_config,
            dir.path().to_owned(),
            temp_dir.path().to_owned(),
            collection_params.clone(),
            hnsw_config,
            HnswGlobalConfig::default(),
            Default::default(),
        );
        let config_mismatch_optimizer = new_config_mismatch_optimizer(
            thresholds_config,
            dir.path().to_owned(),
            temp_dir.path().to_owned(),
            collection_params,
            hnsw_config,
            HnswGlobalConfig::default(),
            Default::default(),
        );

        // Use indexing optimizer to build mmap
        let changed = index_optimizer.optimize_for_test(locked_holder.clone(), vec![segment_id]);
        assert!(
            changed > 0,
            "optimizer should have rebuilt this segment for mmap"
        );
        assert!(
            locked_holder.read().get(segment_id).is_none(),
            "optimized segment should be gone",
        );
        assert_eq!(locked_holder.read().len(), 2, "mmap must be built");

        // Mismatch optimizer should not optimize yet, HNSW config is not changed yet
        let suggested_to_optimize =
            config_mismatch_optimizer.plan_optimizations_for_test(&locked_holder);
        assert_eq!(suggested_to_optimize.len(), 0);

        // Ensure new segment is on disk now
        locked_holder
            .read()
            .iter_original()
            .map(|(_, segment)| segment.read())
            .filter(|segment| segment.total_point_count() > 0)
            .for_each(|segment| {
                assert!(
                    segment.config().vector_data[DEFAULT_VECTOR_NAME]
                        .storage_type
                        .is_on_disk(),
                    "segment must be on disk with mmap",
                );
            });
    }
}
