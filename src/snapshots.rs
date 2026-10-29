use std::io::BufReader;
use std::path::Path;

use collection::collection::Collection;
use collection::config::CollectionConfigInternal;
use collection::shards::shard::PeerId;
use common::fs::{move_dir, safe_delete_in_tmp};
use common::tar_unpack::tar_unpack_file;
use fs_err as fs;
use fs_err::File;
use log::info;
use shard::snapshots::snapshot_data::SnapshotData;
use storage::content_manager::alias_mapping::AliasPersistence;
use storage::content_manager::snapshots::SnapshotConfig;
use storage::content_manager::snapshots::recover::reject_ordinary_private_oram_v2_snapshot_recovery;
use storage::content_manager::toc::{ALIASES_PATH, COLLECTIONS_DIR};
use tempfile::TempDir;

use crate::common::crypto::validate_recovered_collection_crypto_config;
#[cfg(test)]
use crate::common::crypto::validate_recovered_collection_crypto_runtime;
use crate::common::private_hnsw::validate_recovered_private_hnsw_oram_snapshot_signatures;
use crate::common::private_result_oram::validate_recovered_private_result_oram_snapshot_signatures;
use crate::settings::Settings;

fn snapshot_recovery_temp_dir(
    temp_base: Option<&Path>,
    default_base: &Path,
    prefix: &str,
) -> Result<TempDir, String> {
    let base = temp_base.unwrap_or(default_base);
    fs::create_dir_all(base).map_err(|err| {
        format!(
            "Failed to create snapshot recovery temp directory {}: {err}",
            base.display(),
        )
    })?;
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(base)
        .map_err(|err| {
            format!(
                "Failed to create snapshot recovery work directory in {}: {err}",
                base.display(),
            )
        })
}

/// Recover snapshots from the given arguments
///
/// # Arguments
///
/// * `mapping` - `[ <path>:<collection_name> ]`
/// * `force` - if true, allow to overwrite collections from snapshots
///
/// # Returns
///
/// * `Vec<String>` - list of collections that were recovered
pub fn recover_snapshots(
    mapping: &[String],
    force: bool,
    temp_dir: Option<&Path>,
    storage_dir: &Path,
    this_peer_id: PeerId,
    is_distributed: bool,
    settings: &Settings,
) -> Result<Vec<String>, String> {
    let collection_dir_path = storage_dir.join(COLLECTIONS_DIR);
    let mut recovered_collections: Vec<String> = vec![];

    for snapshot_params in mapping {
        let mut split = snapshot_params.split(':');
        let path = split
            .next()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| format!("Snapshot path is missing: {snapshot_params}"))?;

        let snapshot_data = SnapshotData::new_packed_persistent(path);

        let collection_name = split
            .next()
            .filter(|collection_name| !collection_name.is_empty())
            .ok_or_else(|| format!("Collection name is missing: {snapshot_params}"))?;
        if split.next().is_some() {
            return Err(format!(
                "Too many parts in snapshot mapping: {snapshot_params}"
            ));
        }
        info!("Recovering snapshot {collection_name} from {path}");
        // check if collection already exists
        // if it does, we need to check if we want to overwrite it
        // if not, we need to abort
        let collection_path = collection_dir_path.join(collection_name);
        info!("Collection path: {}", collection_path.display());
        if collection_path.exists() {
            if !force {
                return Err(format!(
                    "Collection {collection_name} already exists. Use --force-snapshot to overwrite it."
                ));
            }
            info!("Overwriting collection {collection_name}");
        }
        // A configured temp path is a shared parent, not a directory this recovery owns.
        let collection_temp =
            snapshot_recovery_temp_dir(temp_dir, &collection_dir_path, "collection-snapshot-")?;
        if let Err(err) = Collection::restore_snapshot(
            snapshot_data,
            collection_temp.path(),
            this_peer_id,
            is_distributed,
        ) {
            return Err(format!(
                "Failed to recover snapshot {collection_name}: {err}"
            ));
        }
        validate_restored_collection_crypto_runtime(
            settings,
            collection_name,
            collection_temp.path(),
        )?;

        // Complete a possible cross-filesystem copy before replacing the current collection.
        // Publication can then use one rename on the collection filesystem.
        let install_temp =
            snapshot_recovery_temp_dir(None, &collection_dir_path, ".snapshot-install-")?;
        let install_path = install_temp.path().join("collection");
        move_dir(collection_temp.path(), &install_path).map_err(|err| {
            format!("Failed to stage recovered snapshot for collection {collection_name}: {err}",)
        })?;
        // Remove collection_path directory if exists
        if collection_path.exists()
            && let Err(err) = safe_delete_in_tmp(&collection_path, &storage_dir.join(".deleted"))
                .and_then(|to_delete| to_delete.close())
        {
            return Err(format!(
                "Failed to remove collection {collection_name}: {err}",
            ));
        }
        fs::rename(&install_path, &collection_path).map_err(|err| {
            format!(
                "Failed to move recovered snapshot for collection {collection_name} into place: {err}",
            )
        })?;
        recovered_collections.push(collection_name.to_string());
    }
    Ok(recovered_collections)
}

pub fn recover_full_snapshot(
    temp_dir: Option<&Path>,
    snapshot_path: &str,
    storage_dir: &Path,
    force: bool,
    this_peer_id: PeerId,
    is_distributed: bool,
    settings: &Settings,
) -> Result<Vec<String>, String> {
    let snapshot_temp = snapshot_recovery_temp_dir(temp_dir, storage_dir, "full-snapshot-")?;
    // TempDir makes its path absolute. Preserve the caller's path form when creating CLI
    // mappings: a newly introduced Windows drive colon would be parsed as a separator.
    // The helper creates one named child directly below the requested base.
    let snapshot_temp_name = snapshot_temp
        .path()
        .file_name()
        .ok_or_else(|| "Snapshot recovery work directory name is missing".to_string())?;
    let snapshot_temp_path = temp_dir.unwrap_or(storage_dir).join(snapshot_temp_name);

    // Un-tar snapshot into temporary directory
    tar_unpack_file(Path::new(snapshot_path), &snapshot_temp_path)
        .map_err(|err| format!("Failed to unpack full snapshot {snapshot_path}: {err}"))?;

    // Read configuration file with snapshot-to-collection mapping
    let config_path = snapshot_temp_path.join("config.json");
    let config_file = BufReader::new(File::open(&config_path).map_err(|err| {
        format!(
            "Failed to open full snapshot config {}: {err}",
            config_path.display(),
        )
    })?);
    let config_json: SnapshotConfig = serde_json::from_reader(config_file).map_err(|err| {
        format!(
            "Failed to parse full snapshot config {}: {err}",
            config_path.display(),
        )
    })?;

    // Create mapping from the configuration file
    let mapping: Vec<String> = config_json
        .collections_mapping
        .iter()
        .map(|(collection_name, snapshot_file)| {
            let snapshot_file_path = snapshot_temp_path.join(snapshot_file);
            snapshot_file_path
                .to_str()
                .map(|snapshot_file_path| format!("{snapshot_file_path}:{collection_name}"))
                .ok_or_else(|| {
                    format!(
                        "Full snapshot collection path is not valid UTF-8: {}",
                        snapshot_file_path.display(),
                    )
                })
        })
        .collect::<Result<_, _>>()?;

    // Launch regular recovery of snapshots
    let recovered_collection = recover_snapshots(
        &mapping,
        force,
        temp_dir,
        storage_dir,
        this_peer_id,
        is_distributed,
        settings,
    )?;

    let alias_path = storage_dir.join(ALIASES_PATH);
    let mut alias_persistence = AliasPersistence::open(&alias_path).map_err(|err| {
        format!(
            "Failed to open aliases database {}: {err}",
            alias_path.display(),
        )
    })?;
    for (alias, collection_name) in config_json.collections_aliases {
        if alias_persistence.get(&alias).is_some() && !force {
            return Err(format!(
                "Alias {alias} already exists. Use --force-snapshot to overwrite it.",
            ));
        }
        alias_persistence
            .insert(alias.clone(), collection_name)
            .map_err(|err| format!("Failed to recover alias {alias}: {err}"))?;
    }

    // Remove temporary directory
    snapshot_temp
        .close()
        .map_err(|err| format!("Failed to remove full snapshot recovery work directory: {err}",))?;
    Ok(recovered_collection)
}

fn validate_restored_collection_crypto_runtime(
    settings: &Settings,
    collection_name: &str,
    collection_path: &Path,
) -> Result<(), String> {
    let config = CollectionConfigInternal::load(collection_path).map_err(|err| {
        format!("Failed to load recovered snapshot config for collection {collection_name}: {err}",)
    })?;
    reject_ordinary_private_oram_v2_snapshot_recovery(collection_path).map_err(|err| {
        format!(
            "Failed ordinary snapshot recovery preflight for recovered snapshot \
             {collection_name}: {err}",
        )
    })?;
    validate_recovered_collection_crypto_config(settings, collection_name, &config).map_err(
        |err| {
            format!(
                "Failed to validate crypto runtime for recovered snapshot {collection_name}: {err}",
            )
        },
    )?;
    Collection::validate_private_hnsw_oram_snapshot_restore_layout(
        collection_name,
        &config,
        collection_path,
    )
    .map_err(|err| {
        let detail = sanitize_private_hnsw_snapshot_layout_error(collection_path, err);
        format!(
            "Failed to validate private HNSW ORAM snapshot layout for recovered snapshot \
             {collection_name}: {detail}",
        )
    })?;
    validate_recovered_private_hnsw_oram_snapshot_signatures(
        settings,
        collection_name,
        &config,
        collection_path,
    )
    .map_err(|err| {
        format!(
            "Failed to validate private HNSW ORAM snapshot manifest signatures for recovered \
             snapshot {collection_name}: {err}",
        )
    })?;
    Collection::validate_private_result_oram_snapshot_restore_layout(
        collection_name,
        &config,
        collection_path,
    )
    .map_err(|err| {
        let detail = sanitize_private_result_oram_snapshot_layout_error(collection_path, err);
        format!(
            "Failed to validate private result ORAM snapshot layout for recovered snapshot \
             {collection_name}: {detail}",
        )
    })?;
    validate_recovered_private_result_oram_snapshot_signatures(
        settings,
        collection_name,
        &config,
        collection_path,
    )
    .map_err(|err| {
        format!(
            "Failed to validate private result ORAM snapshot manifest signatures for recovered \
             snapshot {collection_name}: {err}",
        )
    })?;
    Ok(())
}

fn sanitize_private_hnsw_snapshot_layout_error(
    _collection_path: &Path,
    err: collection::operations::types::CollectionError,
) -> String {
    let _ = err;
    "private HNSW ORAM snapshot layout validation failed".to_string()
}

fn sanitize_private_result_oram_snapshot_layout_error(
    _collection_path: &Path,
    err: collection::operations::types::CollectionError,
) -> String {
    let _ = err;
    "private result ORAM snapshot layout validation failed".to_string()
}

#[cfg(test)]
fn validate_restored_collection_crypto_params(
    settings: &Settings,
    collection_name: &str,
    params: &collection::config::CollectionParams,
) -> Result<(), String> {
    validate_recovered_collection_crypto_runtime(settings, collection_name, params).map_err(|err| {
        format!(
            "Failed to validate crypto runtime for recovered snapshot {collection_name}: {err}",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::path::PathBuf;

    use collection::config::{
        COLLECTION_CONFIG_FILE, CollectionConfigInternal, CollectionEncryptionConfig,
        CollectionParams, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, WalConfig,
    };
    use collection::operations::types::VectorsConfig;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::optimizers_builder::OptimizersConfig;
    use collection::private_hnsw_oram_store::{
        PRIVATE_HNSW_ORAM_DIR, PrivateHnswOramEpochState, PrivateHnswOramStore,
    };
    use collection::private_oram_owner_journal::PRIVATE_ORAM_OWNER_JOURNAL_DIR;
    use collection::private_result_oram_store::{
        PRIVATE_RESULT_ORAM_DIR, PrivateResultOramEpochState, PrivateResultOramStore,
    };
    use collection::shards::shard_config::{SHARD_CONFIG_FILE, ShardConfig, ShardType};
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        LocalMasterKeyProvider, MasterKeyProvider, OramKind, OramParams,
        PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_HNSW_ORAM_BINDING,
        PRIVATE_RESULT_ORAM_BINDING, PrivateResultOramBucket,
        PrivateResultOramBucketCommitmentContext, PrivateResultOramManifest,
        RESOURCE_KEY_WRAP_ALGORITHM, SecretKey, private_result_oram_bucket_ciphertext_bytes,
        private_result_oram_bucket_commitment, private_result_oram_merkle_root_for_commitments,
        sign_private_result_oram_manifest,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use segment::types::{Distance, HnswConfig};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;
    use crate::common::private_hnsw_wire_fixture::{
        COLLECTION_ID, KEY_ID, PrivateHnswRouteWireFixture, RK_EPOCH, SIGNING_KEY_ID, VECTOR_NAME,
    };
    use crate::settings::{CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings};

    const RESULT_KEY_ID: &str = "tenant-a/result-private-rk";
    const RESULT_SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v1";

    fn write_cli_plain_snapshot(path: &Path, marker: &[u8]) {
        let mut config = recovered_private_hnsw_config();
        config.params.encryption = None;
        let config = serde_json::to_vec(&config).unwrap();
        // The CLI must restore an actual configured shard. A temporary shard keeps these
        // file-publication tests independent of segment data and replica-state fixtures.
        let shard_config = serde_json::to_vec(&ShardConfig {
            r#type: ShardType::Temporary,
        })
        .unwrap();
        let shard_config_path = format!("0/{SHARD_CONFIG_FILE}");
        let mut archive = tar::Builder::new(fs::File::create(path).unwrap());
        for (name, bytes) in [
            (COLLECTION_CONFIG_FILE, config.as_slice()),
            (shard_config_path.as_str(), shard_config.as_slice()),
            ("restored-content.txt", marker),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o600);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive.append_data(&mut header, name, bytes).unwrap();
        }
        archive.finish().unwrap();
    }

    fn cli_snapshot_mapping(snapshot: &Path, collection: &str) -> Vec<String> {
        vec![format!("{}:{collection}", snapshot.display())]
    }

    fn cli_snapshot_test_root() -> (TempDir, PathBuf) {
        let owner = tempfile::Builder::new()
            .prefix("cli-recovery-test-")
            .tempdir_in(".")
            .unwrap();
        // Keep an absolute RAII owner but pass relative paths to the existing CLI parser,
        // whose path:collection syntax does not support Windows absolute drive paths.
        let root = PathBuf::from(owner.path().file_name().unwrap());
        assert!(root.is_relative());
        (owner, root)
    }

    fn directory_entries(path: &Path) -> Vec<PathBuf> {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    #[test]
    fn cli_snapshot_recovery_preserves_shared_temp_and_creates_collection_parent() {
        let (_owner, root) = cli_snapshot_test_root();
        let snapshot = root.join("plain.snapshot");
        write_cli_plain_snapshot(&snapshot, b"restored collection");
        let temp_base = root.join("shared-temp");
        fs::create_dir(&temp_base).unwrap();
        let unrelated = temp_base.join("unrelated-working-file");
        fs::write(&unrelated, b"keep this file in place").unwrap();
        let storage = root.join("new-storage");

        assert_eq!(
            recover_snapshots(
                &cli_snapshot_mapping(&snapshot, "restored"),
                false,
                Some(&temp_base),
                &storage,
                7,
                false,
                &Settings::new(None).unwrap(),
            )
            .unwrap(),
            vec!["restored"]
        );

        let restored = storage.join(COLLECTIONS_DIR).join("restored");
        assert_eq!(
            fs::read(restored.join("restored-content.txt")).unwrap(),
            b"restored collection"
        );
        assert!(!restored.join("unrelated-working-file").exists());
        assert_eq!(fs::read(&unrelated).unwrap(), b"keep this file in place");
        assert_eq!(directory_entries(&temp_base), vec![unrelated]);
        assert_eq!(
            directory_entries(&storage.join(COLLECTIONS_DIR)),
            vec![restored]
        );
    }

    #[test]
    fn cli_snapshot_recovery_failure_preserves_shared_temp_and_existing_collection() {
        let (_owner, root) = cli_snapshot_test_root();
        let snapshot = root.join("plain.snapshot");
        write_cli_plain_snapshot(&snapshot, b"new collection");
        let broken_snapshot = root.join("broken.snapshot");
        fs::write(&broken_snapshot, b"incomplete archive").unwrap();
        let temp_base = root.join("shared-temp");
        fs::create_dir(&temp_base).unwrap();
        let unrelated = temp_base.join("unrelated-working-file");
        fs::write(&unrelated, b"keep this file in place").unwrap();
        let storage = root.join("storage");
        let restored = storage.join(COLLECTIONS_DIR).join("restored");
        fs::create_dir_all(&restored).unwrap();
        let old_content = restored.join("old-content.txt");
        fs::write(&old_content, b"old collection").unwrap();
        let settings = Settings::new(None).unwrap();

        assert!(
            recover_snapshots(
                &cli_snapshot_mapping(&broken_snapshot, "restored"),
                true,
                Some(&temp_base),
                &storage,
                7,
                false,
                &settings,
            )
            .is_err()
        );
        assert_eq!(fs::read(&old_content).unwrap(), b"old collection");
        assert_eq!(fs::read(&unrelated).unwrap(), b"keep this file in place");
        assert_eq!(directory_entries(&temp_base), vec![unrelated.clone()]);

        recover_snapshots(
            &cli_snapshot_mapping(&snapshot, "restored"),
            true,
            Some(&temp_base),
            &storage,
            7,
            false,
            &settings,
        )
        .unwrap();
        assert!(!old_content.exists());
        assert_eq!(
            fs::read(restored.join("restored-content.txt")).unwrap(),
            b"new collection"
        );
        assert_eq!(directory_entries(&temp_base), vec![unrelated]);
    }

    #[test]
    fn cli_full_snapshot_recovery_isolates_outer_and_collection_work_directories() {
        for custom_temp in [false, true] {
            let (_owner, root) = cli_snapshot_test_root();
            let storage = root.join("new-storage");
            let temp_base = root.join("shared-temp");
            assert!(storage.is_relative());
            assert!(temp_base.is_relative());
            fs::create_dir(&temp_base).unwrap();
            let unrelated = temp_base.join("unrelated-working-file");
            fs::write(&unrelated, b"keep this file in place").unwrap();
            let docs = root.join("docs.snapshot");
            let notes = root.join("notes.snapshot");
            write_cli_plain_snapshot(&docs, b"docs collection");
            write_cli_plain_snapshot(&notes, b"notes collection");
            let full_snapshot = root.join("full.snapshot");
            let config = serde_json::to_vec(&SnapshotConfig {
                collections_mapping: HashMap::from([
                    ("docs".to_string(), "docs.snapshot".to_string()),
                    ("notes".to_string(), "notes.snapshot".to_string()),
                ]),
                collections_aliases: HashMap::from([(
                    "docs-alias".to_string(),
                    "docs".to_string(),
                )]),
            })
            .unwrap();
            let mut archive = tar::Builder::new(fs::File::create(&full_snapshot).unwrap());
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o600);
            header.set_size(config.len() as u64);
            header.set_cksum();
            archive
                .append_data(&mut header, "config.json", config.as_slice())
                .unwrap();
            archive
                .append_path_with_name(&docs, "docs.snapshot")
                .unwrap();
            archive
                .append_path_with_name(&notes, "notes.snapshot")
                .unwrap();
            archive.finish().unwrap();
            drop(archive);

            let mut recovered = recover_full_snapshot(
                custom_temp.then_some(temp_base.as_path()),
                full_snapshot.to_str().unwrap(),
                &storage,
                false,
                7,
                false,
                &Settings::new(None).unwrap(),
            )
            .unwrap();
            recovered.sort();
            assert_eq!(recovered, vec!["docs", "notes"]);
            let collections = storage.join(COLLECTIONS_DIR);
            assert_eq!(
                fs::read(collections.join("docs/restored-content.txt")).unwrap(),
                b"docs collection"
            );
            assert_eq!(
                fs::read(collections.join("notes/restored-content.txt")).unwrap(),
                b"notes collection"
            );
            assert_eq!(
                AliasPersistence::open(&storage.join(ALIASES_PATH))
                    .unwrap()
                    .get("docs-alias"),
                Some("docs".to_string())
            );
            assert_eq!(fs::read(&unrelated).unwrap(), b"keep this file in place");
            assert_eq!(directory_entries(&temp_base), vec![unrelated]);
            assert_eq!(
                directory_entries(&collections),
                vec![collections.join("docs"), collections.join("notes")]
            );
        }
    }

    fn recovered_private_hnsw_config() -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                vectors: VectorsConfig::Multi(BTreeMap::from([(
                    VECTOR_NAME.to_string(),
                    VectorParamsBuilder::new(2, Distance::Euclid).build(),
                )])),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some(KEY_ID.to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: RK_EPOCH,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "text_private_hnsw".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![VECTOR_NAME.to_string()],
                        },
                        instance: "docs_private_hnsw_v1".to_string(),
                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    }],
                }),
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
            uuid: Some(Uuid::parse_str(COLLECTION_ID).unwrap()),
            metadata: None,
        }
    }

    fn recovered_private_result_config() -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                vectors: VectorsConfig::Multi(BTreeMap::from([(
                    VECTOR_NAME.to_string(),
                    VectorParamsBuilder::new(2, Distance::Euclid).build(),
                )])),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some(RESULT_KEY_ID.to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: RK_EPOCH,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "body_private_result".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["body".to_string()],
                        },
                        instance: "payload_result_oram_v1".to_string(),
                        binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                    }],
                }),
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
            uuid: Some(Uuid::parse_str(COLLECTION_ID).unwrap()),
            metadata: None,
        }
    }

    struct PrivateResultSnapshotFixture {
        manifest: PrivateResultOramManifest,
        signature: qdrant_sec::PrivateResultOramSignature,
        buckets: Vec<PrivateResultOramBucket>,
        signing_key: Ed25519KeyPair,
    }

    impl PrivateResultSnapshotFixture {
        fn build() -> Self {
            let signing_key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
            let oram = OramParams {
                kind: OramKind::PathOram,
                bucket_size: 2,
                block_size_bytes: 1024,
                tree_height: 1,
                path_batch_size: 2,
            };
            let bucket_count = (1_u64 << (oram.tree_height + 1)) - 1;
            let mut manifest = PrivateResultOramManifest {
                version: 1,
                provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
                collection_id: COLLECTION_ID.to_string(),
                key_id: RESULT_KEY_ID.to_string(),
                rk_id: RESULT_KEY_ID.to_string(),
                rk_epoch: RK_EPOCH,
                oram: oram.clone(),
                index_epoch: 42,
                root_hash: BASE64URL_NOPAD.encode(&[0; 32]),
                bucket_count,
                logical_result_count: 2,
                dummy_result_count: 1,
                owner_signing_key_id: RESULT_SIGNING_KEY_ID.to_string(),
                created_at_unix: 1,
            };
            let buckets = (0..bucket_count)
                .map(|bucket_id| private_result_snapshot_bucket(bucket_id, &manifest))
                .collect::<Vec<_>>();
            let commitments = buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>();
            manifest.root_hash =
                private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
            let buckets = (0..bucket_count)
                .map(|bucket_id| private_result_snapshot_bucket(bucket_id, &manifest))
                .collect::<Vec<_>>();
            let signature = sign_private_result_oram_manifest(&signing_key, &manifest).unwrap();
            Self {
                manifest,
                signature,
                buckets,
                signing_key,
            }
        }

        fn settings(&self) -> Settings {
            let mut settings = Settings::new(None).unwrap();
            settings.crypto = CryptoSettings {
                zero_trust_profile: Some(crate::settings::ZERO_TRUST_PROFILE_STRICT.to_string()),
                instances: HashMap::from([(
                    "payload_result_oram_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({
                            "key_id": RESULT_KEY_ID,
                            "expected_rk_id": RESULT_KEY_ID,
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
                                RESULT_SIGNING_KEY_ID: BASE64URL_NOPAD.encode(self.signing_key.public_key().as_ref())
                            }
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            };
            settings
        }
    }

    fn private_result_snapshot_bucket(
        bucket_id: u64,
        manifest: &PrivateResultOramManifest,
    ) -> PrivateResultOramBucket {
        let ciphertext_len = private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
        let ciphertext_bytes = vec![bucket_id as u8; ciphertext_len];
        let ciphertext = BASE64URL_NOPAD.encode(&ciphertext_bytes);
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(ciphertext_bytes));
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

    fn write_recovered_private_hnsw_snapshot_fixture(
        collection_dir: &Path,
        fixture: &PrivateHnswRouteWireFixture,
        corrupt_first_bucket_commitment: bool,
    ) {
        let config = recovered_private_hnsw_config();
        fs::write(
            collection_dir.join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();

        let store = PrivateHnswOramStore::new(collection_dir, VECTOR_NAME).unwrap();
        store
            .write_manifest(&fixture.manifest, &fixture.manifest_signature)
            .unwrap();
        store
            .write_initial_epoch(&PrivateHnswOramEpochState {
                index_epoch: fixture.encrypted_build.index_epoch,
                root_hash: fixture.encrypted_build.root_hash.clone(),
            })
            .unwrap();
        store
            .write_merkle_tree_from_commitments(
                fixture.encrypted_build.index_epoch,
                fixture.encrypted_build.root_hash.clone(),
                fixture.leaf_commitments.clone(),
            )
            .unwrap();
        for bucket in &fixture.encrypted_build.buckets {
            let mut bucket = bucket.clone();
            if corrupt_first_bucket_commitment && bucket.bucket_id == 0 {
                bucket.bucket_commitment = BASE64URL_NOPAD.encode(&[99; 32]);
            }
            store
                .write_bucket(
                    &bucket,
                    fixture.encrypted_build.index_epoch,
                    fixture.encrypted_build.bucket_count,
                    crate::common::private_hnsw_wire_fixture::MAX_CIPHERTEXT_BYTES,
                )
                .unwrap();
        }
    }

    fn write_recovered_private_result_snapshot_fixture(
        collection_dir: &Path,
        fixture: &PrivateResultSnapshotFixture,
        tamper_signature: bool,
    ) {
        let config = recovered_private_result_config();
        fs::write(
            collection_dir.join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();

        let store = PrivateResultOramStore::new(collection_dir);
        let mut signature = fixture.signature.clone();
        if tamper_signature {
            signature.sig = BASE64URL_NOPAD.encode(&[5; 64]);
        }
        store.write_manifest(&fixture.manifest, &signature).unwrap();
        store
            .write_initial_epoch(&PrivateResultOramEpochState {
                index_epoch: fixture.manifest.index_epoch,
                root_hash: fixture.manifest.root_hash.clone(),
            })
            .unwrap();
        let commitments = fixture
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        store
            .write_merkle_tree_from_commitments(
                fixture.manifest.index_epoch,
                fixture.manifest.root_hash.clone(),
                commitments,
            )
            .unwrap();
        let block_size = usize::try_from(fixture.manifest.oram.block_size_bytes).unwrap();
        let bucket_size = usize::try_from(fixture.manifest.oram.bucket_size).unwrap();
        let max_ciphertext_bytes = block_size * bucket_size + 4096;
        for bucket in &fixture.buckets {
            store
                .write_bucket(
                    bucket,
                    fixture.manifest.index_epoch,
                    fixture.manifest.bucket_count,
                    max_ciphertext_bytes,
                )
                .unwrap();
        }
    }

    #[test]
    fn cli_snapshot_layout_sanitizers_redact_private_oram_alias_values() {
        let temp_dir = TempDir::new().unwrap();

        let hnsw_leaked_values = [
            "cli-hnsw-bucket-id",
            "cli-hnsw-path-label",
            "cli-hnsw-leaf-hash",
            "cli-hnsw-sibling-hash",
            "cli-hnsw-payload-token",
            "cli-hnsw-signature",
        ];
        let hnsw_detail = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            collection::operations::types::CollectionError::bad_request(format!(
                "private HNSW ORAM bucket_id {} path_label {} proof leaf_hash {} \
                 sibling_hash {} payload_fetch_token {} payload.fetch.token {} \
                 manifest_signature {}",
                hnsw_leaked_values[0],
                hnsw_leaked_values[1],
                hnsw_leaked_values[2],
                hnsw_leaked_values[3],
                hnsw_leaked_values[4],
                hnsw_leaked_values[4],
                hnsw_leaked_values[5],
            )),
        );

        assert_eq!(
            hnsw_detail,
            "private HNSW ORAM snapshot layout validation failed"
        );
        for leaked in hnsw_leaked_values {
            assert!(!hnsw_detail.contains(leaked));
        }

        let result_leaked_values = [
            "cli-result-read-bucket-id",
            "cli-result-bucket-id",
            "cli-result-leaf-hash",
            "cli-result-sibling-hash",
            "cli-result-payload-token",
            "cli-result-read-signature",
            "cli-result-commit-signature",
        ];
        let result_detail = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            collection::operations::types::CollectionError::bad_request(format!(
                "private result ORAM read_bucket_id {} bucket_ids {} proof leaf_hash {} \
                 sibling_hash {} payload_fetch_tokens {} payload.fetch.token {} \
                 read_signature {} commit_signature {}",
                result_leaked_values[0],
                result_leaked_values[1],
                result_leaked_values[2],
                result_leaked_values[3],
                result_leaked_values[4],
                result_leaked_values[4],
                result_leaked_values[5],
                result_leaked_values[6],
            )),
        );

        assert_eq!(
            result_detail,
            "private result ORAM snapshot layout validation failed"
        );
        for leaked in result_leaked_values {
            assert!(!result_detail.contains(leaked));
        }
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_missing_runtime_instance() {
        let settings = Settings::new(None).unwrap();
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("missing runtime instance must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("payload crypto runtime validation failed"));
        assert!(!err.contains("unknown payload crypto instance"));
        assert!(!err.contains("docs_payload_v1"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_hnsw_bucket_root_mismatch() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, true);

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("private HNSW ORAM restore layout mismatch must fail CLI preflight");

        assert!(err.contains("private HNSW ORAM snapshot layout"), "{err}");
        assert!(err.contains("snapshot layout validation failed"), "{err}");
        assert!(!err.contains("bucket 0"), "{err}");
        assert!(!err.contains("commitment context mismatch"), "{err}");
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains("private_hnsw_oram"), "{err}");
        assert!(!err.contains(&fixture.encrypted_build.root_hash), "{err}");
        assert!(
            !err.contains(&fixture.encrypted_build.buckets[0].ciphertext),
            "{err}"
        );
        assert!(
            !err.contains(&fixture.encrypted_build.buckets[0].bucket_commitment),
            "{err}"
        );
        assert!(!err.contains(SIGNING_KEY_ID), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_preflight_rejects_private_oram_v2_owner_state() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);
        fs::create_dir_all(
            collection_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join(VECTOR_NAME)
                .join("temp")
                .join(PRIVATE_ORAM_OWNER_JOURNAL_DIR),
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("CLI recovery must reject V2 owner state before installation");

        assert!(
            err.contains("ordinary snapshot recovery is forbidden"),
            "{err}"
        );
        assert!(
            err.contains("consensus-qualified private ORAM external recovery"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_ORAM_OWNER_JOURNAL_DIR), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_sanitizes_private_hnsw_store_paths() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);
        fs::remove_file(
            collection_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join(VECTOR_NAME)
                .join("buckets")
                .join("00000000.bucket"),
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("missing bucket must fail CLI preflight");

        assert!(
            err.contains("private HNSW ORAM snapshot layout validation failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.encrypted_build.root_hash), "{err}");
        assert!(
            !err.contains(&fixture.encrypted_build.buckets[0].ciphertext),
            "{err}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_hnsw_client_state_alias() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        for alias in [
            "clientState.json",
            "clientStates.json",
            "client_state.json",
            "client_states.json",
            "clientStateBackup.json",
            "clientStateBackups.json",
            "client_state_backup.json",
            "client_state_backups.json",
            "clientStateCiphertext.json",
            "clientStateCiphertextHash.json",
            "clientStateCiphertextHashes.json",
            "clientStateCiphertextSha256.json",
            "clientStateCiphertextsSha256.json",
            "client_state_ciphertext.json",
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_hashes.bin",
            "client_state_ciphertext_hashes.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "client_state_ciphertexts_sha256.bin",
            "client_state_ciphertexts_sha256.json",
            "clientStateSnapshot.json",
            "clientStateSnapshots.json",
            "client.state.snapshot.json",
            "client_state_snapshot.json",
            "client_state_snapshots.json",
            "client.state.snapshots.json",
            "encryptedClientState.json",
            "encryptedClientStates.json",
            "encrypted_client_state.json",
            "encrypted_client_states.json",
            "encryptedClientStateBackup.json",
            "encryptedClientStateBackups.json",
            "encrypted_client_state_backup.json",
            "encrypted_client_state_backups.json",
            "encryptedClientStateCiphertext.json",
            "encryptedClientStateCiphertextHash.json",
            "encryptedClientStateCiphertextHashes.json",
            "encryptedClientStateCiphertextSha256.json",
            "encryptedClientStateCiphertextsSha256.json",
            "encrypted_client_state_ciphertext.json",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_hashes.bin",
            "encrypted_client_state_ciphertext_hashes.json",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "encrypted_client_state_ciphertexts_sha256.bin",
            "encrypted_client_state_ciphertexts_sha256.json",
            "encryptedClientStateSnapshot.json",
            "encryptedClientStateSnapshots.json",
            "encrypted.client.state.json",
            "encrypted.client.state.snapshot.json",
            "encrypted_client_state_snapshot.json",
            "encrypted_client_state_snapshots.json",
            "encrypted.client.state.snapshots.json",
            "oramPositionMapBackup.json",
            "oramPositionMapBackups.json",
            "oram_position_map_backup.json",
            "oram_position_map_backups.json",
            "positionMapBackup.json",
            "positionMapBackups.json",
            "position_map_backup.json",
            "position_map_backups.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
            "state_ciphertexts_sha256.bin",
            "state_ciphertexts_sha256.json",
            "stashBackup.json",
            "stashBackups.json",
            "tokenMapBackup.json",
            "tokenMapBackups.json",
            "token.map.backup.json",
            "token.map.backups.json",
            "token_map_backup.json",
            "token_map_backups.json",
            "tokenPositionMapBackup.json",
            "tokenPositionMapBackups.json",
            "token.position.map.backup.json",
            "token.position.map.backups.json",
            "token_position_map_backup.json",
            "token_position_map_backups.json",
        ] {
            let collection_dir = TempDir::new().unwrap();
            write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);
            fs::write(
                collection_dir
                    .path()
                    .join(PRIVATE_HNSW_ORAM_DIR)
                    .join(VECTOR_NAME)
                    .join(alias),
                b"client state snapshot sentinel",
            )
            .unwrap();

            let err = validate_restored_collection_crypto_runtime(
                &settings,
                "docs",
                collection_dir.path(),
            )
            .expect_err("client-owned private HNSW ORAM state must fail CLI preflight");

            assert!(
                err.contains("private HNSW ORAM snapshot layout validation failed"),
                "{err}"
            );
            assert!(
                !err.contains(collection_dir.path().to_string_lossy().as_ref()),
                "{err}"
            );
            assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR), "{err}");
            assert!(!err.contains(VECTOR_NAME), "{err}");
            assert!(!err.contains(alias), "{err}");
            assert!(!err.contains(alias.trim_end_matches(".json")), "{err}");
            assert!(!err.contains("sentinel"), "{err}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_hnsw_non_empty_temp() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);
        fs::write(
            collection_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join(VECTOR_NAME)
                .join("temp")
                .join("stale-hnsw-write.tmp"),
            b"stale HNSW temp sentinel",
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("non-empty private HNSW ORAM temp must fail CLI preflight");

        assert!(
            err.contains("private HNSW ORAM snapshot layout validation failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR), "{err}");
        assert!(!err.contains(VECTOR_NAME), "{err}");
        assert!(!err.contains("stale-hnsw-write"), "{err}");
        assert!(!err.contains("sentinel"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_accepts_private_hnsw_restore_layout() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);

        validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
            .expect("valid private HNSW ORAM snapshot layout must pass CLI preflight");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_hnsw_manifest_signature_tamper() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);
        let store = PrivateHnswOramStore::new(collection_dir.path(), VECTOR_NAME).unwrap();
        let mut tampered_signature = fixture.manifest_signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[9; 64]);
        store
            .write_manifest(&fixture.manifest, &tampered_signature)
            .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("tampered private HNSW manifest signature must fail CLI preflight");

        assert!(
            err.contains("private HNSW ORAM request validation failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.encrypted_build.root_hash), "{err}");
        assert!(
            !err.contains(&fixture.encrypted_build.buckets[0].ciphertext),
            "{err}"
        );
        assert!(!err.contains(SIGNING_KEY_ID), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_hnsw_runtime_public_key_mismatch() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let mut settings = fixture.route_settings();
        settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["signature_public_keys"][SIGNING_KEY_ID] =
            json!(BASE64URL_NOPAD.encode(&[11; 32]));
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("private HNSW runtime public key mismatch must fail CLI preflight");

        assert!(
            err.contains("private HNSW ORAM request validation failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.encrypted_build.root_hash), "{err}");
        assert!(
            !err.contains(&fixture.encrypted_build.buckets[0].ciphertext),
            "{err}"
        );
        assert!(!err.contains(SIGNING_KEY_ID), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_hnsw_manifest_owner_key_mismatch() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);
        let store = PrivateHnswOramStore::new(collection_dir.path(), VECTOR_NAME).unwrap();
        let alternate_signing_key_id = "tenant-a/private-hnsw-signing-v2";
        let mut mismatched_signature = fixture.manifest_signature.clone();
        mismatched_signature.key_id = alternate_signing_key_id.to_string();
        store
            .write_manifest(&fixture.manifest, &mismatched_signature)
            .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("private HNSW manifest owner key mismatch must fail CLI preflight");

        assert!(
            err.contains("private HNSW ORAM snapshot layout validation failed"),
            "{err}"
        );
        assert!(!err.contains("signature key_id"), "{err}");
        assert!(!err.contains("not configured"), "{err}");
        assert!(!err.contains(alternate_signing_key_id), "{err}");
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.encrypted_build.root_hash), "{err}");
        assert!(
            !err.contains(&fixture.encrypted_build.buckets[0].ciphertext),
            "{err}"
        );
        assert!(!err.contains(SIGNING_KEY_ID), "{err}");
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_unconfigured_private_hnsw_oram_directory() {
        let settings = Settings::new(None).unwrap();
        let collection_dir = TempDir::new().unwrap();
        let mut config = recovered_private_hnsw_config();
        config.params.encryption = None;
        fs::write(
            collection_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        fs::create_dir(collection_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("unconfigured private HNSW ORAM directory must fail CLI preflight");

        assert!(err.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_unconfigured_private_hnsw_oram_symlink() {
        let settings = Settings::new(None).unwrap();
        let collection_dir = TempDir::new().unwrap();
        let mut config = recovered_private_hnsw_config();
        config.params.encryption = None;
        fs::write(
            collection_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            collection_dir.path().join("missing-hnsw-oram-target"),
            collection_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("unconfigured private HNSW ORAM symlink must fail CLI preflight");

        assert!(err.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("missing-hnsw-oram-target"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_configured_private_hnsw_oram_symlink() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        let config = recovered_private_hnsw_config();
        fs::write(
            collection_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            collection_dir
                .path()
                .join("configured-missing-hnsw-oram-target"),
            collection_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("configured private HNSW ORAM symlink must fail CLI preflight");

        assert!(err.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("configured-missing-hnsw-oram-target"));
        assert!(!err.contains(SIGNING_KEY_ID));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_accepts_private_result_oram_snapshot() {
        let fixture = PrivateResultSnapshotFixture::build();
        let settings = fixture.settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_result_snapshot_fixture(collection_dir.path(), &fixture, false);

        validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
            .expect("valid private result ORAM snapshot should pass CLI preflight");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_sanitizes_private_result_store_paths() {
        let fixture = PrivateResultSnapshotFixture::build();
        let settings = fixture.settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_result_snapshot_fixture(collection_dir.path(), &fixture, false);
        fs::remove_file(
            collection_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("buckets")
                .join("00000000.bucket"),
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("missing result ORAM bucket must fail CLI preflight");

        assert!(
            err.contains("private result ORAM snapshot layout validation failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR), "{err}");
        assert!(!err.contains("00000000.bucket"), "{err}");
        assert!(!err.contains("buckets"), "{err}");
        assert!(!err.contains(&fixture.manifest.root_hash), "{err}");
        assert!(!err.contains(&fixture.buckets[0].ciphertext), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_result_client_state_alias() {
        let fixture = PrivateResultSnapshotFixture::build();
        let settings = fixture.settings();
        for alias in [
            "clientState.json",
            "clientStates.json",
            "client_state.json",
            "client_states.json",
            "clientStateBackup.json",
            "clientStateBackups.json",
            "client_state_backup.json",
            "client_state_backups.json",
            "clientStateCiphertext.json",
            "clientStateCiphertextHash.json",
            "clientStateCiphertextHashes.json",
            "clientStateCiphertextSha256.json",
            "clientStateCiphertextsSha256.json",
            "client_state_ciphertext.json",
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_hashes.bin",
            "client_state_ciphertext_hashes.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "client_state_ciphertexts_sha256.bin",
            "client_state_ciphertexts_sha256.json",
            "clientStateSnapshot.json",
            "clientStateSnapshots.json",
            "client.state.snapshot.json",
            "client_state_snapshot.json",
            "client_state_snapshots.json",
            "client.state.snapshots.json",
            "encryptedClientState.json",
            "encryptedClientStates.json",
            "encrypted_client_state.json",
            "encrypted_client_states.json",
            "encryptedClientStateBackup.json",
            "encryptedClientStateBackups.json",
            "encrypted_client_state_backup.json",
            "encrypted_client_state_backups.json",
            "encryptedClientStateCiphertext.json",
            "encryptedClientStateCiphertextHash.json",
            "encryptedClientStateCiphertextHashes.json",
            "encryptedClientStateCiphertextSha256.json",
            "encryptedClientStateCiphertextsSha256.json",
            "encrypted_client_state_ciphertext.json",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_hashes.bin",
            "encrypted_client_state_ciphertext_hashes.json",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "encrypted_client_state_ciphertexts_sha256.bin",
            "encrypted_client_state_ciphertexts_sha256.json",
            "encryptedClientStateSnapshot.json",
            "encryptedClientStateSnapshots.json",
            "encrypted.client.state.json",
            "encrypted.client.state.snapshot.json",
            "encrypted_client_state_snapshot.json",
            "encrypted_client_state_snapshots.json",
            "encrypted.client.state.snapshots.json",
            "oramPositionMapBackup.json",
            "oramPositionMapBackups.json",
            "oram_position_map_backup.json",
            "oram_position_map_backups.json",
            "positionMapBackup.json",
            "positionMapBackups.json",
            "position_map_backup.json",
            "position_map_backups.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
            "state_ciphertexts_sha256.bin",
            "state_ciphertexts_sha256.json",
            "stashBackup.json",
            "stashBackups.json",
            "tokenMapBackup.json",
            "tokenMapBackups.json",
            "token.map.backup.json",
            "token.map.backups.json",
            "token_map_backup.json",
            "token_map_backups.json",
            "tokenPositionMapBackup.json",
            "tokenPositionMapBackups.json",
            "token.position.map.backup.json",
            "token.position.map.backups.json",
            "token_position_map_backup.json",
            "token_position_map_backups.json",
        ] {
            let collection_dir = TempDir::new().unwrap();
            write_recovered_private_result_snapshot_fixture(collection_dir.path(), &fixture, false);
            fs::write(
                collection_dir
                    .path()
                    .join(PRIVATE_RESULT_ORAM_DIR)
                    .join(alias),
                b"result client state snapshot sentinel",
            )
            .unwrap();

            let err = validate_restored_collection_crypto_runtime(
                &settings,
                "docs",
                collection_dir.path(),
            )
            .expect_err("client-owned private result ORAM state must fail CLI preflight");

            assert!(
                err.contains("private result ORAM snapshot layout validation failed"),
                "{err}"
            );
            assert!(
                !err.contains(collection_dir.path().to_string_lossy().as_ref()),
                "{err}"
            );
            assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR), "{err}");
            assert!(!err.contains(alias), "{err}");
            assert!(!err.contains(alias.trim_end_matches(".json")), "{err}");
            assert!(!err.contains("sentinel"), "{err}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_result_non_empty_temp() {
        let fixture = PrivateResultSnapshotFixture::build();
        let settings = fixture.settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_result_snapshot_fixture(collection_dir.path(), &fixture, false);
        fs::write(
            collection_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("temp")
                .join("stale-result-write.tmp"),
            b"stale result temp sentinel",
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("non-empty private result ORAM temp must fail CLI preflight");

        assert!(
            err.contains("private result ORAM snapshot layout validation failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR), "{err}");
        assert!(!err.contains("stale-result-write"), "{err}");
        assert!(!err.contains("sentinel"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_result_bucket_commitment_mismatch() {
        let fixture = PrivateResultSnapshotFixture::build();
        let settings = fixture.settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_result_snapshot_fixture(collection_dir.path(), &fixture, false);
        let store = PrivateResultOramStore::new(collection_dir.path());
        let block_size = usize::try_from(fixture.manifest.oram.block_size_bytes).unwrap();
        let bucket_size = usize::try_from(fixture.manifest.oram.bucket_size).unwrap();
        let max_ciphertext_bytes = block_size * bucket_size + 4096;
        let mut bucket = fixture.buckets[0].clone();
        bucket.bucket_commitment = BASE64URL_NOPAD.encode(&[99; 32]);
        store
            .write_bucket(
                &bucket,
                fixture.manifest.index_epoch,
                fixture.manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("private result bucket commitment mismatch must fail CLI preflight");

        assert!(
            err.contains("private result ORAM snapshot layout validation failed"),
            "{err}"
        );
        assert!(!err.contains("bucket commitment"), "{err}");
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.manifest.root_hash), "{err}");
        assert!(!err.contains(&fixture.buckets[0].ciphertext), "{err}");
        assert!(
            !err.contains(&fixture.buckets[0].bucket_commitment),
            "{err}"
        );
        assert!(!err.contains(RESULT_SIGNING_KEY_ID), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_result_oram_manifest_signature_tamper() {
        let fixture = PrivateResultSnapshotFixture::build();
        let settings = fixture.settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_result_snapshot_fixture(collection_dir.path(), &fixture, true);

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("tampered private result manifest signature must fail CLI preflight");

        assert!(
            err.contains("manifest signature verification failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.manifest.root_hash), "{err}");
        assert!(!err.contains(&fixture.buckets[0].ciphertext), "{err}");
        assert!(!err.contains(RESULT_SIGNING_KEY_ID), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_result_runtime_public_key_mismatch() {
        let fixture = PrivateResultSnapshotFixture::build();
        let mut settings = fixture.settings();
        settings
            .crypto
            .instances
            .get_mut("payload_result_oram_v1")
            .unwrap()
            .options["signature_public_keys"][RESULT_SIGNING_KEY_ID] =
            json!(BASE64URL_NOPAD.encode(&[12; 32]));
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_result_snapshot_fixture(collection_dir.path(), &fixture, false);

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("private result runtime public key mismatch must fail CLI preflight");

        assert!(
            err.contains("manifest signature verification failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.manifest.root_hash), "{err}");
        assert!(!err.contains(&fixture.buckets[0].ciphertext), "{err}");
        assert!(!err.contains(RESULT_SIGNING_KEY_ID), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_result_oram_manifest_owner_key_mismatch() {
        let fixture = PrivateResultSnapshotFixture::build();
        let settings = fixture.settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_result_snapshot_fixture(collection_dir.path(), &fixture, false);
        let store = PrivateResultOramStore::new(collection_dir.path());
        let alternate_signing_key_id = "tenant-a/private-result-signing-v2";
        let mut mismatched_signature = fixture.signature.clone();
        mismatched_signature.key_id = alternate_signing_key_id.to_string();
        store
            .write_manifest(&fixture.manifest, &mismatched_signature)
            .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("private result manifest owner key mismatch must fail CLI preflight");

        assert!(
            err.contains("private result ORAM snapshot layout validation failed"),
            "{err}"
        );
        assert!(!err.contains("signature key_id"), "{err}");
        assert!(!err.contains("not configured"), "{err}");
        assert!(!err.contains(alternate_signing_key_id), "{err}");
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.manifest.root_hash), "{err}");
        assert!(!err.contains(&fixture.buckets[0].ciphertext), "{err}");
        assert!(!err.contains(RESULT_SIGNING_KEY_ID), "{err}");
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_unconfigured_private_result_oram_directory() {
        let settings = Settings::new(None).unwrap();
        let collection_dir = TempDir::new().unwrap();
        let mut config = recovered_private_hnsw_config();
        config.params.encryption = None;
        fs::write(
            collection_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        fs::create_dir(collection_dir.path().join(PRIVATE_RESULT_ORAM_DIR)).unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("unconfigured private result ORAM directory must fail CLI preflight");

        assert!(err.contains("private result ORAM snapshot layout validation failed"));
        assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_unconfigured_private_result_oram_symlink() {
        let settings = Settings::new(None).unwrap();
        let collection_dir = TempDir::new().unwrap();
        let mut config = recovered_private_hnsw_config();
        config.params.encryption = None;
        fs::write(
            collection_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            collection_dir.path().join("missing-result-oram-target"),
            collection_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("unconfigured private result ORAM symlink must fail CLI preflight");

        assert!(err.contains("private result ORAM snapshot layout validation failed"));
        assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("missing-result-oram-target"));
    }

    #[cfg(unix)]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_configured_private_result_oram_symlink() {
        let fixture = PrivateResultSnapshotFixture::build();
        let settings = fixture.settings();
        let collection_dir = TempDir::new().unwrap();
        let config = recovered_private_result_config();
        fs::write(
            collection_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            collection_dir
                .path()
                .join("configured-missing-result-oram-target"),
            collection_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("configured private result ORAM symlink must fail CLI preflight");

        assert!(err.contains("private result ORAM snapshot layout validation failed"));
        assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("configured-missing-result-oram-target"));
        assert!(!err.contains(RESULT_SIGNING_KEY_ID));
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_missing_runtime_material() {
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
                            "tenant-a/missing-payload-rk".to_string(),
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
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("missing runtime material must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("payload crypto runtime validation failed"));
        assert!(!err.contains("sym_key"));
        assert!(!err.contains("tenant-a/missing-payload-v1"));
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_wrong_wrapping_key() {
        let mk_material = "tenant-a/mk-v1";
        let rk_material = "tenant-a/payload-rk-v1";
        let rk_epoch = 1;
        let rk_scope = "collection:docs";
        let wrapping_key = SecretKey::from_bytes([91; 32]);
        let resource_key = SecretKey::from_bytes([92; 32]);
        let wrap_provider =
            LocalMasterKeyProvider::new(mk_material, wrapping_key).expect("valid test MK");
        let wrapped = wrap_provider
            .wrap_resource_key(
                &resource_key,
                &resource_key_wrap_test_aad(
                    rk_material,
                    rk_epoch,
                    rk_scope,
                    mk_material,
                    RESOURCE_KEY_WRAP_ALGORITHM,
                ),
            )
            .expect("test RK should wrap");

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
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "payload/aes-256-gcm@v1".to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            rk_material.to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/payload@v1",
                        }),
                    },
                )]),
                materials: HashMap::from([
                    (
                        mk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: "wrapping_key_32".to_string(),
                            source: Some("inline".to_string()),
                            value_b64: Some(BASE64URL_NOPAD.encode(&[99; 32])),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (
                        rk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: "wrapped_symmetric_key_32".to_string(),
                            wrapped_by: Some(mk_material.to_string()),
                            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                            nonce: Some(wrapped.nonce),
                            wrapped_key_b64: Some(wrapped.wrapped_key),
                            rk_epoch: Some(rk_epoch),
                            state: Some("active".to_string()),
                            scope: Some(rk_scope.to_string()),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                ]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("wrong wrapping key must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("payload crypto runtime validation failed"));
        assert!(!err.contains("decryption authentication failed"));
        assert!(!err.contains("tenant-a/payload-rk-v1"));
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_runtime_key_id_mismatch() {
        let mk_material = "tenant-a/mk-v1";
        let rk_material = "tenant-a/payload-rk-v1";
        let rk_epoch = 1;
        let rk_scope = "collection:docs";
        let wrapping_key_bytes = [91; 32];
        let wrapping_key = SecretKey::from_bytes(wrapping_key_bytes);
        let resource_key = SecretKey::from_bytes([92; 32]);
        let wrap_provider =
            LocalMasterKeyProvider::new(mk_material, wrapping_key).expect("valid test MK");
        let wrapped = wrap_provider
            .wrap_resource_key(
                &resource_key,
                &resource_key_wrap_test_aad(
                    rk_material,
                    rk_epoch,
                    rk_scope,
                    mk_material,
                    RESOURCE_KEY_WRAP_ALGORITHM,
                ),
            )
            .expect("test RK should wrap");

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
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "payload/aes-256-gcm@v1".to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            rk_material.to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:wrong-docs",
                            "material_fingerprint_id": "tenant-a/payload@v1",
                        }),
                    },
                )]),
                materials: HashMap::from([
                    (
                        mk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: "wrapping_key_32".to_string(),
                            source: Some("inline".to_string()),
                            value_b64: Some(BASE64URL_NOPAD.encode(&wrapping_key_bytes)),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (
                        rk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: "wrapped_symmetric_key_32".to_string(),
                            wrapped_by: Some(mk_material.to_string()),
                            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                            nonce: Some(wrapped.nonce),
                            wrapped_key_b64: Some(wrapped.wrapped_key),
                            rk_epoch: Some(rk_epoch),
                            state: Some("active".to_string()),
                            scope: Some(rk_scope.to_string()),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                ]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("runtime key_id mismatch must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("payload crypto runtime validation failed"));
        assert!(!err.contains("key id does not match"));
        assert!(!err.contains("tenant-a:docs"));
        assert!(!err.contains("tenant-a:other"));
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_missing_vector_backend() {
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
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "vector/openfhe-ckks@v1".to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            "tenant-a/vector-rk-v1".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/vector@v1",
                            "profile": "ckks-128-n16384-d4-scale50",
                            "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                            "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                            "score_plaintext_output_tcb_ack": "qdrant-sec-ckks-score-output-tcb-v1",
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/vector-rk-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: "symmetric_key_32".to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "vector_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["text".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("missing vector backend must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("missing backend_ref"));
    }

    fn resource_key_wrap_test_aad(
        material_name: &str,
        epoch: u64,
        scope: &str,
        wrapped_by: &str,
        algorithm: &str,
    ) -> Vec<u8> {
        let epoch = epoch.to_string();
        let values = [
            "qdrant-sec",
            "v1",
            "resource-key-wrap",
            material_name,
            &epoch,
            scope,
            wrapped_by,
            algorithm,
        ];

        let mut aad = Vec::new();
        for value in values {
            let bytes = value.as_bytes();
            aad.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            aad.extend_from_slice(bytes);
        }
        aad
    }
}
