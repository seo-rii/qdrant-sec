pub mod download;
pub mod download_result;
pub mod download_tar;
pub mod private_oram_external_recovery;
pub mod recover;

use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::sync::Arc;

use collection::collection::Collection;
use collection::operations::snapshot_ops::SnapshotDescription;
use collection::operations::verification::new_unchecked_verification_pass;
use fs_err as fs;
use fs_err::tokio as tokio_fs;
use serde::{Deserialize, Serialize};
use tar::Builder as TarBuilder;
use tempfile::TempPath;
use tokio::io::AsyncWriteExt;
use tokio_util::task::AbortOnDropHandle;

use crate::content_manager::toc::FULL_SNAPSHOT_FILE_NAME;
use crate::dispatcher::Dispatcher;
use crate::rbac::{AccessRequirements, Auth};
use crate::{StorageError, TableOfContent};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SnapshotConfig {
    /// Map collection name to snapshot file name
    pub collections_mapping: HashMap<String, String>,
    /// Aliases for collections `<alias>:<collection_name>`
    #[serde(default)]
    pub collections_aliases: HashMap<String, String>,
}

pub struct FullSnapshotPlan {
    collections: Vec<Arc<Collection>>,
    alias_mapping: HashMap<String, String>,
}

impl FullSnapshotPlan {
    pub fn new(
        mut collections: Vec<Arc<Collection>>,
        alias_mapping: HashMap<String, String>,
    ) -> Result<Self, StorageError> {
        collections.sort_by(|left, right| left.name().cmp(right.name()));
        if collections
            .windows(2)
            .any(|pair| pair[0].name() == pair[1].name())
        {
            return Err(StorageError::service_error(
                "full snapshot plan contains duplicate collection names",
            ));
        }
        if alias_mapping.values().any(|target| {
            collections
                .binary_search_by(|collection| collection.name().cmp(target))
                .is_err()
        }) {
            return Err(StorageError::service_error(
                "full snapshot plan alias target is not in the planned collection set",
            ));
        }
        Ok(Self {
            collections,
            alias_mapping,
        })
    }
}

pub struct PreparedFullSnapshot {
    snapshot_name: String,
    archive: TempPath,
}

pub async fn do_delete_full_snapshot(
    dispatcher: &Dispatcher,
    auth: Auth,
    snapshot_name: &str,
) -> Result<bool, StorageError> {
    auth.check_global_access(AccessRequirements::new().manage(), "delete_full_snapshot")?;

    // All checks should've been done at this point.
    let pass = new_unchecked_verification_pass();

    let toc = dispatcher.toc(&auth, &pass);

    let snapshot_manager = toc.get_snapshots_storage_manager()?;
    let snapshot_dir =
        snapshot_manager.get_full_snapshot_path(toc.snapshots_path(), snapshot_name)?;

    let res = tokio::spawn(async move {
        log::info!("Deleting full storage snapshot {snapshot_dir:?}");
        snapshot_manager.delete_snapshot(&snapshot_dir).await
    })
    .await??;

    Ok(res)
}

pub async fn do_delete_collection_snapshot(
    dispatcher: &Dispatcher,
    auth: Auth,
    collection_name: &str,
    snapshot_name: &str,
) -> Result<bool, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write().extras(),
        "delete_collection_snapshot",
    )?;

    // All checks should've been done at this point.
    let pass = new_unchecked_verification_pass();

    let toc = dispatcher.toc(&auth, &pass);

    let snapshot_name = snapshot_name.to_string();
    let collection = toc.get_collection(&collection_pass).await?;
    let snapshot_manager = toc.get_snapshots_storage_manager()?;
    let file_name =
        snapshot_manager.get_snapshot_path(collection.snapshots_path(), &snapshot_name)?;

    let res = tokio::spawn(async move {
        log::info!("Deleting collection snapshot {file_name:?}");
        snapshot_manager.delete_snapshot(&file_name).await
    })
    .await??;

    Ok(res)
}

pub async fn do_list_full_snapshots(
    toc: &TableOfContent,
    auth: Auth,
) -> Result<Vec<SnapshotDescription>, StorageError> {
    auth.check_global_access(
        AccessRequirements::new().snapshot_export(),
        "list_full_snapshots",
    )?;
    let snapshots_manager = toc.get_snapshots_storage_manager()?;
    let snapshots_path = toc.snapshots_path();
    Ok(snapshots_manager.list_snapshots(snapshots_path).await?)
}

pub async fn prepare_full_snapshot(
    toc: &TableOfContent,
    plan: FullSnapshotPlan,
) -> Result<PreparedFullSnapshot, StorageError> {
    let mut prepared_snapshots = Vec::with_capacity(plan.collections.len());
    for collection in &plan.collections {
        let prepared = toc.prepare_snapshot(collection).await?;
        prepared_snapshots.push((Arc::clone(collection), prepared));
    }
    let current_time = chrono::Utc::now().format("%Y-%m-%d-%H-%M-%S").to_string();

    let snapshot_name = format!("{FULL_SNAPSHOT_FILE_NAME}-{current_time}.snapshot");

    let collection_name_to_snapshot_path: HashMap<_, _> = prepared_snapshots
        .iter()
        .map(|(collection, prepared)| (collection.name().to_string(), prepared.name().to_string()))
        .collect();

    let temp_storage_path = toc.optional_temp_or_storage_temp_path()?;
    let config_path = tempfile::Builder::new()
        .prefix(&format!("config-{current_time}-"))
        .suffix(".json.staged")
        .tempfile_in(&temp_storage_path)?
        .into_temp_path();

    {
        let snapshot_config = SnapshotConfig {
            collections_mapping: collection_name_to_snapshot_path,
            collections_aliases: plan.alias_mapping,
        };
        let snapshot_config_json = serde_json::to_vec_pretty(&snapshot_config).map_err(|err| {
            StorageError::service_error(format!("failed to serialize snapshot config: {err}"))
        })?;
        let mut config_file = tokio_fs::File::create(&config_path).await?;
        config_file.write_all(&snapshot_config_json).await?;
        config_file.sync_all().await?;
    }

    let temp_full_snapshot_path = tempfile::Builder::new()
        .prefix(&format!("{snapshot_name}-"))
        .suffix(".staged")
        .tempfile_in(&temp_storage_path)?
        .into_temp_path();

    let config_path_clone = config_path.to_path_buf();
    let collection_archive_paths = prepared_snapshots
        .iter()
        .map(|(_, prepared)| {
            (
                prepared.archive_path().to_path_buf(),
                prepared.name().to_string(),
            )
        })
        .collect::<Vec<_>>();

    let full_snapshot_path_clone = temp_full_snapshot_path.to_path_buf();
    let archiving = tokio::task::spawn_blocking(move || {
        // have to use std here, cause TarBuilder is not async
        let mut file = BufWriter::new(fs::File::create(&full_snapshot_path_clone)?);
        let mut builder = TarBuilder::new(&mut file);
        builder.sparse(true);
        for (archive_path, snapshot_name) in collection_archive_paths {
            builder.append_path_with_name(&archive_path, &snapshot_name)?;
        }
        builder.append_path_with_name(&config_path_clone, "config.json")?;
        builder.finish()?;

        // Explicitly flush write buffer so we can catch IO errors
        drop(builder);
        file.flush()?;

        Ok::<(), StorageError>(())
    });
    AbortOnDropHandle::new(archiving).await??;

    Ok(PreparedFullSnapshot {
        snapshot_name,
        archive: temp_full_snapshot_path,
    })
}

pub async fn publish_full_snapshot(
    toc: &TableOfContent,
    prepared: PreparedFullSnapshot,
) -> Result<SnapshotDescription, StorageError> {
    let PreparedFullSnapshot {
        snapshot_name,
        archive,
    } = prepared;

    let full_snapshot_path = toc.snapshots_path().join(snapshot_name);
    let snapshot_manager = toc.get_snapshots_storage_manager()?;
    Ok(snapshot_manager
        .store_file(&archive, &full_snapshot_path)
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_snapshot_plan_rejects_alias_target_outside_exact_collection_set() {
        let error = FullSnapshotPlan::new(
            Vec::new(),
            HashMap::from([("alias".to_string(), "unplanned".to_string())]),
        )
        .err()
        .expect("alias outside the exact collection set must fail closed");

        assert!(error.to_string().contains("alias target"));
    }

    #[test]
    fn full_snapshot_plan_accepts_empty_exact_collection_set() {
        let plan = FullSnapshotPlan::new(Vec::new(), HashMap::new()).unwrap();

        assert!(plan.collections.is_empty());
        assert!(plan.alias_mapping.is_empty());
    }
}
