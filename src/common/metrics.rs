use std::collections::HashMap;

use api::rest::models::HardwareUsage;
use collection::shards::replica_set::replica_set_state::ReplicaState;
use itertools::Itertools;
use prometheus::TextEncoder;
use prometheus::proto::{Counter, Gauge, LabelPair, Metric, MetricFamily, MetricType};
use segment::common::operation_time_statistics::OperationDurationStatistics;
use shard::PeerId;
use storage::types::ConsensusThreadStatus;

use super::telemetry_ops::hardware::HardwareTelemetry;
use crate::common::telemetry::{PrivateOramExternalRecoveryTelemetry, TelemetryData};
use crate::common::telemetry_ops::app_telemetry::{AppBuildTelemetry, AppFeaturesTelemetry};
use crate::common::telemetry_ops::cluster_telemetry::{ClusterStatusTelemetry, ClusterTelemetry};
use crate::common::telemetry_ops::collections_telemetry::{
    CollectionTelemetryEnum, CollectionsTelemetry,
};
use crate::common::telemetry_ops::memory_telemetry::MemoryTelemetry;
use crate::common::telemetry_ops::requests_telemetry::{
    GrpcTelemetry, RequestsTelemetry, WebApiTelemetry,
};

/// Whitelist for REST endpoints in metrics output.
///
/// Contains selection of search, recommend, scroll, upsert, and private ORAM endpoints.
///
/// This array *must* be sorted.
const REST_ENDPOINT_WHITELIST: &[&str] = &[
    "/collections/{collection_name}/index",
    "/collections/{collection_name}/points",
    "/collections/{collection_name}/points/batch",
    "/collections/{collection_name}/points/count",
    "/collections/{collection_name}/points/delete",
    "/collections/{collection_name}/points/discover",
    "/collections/{collection_name}/points/discover/batch",
    "/collections/{collection_name}/points/facet",
    "/collections/{collection_name}/points/payload",
    "/collections/{collection_name}/points/payload/clear",
    "/collections/{collection_name}/points/payload/delete",
    "/collections/{collection_name}/points/query",
    "/collections/{collection_name}/points/query/batch",
    "/collections/{collection_name}/points/query/groups",
    "/collections/{collection_name}/points/recommend",
    "/collections/{collection_name}/points/recommend/batch",
    "/collections/{collection_name}/points/recommend/groups",
    "/collections/{collection_name}/points/scroll",
    "/collections/{collection_name}/points/search",
    "/collections/{collection_name}/points/search/batch",
    "/collections/{collection_name}/points/search/groups",
    "/collections/{collection_name}/points/search/matrix/offsets",
    "/collections/{collection_name}/points/search/matrix/pairs",
    "/collections/{collection_name}/points/vectors",
    "/collections/{collection_name}/points/vectors/delete",
    "/collections/{collection_name}/private-hnsw/{vector_name}/buckets",
    "/collections/{collection_name}/private-hnsw/{vector_name}/manifest",
    "/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit",
    "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
    "/collections/{collection_name}/private-hnsw/{vector_name}/session",
    "/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close",
    "/collections/{collection_name}/private-oram/recovery/abort",
    "/collections/{collection_name}/private-oram/recovery/begin",
    "/collections/{collection_name}/private-oram/recovery/commit",
    "/collections/{collection_name}/private-oram/recovery/export-context",
    "/collections/{collection_name}/private-oram/recovery/status",
    "/collections/{collection_name}/private-oram/recovery/upload",
    "/collections/{collection_name}/private-oram/recovery/verify",
    "/collections/{collection_name}/private-result-oram/buckets",
    "/collections/{collection_name}/private-result-oram/manifest",
    "/collections/{collection_name}/private-result-oram/oram/commit",
    "/collections/{collection_name}/private-result-oram/oram/read_buckets",
    "/collections/{collection_name}/private-result-oram/session",
    "/collections/{collection_name}/private-result-oram/session/{session_id}/close",
];

/// Whitelist for GRPC endpoints in metrics output.
///
/// Contains selection of search, recommend, scroll, upsert, and private ORAM endpoints.
///
/// This array *must* be sorted.
const GRPC_ENDPOINT_WHITELIST: &[&str] = &[
    "/qdrant.Points/ClearPayload",
    "/qdrant.Points/Count",
    "/qdrant.Points/Delete",
    "/qdrant.Points/DeletePayload",
    "/qdrant.Points/Discover",
    "/qdrant.Points/DiscoverBatch",
    "/qdrant.Points/Facet",
    "/qdrant.Points/Get",
    "/qdrant.Points/OverwritePayload",
    "/qdrant.Points/Query",
    "/qdrant.Points/QueryBatch",
    "/qdrant.Points/QueryGroups",
    "/qdrant.Points/Recommend",
    "/qdrant.Points/RecommendBatch",
    "/qdrant.Points/RecommendGroups",
    "/qdrant.Points/Scroll",
    "/qdrant.Points/Search",
    "/qdrant.Points/SearchBatch",
    "/qdrant.Points/SearchGroups",
    "/qdrant.Points/SetPayload",
    "/qdrant.Points/UpdateBatch",
    "/qdrant.Points/UpdateVectors",
    "/qdrant.Points/Upsert",
    "/qdrant.PrivateHnswOram/ClosePrivateHnswSession",
    "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths",
    "/qdrant.PrivateHnswOram/GetPrivateHnswManifest",
    "/qdrant.PrivateHnswOram/OpenPrivateHnswSession",
    "/qdrant.PrivateHnswOram/ReadPrivateHnswPaths",
    "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets",
    "/qdrant.PrivateHnswOram/UploadPrivateHnswManifest",
    "/qdrant.PrivateResultOram/ClosePrivateResultOramSession",
    "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets",
    "/qdrant.PrivateResultOram/GetPrivateResultOramManifest",
    "/qdrant.PrivateResultOram/OpenPrivateResultOramSession",
    "/qdrant.PrivateResultOram/ReadPrivateResultOramBuckets",
    "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets",
    "/qdrant.PrivateResultOram/UploadPrivateResultOramManifest",
];

fn canonical_rest_endpoint_label(endpoint: &str) -> Option<&str> {
    let endpoint_path = endpoint
        .split_once('?')
        .map_or(endpoint, |(path, _query)| path);
    if REST_ENDPOINT_WHITELIST
        .binary_search(&endpoint_path)
        .is_ok()
    {
        return Some(endpoint_path);
    }

    let segments = endpoint_path
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    match segments.as_slice() {
        ["collections", _, "private-hnsw", _, "buckets"] => {
            Some("/collections/{collection_name}/private-hnsw/{vector_name}/buckets")
        }
        ["collections", _, "private-hnsw", _, "manifest"] => {
            Some("/collections/{collection_name}/private-hnsw/{vector_name}/manifest")
        }
        ["collections", _, "private-hnsw", _, "oram", "commit"] => {
            Some("/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit")
        }
        ["collections", _, "private-hnsw", _, "oram", "read_paths"] => {
            Some("/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths")
        }
        ["collections", _, "private-hnsw", _, "session", _, "close"] => Some(
            "/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close",
        ),
        ["collections", _, "private-hnsw", _, "session"] => {
            Some("/collections/{collection_name}/private-hnsw/{vector_name}/session")
        }
        ["collections", _, "private-oram", "recovery", "abort"] => {
            Some("/collections/{collection_name}/private-oram/recovery/abort")
        }
        ["collections", _, "private-oram", "recovery", "begin"] => {
            Some("/collections/{collection_name}/private-oram/recovery/begin")
        }
        [
            "collections",
            _,
            "private-oram",
            "recovery",
            "export-context",
        ] => Some("/collections/{collection_name}/private-oram/recovery/export-context"),
        ["collections", _, "private-oram", "recovery", "commit"] => {
            Some("/collections/{collection_name}/private-oram/recovery/commit")
        }
        ["collections", _, "private-oram", "recovery", "status"] => {
            Some("/collections/{collection_name}/private-oram/recovery/status")
        }
        ["collections", _, "private-oram", "recovery", "upload"] => {
            Some("/collections/{collection_name}/private-oram/recovery/upload")
        }
        ["collections", _, "private-oram", "recovery", "verify"] => {
            Some("/collections/{collection_name}/private-oram/recovery/verify")
        }
        ["collections", _, "private-result-oram", "buckets"] => {
            Some("/collections/{collection_name}/private-result-oram/buckets")
        }
        ["collections", _, "private-result-oram", "manifest"] => {
            Some("/collections/{collection_name}/private-result-oram/manifest")
        }
        ["collections", _, "private-result-oram", "oram", "commit"] => {
            Some("/collections/{collection_name}/private-result-oram/oram/commit")
        }
        [
            "collections",
            _,
            "private-result-oram",
            "oram",
            "read_buckets",
        ] => Some("/collections/{collection_name}/private-result-oram/oram/read_buckets"),
        [
            "collections",
            _,
            "private-result-oram",
            "session",
            _,
            "close",
        ] => Some("/collections/{collection_name}/private-result-oram/session/{session_id}/close"),
        ["collections", _, "private-result-oram", "session"] => {
            Some("/collections/{collection_name}/private-result-oram/session")
        }
        _ => None,
    }
}

fn canonical_grpc_endpoint_label(endpoint: &str) -> Option<&str> {
    if GRPC_ENDPOINT_WHITELIST.binary_search(&endpoint).is_ok() {
        return Some(endpoint);
    }

    if !endpoint.starts_with("/qdrant.PrivateHnswOram/")
        && !endpoint.starts_with("/qdrant.PrivateResultOram/")
    {
        return None;
    }

    None
}

/// For REST requests, only report timings when having this HTTP response status.
const REST_TIMINGS_FOR_STATUS: u16 = 200;

/// Encapsulates metrics data in Prometheus format.
pub struct MetricsData {
    metrics: Vec<MetricFamily>,
}

impl MetricsData {
    pub fn format_metrics(&self) -> String {
        TextEncoder::new()
            .encode_to_string(&self.metrics)
            .unwrap_or_else(|err| {
                log::error!("failed to encode Prometheus metrics: {err}");
                String::new()
            })
    }

    /// Creates a new `MetricsData` from telemetry data and an optional prefix for metrics names.
    pub fn new_from_telemetry(telemetry_data: TelemetryData, prefix: Option<&str>) -> Self {
        let mut metrics = MetricsData::empty();
        telemetry_data.add_metrics(&mut metrics, prefix);
        metrics
    }

    /// Adds the given `metrics_family` to the `MetricsData` collection, if `Some`.
    fn push_metric(&mut self, metric_family: Option<MetricFamily>) {
        if let Some(metric_family) = metric_family {
            self.metrics.push(metric_family);
        }
    }

    /// Creates an empty collection of Prometheus metric families `MetricsData`.
    /// This should only be used when you explicitly need an empty collection to gather metrics.
    ///
    /// In most cases, you should use [`MetricsData::new_from_telemetry`] to initialize new metrics data.
    fn empty() -> Self {
        Self { metrics: vec![] }
    }
}

trait MetricsProvider {
    /// Add metrics definitions for this.
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>);
}

impl MetricsProvider for TelemetryData {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        if let Some(app) = &self.app {
            app.add_metrics(metrics, prefix);
        }

        let this_peer_id = self.cluster.as_ref().and_then(|i| i.this_peer_id());
        self.collections.add_metrics(metrics, prefix, this_peer_id);

        if let Some(cluster) = &self.cluster {
            cluster.add_metrics(metrics, prefix);
        }
        if let Some(requests) = &self.requests {
            requests.add_metrics(metrics, prefix);
        }
        if let Some(hardware) = &self.hardware {
            hardware.add_metrics(metrics, prefix);
        }
        if let Some(mem) = &self.memory {
            mem.add_metrics(metrics, prefix);
        }
        if let Some(private_oram_external_recovery) = &self.private_oram_external_recovery {
            private_oram_external_recovery.add_metrics(metrics, prefix);
        }

        #[cfg(target_os = "linux")]
        match procfs_metrics::ProcFsMetrics::collect() {
            Ok(procfs_provider) => procfs_provider.add_metrics(metrics, prefix),
            Err(err) => log::warn!("Error reading procfs infos: {err:?}"),
        };
    }
}

impl MetricsProvider for PrivateOramExternalRecoveryTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        for (name, help, value) in [
            (
                "private_oram_external_recovery_reserved_bytes",
                "bytes reserved for staged private ORAM external recovery operations",
                self.reserved_bytes,
            ),
            (
                "private_oram_external_recovery_staging_reservations",
                "number of private ORAM external recovery staging reservations",
                self.staging_reservations,
            ),
            (
                "private_oram_external_recovery_worker_limit",
                "configured private ORAM external recovery heavy worker limit",
                self.worker_limit,
            ),
            (
                "private_oram_external_recovery_workers_in_use",
                "private ORAM external recovery heavy workers currently in use",
                self.workers_in_use,
            ),
        ] {
            metrics.push_metric(metric_family(
                name,
                help,
                MetricType::GAUGE,
                vec![gauge(value as f64, &[])],
                prefix,
            ));
        }
        for (name, help, value) in [
            (
                "private_oram_external_recovery_preflight_scanned_logical_bytes_total",
                "logical archive bytes accepted by private ORAM external recovery preflight",
                self.preflight_scanned_logical_bytes,
            ),
            (
                "private_oram_external_recovery_preflight_scanned_entries_total",
                "archive entries accepted by private ORAM external recovery preflight",
                self.preflight_scanned_entries,
            ),
        ] {
            metrics.push_metric(metric_family(
                name,
                help,
                MetricType::COUNTER,
                vec![counter(value as f64, &[])],
                prefix,
            ));
        }
    }
}

impl MetricsProvider for AppBuildTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        metrics.push_metric(metric_family(
            "app_info",
            "information about qdrant server",
            MetricType::GAUGE,
            vec![gauge(
                1.0,
                &[("name", &self.name), ("version", &self.version)],
            )],
            prefix,
        ));
        self.features
            .iter()
            .for_each(|f| f.add_metrics(metrics, prefix));
    }
}

impl MetricsProvider for AppFeaturesTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        metrics.push_metric(metric_family(
            "app_status_recovery_mode",
            "features enabled in qdrant server",
            MetricType::GAUGE,
            vec![gauge(if self.recovery_mode { 1.0 } else { 0.0 }, &[])],
            prefix,
        ))
    }
}

impl CollectionsTelemetry {
    fn add_metrics(
        &self,
        metrics: &mut MetricsData,
        prefix: Option<&str>,
        peer_id: Option<PeerId>,
    ) {
        metrics.push_metric(metric_family(
            "collections_total",
            "number of collections",
            MetricType::GAUGE,
            vec![gauge(self.number_of_collections as f64, &[])],
            prefix,
        ));

        let num_collections = self.collections.as_ref().map_or(0, |c| c.len());

        // Optimizers
        let mut total_optimizations_running = Vec::with_capacity(num_collections);

        // Min/Max/Expected/Active replicas over all shards.
        let mut total_min_active_replicas = usize::MAX;
        let mut total_max_active_replicas = 0;

        // Points per collection
        let mut points_per_collection = Vec::with_capacity(num_collections);

        // Vectors excluded from index-only requests.
        let mut indexed_only_excluded = Vec::with_capacity(num_collections);

        let mut total_dead_replicas = 0;

        // Snapshot metrics
        let mut snapshots_creation_running = Vec::with_capacity(num_collections);
        let mut snapshots_recovery_running = Vec::with_capacity(num_collections);
        let mut snapshots_created_total = Vec::with_capacity(num_collections);

        let mut vector_count_by_name = Vec::with_capacity(num_collections);

        // Shard transfers
        let mut shard_transfers_in = Vec::with_capacity(num_collections);
        let mut shard_transfers_out = Vec::with_capacity(num_collections);

        // Update queue
        let mut update_queue_length = Vec::with_capacity(num_collections);
        let mut deferred_points_count = Vec::with_capacity(num_collections);

        for collection in self.collections.iter().flatten() {
            let collection = match collection {
                CollectionTelemetryEnum::Full(collection_telemetry) => collection_telemetry,
                CollectionTelemetryEnum::Aggregated(_) => {
                    continue;
                }
            };

            total_optimizations_running.push(gauge(
                collection.count_optimizers_running() as f64,
                &[("id", &collection.id)],
            ));

            let min_max_active_replicas = collection
                .shards
                .iter()
                .flatten()
                // While resharding up, some (shard) replica sets may still be incomplete during
                // the resharding process. In that case we don't want to consider these replica
                // sets at all in the active replica calculation. This is fine because searches nor
                // updates don't depend on them being available yet.
                //
                // More specifically:
                // - in stage 2 (migrate points) of resharding up we don't rely on the replica
                //   to be available yet. In this stage, these replicas will have the `Resharding`
                //   state.
                // - in stage 3 (replicate) of resharding up we activate the the replica and
                //   replicate to match the configuration replication factor. From this point on we
                //   do rely on the replica to be available. Now one replica will be `Active`, and
                //   the other replicas will be in a transfer state. No replica will have `Resharding`
                //   state.
                //
                // So, during stage 2 of resharding up we don't want to adjust the minimum number
                // of active replicas downwards. During stage 3 we do want it to affect the minimum
                // available replica number. It will be 1 for some time until replication transfers
                // complete.
                //
                // To ignore a (shard) replica set that is in stage 2 of resharding up, we simply
                // check if any of it's replicas is in `Resharding` state.
                .filter(|shard| {
                    !shard
                        .replicate_states
                        .values()
                        .any(|i| matches!(i, ReplicaState::Resharding))
                })
                .map(|shard| {
                    shard
                        .replicate_states
                        .values()
                        // While resharding down, all the replicas that we keep will get the
                        // `ReshardingScaleDown` state for a period of time. We simply consider
                        // these replicas to be active. The `is_active` function already accounts
                        // this.
                        .filter(|state| state.is_active())
                        .count()
                })
                .minmax();

            let min_max_active_replicas = match min_max_active_replicas {
                itertools::MinMaxResult::NoElements => None,
                itertools::MinMaxResult::OneElement(one) => Some((one, one)),
                itertools::MinMaxResult::MinMax(min, max) => Some((min, max)),
            };

            if let Some((min, max)) = min_max_active_replicas {
                total_min_active_replicas = total_min_active_replicas.min(min);
                total_max_active_replicas = total_max_active_replicas.max(max);
            }

            points_per_collection.push(gauge(
                collection.count_points() as f64,
                &[("id", &collection.id)],
            ));

            for (vec_name, count) in collection.count_points_per_vector() {
                vector_count_by_name.push(gauge(
                    count as f64,
                    &[("collection", &collection.id), ("vector", &vec_name)],
                ))
            }

            let points_excluded_from_index_only = collection
                .shards
                .iter()
                .flatten()
                .filter_map(|shard| shard.local.as_ref())
                .filter_map(|local| local.indexed_only_excluded_vectors.as_ref())
                .flatten()
                .fold(
                    HashMap::<&str, usize>::default(),
                    |mut acc, (name, vector_size)| {
                        *acc.entry(name).or_insert(0) += vector_size;
                        acc
                    },
                );

            for (name, vector_size) in points_excluded_from_index_only {
                indexed_only_excluded.push(gauge(
                    vector_size as f64,
                    &[("id", &collection.id), ("vector", name)],
                ))
            }

            total_dead_replicas += collection
                .shards
                .iter()
                .flatten()
                .filter(|i| i.replicate_states.values().any(|state| !state.is_active()))
                .count();

            // Shard Transfers

            let mut incoming_transfers = 0;
            let mut outgoing_transfers = 0;

            if let Some(this_peer_id) = peer_id {
                for transfer in collection.transfers.iter().flatten() {
                    if transfer.to == this_peer_id {
                        incoming_transfers += 1;
                    }
                    if transfer.from == this_peer_id {
                        outgoing_transfers += 1;
                    }
                }
            }

            shard_transfers_in.push(gauge(
                f64::from(incoming_transfers),
                &[("id", &collection.id)],
            ));
            shard_transfers_out.push(gauge(
                f64::from(outgoing_transfers),
                &[("id", &collection.id)],
            ));

            // Update queue
            let (total_queue_length, total_deferred_count): (usize, usize) = collection
                .shards
                .iter()
                .flatten()
                .filter_map(|shard| shard.local.as_ref())
                .filter_map(|local| local.update_queue.as_ref())
                .map(|uq| (uq.length, uq.deferred_points))
                .fold((0, 0), |(acc_queue, acc_deferred), (queue, deferred)| {
                    (
                        acc_queue + queue,
                        acc_deferred + deferred.unwrap_or_default(),
                    )
                });

            update_queue_length.push(gauge(total_queue_length as f64, &[("id", &collection.id)]));
            deferred_points_count.push(gauge(
                total_deferred_count as f64,
                &[("id", &collection.id)],
            ));
        }

        for snapshot_telemetry in self.snapshots.iter().flatten() {
            let id = &snapshot_telemetry.id;

            snapshots_recovery_running.push(gauge(
                snapshot_telemetry
                    .running_snapshot_recovery
                    .unwrap_or_default() as f64,
                &[("id", id)],
            ));
            snapshots_creation_running.push(gauge(
                snapshot_telemetry.running_snapshots.unwrap_or_default() as f64,
                &[("id", id)],
            ));

            snapshots_created_total.push(counter(
                snapshot_telemetry
                    .total_snapshot_creations
                    .unwrap_or_default() as f64,
                &[("id", id)],
            ));
        }

        let vector_count = vector_count_by_name
            .iter()
            .map(|m| m.get_gauge().get_value())
            .sum::<f64>()
            // The sum of an empty f64 iterator returns `-0`. Since a negative
            // number of vectors is impossible, taking the absolute value is always safe.
            .abs();

        metrics.push_metric(metric_family(
            "collections_vector_total",
            "total number of vectors in all collections",
            MetricType::GAUGE,
            vec![gauge(vector_count, &[])],
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_vectors",
            "amount of vectors grouped by vector name",
            MetricType::GAUGE,
            vector_count_by_name,
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_indexed_only_excluded_points",
            "amount of points excluded in indexed_only requests",
            MetricType::GAUGE,
            indexed_only_excluded,
            prefix,
        ));

        let total_min_active_replicas = if total_min_active_replicas == usize::MAX {
            0
        } else {
            total_min_active_replicas
        };

        metrics.push_metric(metric_family(
            "collection_active_replicas_min",
            "minimum number of active replicas across all shards",
            MetricType::GAUGE,
            vec![gauge(total_min_active_replicas as f64, &[])],
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_active_replicas_max",
            "maximum number of active replicas across all shards",
            MetricType::GAUGE,
            vec![gauge(total_max_active_replicas as f64, &[])],
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_running_optimizations",
            "number of currently running optimization tasks per collection",
            MetricType::GAUGE,
            total_optimizations_running,
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_points",
            "approximate amount of points per collection",
            MetricType::GAUGE,
            points_per_collection,
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_dead_replicas",
            "total amount of shard replicas in non-active state",
            MetricType::GAUGE,
            vec![gauge(total_dead_replicas as f64, &[])],
            prefix,
        ));

        metrics.push_metric(metric_family(
            "snapshot_creation_running",
            "amount of snapshot creations that are currently running",
            MetricType::GAUGE,
            snapshots_creation_running,
            prefix,
        ));

        metrics.push_metric(metric_family(
            "snapshot_recovery_running",
            "amount of snapshot recovery operations currently running",
            MetricType::GAUGE,
            snapshots_recovery_running,
            prefix,
        ));

        metrics.push_metric(metric_family(
            "snapshot_created_total",
            "total amount of snapshots created",
            MetricType::COUNTER,
            snapshots_created_total,
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_shard_transfer_incoming",
            "incoming shard transfers currently running",
            MetricType::GAUGE,
            shard_transfers_in,
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_shard_transfer_outgoing",
            "outgoing shard transfers currently running",
            MetricType::GAUGE,
            shard_transfers_out,
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_update_queue_length",
            "number of pending operations in update queues per collection",
            MetricType::GAUGE,
            update_queue_length,
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_update_queue_deferred_points",
            "number of points currently hidden during read operations as they're not yet optimized",
            MetricType::GAUGE,
            deferred_points_count,
            prefix,
        ));
    }
}

impl MetricsProvider for ClusterTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        let ClusterTelemetry {
            enabled,
            status,
            config: _,
            peers: _,
            peer_metadata: _,
            metadata: _,
            resharding_enabled: _,
        } = self;

        metrics.push_metric(metric_family(
            "cluster_enabled",
            "is cluster support enabled",
            MetricType::GAUGE,
            vec![gauge(if *enabled { 1.0 } else { 0.0 }, &[])],
            prefix,
        ));

        if let Some(status) = status {
            status.add_metrics(metrics, prefix);
        }
    }
}

impl MetricsProvider for ClusterStatusTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        metrics.push_metric(metric_family(
            "cluster_peers_total",
            "total number of cluster peers",
            MetricType::GAUGE,
            vec![gauge(self.number_of_peers as f64, &[])],
            prefix,
        ));
        metrics.push_metric(metric_family(
            "cluster_term",
            "current cluster term",
            MetricType::COUNTER,
            vec![counter(self.term as f64, &[])],
            prefix,
        ));

        if let Some(ref peer_id) = self.peer_id.map(|p| p.to_string()) {
            metrics.push_metric(metric_family(
                "cluster_commit",
                "index of last committed (finalized) operation cluster peer is aware of",
                MetricType::COUNTER,
                vec![counter(self.commit as f64, &[("peer_id", peer_id)])],
                prefix,
            ));
            metrics.push_metric(metric_family(
                "cluster_pending_operations_total",
                "total number of pending operations for cluster peer",
                MetricType::GAUGE,
                vec![gauge(self.pending_operations as f64, &[])],
                prefix,
            ));
            metrics.push_metric(metric_family(
                "cluster_voter",
                "is cluster peer a voter or learner",
                MetricType::GAUGE,
                vec![gauge(if self.is_voter { 1.0 } else { 0.0 }, &[])],
                prefix,
            ));
        }

        // Initialize all states so that every state has a zeroed metric by default.
        let mut state_working = 0.0;
        let mut state_stopped = 0.0;

        match &self.consensus_thread_status {
            ConsensusThreadStatus::Working { last_update } => {
                let timestamp = last_update.timestamp();

                metrics.push_metric(metric_family(
                    "cluster_last_update_timestamp_seconds",
                    "unix timestamp of last update",
                    MetricType::COUNTER,
                    vec![counter(timestamp as f64, &[])],
                    prefix,
                ));

                state_working = 1.0;
            }
            ConsensusThreadStatus::Stopped | ConsensusThreadStatus::StoppedWithErr { err: _ } => {
                state_stopped = 1.0;
            }
        }

        let working_states = vec![
            gauge(state_working, &[("state", "working")]),
            gauge(state_stopped, &[("state", "stopped")]),
        ];

        metrics.push_metric(metric_family(
            "cluster_working_state",
            "working state of the cluster",
            MetricType::GAUGE,
            working_states,
            prefix,
        ));
    }
}

impl MetricsProvider for RequestsTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        self.rest.add_metrics(metrics, prefix);
        self.grpc.add_metrics(metrics, prefix);
    }
}

impl MetricsProvider for WebApiTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        // Mode decision: when `per_collection_responses` is populated (i.e. per_collection
        // was requested via query parameter), we render per-collection metrics with a
        // `collection` label and skip global ones.
        if self.per_collection_responses.is_empty() {
            // Global mode: render global metrics as before
            let mut builder = OperationDurationMetricsBuilder::default();
            for (endpoint, responses) in &self.responses {
                let Some((method, raw_endpoint)) = endpoint.split_once(' ') else {
                    continue;
                };
                let Some(endpoint) = canonical_rest_endpoint_label(raw_endpoint) else {
                    continue;
                };
                for (status, stats) in responses {
                    builder.add(
                        stats,
                        &[
                            ("method", method),
                            ("endpoint", endpoint),
                            ("status", &status.to_string()),
                        ],
                        *status == REST_TIMINGS_FOR_STATUS,
                    );
                }
            }
            builder.build(prefix, "rest", metrics);
        } else {
            // Per-collection mode: render per-collection metrics with `collection` label
            let mut builder = OperationDurationMetricsBuilder::default();
            for (collection, methods) in &self.per_collection_responses {
                for (endpoint, responses) in methods {
                    let Some((method, raw_endpoint)) = endpoint.split_once(' ') else {
                        continue;
                    };
                    let Some(endpoint) = canonical_rest_endpoint_label(raw_endpoint) else {
                        continue;
                    };
                    for (status, stats) in responses {
                        builder.add(
                            stats,
                            &[
                                ("method", method),
                                ("endpoint", endpoint),
                                ("status", &status.to_string()),
                                ("collection", collection),
                            ],
                            *status == REST_TIMINGS_FOR_STATUS,
                        );
                    }
                }
            }
            builder.build(prefix, "rest", metrics);
        }
    }
}

impl MetricsProvider for GrpcTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        // Same mode-switching logic as WebApiTelemetry::add_metrics — see comment there.
        if self.per_collection_responses.is_empty() {
            // Global mode: render global metrics as before
            let mut builder = OperationDurationMetricsBuilder::default();
            for (endpoint, responses) in &self.responses {
                let Some(endpoint) = canonical_grpc_endpoint_label(endpoint) else {
                    continue;
                };
                for (status, stats) in responses {
                    builder.add(
                        stats,
                        &[("endpoint", endpoint), ("status", &status.to_string())],
                        true,
                    );
                }
            }
            builder.build(prefix, "grpc", metrics);
        } else {
            // Per-collection mode: render per-collection metrics with `collection` label
            let mut builder = OperationDurationMetricsBuilder::default();
            for (collection, methods) in &self.per_collection_responses {
                for (endpoint, responses) in methods {
                    let Some(endpoint) = canonical_grpc_endpoint_label(endpoint) else {
                        continue;
                    };
                    for (status, stats) in responses {
                        builder.add(
                            stats,
                            &[
                                ("endpoint", endpoint),
                                ("status", &status.to_string()),
                                ("collection", collection),
                            ],
                            true,
                        );
                    }
                }
            }
            builder.build(prefix, "grpc", metrics);
        }
    }
}

impl MetricsProvider for MemoryTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        metrics.push_metric(metric_family(
            "memory_active_bytes",
            "Total number of bytes in active pages allocated by the application",
            MetricType::GAUGE,
            vec![gauge(self.active_bytes as f64, &[])],
            prefix,
        ));
        metrics.push_metric(metric_family(
            "memory_allocated_bytes",
            "Total number of bytes allocated by the application",
            MetricType::GAUGE,
            vec![gauge(self.allocated_bytes as f64, &[])],
            prefix,
        ));
        metrics.push_metric(metric_family(
            "memory_metadata_bytes",
            "Total number of bytes dedicated to metadata",
            MetricType::GAUGE,
            vec![gauge(self.metadata_bytes as f64, &[])],
            prefix,
        ));
        metrics.push_metric(metric_family(
            "memory_resident_bytes",
            "Maximum number of bytes in physically resident data pages mapped",
            MetricType::GAUGE,
            vec![gauge(self.resident_bytes as f64, &[])],
            prefix,
        ));
        metrics.push_metric(metric_family(
            "memory_retained_bytes",
            "Total number of bytes in virtual memory mappings",
            MetricType::GAUGE,
            vec![gauge(self.retained_bytes as f64, &[])],
            prefix,
        ));
    }
}

impl HardwareTelemetry {
    // Helper function to create counter metrics of a single Hw type, like cpu.
    fn make_metric_counters<F: Fn(&HardwareUsage) -> usize>(&self, f: F) -> Vec<Metric> {
        self.collection_data
            .iter()
            .map(|(collection_id, hw_usage)| counter(f(hw_usage) as f64, &[("id", collection_id)]))
            .collect()
    }
}

impl MetricsProvider for HardwareTelemetry {
    fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
        // MetricType::COUNTER requires non-empty collection data.
        if self.collection_data.is_empty() {
            return;
        }

        // Keep a dummy type decomposition of HwUsage here to enforce coverage of new fields in metrics.
        // This gets optimized away by the compiler: https://godbolt.org/z/9cMTzcYr4
        let HardwareUsage {
            cpu: _,
            payload_io_read: _,
            payload_io_write: _,
            payload_index_io_read: _,
            payload_index_io_write: _,
            vector_io_read: _,
            vector_io_write: _,
        } = HardwareUsage::default();

        metrics.push_metric(metric_family(
            "collection_hardware_metric_cpu",
            "CPU measurements of a collection",
            MetricType::COUNTER,
            self.make_metric_counters(|hw| hw.cpu),
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_hardware_metric_payload_io_read",
            "Total IO payload read metrics of a collection",
            MetricType::COUNTER,
            self.make_metric_counters(|hw| hw.payload_io_read),
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_hardware_metric_payload_index_io_read",
            "Total IO payload index read metrics of a collection",
            MetricType::COUNTER,
            self.make_metric_counters(|hw| hw.payload_index_io_read),
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_hardware_metric_payload_index_io_write",
            "Total IO payload index write metrics of a collection",
            MetricType::COUNTER,
            self.make_metric_counters(|hw| hw.payload_index_io_write),
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_hardware_metric_payload_io_write",
            "Total IO payload write metrics of a collection",
            MetricType::COUNTER,
            self.make_metric_counters(|hw| hw.payload_io_write),
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_hardware_metric_vector_io_read",
            "Total IO vector read metrics of a collection",
            MetricType::COUNTER,
            self.make_metric_counters(|hw| hw.vector_io_read),
            prefix,
        ));

        metrics.push_metric(metric_family(
            "collection_hardware_metric_vector_io_write",
            "Total IO vector write metrics of a collection",
            MetricType::COUNTER,
            self.make_metric_counters(|hw| hw.vector_io_write),
            prefix,
        ));
    }
}

/// A helper struct to build a vector of [`MetricFamily`] out of a collection of
/// [`OperationDurationStatistics`].
#[derive(Default)]
struct OperationDurationMetricsBuilder {
    total: Vec<Metric>,
    avg_secs: Vec<Metric>,
    min_secs: Vec<Metric>,
    max_secs: Vec<Metric>,
    duration_histogram_secs: Vec<Metric>,
}

impl OperationDurationMetricsBuilder {
    /// Add metrics for the provided statistics.
    /// If `add_timings` is `false`, only the total and fail_total counters will be added.
    pub fn add(
        &mut self,
        stat: &OperationDurationStatistics,
        labels: &[(&str, &str)],
        add_timings: bool,
    ) {
        self.total.push(counter(stat.count as f64, labels));

        if !add_timings {
            return;
        }

        self.avg_secs.push(gauge(
            f64::from(stat.avg_duration_micros.unwrap_or(0.0)) / 1_000_000.0,
            labels,
        ));
        self.min_secs.push(gauge(
            f64::from(stat.min_duration_micros.unwrap_or(0.0)) / 1_000_000.0,
            labels,
        ));
        self.max_secs.push(gauge(
            f64::from(stat.max_duration_micros.unwrap_or(0.0)) / 1_000_000.0,
            labels,
        ));
        self.duration_histogram_secs.push(histogram(
            stat.count as u64,
            stat.total_duration_micros.unwrap_or(0) as f64 / 1_000_000.0,
            &stat
                .duration_micros_histogram
                .iter()
                .map(|&(b, c)| (f64::from(b) / 1_000_000.0, c as u64))
                .collect::<Vec<_>>(),
            labels,
        ));
    }

    /// Build metrics and add them to the provided vector.
    pub fn build(self, global_prefix: Option<&str>, prefix: &str, metrics: &mut MetricsData) {
        let OperationDurationMetricsBuilder {
            total,
            avg_secs,
            min_secs,
            max_secs,
            duration_histogram_secs,
        } = self;

        let prefix = format!("{}{prefix}_", global_prefix.unwrap_or(""));

        metrics.push_metric(metric_family(
            "responses_total",
            "total number of responses",
            MetricType::COUNTER,
            total,
            Some(&prefix),
        ));
        metrics.push_metric(metric_family(
            "responses_avg_duration_seconds",
            "average response duration",
            MetricType::GAUGE,
            avg_secs,
            Some(&prefix),
        ));
        metrics.push_metric(metric_family(
            "responses_min_duration_seconds",
            "minimum response duration",
            MetricType::GAUGE,
            min_secs,
            Some(&prefix),
        ));
        metrics.push_metric(metric_family(
            "responses_max_duration_seconds",
            "maximum response duration",
            MetricType::GAUGE,
            max_secs,
            Some(&prefix),
        ));
        metrics.push_metric(metric_family(
            "responses_duration_seconds",
            "response duration histogram",
            MetricType::HISTOGRAM,
            duration_histogram_secs,
            Some(&prefix),
        ));
    }
}

fn metric_family(
    name: &str,
    help: &str,
    r#type: MetricType,
    metrics: Vec<Metric>,
    prefix: Option<&str>,
) -> Option<MetricFamily> {
    // We can't create a new `MetricsFamily` without metrics.
    if metrics.is_empty() {
        return None;
    }

    let mut metric_family = MetricFamily::default();

    let name_with_prefix = prefix
        .map(|prefix| format!("{prefix}{name}"))
        .unwrap_or_else(|| name.to_string());

    metric_family.set_name(name_with_prefix);
    metric_family.set_help(help.into());
    metric_family.set_field_type(r#type);
    metric_family.set_metric(metrics);

    Some(metric_family)
}

fn counter(value: f64, labels: &[(&str, &str)]) -> Metric {
    let mut metric = Metric::default();
    metric.set_label(labels.iter().map(|(n, v)| label_pair(n, v)).collect());
    metric.set_counter({
        let mut counter = Counter::default();
        counter.set_value(value);
        counter
    });
    metric
}

fn gauge(value: f64, labels: &[(&str, &str)]) -> Metric {
    let mut metric = Metric::default();
    metric.set_label(labels.iter().map(|(n, v)| label_pair(n, v)).collect());
    metric.set_gauge({
        let mut gauge = Gauge::default();
        gauge.set_value(value);
        gauge
    });
    metric
}

fn histogram(
    sample_count: u64,
    sample_sum: f64,
    buckets: &[(f64, u64)],
    labels: &[(&str, &str)],
) -> Metric {
    let mut metric = Metric::default();
    metric.set_label(labels.iter().map(|(n, v)| label_pair(n, v)).collect());
    metric.set_histogram({
        let mut histogram = prometheus::proto::Histogram::default();
        histogram.set_sample_count(sample_count);
        histogram.set_sample_sum(sample_sum);
        histogram.set_bucket(
            buckets
                .iter()
                .map(|&(upper_bound, cumulative_count)| {
                    let mut bucket = prometheus::proto::Bucket::default();
                    bucket.set_cumulative_count(cumulative_count);
                    bucket.set_upper_bound(upper_bound);
                    bucket
                })
                .collect(),
        );
        histogram
    });
    metric
}

fn label_pair(name: &str, value: &str) -> LabelPair {
    let mut label = LabelPair::default();
    label.set_name(name.into());
    label.set_value(value.into());
    label
}

#[cfg(target_os = "linux")]
mod procfs_metrics {
    use std::cmp::min;

    use ahash::AHashSet;
    use itertools::Itertools;
    use procfs::ProcError;
    use procfs::process::{LimitValue, Process};
    use prometheus::proto::MetricType;

    use super::{MetricsData, MetricsProvider, counter, gauge, metric_family};

    type Pid = i32;

    /// Structure for holding /procfs metrics, that can be easily populated in metrics API.
    pub(super) struct ProcFsMetrics {
        thread_count: usize,
        mmap_count: usize,
        system_mmap_limit: u64,
        open_fds: usize,
        max_fds_soft: LimitValue,
        max_fds_hard: LimitValue,
        minor_page_faults: u64,
        major_page_faults: u64,
        minor_children_page_faults: u64,
        major_children_page_faults: u64,
        minor_alive_child_page_faults: u64,
        major_alive_child_page_faults: u64,
    }

    impl ProcFsMetrics {
        /// Collect metrics from /procfs.
        pub(super) fn collect() -> Result<Self, procfs::ProcError> {
            let current_process = Process::myself()?;

            let thread_count = current_process.tasks()?.flatten().count();
            let stat = current_process.stat()?;
            let limits = current_process.limits()?;

            let (minor_alive_child_page_faults, major_alive_child_page_faults) =
                faults_for_all_children(current_process.pid)?;

            Ok(Self {
                thread_count,
                mmap_count: current_process.maps()?.len(),
                system_mmap_limit: procfs::sys::vm::max_map_count()?,
                open_fds: current_process.fd_count()?,
                max_fds_soft: limits.max_open_files.soft_limit,
                max_fds_hard: limits.max_open_files.hard_limit,
                minor_page_faults: stat.minflt,
                major_page_faults: stat.majflt,
                minor_children_page_faults: stat.cminflt,
                major_children_page_faults: stat.cmajflt,
                minor_alive_child_page_faults,
                major_alive_child_page_faults,
            })
        }
    }

    impl MetricsProvider for ProcFsMetrics {
        fn add_metrics(&self, metrics: &mut MetricsData, prefix: Option<&str>) {
            metrics.push_metric(metric_family(
                "process_threads",
                "count of active threads",
                MetricType::GAUGE,
                vec![gauge(self.thread_count as f64, &[])],
                prefix,
            ));

            metrics.push_metric(metric_family(
                "process_open_mmaps",
                "count of open mmaps",
                MetricType::GAUGE,
                vec![gauge(self.mmap_count as f64, &[])],
                prefix,
            ));

            metrics.push_metric(metric_family(
                "system_max_mmaps",
                "system wide limit of open mmaps",
                MetricType::GAUGE,
                vec![gauge(self.system_mmap_limit as f64, &[])],
                prefix,
            ));

            metrics.push_metric(metric_family(
                "process_open_fds",
                "count of currently open file descriptors",
                MetricType::GAUGE,
                vec![gauge(self.open_fds as f64, &[])],
                prefix,
            ));

            let fds_limit = match (self.max_fds_soft, self.max_fds_hard) {
                (LimitValue::Unlimited, LimitValue::Value(hard)) => hard, // soft unlimited, use hard
                (LimitValue::Value(soft), LimitValue::Unlimited) => soft, // hard unlimited, use soft
                (LimitValue::Value(soft), LimitValue::Value(hard)) => min(soft, hard), // both limited, use minimum
                (LimitValue::Unlimited, LimitValue::Unlimited) => 0, // both unlimited
            };
            metrics.push_metric(metric_family(
                "process_max_fds",
                "limit for open file descriptors",
                MetricType::GAUGE,
                vec![gauge(fds_limit as f64, &[])],
                prefix,
            ));

            let minor_page_faults = self.minor_page_faults
                + self.minor_children_page_faults
                + self.minor_alive_child_page_faults;

            let major_page_faults = self.major_page_faults
                + self.major_children_page_faults
                + self.major_alive_child_page_faults;

            metrics.push_metric(metric_family(
                "process_minor_page_faults_total",
                "count of minor page faults which didn't cause a disk access",
                MetricType::COUNTER,
                vec![counter(minor_page_faults as f64, &[])],
                prefix,
            ));

            metrics.push_metric(metric_family(
                "process_major_page_faults_total",
                "count of disk accesses caused by a mmap page fault",
                MetricType::COUNTER,
                vec![counter(major_page_faults as f64, &[])],
                prefix,
            ));
        }
    }

    /// Returns the minor and major page faults of all children including grandchildren, etc.
    pub fn faults_for_all_children(parent: Pid) -> Result<(u64, u64), ProcError> {
        let children = child_processes_helper(parent)?;
        let (mut min, mut maj) = (0, 0);
        for child in children {
            let stat = match Process::new(child).and_then(|i| i.stat()) {
                Ok(proc) => proc,
                // Ignore children that don't exist anymore.
                Err(ProcError::NotFound(_)) => continue,
                Err(err) => return Err(err),
            };

            min += stat.minflt + stat.cminflt;
            maj += stat.majflt + stat.cmajflt;
        }
        Ok((min, maj))
    }

    /// Returns a list of all children of a given process. This works recursively, including grandchildren, etc.
    fn child_processes_helper(pid: Pid) -> Result<AHashSet<Pid>, ProcError> {
        let mut pids = AHashSet::default();
        child_processes_recursive(pid, &mut pids)?;

        // We don't expect to include parent Pid
        debug_assert!(!pids.contains(&pid));

        Ok(pids)
    }

    /// Recursively collects all children of a process, specified by `pid`.
    fn child_processes_recursive(pid: Pid, pids: &mut AHashSet<Pid>) -> Result<(), ProcError> {
        for child_pid in child_processes(pid) {
            let child_pid = child_pid?;

            let is_new = pids.insert(child_pid);

            // If PID is new we recurse into it
            if is_new {
                child_processes_recursive(child_pid, pids)?;
            }
        }

        Ok(())
    }

    /// Returns all new child processes of a parent process, specified by `parent_pid`.
    fn child_processes(parent_pid: Pid) -> Box<dyn Iterator<Item = Result<Pid, ProcError>>> {
        let process = match Process::new(parent_pid) {
            Ok(proc) => proc,
            // Ignore children that don't exist anymore.
            Err(ProcError::NotFound(_)) => return Box::new(std::iter::empty()),
            Err(err) => return Box::new(std::iter::once(Err(err))),
        };

        let tasks = match process.tasks() {
            Ok(tasks) => tasks,
            Err(err) => return Box::new(std::iter::once(Err(err))),
        };

        let pids = tasks
            .filter_map(|task| {
                let children = task.and_then(|task| task.children());
                match children {
                    Ok(children) => Some(Ok(children)),
                    // Filter out tasks/children that might not exist anymore.
                    Err(ProcError::NotFound(_)) => None,
                    Err(err) => Some(Err(err)),
                }
            })
            .flatten_ok()
            .map_ok(|i| i as Pid);

        Box::new(pids)
    }

    #[test]
    fn test_child_processes() {
        use nix::sys::wait::waitpid;
        use nix::unistd::{ForkResult, fork};

        let my_pid = procfs::process::Process::myself().unwrap().pid;

        // We have no children now
        assert_eq!(child_processes_helper(my_pid).unwrap(), AHashSet::new(),);

        // Spawn two child processes
        let mut child_1 = std::process::Command::new("sleep")
            .arg("3s")
            .spawn()
            .unwrap();
        let mut child_2 = std::process::Command::new("sleep")
            .arg("3s")
            .spawn()
            .unwrap();
        let child_1_pid = child_1.id() as Pid;
        let child_2_pid = child_2.id() as Pid;

        // Recursively fork process to create a grandchild
        let fork_1 = match unsafe { fork().unwrap() } {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                let fork_2 = match unsafe { fork().unwrap() } {
                    ForkResult::Parent { child } => child,
                    ForkResult::Child => {
                        std::thread::sleep(std::time::Duration::from_secs(3));
                        std::process::exit(0);
                    }
                };
                waitpid(fork_2, None).unwrap();
                std::process::exit(0);
            }
        };

        // Give forks a second to spawn
        std::thread::sleep(std::time::Duration::from_secs(1));

        // We expect exactly 4 children (3 direct, 1 grandchild)
        // We don't know the PID of the grandchild here, so we expect three children and one extra
        let child_pids = child_processes_helper(my_pid).unwrap();
        assert_eq!(child_pids.len(), 4);
        assert_eq!(
            child_pids
                .difference(&AHashSet::from([child_1_pid, child_2_pid, fork_1.into()]))
                .count(),
            1,
            "expect exactly one extra child",
        );

        // Cleanup fork
        waitpid(fork_1, None).unwrap();

        // Cleanup processes
        child_1.kill().unwrap();
        child_2.kill().unwrap();
        let _ = child_1.wait();
        let _ = child_2.wait();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_endpoint_whitelists_sorted() {
        use super::{GRPC_ENDPOINT_WHITELIST, REST_ENDPOINT_WHITELIST};

        assert!(
            REST_ENDPOINT_WHITELIST.array_windows().all(|[a, b]| a <= b),
            "REST_ENDPOINT_WHITELIST must be sorted in code to allow binary search",
        );
        assert!(
            GRPC_ENDPOINT_WHITELIST.array_windows().all(|[a, b]| a <= b),
            "GRPC_ENDPOINT_WHITELIST must be sorted in code to allow binary search",
        );
    }

    #[test]
    fn test_rest_whitelist_uses_collection_name_param() {
        use super::REST_ENDPOINT_WHITELIST;

        for endpoint in REST_ENDPOINT_WHITELIST {
            assert!(
                endpoint.contains("{collection_name}"),
                "REST_ENDPOINT_WHITELIST entry `{endpoint}` must use \
                 `{{collection_name}}` as the collection path parameter",
            );
        }
    }

    #[test]
    fn test_private_oram_endpoints_whitelisted() {
        use super::{GRPC_ENDPOINT_WHITELIST, REST_ENDPOINT_WHITELIST};

        let rest_private_oram_endpoints = [
            "/collections/{collection_name}/private-hnsw/{vector_name}/buckets",
            "/collections/{collection_name}/private-hnsw/{vector_name}/manifest",
            "/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit",
            "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            "/collections/{collection_name}/private-hnsw/{vector_name}/session",
            "/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close",
            "/collections/{collection_name}/private-oram/recovery/abort",
            "/collections/{collection_name}/private-oram/recovery/begin",
            "/collections/{collection_name}/private-oram/recovery/commit",
            "/collections/{collection_name}/private-oram/recovery/export-context",
            "/collections/{collection_name}/private-oram/recovery/status",
            "/collections/{collection_name}/private-oram/recovery/upload",
            "/collections/{collection_name}/private-oram/recovery/verify",
            "/collections/{collection_name}/private-result-oram/buckets",
            "/collections/{collection_name}/private-result-oram/manifest",
            "/collections/{collection_name}/private-result-oram/oram/commit",
            "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            "/collections/{collection_name}/private-result-oram/session",
            "/collections/{collection_name}/private-result-oram/session/{session_id}/close",
        ];
        for endpoint in rest_private_oram_endpoints {
            assert!(
                REST_ENDPOINT_WHITELIST.binary_search(&endpoint).is_ok(),
                "REST private ORAM endpoint `{endpoint}` must be whitelisted for metrics",
            );
        }

        let grpc_private_oram_endpoints = [
            "/qdrant.PrivateHnswOram/ClosePrivateHnswSession",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths",
            "/qdrant.PrivateHnswOram/GetPrivateHnswManifest",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession",
            "/qdrant.PrivateHnswOram/ReadPrivateHnswPaths",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswManifest",
            "/qdrant.PrivateResultOram/ClosePrivateResultOramSession",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets",
            "/qdrant.PrivateResultOram/GetPrivateResultOramManifest",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession",
            "/qdrant.PrivateResultOram/ReadPrivateResultOramBuckets",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramManifest",
        ];
        for endpoint in grpc_private_oram_endpoints {
            assert!(
                GRPC_ENDPOINT_WHITELIST.binary_search(&endpoint).is_ok(),
                "gRPC private ORAM endpoint `{endpoint}` must be whitelisted for metrics",
            );
        }
    }

    #[test]
    fn test_private_oram_external_recovery_resource_metrics_are_unlabelled() {
        use super::{MetricsData, MetricsProvider, PrivateOramExternalRecoveryTelemetry};

        let telemetry = PrivateOramExternalRecoveryTelemetry {
            reserved_bytes: 11,
            staging_reservations: 2,
            worker_limit: 3,
            workers_in_use: 1,
            preflight_scanned_logical_bytes: 17,
            preflight_scanned_entries: 5,
        };
        let mut metrics = MetricsData::empty();
        telemetry.add_metrics(&mut metrics, Some("qdrant_"));
        let output = metrics.format_metrics();

        for expected in [
            "qdrant_private_oram_external_recovery_reserved_bytes 11",
            "qdrant_private_oram_external_recovery_staging_reservations 2",
            "qdrant_private_oram_external_recovery_worker_limit 3",
            "qdrant_private_oram_external_recovery_workers_in_use 1",
            "qdrant_private_oram_external_recovery_preflight_scanned_logical_bytes_total 17",
            "qdrant_private_oram_external_recovery_preflight_scanned_entries_total 5",
        ] {
            assert!(
                output.contains(expected),
                "missing metric `{expected}`:\n{output}"
            );
        }
        assert!(!output.contains('{'));
        assert!(!output.contains("collection=\""));
        assert!(!output.contains("operation_id=\""));
        assert!(!output.contains("root_hash=\""));
    }

    #[test]
    fn test_private_oram_recovery_metrics_normalizes_only_fixed_route_shapes() {
        use super::canonical_rest_endpoint_label;

        for action in [
            "begin",
            "export-context",
            "upload",
            "status",
            "verify",
            "commit",
            "abort",
        ] {
            let raw =
                format!("/collections/docs/private-oram/recovery/{action}?operation_id=sentinel");
            let canonical =
                format!("/collections/{{collection_name}}/private-oram/recovery/{action}");
            assert_eq!(
                canonical_rest_endpoint_label(&raw),
                Some(canonical.as_str()),
                "{raw} must normalize without collection or query values"
            );
        }

        for raw in [
            "/collections/docs/private-oram/recovery/finalize",
            "/collections/docs/private-oram/recovery/begin/operation-token-sentinel",
            "/collections/docs/private-oram/recover/begin",
            "/collections/docs/private-oramish/recovery/begin",
            "/collections/private-oram/points/search",
        ] {
            assert_eq!(
                canonical_rest_endpoint_label(raw),
                None,
                "lookalike or malformed recovery path must not become a fixed metrics label: {raw}"
            );
        }
    }

    #[test]
    fn test_private_oram_metrics_canonicalizes_only_fixed_route_shapes() {
        use super::{canonical_grpc_endpoint_label, canonical_rest_endpoint_label};

        let rest_cases = [
            (
                "/collections/docs/private-hnsw/text/buckets",
                "/collections/{collection_name}/private-hnsw/{vector_name}/buckets",
            ),
            (
                "/collections/docs/private-hnsw/text/manifest",
                "/collections/{collection_name}/private-hnsw/{vector_name}/manifest",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?paths=hnsw-query-leaf-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?proof_value=hnsw-query-proof-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?proof.value=hnsw-query-proof-dot-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?proofValue=hnsw-query-proofValue-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access_count=hnsw-query-access-count-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access.count=hnsw-query-access-count-dot-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?path.count=hnsw-query-path-count-dot-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?accessCounts=hnsw-query-accessCounts-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access_volume=hnsw-query-access-volume-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access.volume=hnsw-query-access-volume-dot-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access_volumes=hnsw-query-access-volumes-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access.volumes=hnsw-query-access-volumes-dot-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?accessVolume=hnsw-query-accessVolume-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?accessVolumes=hnsw-query-accessVolumes-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access_volume_counts=hnsw-query-access-volume-counts-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access.volume.counts=hnsw-query-access-volume-counts-dot-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?accessVolumeCounts=hnsw-query-accessVolumeCounts-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access_volume_len=hnsw-query-access-volume-len-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access.volume.len=hnsw-query-access-volume-len-dot-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access_volume_lengths=hnsw-query-access-volume-lengths-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?access.volume.lengths=hnsw-query-access-volume-lengths-dot-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?accessVolumeLengths=hnsw-query-accessVolumeLengths-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?payload_fetch_token=hnsw-query-payload-fetch-token-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?payloadFetchTokens=hnsw-query-payloadFetchTokens-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/read_paths?payload.fetch.token=hnsw-query-payload-fetch-token-dot-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            ),
            (
                "/collections/docs/private-hnsw/text/oram/commit",
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit",
            ),
            (
                "/collections/docs/private-hnsw/text/session",
                "/collections/{collection_name}/private-hnsw/{vector_name}/session",
            ),
            (
                "/collections/docs/private-hnsw/text/session/session-id-sentinel/close",
                "/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close",
            ),
            (
                "/collections/docs/private-hnsw/text/session/hnsw-session-id-sentinel/close?session_id=hnsw-query-session-sentinel",
                "/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close",
            ),
            (
                "/collections/docs/private-result-oram/session",
                "/collections/{collection_name}/private-result-oram/session",
            ),
            (
                "/collections/docs/private-result-oram/buckets",
                "/collections/{collection_name}/private-result-oram/buckets",
            ),
            (
                "/collections/docs/private-result-oram/manifest",
                "/collections/{collection_name}/private-result-oram/manifest",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?bucket_ids=result-query-bucket-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?bucket_id=result-query-bucket-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?proof_values=result-query-proof-values-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?proof.values=result-query-proof-values-dot-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?proofValue=result-query-proofValue-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access_counts=result-query-access-counts-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access.counts=result-query-access-counts-dot-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?accessCount=result-query-accessCount-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access_volume_count=result-query-access-volume-count-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access.volume.count=result-query-access-volume-count-dot-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access_volume_counts=result-query-access-volume-counts-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access.volume.counts=result-query-access-volume-counts-dot-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access_volumes=result-query-access-volumes-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access.volumes=result-query-access-volumes-dot-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?accessVolumeCounts=result-query-accessVolumeCounts-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access_volume_len=result-query-access-volume-len-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access.volume.len=result-query-access-volume-len-dot-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?accessVolumeLength=result-query-accessVolumeLength-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access_volume_lengths=result-query-access-volume-lengths-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?access.volume.lengths=result-query-access-volume-lengths-dot-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?accessVolumeLengths=result-query-accessVolumeLengths-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?accessVolumes=result-query-accessVolumes-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?payload_fetch_token=result-query-payload-fetch-token-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?payloadFetchTokens=result-query-payloadFetchTokens-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/read_buckets?payload.fetch.token=result-query-payload-fetch-token-dot-sentinel",
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            ),
            (
                "/collections/docs/private-result-oram/oram/commit",
                "/collections/{collection_name}/private-result-oram/oram/commit",
            ),
            (
                "/collections/docs/private-result-oram/session/result-session-id-sentinel/close",
                "/collections/{collection_name}/private-result-oram/session/{session_id}/close",
            ),
            (
                "/collections/docs/private-result-oram/session/result-session-id-sentinel/close?session_id=result-query-session-sentinel",
                "/collections/{collection_name}/private-result-oram/session/{session_id}/close",
            ),
        ];
        for (raw, canonical) in rest_cases {
            let label =
                canonical_rest_endpoint_label(raw).expect("private ORAM path canonicalizes");
            assert_eq!(label, canonical);
            for leaked in [
                "docs",
                "text",
                "bucket-id-sentinel",
                "root-hash-sentinel",
                "leaf-label-sentinel",
                "hnsw-query-leaf-sentinel",
                "hnsw-query-proof-sentinel",
                "hnsw-query-proofValue-sentinel",
                "hnsw-query-access-count-sentinel",
                "hnsw-query-accessCounts-sentinel",
                "hnsw-query-access-volume-sentinel",
                "hnsw-query-access-volumes-sentinel",
                "hnsw-query-accessVolume-sentinel",
                "hnsw-query-accessVolumes-sentinel",
                "hnsw-query-access-volume-counts-sentinel",
                "hnsw-query-accessVolumeCounts-sentinel",
                "hnsw-query-access-volume-len-sentinel",
                "hnsw-query-access-volume-lengths-sentinel",
                "hnsw-query-accessVolumeLengths-sentinel",
                "hnsw-query-payload-fetch-token-sentinel",
                "hnsw-query-payloadFetchTokens-sentinel",
                "hnsw-query-payload-fetch-token-dot-sentinel",
                "updated-bucket-sentinel",
                "accessCount-sentinel",
                "accessCounts-sentinel",
                "access_count-sentinel",
                "access.count-sentinel",
                "access_counts-sentinel",
                "access.counts-sentinel",
                "accessVolume-sentinel",
                "accessVolumes-sentinel",
                "accessVolumeCount-sentinel",
                "accessVolumeCounts-sentinel",
                "accessVolumeLength-sentinel",
                "accessVolumeLengths-sentinel",
                "access_volume-sentinel",
                "access.volume-sentinel",
                "access_volumes-sentinel",
                "access.volumes-sentinel",
                "access_volume_len-sentinel",
                "access.volume.len-sentinel",
                "access_volume_count-sentinel",
                "access.volume.count-sentinel",
                "access_volume_counts-sentinel",
                "access.volume.counts-sentinel",
                "access_volume_length-sentinel",
                "access.volume.length-sentinel",
                "access_volume_lengths-sentinel",
                "access.volume.lengths-sentinel",
                "client-state-sentinel",
                "client-state-backup-sentinel",
                "client_states-sentinel",
                "clientStates-sentinel",
                "clientStateBackup-sentinel",
                "client_state_backup-sentinel",
                "clientStateSnapshot-sentinel",
                "clientStateSnapshots-sentinel",
                "client.state.snapshot-sentinel",
                "client.state.snapshot.json-sentinel",
                "client.state.snapshots.json-sentinel",
                "client_state_snapshot-sentinel",
                "client_state_snapshots-sentinel",
                "clientStateCiphertext-sentinel",
                "clientStateCiphertextHash-sentinel",
                "clientStateCiphertextHashes-sentinel",
                "clientStateCiphertextSha256-sentinel",
                "clientStateCiphertextsSha256-sentinel",
                "client_state_ciphertext-sentinel",
                "client_state_ciphertext_hash-sentinel",
                "client_state_ciphertext_hashes.bin-sentinel",
                "client_state_ciphertext_hashes.json-sentinel",
                "client_state_ciphertext_sha256-sentinel",
                "client_state_ciphertexts_sha256-sentinel",
                "client_state_ciphertexts_sha256.bin-sentinel",
                "client_state_ciphertexts_sha256.json-sentinel",
                "encryptedClientStateBackup-sentinel",
                "encryptedClientStateBackups-sentinel",
                "encryptedClientStateSnapshot-sentinel",
                "encryptedClientStateSnapshots-sentinel",
                "encrypted.client.state-sentinel",
                "encrypted.client.state.json-sentinel",
                "encrypted.client.state.snapshot-sentinel",
                "encrypted.client.state.snapshot.json-sentinel",
                "encrypted.client.state.snapshots.json-sentinel",
                "encrypted_client_state-sentinel",
                "encrypted_client_state_backup-sentinel",
                "encrypted_client_state_backups-sentinel",
                "encrypted_client_state_snapshot-sentinel",
                "encrypted_client_state_snapshot.bin-sentinel",
                "encrypted_client_state_snapshot.json-sentinel",
                "encrypted_client_state_snapshots-sentinel",
                "encrypted_client_state_snapshots.json-sentinel",
                "encryptedClientStateCiphertext-sentinel",
                "encrypted_client_state_ciphertext-sentinel",
                "encryptedClientStateCiphertextHash-sentinel",
                "encryptedClientStateCiphertextHashes-sentinel",
                "encryptedClientStateCiphertextSha256-sentinel",
                "encryptedClientStateCiphertextsSha256-sentinel",
                "encrypted_client_state_ciphertext_hash-sentinel",
                "encrypted_client_state_ciphertext_hashes-sentinel",
                "encrypted_client_state_ciphertext_hashes.bin-sentinel",
                "encrypted_client_state_ciphertext_hashes.json-sentinel",
                "encrypted_client_state_ciphertext_sha256-sentinel",
                "encrypted_client_state_ciphertexts_sha256-sentinel",
                "encrypted_client_state_ciphertexts_sha256.bin-sentinel",
                "encrypted_client_state_ciphertexts_sha256.json-sentinel",
                "oramPositionMapBackup-sentinel",
                "oramPositionMapBackups-sentinel",
                "oram_position_map_backup-sentinel",
                "oram_position_map_backups-sentinel",
                "positionMapBackup-sentinel",
                "positionMapBackups-sentinel",
                "position_map_backup-sentinel",
                "position_map_backups-sentinel",
                "session-id-sentinel",
                "stashBackup-sentinel",
                "stashBackups-sentinel",
                "hnsw-session-id-sentinel",
                "hnsw-query-session-sentinel",
                "token-position-map-sentinel",
                "token-position-map-backup-sentinel",
                "tokenMapBackup-sentinel",
                "tokenMapBackups-sentinel",
                "token.map.backup-sentinel",
                "token.map.backup.json-sentinel",
                "token.map.backups-sentinel",
                "token.map.backups.json-sentinel",
                "token_map-sentinel",
                "token_map_backup-sentinel",
                "token_map_backups-sentinel",
                "tokenPositionMapBackup-sentinel",
                "tokenPositionMapBackups-sentinel",
                "token.position.map.backup-sentinel",
                "token.position.map.backup.json-sentinel",
                "token.position.map.backups-sentinel",
                "token.position.map.backups.json-sentinel",
                "token_position_map-sentinel",
                "token_position_map_backup-sentinel",
                "token_position_map_backups-sentinel",
                "stateCiphertext-sentinel",
                "stateCiphertextHash-sentinel",
                "stateCiphertextHashes-sentinel",
                "stateCiphertextSha256-sentinel",
                "stateCiphertextsSha256-sentinel",
                "state_ciphertext-sentinel",
                "state_ciphertext_hash-sentinel",
                "state_ciphertext_hashes-sentinel",
                "state_ciphertext_hashes.json-sentinel",
                "state_ciphertext_sha256-sentinel",
                "state_ciphertexts_sha256-sentinel",
                "state_ciphertexts_sha256.bin-sentinel",
                "state_ciphertexts_sha256.json-sentinel",
                "result-bucket-id-sentinel",
                "result-root-hash-sentinel",
                "result-query-bucket-sentinel",
                "result-query-proof-values-sentinel",
                "result-query-proofValue-sentinel",
                "result-query-access-counts-sentinel",
                "result-query-accessCount-sentinel",
                "result-query-access-volume-count-sentinel",
                "result-query-access-volume-counts-sentinel",
                "result-query-access-volumes-sentinel",
                "result-query-accessVolumeLength-sentinel",
                "result-query-accessVolumeCounts-sentinel",
                "result-query-accessVolumes-sentinel",
                "result-query-access-volume-len-sentinel",
                "result-query-access-volume-lengths-sentinel",
                "result-query-accessVolumeLengths-sentinel",
                "result-query-payload-fetch-token-sentinel",
                "result-query-payloadFetchTokens-sentinel",
                "result-query-payload-fetch-token-dot-sentinel",
                "result-updated-bucket-sentinel",
                "result-session-id-sentinel",
                "result-query-session-sentinel",
            ] {
                assert!(!label.contains(leaked), "{raw} canonicalized to {label}");
            }
        }
        assert_eq!(
            canonical_rest_endpoint_label("/collections/docs/points/search/not-whitelisted"),
            None,
        );
        for raw in [
            "/collections/docs/private-hnsw/text/buckets/bucket-id-sentinel",
            "/collections/docs/private-hnsw/text/manifest/root-hash-sentinel",
            "/collections/docs/private-hnsw/text/oram/read_paths/leaf-label-sentinel",
            "/collections/docs/private-hnsw/text/oram/commit/updated-bucket-sentinel",
            "/collections/docs/private-hnsw/text/session/client-state-sentinel",
            "/collections/docs/private-hnsw/text/session/client-state-backup-sentinel",
            "/collections/docs/private-hnsw/text/session/client_states-sentinel",
            "/collections/docs/private-hnsw/text/session/clientStates-sentinel",
            "/collections/docs/private-hnsw/text/session/accessCount-sentinel",
            "/collections/docs/private-hnsw/text/session/accessCounts-sentinel",
            "/collections/docs/private-hnsw/text/session/access_count-sentinel",
            "/collections/docs/private-hnsw/text/session/access.count-sentinel",
            "/collections/docs/private-hnsw/text/session/access_counts-sentinel",
            "/collections/docs/private-hnsw/text/session/access.counts-sentinel",
            "/collections/docs/private-hnsw/text/session/accessVolume-sentinel",
            "/collections/docs/private-hnsw/text/session/accessVolumes-sentinel",
            "/collections/docs/private-hnsw/text/session/accessVolumeCount-sentinel",
            "/collections/docs/private-hnsw/text/session/accessVolumeCounts-sentinel",
            "/collections/docs/private-hnsw/text/session/accessVolumeLength-sentinel",
            "/collections/docs/private-hnsw/text/session/accessVolumeLengths-sentinel",
            "/collections/docs/private-hnsw/text/session/access_volume-sentinel",
            "/collections/docs/private-hnsw/text/session/access.volume-sentinel",
            "/collections/docs/private-hnsw/text/session/access_volumes-sentinel",
            "/collections/docs/private-hnsw/text/session/access.volumes-sentinel",
            "/collections/docs/private-hnsw/text/session/access_volume_len-sentinel",
            "/collections/docs/private-hnsw/text/session/access.volume.len-sentinel",
            "/collections/docs/private-hnsw/text/session/access_volume_count-sentinel",
            "/collections/docs/private-hnsw/text/session/access.volume.count-sentinel",
            "/collections/docs/private-hnsw/text/session/access_volume_counts-sentinel",
            "/collections/docs/private-hnsw/text/session/access.volume.counts-sentinel",
            "/collections/docs/private-hnsw/text/session/access_volume_length-sentinel",
            "/collections/docs/private-hnsw/text/session/access.volume.length-sentinel",
            "/collections/docs/private-hnsw/text/session/access_volume_lengths-sentinel",
            "/collections/docs/private-hnsw/text/session/access.volume.lengths-sentinel",
            "/collections/docs/private-hnsw/text/session/clientStateBackup-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_backup-sentinel",
            "/collections/docs/private-hnsw/text/session/clientStateSnapshot-sentinel",
            "/collections/docs/private-hnsw/text/session/clientStateSnapshots-sentinel",
            "/collections/docs/private-hnsw/text/session/client.state.snapshot-sentinel",
            "/collections/docs/private-hnsw/text/session/client.state.snapshot.json-sentinel",
            "/collections/docs/private-hnsw/text/session/client.state.snapshots.json-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_snapshot-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_snapshots-sentinel",
            "/collections/docs/private-hnsw/text/session/clientStateCiphertext-sentinel",
            "/collections/docs/private-hnsw/text/session/clientStateCiphertextHash-sentinel",
            "/collections/docs/private-hnsw/text/session/clientStateCiphertextHashes-sentinel",
            "/collections/docs/private-hnsw/text/session/clientStateCiphertextSha256-sentinel",
            "/collections/docs/private-hnsw/text/session/clientStateCiphertextsSha256-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_ciphertext-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_ciphertext_hash-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_ciphertext_hashes.bin-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_ciphertext_hashes.json-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_ciphertext_sha256-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_ciphertexts_sha256-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_ciphertexts_sha256.bin-sentinel",
            "/collections/docs/private-hnsw/text/session/client_state_ciphertexts_sha256.json-sentinel",
            "/collections/docs/private-hnsw/text/session/encryptedClientStateBackup-sentinel",
            "/collections/docs/private-hnsw/text/session/encryptedClientStateBackups-sentinel",
            "/collections/docs/private-hnsw/text/session/encryptedClientStateSnapshot-sentinel",
            "/collections/docs/private-hnsw/text/session/encryptedClientStateSnapshots-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted.client.state-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted.client.state.json-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted.client.state.snapshot-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted.client.state.snapshot.json-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted.client.state.snapshots.json-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_backup-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_backups-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_snapshot-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_snapshot.bin-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_snapshot.json-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_snapshots-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_snapshots.json-sentinel",
            "/collections/docs/private-hnsw/text/session/encryptedClientStateCiphertext-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext-sentinel",
            "/collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextHash-sentinel",
            "/collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextHashes-sentinel",
            "/collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextSha256-sentinel",
            "/collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextsSha256-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_hash-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_hashes-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_hashes.bin-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_hashes.json-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_sha256-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertexts_sha256-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertexts_sha256.bin-sentinel",
            "/collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertexts_sha256.json-sentinel",
            "/collections/docs/private-hnsw/text/session/oramPositionMapBackup-sentinel",
            "/collections/docs/private-hnsw/text/session/oramPositionMapBackups-sentinel",
            "/collections/docs/private-hnsw/text/session/oram_position_map_backup-sentinel",
            "/collections/docs/private-hnsw/text/session/oram_position_map_backups-sentinel",
            "/collections/docs/private-hnsw/text/session/positionMapBackup-sentinel",
            "/collections/docs/private-hnsw/text/session/positionMapBackups-sentinel",
            "/collections/docs/private-hnsw/text/session/position_map_backup-sentinel",
            "/collections/docs/private-hnsw/text/session/position_map_backups-sentinel",
            "/collections/docs/private-hnsw/text/session/tokenMapBackup-sentinel",
            "/collections/docs/private-hnsw/text/session/tokenMapBackups-sentinel",
            "/collections/docs/private-hnsw/text/session/token.map.backup-sentinel",
            "/collections/docs/private-hnsw/text/session/token.map.backup.json-sentinel",
            "/collections/docs/private-hnsw/text/session/token.map.backups-sentinel",
            "/collections/docs/private-hnsw/text/session/token.map.backups.json-sentinel",
            "/collections/docs/private-hnsw/text/session/token_map-sentinel",
            "/collections/docs/private-hnsw/text/session/token_map_backup-sentinel",
            "/collections/docs/private-hnsw/text/session/token_map_backups-sentinel",
            "/collections/docs/private-hnsw/text/session/payloadFetchToken-sentinel",
            "/collections/docs/private-hnsw/text/session/payloadFetchTokens-sentinel",
            "/collections/docs/private-hnsw/text/session/payload_fetch_token-sentinel",
            "/collections/docs/private-hnsw/text/session/payload_fetch_tokens-sentinel",
            "/collections/docs/private-hnsw/text/session/payload.fetch.token-sentinel",
            "/collections/docs/private-hnsw/text/session/payload.fetch.tokens-sentinel",
            "/collections/docs/private-hnsw/text/session/tokenPositionMapBackup-sentinel",
            "/collections/docs/private-hnsw/text/session/tokenPositionMapBackups-sentinel",
            "/collections/docs/private-hnsw/text/session/token.position.map.backup-sentinel",
            "/collections/docs/private-hnsw/text/session/token.position.map.backup.json-sentinel",
            "/collections/docs/private-hnsw/text/session/token.position.map.backups-sentinel",
            "/collections/docs/private-hnsw/text/session/token.position.map.backups.json-sentinel",
            "/collections/docs/private-hnsw/text/session/token_position_map-sentinel",
            "/collections/docs/private-hnsw/text/session/token_position_map_backup-sentinel",
            "/collections/docs/private-hnsw/text/session/token_position_map_backups-sentinel",
            "/collections/docs/private-hnsw/text/session/stashBackup-sentinel",
            "/collections/docs/private-hnsw/text/session/stashBackups-sentinel",
            "/collections/docs/private-hnsw/text/session/bad/hnsw-session-id-sentinel/close",
            "/collections/docs/private-result-oram/buckets/result-bucket-id-sentinel",
            "/collections/docs/private-result-oram/manifest/result-root-hash-sentinel",
            "/collections/docs/private-result-oram/oram/read_buckets/result-bucket-id-sentinel",
            "/collections/docs/private-result-oram/oram/commit/result-updated-bucket-sentinel",
            "/collections/docs/private-result-oram/session/token-position-map-sentinel",
            "/collections/docs/private-result-oram/session/token-position-map-backup-sentinel",
            "/collections/docs/private-result-oram/session/tokenMapBackup-sentinel",
            "/collections/docs/private-result-oram/session/tokenMapBackups-sentinel",
            "/collections/docs/private-result-oram/session/token.map.backup-sentinel",
            "/collections/docs/private-result-oram/session/token.map.backup.json-sentinel",
            "/collections/docs/private-result-oram/session/token.map.backups-sentinel",
            "/collections/docs/private-result-oram/session/token.map.backups.json-sentinel",
            "/collections/docs/private-result-oram/session/token_map-sentinel",
            "/collections/docs/private-result-oram/session/token_map_backup-sentinel",
            "/collections/docs/private-result-oram/session/token_map_backups-sentinel",
            "/collections/docs/private-result-oram/session/payloadFetchToken-sentinel",
            "/collections/docs/private-result-oram/session/payloadFetchTokens-sentinel",
            "/collections/docs/private-result-oram/session/payload_fetch_token-sentinel",
            "/collections/docs/private-result-oram/session/payload_fetch_tokens-sentinel",
            "/collections/docs/private-result-oram/session/payload.fetch.token-sentinel",
            "/collections/docs/private-result-oram/session/payload.fetch.tokens-sentinel",
            "/collections/docs/private-result-oram/session/accessCount-sentinel",
            "/collections/docs/private-result-oram/session/accessCounts-sentinel",
            "/collections/docs/private-result-oram/session/access_count-sentinel",
            "/collections/docs/private-result-oram/session/access.count-sentinel",
            "/collections/docs/private-result-oram/session/access_counts-sentinel",
            "/collections/docs/private-result-oram/session/access.counts-sentinel",
            "/collections/docs/private-result-oram/session/accessVolume-sentinel",
            "/collections/docs/private-result-oram/session/accessVolumes-sentinel",
            "/collections/docs/private-result-oram/session/accessVolumeCount-sentinel",
            "/collections/docs/private-result-oram/session/accessVolumeCounts-sentinel",
            "/collections/docs/private-result-oram/session/accessVolumeLength-sentinel",
            "/collections/docs/private-result-oram/session/accessVolumeLengths-sentinel",
            "/collections/docs/private-result-oram/session/access_volume-sentinel",
            "/collections/docs/private-result-oram/session/access.volume-sentinel",
            "/collections/docs/private-result-oram/session/access_volumes-sentinel",
            "/collections/docs/private-result-oram/session/access.volumes-sentinel",
            "/collections/docs/private-result-oram/session/access_volume_len-sentinel",
            "/collections/docs/private-result-oram/session/access.volume.len-sentinel",
            "/collections/docs/private-result-oram/session/access_volume_count-sentinel",
            "/collections/docs/private-result-oram/session/access.volume.count-sentinel",
            "/collections/docs/private-result-oram/session/access_volume_counts-sentinel",
            "/collections/docs/private-result-oram/session/access.volume.counts-sentinel",
            "/collections/docs/private-result-oram/session/access_volume_length-sentinel",
            "/collections/docs/private-result-oram/session/access.volume.length-sentinel",
            "/collections/docs/private-result-oram/session/access_volume_lengths-sentinel",
            "/collections/docs/private-result-oram/session/access.volume.lengths-sentinel",
            "/collections/docs/private-result-oram/session/oramPositionMapBackup-sentinel",
            "/collections/docs/private-result-oram/session/oramPositionMapBackups-sentinel",
            "/collections/docs/private-result-oram/session/oram_position_map_backup-sentinel",
            "/collections/docs/private-result-oram/session/oram_position_map_backups-sentinel",
            "/collections/docs/private-result-oram/session/positionMapBackup-sentinel",
            "/collections/docs/private-result-oram/session/positionMapBackups-sentinel",
            "/collections/docs/private-result-oram/session/position_map_backup-sentinel",
            "/collections/docs/private-result-oram/session/position_map_backups-sentinel",
            "/collections/docs/private-result-oram/session/stashBackup-sentinel",
            "/collections/docs/private-result-oram/session/stashBackups-sentinel",
            "/collections/docs/private-result-oram/session/tokenPositionMapBackup-sentinel",
            "/collections/docs/private-result-oram/session/tokenPositionMapBackups-sentinel",
            "/collections/docs/private-result-oram/session/token.position.map.backup-sentinel",
            "/collections/docs/private-result-oram/session/token.position.map.backup.json-sentinel",
            "/collections/docs/private-result-oram/session/token.position.map.backups-sentinel",
            "/collections/docs/private-result-oram/session/token.position.map.backups.json-sentinel",
            "/collections/docs/private-result-oram/session/token_position_map-sentinel",
            "/collections/docs/private-result-oram/session/token_position_map_backup-sentinel",
            "/collections/docs/private-result-oram/session/token_position_map_backups-sentinel",
            "/collections/docs/private-result-oram/session/stateCiphertext-sentinel",
            "/collections/docs/private-result-oram/session/stateCiphertextHash-sentinel",
            "/collections/docs/private-result-oram/session/stateCiphertextHashes-sentinel",
            "/collections/docs/private-result-oram/session/stateCiphertextSha256-sentinel",
            "/collections/docs/private-result-oram/session/stateCiphertextsSha256-sentinel",
            "/collections/docs/private-result-oram/session/state_ciphertext-sentinel",
            "/collections/docs/private-result-oram/session/state_ciphertext_hash-sentinel",
            "/collections/docs/private-result-oram/session/state_ciphertext_hashes-sentinel",
            "/collections/docs/private-result-oram/session/state_ciphertext_hashes.json-sentinel",
            "/collections/docs/private-result-oram/session/state_ciphertext_sha256-sentinel",
            "/collections/docs/private-result-oram/session/state_ciphertexts_sha256-sentinel",
            "/collections/docs/private-result-oram/session/state_ciphertexts_sha256.bin-sentinel",
            "/collections/docs/private-result-oram/session/state_ciphertexts_sha256.json-sentinel",
            "/collections/docs/private-result-oram/session/bad/result-session-id-sentinel/close",
            "/collections/docs/private-hnsw?leaf=hnsw-query-leaf-sentinel",
            "/collections/docs/private-result-oram?token=result-query-token-sentinel",
            "/collections/docs/not-private-hnsw/text/session/session-id-sentinel",
            "/collections/docs/private-result-oramish/session/result-session-id-sentinel",
            "/collections/private-hnsw/points/search?leaf=hnsw-query-leaf-sentinel",
        ] {
            assert_eq!(
                canonical_rest_endpoint_label(raw),
                None,
                "malformed or lookalike private ORAM path must not become a fixed metrics label: {raw}"
            );
        }

        let grpc_cases = [
            "/qdrant.PrivateHnswOram/GetPrivateHnswManifest",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswManifest",
            "/qdrant.PrivateHnswOram/ReadPrivateHnswPaths",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths",
            "/qdrant.PrivateHnswOram/ClosePrivateHnswSession",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets",
            "/qdrant.PrivateResultOram/GetPrivateResultOramManifest",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession",
            "/qdrant.PrivateResultOram/ReadPrivateResultOramBuckets",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramManifest",
            "/qdrant.PrivateResultOram/ClosePrivateResultOramSession",
        ];
        for raw in grpc_cases {
            let label =
                canonical_grpc_endpoint_label(raw).expect("private ORAM gRPC method canonicalizes");
            assert_eq!(label, raw);
            for leaked in [
                "client-state-sentinel",
                "client-state-backup-sentinel",
                "client_states-sentinel",
                "clientStates-sentinel",
                "clientStateBackup-sentinel",
                "client_state_backup-sentinel",
                "clientStateSnapshot-sentinel",
                "clientStateSnapshots-sentinel",
                "client.state.snapshot-sentinel",
                "client.state.snapshot.json-sentinel",
                "client.state.snapshots.json-sentinel",
                "client_state_snapshot-sentinel",
                "client_state_snapshots-sentinel",
                "clientStateCiphertext-sentinel",
                "clientStateCiphertextHash-sentinel",
                "clientStateCiphertextHashes-sentinel",
                "clientStateCiphertextSha256-sentinel",
                "clientStateCiphertextsSha256-sentinel",
                "client_state_ciphertext-sentinel",
                "client_state_ciphertext_hash-sentinel",
                "client_state_ciphertext_hashes.bin-sentinel",
                "client_state_ciphertext_hashes.json-sentinel",
                "client_state_ciphertext_sha256-sentinel",
                "client_state_ciphertexts_sha256-sentinel",
                "client_state_ciphertexts_sha256.bin-sentinel",
                "client_state_ciphertexts_sha256.json-sentinel",
                "encryptedClientStateBackup-sentinel",
                "encryptedClientStateBackups-sentinel",
                "encryptedClientStateSnapshot-sentinel",
                "encryptedClientStateSnapshots-sentinel",
                "encrypted.client.state-sentinel",
                "encrypted.client.state.json-sentinel",
                "encrypted.client.state.snapshot-sentinel",
                "encrypted.client.state.snapshot.json-sentinel",
                "encrypted.client.state.snapshots.json-sentinel",
                "encrypted_client_state-sentinel",
                "encrypted_client_state_backup-sentinel",
                "encrypted_client_state_backups-sentinel",
                "encrypted_client_state_snapshot-sentinel",
                "encrypted_client_state_snapshot.bin-sentinel",
                "encrypted_client_state_snapshot.json-sentinel",
                "encrypted_client_state_snapshots-sentinel",
                "encrypted_client_state_snapshots.json-sentinel",
                "encryptedClientStateCiphertext-sentinel",
                "encrypted_client_state_ciphertext-sentinel",
                "encryptedClientStateCiphertextHash-sentinel",
                "encryptedClientStateCiphertextHashes-sentinel",
                "encryptedClientStateCiphertextSha256-sentinel",
                "encryptedClientStateCiphertextsSha256-sentinel",
                "encrypted_client_state_ciphertext_hash-sentinel",
                "encrypted_client_state_ciphertext_hashes-sentinel",
                "encrypted_client_state_ciphertext_hashes.bin-sentinel",
                "encrypted_client_state_ciphertext_hashes.json-sentinel",
                "encrypted_client_state_ciphertext_sha256-sentinel",
                "encrypted_client_state_ciphertexts_sha256-sentinel",
                "encrypted_client_state_ciphertexts_sha256.bin-sentinel",
                "encrypted_client_state_ciphertexts_sha256.json-sentinel",
                "oramPositionMapBackup-sentinel",
                "oramPositionMapBackups-sentinel",
                "oram_position_map_backup-sentinel",
                "oram_position_map_backups-sentinel",
                "positionMapBackup-sentinel",
                "positionMapBackups-sentinel",
                "position_map_backup-sentinel",
                "position_map_backups-sentinel",
                "hnsw-bucket-id-sentinel",
                "leaf-label-sentinel",
                "root-hash-sentinel",
                "updated-bucket-sentinel",
                "session-id-sentinel",
                "stashBackup-sentinel",
                "stashBackups-sentinel",
                "result-updated-bucket-sentinel",
                "token-position-map-sentinel",
                "token-position-map-backup-sentinel",
                "tokenMapBackup-sentinel",
                "tokenMapBackups-sentinel",
                "token.map.backup-sentinel",
                "token.map.backup.json-sentinel",
                "token.map.backups-sentinel",
                "token.map.backups.json-sentinel",
                "token_map-sentinel",
                "token_map_backup-sentinel",
                "token_map_backups-sentinel",
                "tokenPositionMapBackup-sentinel",
                "tokenPositionMapBackups-sentinel",
                "token.position.map.backup-sentinel",
                "token.position.map.backup.json-sentinel",
                "token.position.map.backups-sentinel",
                "token.position.map.backups.json-sentinel",
                "token_position_map-sentinel",
                "token_position_map_backup-sentinel",
                "token_position_map_backups-sentinel",
                "stateCiphertext-sentinel",
                "stateCiphertextHash-sentinel",
                "stateCiphertextHashes-sentinel",
                "stateCiphertextSha256-sentinel",
                "stateCiphertextsSha256-sentinel",
                "state_ciphertext-sentinel",
                "state_ciphertext_hash-sentinel",
                "state_ciphertext_hashes-sentinel",
                "state_ciphertext_hashes.json-sentinel",
                "state_ciphertext_sha256-sentinel",
                "state_ciphertexts_sha256-sentinel",
                "state_ciphertexts_sha256.bin-sentinel",
                "state_ciphertexts_sha256.json-sentinel",
                "result-bucket-id-sentinel",
                "result-root-hash-sentinel",
                "result-session-id-sentinel",
            ] {
                assert!(!label.contains(leaked), "{raw} canonicalized to {label}");
            }
        }
        assert_eq!(
            canonical_grpc_endpoint_label("/qdrant.Points/Search/vector-name-sentinel"),
            None,
        );
        for raw in [
            "/qdrant.PrivateHnswOram",
            "/qdrant.PrivateHnswOramish/ReadPrivateHnswPaths/leaf-label-sentinel",
            "/qdrant.PrivateHnswOram/ReadPrivateHnswPathsExtra/leaf-label-sentinel",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPathsExtra/updated-bucket-sentinel",
            "/qdrant.PrivateHnswOram/GetPrivateHnswManifest/root-hash-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client-state-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client-state-backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_states-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStates-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateSnapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateSnapshots-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client.state.snapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client.state.snapshot.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client.state.snapshots.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_snapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_snapshots-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertext-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertextHash-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertextHashes-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertextSha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertextsSha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext_hash-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext_hashes.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext_hashes.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext_sha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertexts_sha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertexts_sha256.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertexts_sha256.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateBackups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateSnapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateSnapshots-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state.snapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state.snapshot.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state.snapshots.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_backups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshot.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshot.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshots-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshots.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertext-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertextHash-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertextHashes-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertextSha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertextsSha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_hash-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_hashes-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_hashes.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_hashes.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_sha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertexts_sha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertexts_sha256.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertexts_sha256.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/oramPositionMapBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/oramPositionMapBackups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/oram_position_map_backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/oram_position_map_backups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/positionMapBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/positionMapBackups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/position_map_backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/position_map_backups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payloadFetchToken-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payloadFetchTokens-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payload_fetch_token-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payload_fetch_tokens-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payload.fetch.token-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/stashBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/stashBackups-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/hnsw-bucket-id-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswManifest/root-hash-sentinel",
            "/qdrant.PrivateHnswOram/ReadPrivateHnswPaths/leaf-label-sentinel",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths/updated-bucket-sentinel",
            "/qdrant.PrivateHnswOram/ClosePrivateHnswSession/session-id-sentinel",
            "/qdrant.PrivateResultOramish/ReadPrivateResultOramBuckets/result-bucket-id-sentinel",
            "/qdrant.PrivateResultOram/ReadPrivateResultOramBucketsExtra/result-bucket-id-sentinel",
            "/qdrant.PrivateResultOram/ClosePrivateResultOramSessionExtra/result-session-id-sentinel",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets/result-updated-bucket-sentinel",
            "/qdrant.PrivateResultOram/GetPrivateResultOramManifest/result-root-hash-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token-position-map-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token-position-map-backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/tokenMapBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/tokenMapBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.map.backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.map.backup.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.map.backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.map.backups.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_map-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_map_backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_map_backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payloadFetchToken-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payloadFetchTokens-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payload_fetch_token-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payload_fetch_tokens-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payload.fetch.token-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/oramPositionMapBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/oramPositionMapBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/oram_position_map_backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/oram_position_map_backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/positionMapBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/positionMapBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/position_map_backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/position_map_backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stashBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stashBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/tokenPositionMapBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/tokenPositionMapBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.position.map.backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.position.map.backup.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.position.map.backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.position.map.backups.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_position_map-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_position_map_backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_position_map_backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertext-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertextHash-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertextHashes-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertextSha256-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertextsSha256-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext_hash-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext_hashes-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext_hashes.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext_sha256-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertexts_sha256-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertexts_sha256.bin-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertexts_sha256.json-sentinel",
            "/qdrant.PrivateResultOram/ReadPrivateResultOramBuckets/result-bucket-id-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-bucket-id-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramManifest/result-root-hash-sentinel",
            "/qdrant.PrivateResultOram/ClosePrivateResultOramSession/result-session-id-sentinel",
        ] {
            assert_eq!(
                canonical_grpc_endpoint_label(raw),
                None,
                "malformed or lookalike private ORAM gRPC method must not become a fixed metrics label: {raw}"
            );
        }
    }

    fn is_private_oram_openapi_path(path: &str) -> bool {
        let segments = path.split('/').collect::<Vec<_>>();
        matches!(
            segments.as_slice(),
            ["", "collections", "{collection_name}", "private-hnsw", ..]
                | [
                    "",
                    "collections",
                    "{collection_name}",
                    "private-result-oram",
                    ..
                ]
        )
    }

    #[test]
    fn test_private_oram_openapi_surface_is_fixed() {
        let openapi: serde_json::Value =
            serde_json::from_str(include_str!("../../docs/redoc/master/openapi.json"))
                .expect("OpenAPI fixture must parse");
        let paths = openapi
            .get("paths")
            .and_then(serde_json::Value::as_object)
            .expect("OpenAPI fixture must contain paths");
        let expected = [
            (
                "/collections/{collection_name}/private-hnsw/{vector_name}/buckets",
                "post",
                "upload_private_hnsw_buckets",
            ),
            (
                "/collections/{collection_name}/private-hnsw/{vector_name}/manifest",
                "get",
                "get_private_hnsw_manifest",
            ),
            (
                "/collections/{collection_name}/private-hnsw/{vector_name}/manifest",
                "post",
                "upload_private_hnsw_manifest",
            ),
            (
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit",
                "post",
                "commit_private_hnsw_paths",
            ),
            (
                "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
                "post",
                "read_private_hnsw_paths",
            ),
            (
                "/collections/{collection_name}/private-hnsw/{vector_name}/session",
                "post",
                "open_private_hnsw_session",
            ),
            (
                "/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close",
                "post",
                "close_private_hnsw_session",
            ),
            (
                "/collections/{collection_name}/private-result-oram/buckets",
                "post",
                "upload_private_result_oram_buckets",
            ),
            (
                "/collections/{collection_name}/private-result-oram/manifest",
                "get",
                "get_private_result_oram_manifest",
            ),
            (
                "/collections/{collection_name}/private-result-oram/manifest",
                "post",
                "upload_private_result_oram_manifest",
            ),
            (
                "/collections/{collection_name}/private-result-oram/oram/commit",
                "post",
                "commit_private_result_oram_buckets",
            ),
            (
                "/collections/{collection_name}/private-result-oram/oram/read_buckets",
                "post",
                "read_private_result_oram_buckets",
            ),
            (
                "/collections/{collection_name}/private-result-oram/session",
                "post",
                "open_private_result_oram_session",
            ),
            (
                "/collections/{collection_name}/private-result-oram/session/{session_id}/close",
                "post",
                "close_private_result_oram_session",
            ),
        ];

        for (path, method, operation_id) in expected {
            let operation = paths
                .get(path)
                .and_then(|path_item| path_item.get(method))
                .unwrap_or_else(|| panic!("OpenAPI must expose {method} {path}"));
            assert_eq!(
                operation
                    .get("operationId")
                    .and_then(serde_json::Value::as_str),
                Some(operation_id),
                "OpenAPI operationId drift for {method} {path}",
            );
        }

        let private_oram_path_count = paths
            .keys()
            .filter(|path| is_private_oram_openapi_path(path))
            .count();
        assert_eq!(
            private_oram_path_count, 12,
            "OpenAPI private ORAM path surface changed",
        );

        let private_oram_method_count = paths
            .iter()
            .filter(|(path, _)| is_private_oram_openapi_path(path))
            .map(|(_, path_item)| {
                path_item
                    .as_object()
                    .expect("OpenAPI path item must be an object")
                    .keys()
                    .filter(|method| matches!(method.as_str(), "get" | "post"))
                    .count()
            })
            .sum::<usize>();
        assert_eq!(
            private_oram_method_count, 14,
            "OpenAPI private ORAM method surface changed",
        );
    }

    #[test]
    fn test_rest_metrics_global_mode() {
        use std::collections::HashMap;

        use segment::common::operation_time_statistics::OperationDurationStatistics;

        use super::{MetricsData, MetricsProvider, WebApiTelemetry};

        let mut responses = HashMap::new();
        let mut status_map = HashMap::new();
        status_map.insert(
            200u16,
            OperationDurationStatistics {
                count: 10,
                ..Default::default()
            },
        );
        responses.insert(
            "POST /collections/{collection_name}/points/search".to_string(),
            status_map,
        );

        let telemetry = WebApiTelemetry {
            responses,
            per_collection_responses: HashMap::new(),
        };

        let mut metrics = MetricsData::empty();
        telemetry.add_metrics(&mut metrics, None);
        let output = metrics.format_metrics();

        // Should contain global metrics without collection label
        assert!(output.contains("rest_responses_total"));
        assert!(!output.contains("collection="));
    }

    #[test]
    fn test_rest_metrics_per_collection_mode() {
        use std::collections::HashMap;

        use segment::common::operation_time_statistics::OperationDurationStatistics;

        use super::{MetricsData, MetricsProvider, WebApiTelemetry};

        // Global responses present but per_collection too
        let mut responses = HashMap::new();
        let mut status_map = HashMap::new();
        status_map.insert(
            200u16,
            OperationDurationStatistics {
                count: 10,
                ..Default::default()
            },
        );
        responses.insert(
            "POST /collections/{collection_name}/points/search".to_string(),
            status_map,
        );

        let mut per_collection = HashMap::new();
        let mut methods = HashMap::new();
        let mut col_status_map = HashMap::new();
        col_status_map.insert(
            200u16,
            OperationDurationStatistics {
                count: 5,
                ..Default::default()
            },
        );
        methods.insert(
            "POST /collections/{collection_name}/points/search".to_string(),
            col_status_map,
        );
        per_collection.insert("my_collection".to_string(), methods);

        let telemetry = WebApiTelemetry {
            responses,
            per_collection_responses: per_collection,
        };

        let mut metrics = MetricsData::empty();
        telemetry.add_metrics(&mut metrics, None);
        let output = metrics.format_metrics();

        // Should contain collection label
        assert!(
            output.contains("collection=\"my_collection\""),
            "Expected collection label in output:\n{output}"
        );
        // Should still have rest_ prefix metrics
        assert!(output.contains("rest_responses_total"));
    }

    #[test]
    fn test_grpc_metrics_per_collection_mode() {
        use std::collections::HashMap;

        use segment::common::operation_time_statistics::OperationDurationStatistics;

        use super::{GrpcTelemetry, MetricsData, MetricsProvider};

        let mut per_collection = HashMap::new();
        let mut methods = HashMap::new();
        let mut status_map = HashMap::new();
        status_map.insert(
            0i32,
            OperationDurationStatistics {
                count: 7,
                ..Default::default()
            },
        );
        methods.insert("/qdrant.Points/Search".to_string(), status_map);
        per_collection.insert("test_col".to_string(), methods);

        let telemetry = GrpcTelemetry {
            responses: HashMap::new(),
            per_collection_responses: per_collection,
        };

        let mut metrics = MetricsData::empty();
        telemetry.add_metrics(&mut metrics, None);
        let output = metrics.format_metrics();

        assert!(
            output.contains("collection=\"test_col\""),
            "Expected collection label in output:\n{output}"
        );
        assert!(output.contains("grpc_responses_total"));
    }

    #[test]
    fn test_private_oram_metrics_use_fixed_endpoint_labels() {
        use std::collections::HashMap;

        use segment::common::operation_time_statistics::OperationDurationStatistics;

        use super::{GrpcTelemetry, MetricsData, MetricsProvider, WebApiTelemetry};

        fn rest_status_map(count: usize) -> HashMap<u16, OperationDurationStatistics> {
            let mut status_map = HashMap::new();
            status_map.insert(
                200u16,
                OperationDurationStatistics {
                    count,
                    ..Default::default()
                },
            );
            status_map
        }

        fn grpc_status_map(count: usize) -> HashMap<i32, OperationDurationStatistics> {
            let mut status_map = HashMap::new();
            status_map.insert(
                0i32,
                OperationDurationStatistics {
                    count,
                    ..Default::default()
                },
            );
            status_map
        }

        let mut rest_per_collection = HashMap::new();
        let mut rest_methods = HashMap::new();
        let rest_fixed_endpoints = [
            "POST /collections/{collection_name}/private-hnsw/{vector_name}/buckets",
            "GET /collections/{collection_name}/private-hnsw/{vector_name}/manifest",
            "POST /collections/{collection_name}/private-hnsw/{vector_name}/manifest",
            "POST /collections/{collection_name}/private-hnsw/{vector_name}/oram/commit",
            "POST /collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            "POST /collections/{collection_name}/private-hnsw/{vector_name}/session",
            "POST /collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close",
            "POST /collections/{collection_name}/private-result-oram/buckets",
            "GET /collections/{collection_name}/private-result-oram/manifest",
            "POST /collections/{collection_name}/private-result-oram/manifest",
            "POST /collections/{collection_name}/private-result-oram/oram/commit",
            "POST /collections/{collection_name}/private-result-oram/oram/read_buckets",
            "POST /collections/{collection_name}/private-result-oram/session",
            "POST /collections/{collection_name}/private-result-oram/session/{session_id}/close",
        ];
        for (idx, endpoint) in rest_fixed_endpoints.iter().enumerate() {
            rest_methods.insert((*endpoint).to_string(), rest_status_map(idx + 1));
        }

        let rest_dynamic_endpoints = [
            "POST /collections/docs/private-hnsw/text/buckets/bucket-id-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/ciphertextSha256-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/ciphertextsSha256-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/ciphertext_sha256-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/ciphertexts_sha256-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/bucketCommitment-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/bucketCommitments-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/bucket_commitment-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/bucket.commitment-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/bucket_commitments-sentinel",
            "POST /collections/docs/private-hnsw/text/buckets/bucket.commitments-sentinel",
            "GET /collections/docs/private-hnsw/text/manifest/root-hash-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/commit/updated-bucket-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/commit/updatedBucketCommitment-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/commit/updatedBucketCommitments-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/commit/updated_bucket_commitment-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/commit/updated.bucket.commitment-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/commit/updated_bucket_commitments-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/commit/updated.bucket.commitments-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths/leaf-label-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?paths=hnsw-query-leaf-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?proof_value=hnsw-query-proof-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?proof.value=hnsw-query-proof-dot-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?proofValue=hnsw-query-proofValue-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access_count=hnsw-query-access-count-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access.count=hnsw-query-access-count-dot-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?path.count=hnsw-query-path-count-dot-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?accessCounts=hnsw-query-accessCounts-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access_volume=hnsw-query-access-volume-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access.volume=hnsw-query-access-volume-dot-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access_volumes=hnsw-query-access-volumes-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access.volumes=hnsw-query-access-volumes-dot-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?accessVolume=hnsw-query-accessVolume-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?accessVolumes=hnsw-query-accessVolumes-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access_volume_counts=hnsw-query-access-volume-counts-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access.volume.counts=hnsw-query-access-volume-counts-dot-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?accessVolumeCounts=hnsw-query-accessVolumeCounts-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access_volume_len=hnsw-query-access-volume-len-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access.volume.len=hnsw-query-access-volume-len-dot-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access_volume_lengths=hnsw-query-access-volume-lengths-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?access.volume.lengths=hnsw-query-access-volume-lengths-dot-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?accessVolumeLengths=hnsw-query-accessVolumeLengths-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?payload_fetch_token=hnsw-query-payload-fetch-token-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?payloadFetchTokens=hnsw-query-payloadFetchTokens-sentinel",
            "POST /collections/docs/private-hnsw/text/oram/read_paths?payload.fetch.token=hnsw-query-payload-fetch-token-dot-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client-state-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client-state-backup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_states-sentinel",
            "POST /collections/docs/private-hnsw/text/session/clientStates-sentinel",
            "POST /collections/docs/private-hnsw/text/session/clientStateBackup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_backup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/clientStateSnapshot-sentinel",
            "POST /collections/docs/private-hnsw/text/session/clientStateSnapshots-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client.state.snapshot-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client.state.snapshot.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client.state.snapshots.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_snapshot-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_snapshots-sentinel",
            "POST /collections/docs/private-hnsw/text/session/clientStateCiphertext-sentinel",
            "POST /collections/docs/private-hnsw/text/session/clientStateCiphertextHash-sentinel",
            "POST /collections/docs/private-hnsw/text/session/clientStateCiphertextHashes-sentinel",
            "POST /collections/docs/private-hnsw/text/session/clientStateCiphertextSha256-sentinel",
            "POST /collections/docs/private-hnsw/text/session/clientStateCiphertextsSha256-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_ciphertext-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_ciphertext_hash-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_ciphertext_hashes.bin-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_ciphertext_hashes.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_ciphertext_sha256-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_ciphertexts_sha256-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_ciphertexts_sha256.bin-sentinel",
            "POST /collections/docs/private-hnsw/text/session/client_state_ciphertexts_sha256.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encryptedClientStateBackup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encryptedClientStateBackups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encryptedClientStateSnapshot-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encryptedClientStateSnapshots-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted.client.state-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted.client.state.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted.client.state.snapshot-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted.client.state.snapshot.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted.client.state.snapshots.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_backup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_backups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_snapshot-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_snapshot.bin-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_snapshot.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_snapshots-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_snapshots.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encryptedClientStateCiphertext-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextHash-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextHashes-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextSha256-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encryptedClientStateCiphertextsSha256-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_hash-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_hashes-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_hashes.bin-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_hashes.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertext_sha256-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertexts_sha256-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertexts_sha256.bin-sentinel",
            "POST /collections/docs/private-hnsw/text/session/encrypted_client_state_ciphertexts_sha256.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/oramPositionMapBackup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/oramPositionMapBackups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/oram_position_map_backup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/oram_position_map_backups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/positionMapBackup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/positionMapBackups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/position_map_backup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/position_map_backups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/tokenMapBackup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/tokenMapBackups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token.map.backup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token.map.backup.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token.map.backups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token.map.backups.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token_map-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token_map_backup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token_map_backups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/payloadFetchToken-sentinel",
            "POST /collections/docs/private-hnsw/text/session/payloadFetchTokens-sentinel",
            "POST /collections/docs/private-hnsw/text/session/payload_fetch_token-sentinel",
            "POST /collections/docs/private-hnsw/text/session/payload_fetch_tokens-sentinel",
            "POST /collections/docs/private-hnsw/text/session/payload.fetch.token-sentinel",
            "POST /collections/docs/private-hnsw/text/session/payload.fetch.tokens-sentinel",
            "POST /collections/docs/private-hnsw/text/session/tokenPositionMapBackup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/tokenPositionMapBackups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token.position.map.backup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token.position.map.backup.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token.position.map.backups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token.position.map.backups.json-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token_position_map-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token_position_map_backup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/token_position_map_backups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/stashBackup-sentinel",
            "POST /collections/docs/private-hnsw/text/session/stashBackups-sentinel",
            "POST /collections/docs/private-hnsw/text/session/session-id-sentinel/close",
            "POST /collections/docs/private-hnsw/text/session/bad/hnsw-session-id-sentinel/close",
            "POST /collections/docs/private-result-oram/buckets/result-bucket-id-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-ciphertextSha256-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-ciphertextsSha256-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-ciphertext_sha256-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-ciphertexts_sha256-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-bucketCommitment-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-bucketCommitments-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-bucket_commitment-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-bucket.commitment-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-bucket_commitments-sentinel",
            "POST /collections/docs/private-result-oram/buckets/result-bucket.commitments-sentinel",
            "GET /collections/docs/private-result-oram/manifest/result-root-hash-sentinel",
            "POST /collections/docs/private-result-oram/oram/commit/result-updated-bucket-sentinel",
            "POST /collections/docs/private-result-oram/oram/commit/result-updatedBucketCommitment-sentinel",
            "POST /collections/docs/private-result-oram/oram/commit/result-updatedBucketCommitments-sentinel",
            "POST /collections/docs/private-result-oram/oram/commit/result-updated_bucket_commitment-sentinel",
            "POST /collections/docs/private-result-oram/oram/commit/result-updated.bucket.commitment-sentinel",
            "POST /collections/docs/private-result-oram/oram/commit/result-updated_bucket_commitments-sentinel",
            "POST /collections/docs/private-result-oram/oram/commit/result-updated.bucket.commitments-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets/result-bucket-id-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?bucket_id=result-query-bucket-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?bucket_ids=result-query-bucket-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?proof_values=result-query-proof-values-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?proof.values=result-query-proof-values-dot-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?proofValue=result-query-proofValue-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access_counts=result-query-access-counts-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access.counts=result-query-access-counts-dot-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?accessCount=result-query-accessCount-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access_volume_count=result-query-access-volume-count-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access.volume.count=result-query-access-volume-count-dot-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access_volume_counts=result-query-access-volume-counts-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access.volume.counts=result-query-access-volume-counts-dot-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access_volumes=result-query-access-volumes-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access.volumes=result-query-access-volumes-dot-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access_volume_len=result-query-access-volume-len-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access.volume.len=result-query-access-volume-len-dot-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?accessVolumeLength=result-query-accessVolumeLength-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?accessVolumeCounts=result-query-accessVolumeCounts-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?accessVolumes=result-query-accessVolumes-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access_volume_lengths=result-query-access-volume-lengths-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?access.volume.lengths=result-query-access-volume-lengths-dot-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?accessVolumeLengths=result-query-accessVolumeLengths-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?payload_fetch_token=result-query-payload-fetch-token-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?payloadFetchTokens=result-query-payloadFetchTokens-sentinel",
            "POST /collections/docs/private-result-oram/oram/read_buckets?payload.fetch.token=result-query-payload-fetch-token-dot-sentinel",
            "POST /collections/docs/private-result-oram/session/token-position-map-sentinel",
            "POST /collections/docs/private-result-oram/session/token-position-map-backup-sentinel",
            "POST /collections/docs/private-result-oram/session/tokenMapBackup-sentinel",
            "POST /collections/docs/private-result-oram/session/tokenMapBackups-sentinel",
            "POST /collections/docs/private-result-oram/session/token.map.backup-sentinel",
            "POST /collections/docs/private-result-oram/session/token.map.backup.json-sentinel",
            "POST /collections/docs/private-result-oram/session/token.map.backups-sentinel",
            "POST /collections/docs/private-result-oram/session/token.map.backups.json-sentinel",
            "POST /collections/docs/private-result-oram/session/token_map-sentinel",
            "POST /collections/docs/private-result-oram/session/token_map_backup-sentinel",
            "POST /collections/docs/private-result-oram/session/token_map_backups-sentinel",
            "POST /collections/docs/private-result-oram/session/payloadFetchToken-sentinel",
            "POST /collections/docs/private-result-oram/session/payloadFetchTokens-sentinel",
            "POST /collections/docs/private-result-oram/session/payload_fetch_token-sentinel",
            "POST /collections/docs/private-result-oram/session/payload_fetch_tokens-sentinel",
            "POST /collections/docs/private-result-oram/session/payload.fetch.token-sentinel",
            "POST /collections/docs/private-result-oram/session/oramPositionMapBackup-sentinel",
            "POST /collections/docs/private-result-oram/session/oramPositionMapBackups-sentinel",
            "POST /collections/docs/private-result-oram/session/oram_position_map_backup-sentinel",
            "POST /collections/docs/private-result-oram/session/oram_position_map_backups-sentinel",
            "POST /collections/docs/private-result-oram/session/positionMapBackup-sentinel",
            "POST /collections/docs/private-result-oram/session/positionMapBackups-sentinel",
            "POST /collections/docs/private-result-oram/session/position_map_backup-sentinel",
            "POST /collections/docs/private-result-oram/session/position_map_backups-sentinel",
            "POST /collections/docs/private-result-oram/session/stashBackup-sentinel",
            "POST /collections/docs/private-result-oram/session/stashBackups-sentinel",
            "POST /collections/docs/private-result-oram/session/tokenPositionMapBackup-sentinel",
            "POST /collections/docs/private-result-oram/session/tokenPositionMapBackups-sentinel",
            "POST /collections/docs/private-result-oram/session/token.position.map.backup-sentinel",
            "POST /collections/docs/private-result-oram/session/token.position.map.backup.json-sentinel",
            "POST /collections/docs/private-result-oram/session/token.position.map.backups-sentinel",
            "POST /collections/docs/private-result-oram/session/token.position.map.backups.json-sentinel",
            "POST /collections/docs/private-result-oram/session/token_position_map-sentinel",
            "POST /collections/docs/private-result-oram/session/token_position_map_backup-sentinel",
            "POST /collections/docs/private-result-oram/session/token_position_map_backups-sentinel",
            "POST /collections/docs/private-result-oram/session/stateCiphertext-sentinel",
            "POST /collections/docs/private-result-oram/session/stateCiphertextHash-sentinel",
            "POST /collections/docs/private-result-oram/session/stateCiphertextHashes-sentinel",
            "POST /collections/docs/private-result-oram/session/stateCiphertextSha256-sentinel",
            "POST /collections/docs/private-result-oram/session/stateCiphertextsSha256-sentinel",
            "POST /collections/docs/private-result-oram/session/state_ciphertext-sentinel",
            "POST /collections/docs/private-result-oram/session/state_ciphertext_hash-sentinel",
            "POST /collections/docs/private-result-oram/session/state_ciphertext_hashes-sentinel",
            "POST /collections/docs/private-result-oram/session/state_ciphertext_hashes.json-sentinel",
            "POST /collections/docs/private-result-oram/session/state_ciphertext_sha256-sentinel",
            "POST /collections/docs/private-result-oram/session/state_ciphertexts_sha256-sentinel",
            "POST /collections/docs/private-result-oram/session/state_ciphertexts_sha256.bin-sentinel",
            "POST /collections/docs/private-result-oram/session/state_ciphertexts_sha256.json-sentinel",
            "POST /collections/docs/private-result-oram/session/result-session-id-sentinel/close",
            "POST /collections/docs/private-result-oram/session/bad/result-session-id-sentinel/close",
        ];
        for endpoint in rest_dynamic_endpoints {
            rest_methods.insert(endpoint.to_string(), rest_status_map(1));
        }
        rest_per_collection.insert("docs".to_string(), rest_methods);

        let rest_telemetry = WebApiTelemetry {
            responses: HashMap::new(),
            per_collection_responses: rest_per_collection,
        };
        let mut rest_metrics = MetricsData::empty();
        rest_telemetry.add_metrics(&mut rest_metrics, None);
        let rest_output = rest_metrics.format_metrics();

        assert!(rest_output.contains("rest_responses_total"));
        assert!(rest_output.contains("collection=\"docs\""));
        let expected_rest_labels = [
            "/collections/{collection_name}/private-hnsw/{vector_name}/buckets",
            "/collections/{collection_name}/private-hnsw/{vector_name}/manifest",
            "/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit",
            "/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths",
            "/collections/{collection_name}/private-hnsw/{vector_name}/session",
            "/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close",
            "/collections/{collection_name}/private-result-oram/buckets",
            "/collections/{collection_name}/private-result-oram/manifest",
            "/collections/{collection_name}/private-result-oram/oram/commit",
            "/collections/{collection_name}/private-result-oram/oram/read_buckets",
            "/collections/{collection_name}/private-result-oram/session",
            "/collections/{collection_name}/private-result-oram/session/{session_id}/close",
        ];
        for endpoint in expected_rest_labels {
            assert!(
                rest_output.contains(&format!("endpoint=\"{endpoint}\"")),
                "expected fixed REST endpoint label `{endpoint}` in output:\n{rest_output}",
            );
        }

        let redacted_sentinels = [
            "bucket-id-sentinel",
            "bucketCommitment-sentinel",
            "bucketCommitments-sentinel",
            "bucket_commitment-sentinel",
            "bucket.commitment-sentinel",
            "bucket_commitments-sentinel",
            "bucket.commitments-sentinel",
            "ciphertextSha256-sentinel",
            "ciphertextsSha256-sentinel",
            "ciphertext_sha256-sentinel",
            "ciphertexts_sha256-sentinel",
            "client-state-sentinel",
            "client-state-backup-sentinel",
            "client_states-sentinel",
            "clientStates-sentinel",
            "clientStateBackup-sentinel",
            "client_state_backup-sentinel",
            "clientStateSnapshot-sentinel",
            "clientStateSnapshots-sentinel",
            "client.state.snapshot-sentinel",
            "client.state.snapshot.json-sentinel",
            "client.state.snapshots.json-sentinel",
            "client_state_snapshot-sentinel",
            "client_state_snapshots-sentinel",
            "clientStateCiphertext-sentinel",
            "clientStateCiphertextHash-sentinel",
            "clientStateCiphertextHashes-sentinel",
            "clientStateCiphertextSha256-sentinel",
            "clientStateCiphertextsSha256-sentinel",
            "client_state_ciphertext-sentinel",
            "client_state_ciphertext_hash-sentinel",
            "client_state_ciphertext_hashes.bin-sentinel",
            "client_state_ciphertext_hashes.json-sentinel",
            "client_state_ciphertext_sha256-sentinel",
            "client_state_ciphertexts_sha256-sentinel",
            "client_state_ciphertexts_sha256.bin-sentinel",
            "client_state_ciphertexts_sha256.json-sentinel",
            "encryptedClientStateBackup-sentinel",
            "encryptedClientStateBackups-sentinel",
            "encryptedClientStateSnapshot-sentinel",
            "encryptedClientStateSnapshots-sentinel",
            "encrypted.client.state-sentinel",
            "encrypted.client.state.json-sentinel",
            "encrypted.client.state.snapshot-sentinel",
            "encrypted.client.state.snapshot.json-sentinel",
            "encrypted.client.state.snapshots.json-sentinel",
            "encrypted_client_state-sentinel",
            "encrypted_client_state_backup-sentinel",
            "encrypted_client_state_backups-sentinel",
            "encrypted_client_state_snapshot-sentinel",
            "encrypted_client_state_snapshot.bin-sentinel",
            "encrypted_client_state_snapshot.json-sentinel",
            "encrypted_client_state_snapshots-sentinel",
            "encrypted_client_state_snapshots.json-sentinel",
            "encryptedClientStateCiphertext-sentinel",
            "encrypted_client_state_ciphertext-sentinel",
            "encryptedClientStateCiphertextHash-sentinel",
            "encryptedClientStateCiphertextHashes-sentinel",
            "encryptedClientStateCiphertextSha256-sentinel",
            "encryptedClientStateCiphertextsSha256-sentinel",
            "encrypted_client_state_ciphertext_hash-sentinel",
            "encrypted_client_state_ciphertext_hashes-sentinel",
            "encrypted_client_state_ciphertext_hashes.bin-sentinel",
            "encrypted_client_state_ciphertext_hashes.json-sentinel",
            "encrypted_client_state_ciphertext_sha256-sentinel",
            "encrypted_client_state_ciphertexts_sha256-sentinel",
            "encrypted_client_state_ciphertexts_sha256.bin-sentinel",
            "encrypted_client_state_ciphertexts_sha256.json-sentinel",
            "hnsw-query-leaf-sentinel",
            "hnsw-query-proof-sentinel",
            "hnsw-query-proofValue-sentinel",
            "hnsw-query-access-count-sentinel",
            "hnsw-query-accessCounts-sentinel",
            "hnsw-query-access-volume-sentinel",
            "hnsw-query-access-volumes-sentinel",
            "hnsw-query-accessVolume-sentinel",
            "hnsw-query-accessVolumes-sentinel",
            "hnsw-query-access-volume-counts-sentinel",
            "hnsw-query-accessVolumeCounts-sentinel",
            "hnsw-query-access-volume-len-sentinel",
            "hnsw-query-access-volume-lengths-sentinel",
            "hnsw-query-accessVolumeLengths-sentinel",
            "hnsw-query-payload-fetch-token-sentinel",
            "hnsw-query-payloadFetchTokens-sentinel",
            "hnsw-query-payload-fetch-token-dot-sentinel",
            "hnsw-session-id-sentinel",
            "leaf-label-sentinel",
            "oramPositionMapBackup-sentinel",
            "oramPositionMapBackups-sentinel",
            "oram_position_map_backup-sentinel",
            "oram_position_map_backups-sentinel",
            "positionMapBackup-sentinel",
            "positionMapBackups-sentinel",
            "position_map_backup-sentinel",
            "position_map_backups-sentinel",
            "result-bucket-id-sentinel",
            "result-bucketCommitment-sentinel",
            "result-bucketCommitments-sentinel",
            "result-bucket_commitment-sentinel",
            "result-bucket_commitments-sentinel",
            "result-ciphertextSha256-sentinel",
            "result-ciphertextsSha256-sentinel",
            "result-ciphertext_sha256-sentinel",
            "result-ciphertexts_sha256-sentinel",
            "result-query-bucket-sentinel",
            "result-query-proof-values-sentinel",
            "result-query-proofValue-sentinel",
            "result-query-access-counts-sentinel",
            "result-query-accessCount-sentinel",
            "result-query-access-volume-count-sentinel",
            "result-query-access-volume-counts-sentinel",
            "result-query-access-volumes-sentinel",
            "result-query-accessVolumeLength-sentinel",
            "result-query-accessVolumeCounts-sentinel",
            "result-query-accessVolumes-sentinel",
            "result-query-access-volume-len-sentinel",
            "result-query-access-volume-lengths-sentinel",
            "result-query-accessVolumeLengths-sentinel",
            "result-query-payload-fetch-token-sentinel",
            "result-query-payloadFetchTokens-sentinel",
            "result-query-payload-fetch-token-dot-sentinel",
            "result-root-hash-sentinel",
            "result-session-id-sentinel",
            "result-updated-bucket-sentinel",
            "root-hash-sentinel",
            "session-id-sentinel",
            "stashBackup-sentinel",
            "stashBackups-sentinel",
            "stateCiphertext-sentinel",
            "stateCiphertextHash-sentinel",
            "stateCiphertextHashes-sentinel",
            "stateCiphertextSha256-sentinel",
            "stateCiphertextsSha256-sentinel",
            "state_ciphertext-sentinel",
            "state_ciphertext_hash-sentinel",
            "state_ciphertext_hashes-sentinel",
            "state_ciphertext_hashes.json-sentinel",
            "state_ciphertext_sha256-sentinel",
            "state_ciphertexts_sha256-sentinel",
            "state_ciphertexts_sha256.bin-sentinel",
            "state_ciphertexts_sha256.json-sentinel",
            "token-position-map-sentinel",
            "token-position-map-backup-sentinel",
            "tokenMapBackup-sentinel",
            "tokenMapBackups-sentinel",
            "token.map.backup-sentinel",
            "token.map.backup.json-sentinel",
            "token.map.backups-sentinel",
            "token.map.backups.json-sentinel",
            "token_map-sentinel",
            "token_map_backup-sentinel",
            "token_map_backups-sentinel",
            "payloadFetchToken-sentinel",
            "payloadFetchTokens-sentinel",
            "payload_fetch_token-sentinel",
            "payload_fetch_tokens-sentinel",
            "payload.fetch.token-sentinel",
            "payload.fetch.tokens-sentinel",
            "tokenPositionMapBackup-sentinel",
            "tokenPositionMapBackups-sentinel",
            "token.position.map.backup-sentinel",
            "token.position.map.backup.json-sentinel",
            "token.position.map.backups-sentinel",
            "token.position.map.backups.json-sentinel",
            "token_position_map-sentinel",
            "token_position_map_backup-sentinel",
            "token_position_map_backups-sentinel",
            "updated-bucket-sentinel",
            "updatedBucketCommitment-sentinel",
            "updatedBucketCommitments-sentinel",
            "updated_bucket_commitment-sentinel",
            "updated.bucket.commitment-sentinel",
            "updated_bucket_commitments-sentinel",
            "updated.bucket.commitments-sentinel",
            "result-updatedBucketCommitment-sentinel",
            "result-updatedBucketCommitments-sentinel",
            "result-updated_bucket_commitment-sentinel",
            "result-updated.bucket.commitment-sentinel",
            "result-updated_bucket_commitments-sentinel",
            "result-updated.bucket.commitments-sentinel",
        ];
        for sentinel in redacted_sentinels {
            assert!(
                !rest_output.contains(sentinel),
                "REST metrics must not expose `{sentinel}`:\n{rest_output}",
            );
        }

        let mut grpc_per_collection = HashMap::new();
        let mut grpc_methods = HashMap::new();
        let grpc_fixed_endpoints = [
            "/qdrant.PrivateHnswOram/ClosePrivateHnswSession",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths",
            "/qdrant.PrivateHnswOram/GetPrivateHnswManifest",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession",
            "/qdrant.PrivateHnswOram/ReadPrivateHnswPaths",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswManifest",
            "/qdrant.PrivateResultOram/ClosePrivateResultOramSession",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets",
            "/qdrant.PrivateResultOram/GetPrivateResultOramManifest",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession",
            "/qdrant.PrivateResultOram/ReadPrivateResultOramBuckets",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramManifest",
        ];
        for (idx, endpoint) in grpc_fixed_endpoints.iter().enumerate() {
            grpc_methods.insert((*endpoint).to_string(), grpc_status_map(idx + 1));
        }

        let grpc_dynamic_endpoints = [
            "/qdrant.PrivateHnswOram/ClosePrivateHnswSession/session-id-sentinel",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths/updated-bucket-sentinel",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths/updatedBucketCommitment-sentinel",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths/updatedBucketCommitments-sentinel",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths/updated_bucket_commitment-sentinel",
            "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths/updated_bucket_commitments-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client-state-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client-state-backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_states-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStates-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateSnapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateSnapshots-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client.state.snapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client.state.snapshot.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client.state.snapshots.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_snapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_snapshots-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertext-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertextHash-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertextHashes-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertextSha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/clientStateCiphertextsSha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext_hash-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext_hashes.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext_hashes.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertext_sha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertexts_sha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertexts_sha256.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/client_state_ciphertexts_sha256.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateBackups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateSnapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateSnapshots-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state.snapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state.snapshot.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted.client.state.snapshots.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_backups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshot-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshot.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshot.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshots-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_snapshots.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertext-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertextHash-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertextHashes-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertextSha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encryptedClientStateCiphertextsSha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_hash-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_hashes-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_hashes.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_hashes.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertext_sha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertexts_sha256-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertexts_sha256.bin-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/encrypted_client_state_ciphertexts_sha256.json-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/oramPositionMapBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/oramPositionMapBackups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/oram_position_map_backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/oram_position_map_backups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/positionMapBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/positionMapBackups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/position_map_backup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/position_map_backups-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payloadFetchToken-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payloadFetchTokens-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payload_fetch_token-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payload_fetch_tokens-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payload.fetch.token-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/payload.fetch.tokens-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/stashBackup-sentinel",
            "/qdrant.PrivateHnswOram/OpenPrivateHnswSession/stashBackups-sentinel",
            "/qdrant.PrivateHnswOram/ReadPrivateHnswPaths/leaf-label-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/bucket-id-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/ciphertextSha256-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/ciphertextsSha256-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/ciphertext_sha256-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/ciphertexts_sha256-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/bucketCommitment-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/bucketCommitments-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/bucket_commitment-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/bucket.commitment-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/bucket_commitments-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets/bucket.commitments-sentinel",
            "/qdrant.PrivateHnswOram/UploadPrivateHnswManifest/root-hash-sentinel",
            "/qdrant.PrivateResultOram/ClosePrivateResultOramSession/result-session-id-sentinel",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets/result-updated-bucket-sentinel",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets/result-updatedBucketCommitment-sentinel",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets/result-updatedBucketCommitments-sentinel",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets/result-updated_bucket_commitment-sentinel",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets/result-updated.bucket.commitment-sentinel",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets/result-updated_bucket_commitments-sentinel",
            "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets/result-updated.bucket.commitments-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token-position-map-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token-position-map-backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/tokenMapBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/tokenMapBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.map.backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.map.backup.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.map.backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.map.backups.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_map-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_map_backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_map_backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payloadFetchToken-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payloadFetchTokens-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payload_fetch_token-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payload_fetch_tokens-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payload.fetch.token-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/payload.fetch.tokens-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/oramPositionMapBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/oramPositionMapBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/oram_position_map_backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/oram_position_map_backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/positionMapBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/positionMapBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/position_map_backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/position_map_backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stashBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stashBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/tokenPositionMapBackup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/tokenPositionMapBackups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.position.map.backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.position.map.backup.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.position.map.backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token.position.map.backups.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_position_map-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_position_map_backup-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/token_position_map_backups-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertext-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertextHash-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertextHashes-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertextSha256-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/stateCiphertextsSha256-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext_hash-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext_hashes-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext_hashes.json-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertext_sha256-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertexts_sha256-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertexts_sha256.bin-sentinel",
            "/qdrant.PrivateResultOram/OpenPrivateResultOramSession/state_ciphertexts_sha256.json-sentinel",
            "/qdrant.PrivateResultOram/ReadPrivateResultOramBuckets/result-bucket-id-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-bucket-id-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-ciphertextSha256-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-ciphertextsSha256-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-ciphertext_sha256-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-ciphertexts_sha256-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-bucketCommitment-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-bucketCommitments-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-bucket_commitment-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-bucket.commitment-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-bucket_commitments-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets/result-bucket.commitments-sentinel",
            "/qdrant.PrivateResultOram/UploadPrivateResultOramManifest/result-root-hash-sentinel",
        ];
        for endpoint in grpc_dynamic_endpoints {
            grpc_methods.insert(endpoint.to_string(), grpc_status_map(1));
        }
        grpc_per_collection.insert("docs".to_string(), grpc_methods);

        let grpc_telemetry = GrpcTelemetry {
            responses: HashMap::new(),
            per_collection_responses: grpc_per_collection,
        };
        let mut grpc_metrics = MetricsData::empty();
        grpc_telemetry.add_metrics(&mut grpc_metrics, None);
        let grpc_output = grpc_metrics.format_metrics();

        assert!(grpc_output.contains("grpc_responses_total"));
        assert!(grpc_output.contains("collection=\"docs\""));
        for endpoint in grpc_fixed_endpoints {
            assert!(
                grpc_output.contains(&format!("endpoint=\"{endpoint}\"")),
                "expected fixed gRPC endpoint label `{endpoint}` in output:\n{grpc_output}",
            );
        }
        for sentinel in redacted_sentinels {
            assert!(
                !grpc_output.contains(sentinel),
                "gRPC metrics must not expose `{sentinel}`:\n{grpc_output}",
            );
        }
    }

    #[test]
    fn test_per_collection_skips_non_whitelisted() {
        use std::collections::HashMap;

        use segment::common::operation_time_statistics::OperationDurationStatistics;

        use super::{MetricsData, MetricsProvider, WebApiTelemetry};

        let mut per_collection = HashMap::new();
        let mut methods = HashMap::new();
        let mut status_map = HashMap::new();
        status_map.insert(
            200u16,
            OperationDurationStatistics {
                count: 3,
                ..Default::default()
            },
        );
        // This endpoint is NOT in the whitelist
        methods.insert("GET /collections".to_string(), status_map);
        per_collection.insert("col".to_string(), methods);

        let telemetry = WebApiTelemetry {
            responses: HashMap::new(),
            per_collection_responses: per_collection,
        };

        let mut metrics = MetricsData::empty();
        telemetry.add_metrics(&mut metrics, None);
        let output = metrics.format_metrics();

        // Non-whitelisted endpoints should not appear
        assert!(
            !output.contains("collection=\"col\""),
            "Non-whitelisted endpoint should not appear:\n{output}"
        );
    }
}
