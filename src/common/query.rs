use std::collections::{HashMap, VecDeque};
#[cfg(test)]
use std::fs::DirBuilder;
use std::fs::{self, OpenOptions};
use std::io::Read;
#[cfg(test)]
use std::io::Write;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
#[cfg(test)]
use std::time::SystemTime;
use std::time::{Duration, Instant};

use api::rest::{RecommendStrategy, SearchGroupsRequestInternal, SearchRequestInternal};
use collection::collection::ckks_search::{
    CkksCiphertextSegmentIndexSnapshot, CkksCiphertextSegmentSearchRecord,
};
use collection::collection::distance_matrix::*;
use collection::common::batching::batch_requests;
use collection::config::{
    CollectionEncryptionConfig, EncryptedVectorReturnRequest, EncryptionSelector,
    encrypted_vector_return_request, encryption_rule_uses_private_result_oram,
    private_hnsw_oram_api_required_message, private_result_oram_api_required_message,
    private_result_oram_payload_selector_overlap_message,
};
use collection::grouping::group_by::GroupRequest;
use collection::lookup::lookup_ids;
use collection::lookup::types::PseudoId;
use collection::operations::consistency_params::ReadConsistency;
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::types::*;
use collection::operations::universal_query::collection_query::*;
use collection::operations::universal_query::shard_query::{
    FusionInternal, SampleInternal, ScoringQuery, ShardQueryRequest,
};
use collection::recommendations::avg_vector_for_recommendation;
use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::math::scaled_fast_sigmoid;
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CKKS_SCHEME, ENCRYPTED_CKKS_VECTOR_MARKER,
    ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector,
};
use segment::common::reciprocal_rank_fusion::rrf_scoring;
use segment::common::score_fusion::{ScoreFusion, score_fusion};
use segment::data_types::groups::GroupId;
use segment::data_types::vectors::{
    DEFAULT_VECTOR_NAME, Named, NamedQuery, VectorInternal, VectorRef,
};
use segment::index::hnsw_index::ckks_ciphertext_graph::{
    CkksCiphertextHnswGraph, CkksCiphertextIndexedRecord, CkksCiphertextScoreError,
    CkksCiphertextVectorIndex, ckks_ciphertext_from_payload,
};
use segment::json_path::JsonPath;
use segment::types::{
    Distance, EncryptedPayloadReadMode, Filter, Order, Payload, PayloadContainer,
    PayloadEncryptedReadPolicy, PayloadSelector, PointIdType, ScoredPoint, SearchParams, ShardKey,
    WithPayloadInterface, WithVector,
};
use segment::utils::scored_point_ties::ScoredPointTies;
use segment::vector_storage::query::ContextPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shard::query::query_enum::QueryEnum;
use shard::retrieve::record_internal::RecordInternal;
use shard::scroll::ScrollRequestInternal;
use shard::search::CoreSearchRequestBatch;
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::rbac::{AccessRequirements, Auth};

use crate::common::crypto::{
    PayloadWritePlan, payload_write_plan_for_collection_with_crypto_id,
    vector_write_plan_for_collection_with_crypto_id,
};
use crate::settings::Settings;

#[derive(Clone)]
struct CkksSidecarSearchRecord {
    id: PointIdType,
    shard_key: Option<ShardKey>,
    point_id: String,
    encrypted: EncryptedCkksVector,
}

enum CkksSidecarScoring<'a> {
    Nearest {
        query_values: &'a [f32],
    },
    NearestResolved {
        query: CkksSidecarQuerySource<'a>,
    },
    StoredNearest {
        query_point_id: String,
        query_encrypted: EncryptedCkksVector,
    },
    NearestMmr {
        query: CkksSidecarQuerySource<'a>,
        lambda: f32,
        candidates_limit: usize,
    },
    RecommendAverageVectorResolved {
        positives: Vec<CkksSidecarQuerySource<'a>>,
        negatives: Vec<CkksSidecarQuerySource<'a>>,
    },
    RecommendBestScore {
        positives: Vec<&'a [f32]>,
        negatives: Vec<&'a [f32]>,
    },
    RecommendBestScoreResolved {
        positives: Vec<CkksSidecarQuerySource<'a>>,
        negatives: Vec<CkksSidecarQuerySource<'a>>,
    },
    RecommendSumScores {
        positives: Vec<&'a [f32]>,
        negatives: Vec<&'a [f32]>,
    },
    RecommendSumScoresResolved {
        positives: Vec<CkksSidecarQuerySource<'a>>,
        negatives: Vec<CkksSidecarQuerySource<'a>>,
    },
    Discover {
        target: &'a [f32],
        pairs: Vec<(&'a [f32], &'a [f32])>,
    },
    DiscoverResolved {
        target: CkksSidecarQuerySource<'a>,
        pairs: Vec<(CkksSidecarQuerySource<'a>, CkksSidecarQuerySource<'a>)>,
    },
    Context {
        pairs: Vec<(&'a [f32], &'a [f32])>,
    },
    ContextResolved {
        pairs: Vec<(CkksSidecarQuerySource<'a>, CkksSidecarQuerySource<'a>)>,
    },
}

enum CkksSidecarQuerySource<'a> {
    Dense(&'a [f32]),
    ClientEncrypted {
        collection_id: &'a str,
        vector_name: &'a str,
        key_id: &'a str,
        rk_id: &'a str,
        rk_epoch: u64,
        query_nonce: &'a str,
        context_digest: &'a str,
        slots: usize,
        ciphertext: Vec<u8>,
        signature_alg: &'a str,
        signature_key_id: &'a str,
        signature_b64: &'a str,
    },
    Stored {
        point_id: String,
        encrypted: EncryptedCkksVector,
    },
}

#[derive(Clone, Copy)]
enum CkksSidecarHnswQuery<'a> {
    Dense(&'a [f32]),
    ClientEncrypted {
        collection_id: &'a str,
        vector_name: &'a str,
        key_id: &'a str,
        rk_id: &'a str,
        rk_epoch: u64,
        query_nonce: &'a str,
        context_digest: &'a str,
        slots: usize,
        ciphertext: &'a [u8],
        signature_alg: &'a str,
        signature_key_id: &'a str,
        signature_b64: &'a str,
    },
    Stored {
        query_point_id: &'a str,
        query_encrypted: &'a EncryptedCkksVector,
    },
}

fn ckks_sidecar_scoring_source_batches(scoring: &CkksSidecarScoring<'_>) -> usize {
    match scoring {
        CkksSidecarScoring::Nearest { .. }
        | CkksSidecarScoring::NearestResolved { .. }
        | CkksSidecarScoring::StoredNearest { .. }
        | CkksSidecarScoring::NearestMmr { .. } => 1,
        CkksSidecarScoring::RecommendAverageVectorResolved {
            positives,
            negatives,
        } => positives.len().saturating_add(negatives.len()),
        CkksSidecarScoring::RecommendBestScore {
            positives,
            negatives,
        } => positives.len().saturating_add(negatives.len()),
        CkksSidecarScoring::RecommendBestScoreResolved {
            positives,
            negatives,
        } => positives.len().saturating_add(negatives.len()),
        CkksSidecarScoring::RecommendSumScores {
            positives,
            negatives,
        } => positives.len().saturating_add(negatives.len()),
        CkksSidecarScoring::RecommendSumScoresResolved {
            positives,
            negatives,
        } => positives.len().saturating_add(negatives.len()),
        CkksSidecarScoring::Discover { pairs, .. } => {
            1usize.saturating_add(pairs.len().saturating_mul(2))
        }
        CkksSidecarScoring::DiscoverResolved { pairs, .. } => {
            1usize.saturating_add(pairs.len().saturating_mul(2))
        }
        CkksSidecarScoring::Context { pairs } => pairs.len().saturating_mul(2),
        CkksSidecarScoring::ContextResolved { pairs } => pairs.len().saturating_mul(2),
    }
}

#[allow(clippy::too_many_arguments)]
fn record_ckks_client_query_nonce(
    collection_id: &str,
    vector_name: &str,
    key_id: &str,
    rk_id: &str,
    rk_epoch: u64,
    query_nonce: &str,
    _signature_key_id: &str,
    plan: &crate::common::crypto::VectorWritePlan,
) -> Result<(), StorageError> {
    let key = format!(
        "{collection_id}\x1f{vector_name}\x1f{key_id}\x1f{rk_id}\x1f{rk_epoch}\x1f{query_nonce}"
    );
    let mut cache = CKKS_CLIENT_QUERY_NONCE_REPLAY_CACHE.lock().map_err(|_| {
        StorageError::service_error("CKKS client query nonce replay cache mutex was poisoned")
    })?;
    if cache.record(
        key,
        Instant::now(),
        plan.ckks_query_nonce_replay_ttl(),
        plan.ckks_query_nonce_replay_cache_max_entries(),
    ) {
        return Ok(());
    }

    log::warn!("rejected replayed client CKKS query nonce for encrypted vector query");

    Err(StorageError::bad_input(
        "encrypted query nonce was already used recently; regenerate the client-side CKKS query envelope with a fresh query_nonce before retrying",
    ))
}

const CKKS_SIDECAR_HNSW_GRAPH_CACHE_CAPACITY: usize = 16;
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR: &str = "ckks_sidecar_hnsw_graphs";
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_VERSION: u8 = 1;
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(test)]
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_FILES: usize = 32;
#[cfg(test)]
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const CKKS_CLIENT_QUERY_CONTEXT_DIGEST_B64_LEN: usize = 43;
const CKKS_CLIENT_QUERY_CIPHERTEXT_SHA256_B64_LEN: usize = 43;
const CKKS_CLIENT_QUERY_CIPHERTEXT_MAX_BYTES: usize = 16 * 1024 * 1024;
const CKKS_CLIENT_QUERY_CIPHERTEXT_MAX_ENCODED_BYTES: usize =
    (CKKS_CLIENT_QUERY_CIPHERTEXT_MAX_BYTES + 2) / 3 * 4;
const CKKS_GROUPED_SEARCH_CANDIDATE_OVERSAMPLING: usize = 32;
const CKKS_MATRIX_SAMPLE_MAX: usize = 512;
const CKKS_MATRIX_SCORE_PAIR_MAX: usize = CKKS_MATRIX_SAMPLE_MAX * CKKS_MATRIX_SAMPLE_MAX;
const CKKS_SEARCH_FILL_RETRY_SLACK: usize = 32;
const CKKS_SEARCH_FILL_RETRY_MULTIPLIER: usize = 4;

static CKKS_SIDECAR_HNSW_GRAPH_CACHE: LazyLock<Mutex<CkksSidecarHnswGraphCache>> =
    LazyLock::new(|| Mutex::new(CkksSidecarHnswGraphCache::default()));

static CKKS_CLIENT_QUERY_NONCE_REPLAY_CACHE: LazyLock<Mutex<CkksClientQueryNonceReplayCache>> =
    LazyLock::new(|| Mutex::new(CkksClientQueryNonceReplayCache::default()));

#[derive(Default)]
struct CkksClientQueryNonceReplayCache {
    entries: HashMap<String, Instant>,
    order: VecDeque<(String, Instant)>,
}

impl CkksClientQueryNonceReplayCache {
    fn record(&mut self, key: String, now: Instant, ttl: Duration, max_entries: usize) -> bool {
        self.prune(now);
        if self
            .entries
            .get(&key)
            .is_some_and(|expires_at| *expires_at > now)
        {
            return false;
        }

        let expires_at = now + ttl;
        self.entries.insert(key.clone(), expires_at);
        self.order.push_back((key, expires_at));
        while self.entries.len() > max_entries {
            let Some((old_key, old_expires_at)) = self.order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&old_key)
                .is_some_and(|expires_at| *expires_at == old_expires_at)
            {
                self.entries.remove(&old_key);
            }
        }
        true
    }

    fn prune(&mut self, now: Instant) {
        while let Some((key, expires_at)) = self.order.front().cloned() {
            if expires_at > now {
                break;
            }
            self.order.pop_front();
            if self
                .entries
                .get(&key)
                .is_some_and(|current| *current == expires_at)
            {
                self.entries.remove(&key);
            }
        }
    }
}

#[cfg(test)]
fn clear_ckks_client_query_nonce_replay_cache_for_tests() {
    *CKKS_CLIENT_QUERY_NONCE_REPLAY_CACHE.lock().unwrap() =
        CkksClientQueryNonceReplayCache::default();
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CkksSidecarHnswGraphCacheKey {
    collection_identity: String,
    vector_name: String,
    distance: &'static str,
    score_order: &'static str,
    m: usize,
    records_fingerprint: String,
}

type CkksSidecarHnswGraph = CkksCiphertextHnswGraph;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CkksSidecarHnswGraphDisk {
    version: u8,
    collection_identity: String,
    vector_name: String,
    distance: String,
    score_order: String,
    m: usize,
    records_fingerprint: String,
    links: Vec<Vec<usize>>,
}

#[derive(Default)]
struct CkksSidecarHnswGraphCache {
    entries: HashMap<CkksSidecarHnswGraphCacheKey, Arc<CkksSidecarHnswGraph>>,
    order: VecDeque<CkksSidecarHnswGraphCacheKey>,
}

impl CkksSidecarHnswGraphCache {
    fn get(&mut self, key: &CkksSidecarHnswGraphCacheKey) -> Option<Arc<CkksSidecarHnswGraph>> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: CkksSidecarHnswGraphCacheKey, graph: Arc<CkksSidecarHnswGraph>) {
        if self.entries.contains_key(&key) {
            self.entries.insert(key, graph);
            return;
        }

        while self.entries.len() >= CKKS_SIDECAR_HNSW_GRAPH_CACHE_CAPACITY {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&evicted);
        }

        self.order.push_back(key.clone());
        self.entries.insert(key, graph);
    }

    fn invalidate_collection_vectors(
        &mut self,
        collection_identity: &str,
        vector_names: &[String],
    ) {
        if vector_names.is_empty() {
            return;
        }
        self.entries.retain(|key, _| {
            key.collection_identity != collection_identity
                || !vector_names
                    .iter()
                    .any(|vector_name| vector_name.as_str() == key.vector_name)
        });
        self.order.retain(|key| {
            key.collection_identity != collection_identity
                || !vector_names
                    .iter()
                    .any(|vector_name| vector_name.as_str() == key.vector_name)
        });
    }
}

pub(crate) fn invalidate_ckks_sidecar_hnsw_graph_cache(
    collection_identity: &str,
    vector_names: &[String],
) -> Result<(), StorageError> {
    let mut cache = CKKS_SIDECAR_HNSW_GRAPH_CACHE.lock().map_err(|_| {
        StorageError::service_error("CKKS sidecar HNSW graph cache mutex was poisoned")
    })?;
    cache.invalidate_collection_vectors(collection_identity, vector_names);
    Ok(())
}

pub(crate) fn invalidate_ckks_sidecar_hnsw_graph_cache_for_collection_path(
    collection_path: &Path,
    collection_identity: &str,
    vector_names: &[String],
) -> Result<(), StorageError> {
    invalidate_ckks_sidecar_hnsw_graph_cache(collection_identity, vector_names)?;
    if vector_names.is_empty() {
        return Ok(());
    }

    let directory = collection_path.join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
    if !ckks_sidecar_hnsw_existing_cache_directory_is_safe(&directory)? {
        return Ok(());
    }

    let entries = fs::read_dir(&directory).map_err(|_| {
        StorageError::service_error("failed to read CKKS sidecar HNSW graph cache directory")
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            StorageError::service_error(
                "failed to read CKKS sidecar HNSW graph cache directory entry",
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }

        let metadata = fs::symlink_metadata(&path).map_err(|_| {
            StorageError::service_error("failed to inspect CKKS sidecar HNSW graph cache file")
        })?;
        if metadata.file_type().is_symlink() {
            fs::remove_file(&path).map_err(|_| {
                StorageError::service_error("failed to prune CKKS sidecar HNSW graph cache symlink")
            })?;
            ckks_sidecar_hnsw_sync_parent(&path).map_err(|_| {
                StorageError::service_error(
                    "failed to sync CKKS sidecar HNSW graph cache directory after pruning symlink",
                )
            })?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        if metadata.len() > CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES {
            fs::remove_file(&path).map_err(|_| {
                StorageError::service_error(
                    "failed to prune oversized CKKS sidecar HNSW graph cache",
                )
            })?;
            ckks_sidecar_hnsw_sync_parent(&path).map_err(|_| {
                StorageError::service_error("failed to sync CKKS sidecar HNSW graph cache directory after pruning oversized cache")
            })?;
            continue;
        }
        #[cfg(unix)]
        if ckks_sidecar_hnsw_validate_cache_file_unix_metadata(&path, &metadata, "file").is_err() {
            continue;
        }

        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        }
        let Ok(file) = options.open(&path) else {
            continue;
        };
        let mut content = String::with_capacity(metadata.len() as usize);
        let mut limited_file = file.take(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES + 1);
        if limited_file.read_to_string(&mut content).is_err()
            || content.len() as u64 > CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES
        {
            fs::remove_file(&path).map_err(|_| {
                StorageError::service_error(
                    "failed to prune unreadable CKKS sidecar HNSW graph cache",
                )
            })?;
            ckks_sidecar_hnsw_sync_parent(&path).map_err(|_| {
                StorageError::service_error("failed to sync CKKS sidecar HNSW graph cache directory after pruning unreadable cache")
            })?;
            continue;
        }
        let Ok(disk) = serde_json::from_str::<CkksSidecarHnswGraphDisk>(&content) else {
            fs::remove_file(&path).map_err(|_| {
                StorageError::service_error(
                    "failed to prune malformed CKKS sidecar HNSW graph cache",
                )
            })?;
            ckks_sidecar_hnsw_sync_parent(&path).map_err(|_| {
                StorageError::service_error("failed to sync CKKS sidecar HNSW graph cache directory after pruning malformed cache")
            })?;
            continue;
        };
        if disk.collection_identity == collection_identity
            && vector_names
                .iter()
                .any(|vector_name| vector_name == &disk.vector_name)
        {
            fs::remove_file(&path).map_err(|_| {
                StorageError::service_error("failed to invalidate CKKS sidecar HNSW graph cache")
            })?;
            ckks_sidecar_hnsw_sync_parent(&path).map_err(|_| {
                StorageError::service_error("failed to sync CKKS sidecar HNSW graph cache directory after invalidating cache file")
            })?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn do_core_search_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: CoreSearchRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let batch_res = do_core_search_batch_points(
        toc,
        collection_name,
        CoreSearchRequestBatch {
            searches: vec![request],
        },
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc.clone(),
        runtime_settings,
    )
    .await?;
    batch_res
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::service_error("Empty search result"))
}

#[allow(clippy::too_many_arguments)]
pub async fn do_search_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: SearchRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    if let Some(query_request) = ckks_legacy_search_as_query_request(&request) {
        return do_query_points(
            toc,
            collection_name,
            query_request,
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            runtime_settings,
        )
        .await;
    }

    do_core_search_points(
        toc,
        collection_name,
        request.into(),
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
        runtime_settings,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn do_search_batch_points_from_rest(
    toc: &TableOfContent,
    collection_name: &str,
    requests: Vec<(SearchRequestInternal, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let mut results = Vec::with_capacity(requests.len());
    for (request, shard_selection) in requests {
        results.push(
            do_search_points(
                toc,
                collection_name,
                request,
                read_consistency,
                shard_selection,
                auth.clone(),
                timeout,
                hw_measurement_acc.clone(),
                runtime_settings,
            )
            .await?,
        );
    }
    Ok(results)
}

#[allow(dead_code)]
pub async fn do_search_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    requests: Vec<(CoreSearchRequest, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let requests = batch_requests::<
        (CoreSearchRequest, ShardSelectorInternal),
        ShardSelectorInternal,
        Vec<CoreSearchRequest>,
        Vec<_>,
    >(
        requests,
        |(_, shard_selector)| shard_selector,
        |(request, _), core_reqs| {
            core_reqs.push(request);
            Ok(())
        },
        |shard_selector, core_requests, res| {
            if core_requests.is_empty() {
                return Ok(());
            }

            let core_batch = CoreSearchRequestBatch {
                searches: core_requests,
            };

            let req = do_core_search_batch_points(
                toc,
                collection_name,
                core_batch,
                read_consistency,
                shard_selector,
                auth.clone(),
                timeout,
                hw_measurement_acc.clone(),
                runtime_settings,
            );
            res.push(req);
            Ok(())
        },
    )?;

    let results = futures::future::try_join_all(requests).await?;
    let flatten_results: Vec<Vec<_>> = results.into_iter().flatten().collect();
    Ok(flatten_results)
}

fn ckks_legacy_search_as_query_request(
    request: &SearchRequestInternal,
) -> Option<CollectionQueryRequest> {
    let api::rest::NamedVectorStruct::CkksEncryptedQuery(query) = &request.vector else {
        return None;
    };
    Some(CollectionQueryRequest {
        prefetch: Vec::new(),
        query: Some(Query::Vector(VectorQuery::Nearest(
            VectorInputInternal::CkksEncryptedQuery(CkksEncryptedQueryInput {
                version: query.envelope.version,
                scheme: query.envelope.scheme.clone(),
                security_profile: query.envelope.security_profile.clone(),
                collection_id: query.envelope.collection_id.clone(),
                vector_name: query.envelope.vector_name.clone(),
                key_id: query.envelope.key_id.clone(),
                rk_id: query.envelope.rk_id.clone(),
                rk_epoch: query.envelope.rk_epoch,
                query_nonce: query.envelope.query_nonce.clone(),
                context_digest: query.envelope.context_digest.clone(),
                slots: query.envelope.slots,
                ciphertext_sha256: query.envelope.ciphertext_sha256.clone(),
                ciphertext: query.envelope.ciphertext.clone(),
                signature_alg: query.envelope.signature.alg.clone(),
                signature_key_id: query.envelope.signature.key_id.clone(),
                signature_b64: query.envelope.signature.sig.clone(),
            }),
        ))),
        using: query
            .name
            .clone()
            .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string()),
        filter: request.filter.clone(),
        score_threshold: request.score_threshold,
        limit: request.limit,
        offset: request.offset.unwrap_or_default(),
        params: request.params.clone(),
        with_vector: request.with_vector.clone().unwrap_or_default(),
        with_payload: request
            .with_payload
            .clone()
            .unwrap_or(WithPayloadInterface::Bool(false)),
        lookup_from: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn do_core_search_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    mut request: CoreSearchRequestBatch,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let encrypted_payload_read_modes = request
        .searches
        .iter_mut()
        .map(|search| {
            let mode = encrypted_payload_read_mode(search.with_payload.as_ref());
            request_raw_encrypted_payload_for_collection_read(&mut search.with_payload, mode);
            mode
        })
        .collect::<Vec<_>>();
    for search in &request.searches {
        preflight_private_result_oram_raw_payload_read(
            toc,
            collection_name,
            search.with_payload.as_ref(),
            "search",
            &auth,
        )
        .await?;
    }
    preflight_payload_decrypt_modes_for_read(
        toc,
        collection_name,
        &encrypted_payload_read_modes,
        runtime_settings,
        &auth,
    )
    .await?;
    if runtime_settings.is_none() {
        let private_hnsw_vectors =
            private_hnsw_oram_vector_names_for_collection(toc, collection_name, &auth).await?;
        ensure_core_search_batch_does_not_use_private_hnsw_oram_vectors(
            &request,
            &private_hnsw_vectors,
        )?;
    }

    if let Some(settings) = runtime_settings
        && let Some(mut results) = try_ckks_vector_search_batch_points(
            toc,
            collection_name,
            &request,
            read_consistency,
            &shard_selection,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
        )
        .await?
    {
        decrypt_scored_point_batches_for_read(
            toc,
            collection_name,
            &encrypted_payload_read_modes,
            &mut results,
            runtime_settings,
            &auth,
        )
        .await?;
        return Ok(results);
    }

    for search in &request.searches {
        let with_vector = search.with_vector.clone().unwrap_or_default();
        ensure_with_vector_does_not_request_encrypted_vectors(
            toc,
            collection_name,
            &with_vector,
            &auth,
            "search",
        )
        .await?;
    }

    let mut results = toc
        .core_search_batch(
            collection_name,
            request,
            read_consistency,
            shard_selection,
            auth.clone(),
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
    decrypt_scored_point_batches_for_read(
        toc,
        collection_name,
        &encrypted_payload_read_modes,
        &mut results,
        runtime_settings,
        &auth,
    )
    .await?;
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_search_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: &CoreSearchRequestBatch,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
) -> Result<Option<Vec<Vec<ScoredPoint>>>, StorageError> {
    if request.searches.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_search",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let mut has_encrypted_search = false;
    for search in &request.searches {
        if plan.contains_vector_name(search.query.get_vector_name()) {
            has_encrypted_search = true;
        }
    }

    if !has_encrypted_search {
        return Ok(None);
    }

    let mut results = Vec::with_capacity(request.searches.len());
    for search in &request.searches {
        let vector_name = search.query.get_vector_name();
        if let Some(err) = plan.private_hnsw_oram_api_required_error(vector_name) {
            return Err(err);
        }
        if plan.contains_vector_name(vector_name) {
            results.push(
                ckks_vector_search_points(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    search,
                    &plan,
                    read_consistency,
                    shard_selection,
                    timeout,
                    None,
                    hw_measurement_acc.clone(),
                )
                .await?,
            );
        } else {
            let with_vector = search.with_vector.clone().unwrap_or_default();
            ensure_with_vector_does_not_request_encrypted_vectors(
                toc,
                collection_name,
                &with_vector,
                auth,
                "search",
            )
            .await?;
            let mut plain_results = toc
                .core_search_batch(
                    collection_name,
                    CoreSearchRequestBatch {
                        searches: vec![search.clone()],
                    },
                    read_consistency,
                    shard_selection.clone(),
                    auth.clone(),
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?;
            results.push(plain_results.pop().ok_or_else(|| {
                StorageError::service_error(
                    "plaintext search result missing from mixed CKKS vector batch",
                )
            })?);
        }
    }

    Ok(Some(results))
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_search_points(
    collection: &collection::collection::Collection,
    collection_name: &str,
    collection_crypto_id: &str,
    search: &CoreSearchRequest,
    plan: &crate::common::crypto::VectorWritePlan,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    candidate_scan_limit: Option<usize>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let (vector_name, scoring) = match &search.query {
        QueryEnum::Nearest(named_query) => {
            let VectorInternal::Dense(query_values) = &named_query.query else {
                return Err(StorageError::bad_input(
                    "encrypted vector only supports dense query vectors",
                ));
            };
            (
                named_query.get_name(),
                CkksSidecarScoring::Nearest { query_values },
            )
        }
        QueryEnum::RecommendBestScore(named_query) => (
            named_query.get_name(),
            CkksSidecarScoring::RecommendBestScore {
                positives: query_vectors_as_dense_slices(
                    &named_query.query.positives,
                    named_query.get_name(),
                    "positive",
                )?,
                negatives: query_vectors_as_dense_slices(
                    &named_query.query.negatives,
                    named_query.get_name(),
                    "negative",
                )?,
            },
        ),
        QueryEnum::RecommendSumScores(named_query) => (
            named_query.get_name(),
            CkksSidecarScoring::RecommendSumScores {
                positives: query_vectors_as_dense_slices(
                    &named_query.query.positives,
                    named_query.get_name(),
                    "positive",
                )?,
                negatives: query_vectors_as_dense_slices(
                    &named_query.query.negatives,
                    named_query.get_name(),
                    "negative",
                )?,
            },
        ),
        QueryEnum::Discover(named_query) => {
            let VectorInternal::Dense(target) = &named_query.query.target else {
                return Err(StorageError::bad_input(
                    "encrypted vector discover cannot resolve point-id or non-dense target examples because plaintext vectors are not stored",
                ));
            };
            (
                named_query.get_name(),
                CkksSidecarScoring::Discover {
                    target,
                    pairs: query_context_pairs_as_dense_slices(
                        &named_query.query.pairs,
                        named_query.get_name(),
                    )?,
                },
            )
        }
        QueryEnum::Context(named_query) => (
            named_query.get_name(),
            CkksSidecarScoring::Context {
                pairs: query_context_pairs_as_dense_slices(
                    &named_query.query.pairs,
                    named_query.get_name(),
                )?,
            },
        ),
        _ => {
            return Err(StorageError::bad_input(
                "encrypted vector only supports dense nearest-neighbor search, raw-dense recommend, raw-dense discover, and raw-dense context over the CKKS sidecar",
            ));
        }
    };
    ckks_vector_search_points_with_scoring(
        collection,
        collection_name,
        collection_crypto_id,
        vector_name,
        scoring,
        search.filter.clone(),
        search.params.clone(),
        search.limit,
        search.offset,
        search.with_payload.clone(),
        search.with_vector.clone(),
        search.score_threshold,
        candidate_scan_limit,
        plan,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_search_points_with_scoring(
    collection: &collection::collection::Collection,
    collection_name: &str,
    collection_crypto_id: &str,
    vector_name: &str,
    scoring: CkksSidecarScoring<'_>,
    filter: Option<Filter>,
    params: Option<SearchParams>,
    limit: usize,
    offset: usize,
    with_payload: Option<WithPayloadInterface>,
    with_vector: Option<WithVector>,
    score_threshold: Option<f32>,
    candidate_scan_limit: Option<usize>,
    plan: &crate::common::crypto::VectorWritePlan,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<ScoredPoint>, StorageError> {
    if matches!(candidate_scan_limit, Some(0)) || limit == 0 {
        return Ok(Vec::new());
    }
    let distance = plan
        .distance_for_vector(vector_name)
        .ok_or_else(ckks_search_plan_lost_rule_error)?;
    let score_order = match &scoring {
        CkksSidecarScoring::Nearest { .. }
        | CkksSidecarScoring::NearestResolved { .. }
        | CkksSidecarScoring::StoredNearest { .. } => distance.distance_order(),
        CkksSidecarScoring::NearestMmr { .. } => {
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(
                    "encrypted vector MMR requires a large-better metric such as dot or cosine",
                ));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::RecommendAverageVectorResolved {
            positives,
            negatives: _,
        } => {
            if positives.is_empty() {
                return Err(StorageError::bad_input(
                    "encrypted vector average-vector recommend requires at least one positive example",
                ));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(
                    "encrypted vector average-vector point-id recommend requires a large-better metric such as dot or cosine",
                ));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::RecommendBestScore {
            positives,
            negatives,
        }
        | CkksSidecarScoring::RecommendSumScores {
            positives,
            negatives,
        } => {
            if positives.is_empty() && negatives.is_empty() {
                return Err(StorageError::bad_input(
                    "encrypted vector recommend requires at least one raw dense example",
                ));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(
                    "encrypted vector recommend best-score and sum-scores require a large-better metric such as dot or cosine",
                ));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::RecommendBestScoreResolved {
            positives,
            negatives,
        }
        | CkksSidecarScoring::RecommendSumScoresResolved {
            positives,
            negatives,
        } => {
            if positives.is_empty() && negatives.is_empty() {
                return Err(StorageError::bad_input(
                    "encrypted vector recommend requires at least one example",
                ));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(
                    "encrypted vector recommend best-score and sum-scores require a large-better metric such as dot or cosine",
                ));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::Discover { .. } | CkksSidecarScoring::DiscoverResolved { .. } => {
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(
                    "encrypted vector discover with sidecar scoring requires a large-better metric such as dot or cosine",
                ));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::Context { pairs } => {
            if pairs.is_empty() {
                return Err(StorageError::bad_input(
                    "encrypted vector context query requires at least one raw dense context pair",
                ));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(
                    "encrypted vector context query with sidecar scoring requires a large-better metric such as dot or cosine",
                ));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::ContextResolved { pairs } => {
            if pairs.is_empty() {
                return Err(StorageError::bad_input(
                    "encrypted vector context query requires at least one context pair",
                ));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(
                    "encrypted vector context query with sidecar scoring requires a large-better metric such as dot or cosine",
                ));
            }
            Order::LargeBetter
        }
    };
    let source_batches = ckks_sidecar_scoring_source_batches(&scoring);
    let source_batch_max = plan.ckks_scoring_source_batch_max();
    if source_batches > source_batch_max {
        return Err(StorageError::bad_input(format!(
            "encrypted vector CKKS query uses {source_batches} scoring source batches; maximum is {source_batch_max}",
        )));
    }
    if let CkksSidecarScoring::NearestResolved {
        query:
            CkksSidecarQuerySource::ClientEncrypted {
                collection_id,
                vector_name: envelope_vector_name,
                key_id,
                rk_id,
                rk_epoch,
                query_nonce,
                context_digest,
                slots,
                ciphertext,
                signature_alg,
                signature_key_id,
                signature_b64,
            },
    } = &scoring
    {
        plan.validate_client_encrypted_query(
            collection_name,
            vector_name,
            collection_id,
            envelope_vector_name,
            key_id,
            rk_id,
            *rk_epoch,
            query_nonce,
            context_digest,
            *slots,
            ciphertext,
            signature_alg,
            signature_key_id,
            signature_b64,
        )?
        .ok_or_else(ckks_search_plan_lost_rule_error)?;
        record_ckks_client_query_nonce(
            collection_id,
            envelope_vector_name,
            key_id,
            rk_id,
            *rk_epoch,
            query_nonce,
            signature_key_id,
            plan,
        )?;
    }
    let with_vector = with_vector.unwrap_or_default();
    if with_vector.is_enabled() {
        return Err(StorageError::bad_input(
            "cannot return encrypted vector; CKKS vector ciphertext read path returns payload sidecar only",
        ));
    }
    if let Some(params) = params.as_ref()
        && !ckks_search_params_supported(params)
    {
        return Err(StorageError::bad_input(
            "encrypted vector CKKS sidecar scoring does not support quantization, indexed_only, or ACORN search params",
        ));
    }
    let hnsw_ef = params
        .as_ref()
        .and_then(|params| (!params.exact).then_some(params.hnsw_ef).flatten());
    if hnsw_ef.is_some()
        && !matches!(
            &scoring,
            CkksSidecarScoring::Nearest { .. }
                | CkksSidecarScoring::StoredNearest { .. }
                | CkksSidecarScoring::NearestResolved {
                    query: CkksSidecarQuerySource::ClientEncrypted { .. },
                }
        )
    {
        return Err(StorageError::bad_input(
            "encrypted vector HNSW sidecar search currently supports only dense, client-encrypted, or point-id nearest-neighbor queries",
        ));
    }
    if let Some(hnsw_ef) = hnsw_ef
        && filter.is_none()
        && read_consistency.is_none()
    {
        let segment_snapshot = collection
            .ckks_ciphertext_segment_search_snapshot(vector_name, shard_selection)
            .await?;
        if segment_snapshot.complete {
            let hnsw_query = match &scoring {
                CkksSidecarScoring::Nearest { query_values } => {
                    CkksSidecarHnswQuery::Dense(query_values)
                }
                CkksSidecarScoring::NearestResolved {
                    query:
                        CkksSidecarQuerySource::ClientEncrypted {
                            collection_id,
                            vector_name: envelope_vector_name,
                            key_id,
                            rk_id,
                            rk_epoch,
                            query_nonce,
                            context_digest,
                            slots,
                            ciphertext,
                            signature_alg,
                            signature_key_id,
                            signature_b64,
                        },
                } => CkksSidecarHnswQuery::ClientEncrypted {
                    collection_id,
                    vector_name: envelope_vector_name,
                    key_id,
                    rk_id,
                    rk_epoch: *rk_epoch,
                    query_nonce,
                    context_digest,
                    slots: *slots,
                    ciphertext,
                    signature_alg,
                    signature_key_id,
                    signature_b64,
                },
                CkksSidecarScoring::StoredNearest {
                    query_point_id,
                    query_encrypted,
                } => CkksSidecarHnswQuery::Stored {
                    query_point_id,
                    query_encrypted,
                },
                _ => {
                    return Err(StorageError::service_error(
                        "CKKS HNSW segment search received a non-nearest scoring request",
                    ));
                }
            };
            let hnsw_top = ckks_scored_fill_candidate_limit(offset, limit, candidate_scan_limit);
            let mut segment_scored_by_id = HashMap::<_, ScoredPoint>::new();
            let indexed_points = ckks_sidecar_hnsw_search_segment_snapshots(
                collection_name,
                vector_name,
                plan,
                &segment_snapshot.indexed_segments,
                hnsw_query,
                score_order,
                score_threshold,
                hnsw_ef,
                hnsw_top,
            )?;
            let residual_records = segment_snapshot
                .residual_records
                .into_iter()
                .map(
                    |CkksCiphertextSegmentSearchRecord {
                         id,
                         shard_key,
                         point_id,
                         encrypted,
                         ..
                     }| CkksSidecarSearchRecord {
                        id,
                        shard_key,
                        point_id,
                        encrypted,
                    },
                )
                .collect::<Vec<_>>();
            let residual_points = ckks_sidecar_hnsw_search_points(
                collection_name,
                collection_crypto_id,
                vector_name,
                collection.path(),
                plan,
                &residual_records,
                hnsw_query,
                distance,
                score_order,
                score_threshold,
                hnsw_ef,
                hnsw_top,
            )?;

            for scored_point in indexed_points.into_iter().chain(residual_points) {
                match segment_scored_by_id.entry(scored_point.id) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        if ckks_scored_point_is_better(score_order, &scored_point, entry.get()) {
                            entry.insert(scored_point);
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(scored_point);
                    }
                }
            }

            let mut scored = segment_scored_by_id.into_values().collect::<Vec<_>>();
            sort_ckks_scored_points(score_order, &mut scored);
            let top = ckks_select_and_fill_scored_points_payload_or_vectors(
                collection,
                scored,
                offset,
                limit,
                with_payload.unwrap_or(WithPayloadInterface::Bool(false)),
                with_vector,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await?;

            return Ok(top);
        }
    }

    let mut next_offset = None;
    let mut remaining_candidate_scan_limit = candidate_scan_limit;
    let mut scored_by_id = std::collections::HashMap::<_, ScoredPoint>::new();
    // Stored ciphertexts are only needed again for MMR re-ranking; every other scoring mode
    // must not pin the whole collection's ciphertexts in memory for the duration of a search.
    let retain_ciphertexts_for_mmr = matches!(scoring, CkksSidecarScoring::NearestMmr { .. });
    let mut encrypted_by_id =
        std::collections::HashMap::<PointIdType, (String, EncryptedCkksVector)>::new();
    let mut hnsw_records = Vec::new();
    const BATCH_SIZE: usize = 512;

    loop {
        let scroll_result = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: next_offset,
                    limit: Some(BATCH_SIZE),
                    filter: filter.clone(),
                    with_payload: Some(encrypted_vector_sidecar_payload_selector()),
                    with_vector: WithVector::Bool(false),
                    order_by: None,
                },
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;

        let mut encrypted_records = Vec::new();
        for record in scroll_result.points {
            let Some(payload) = record.payload.as_ref() else {
                continue;
            };
            let Some(encrypted) = encrypted_vector_from_payload(payload, vector_name)? else {
                continue;
            };
            let point_id = record.id.to_string();
            encrypted_records.push(CkksSidecarSearchRecord {
                id: record.id,
                shard_key: record.shard_key,
                point_id,
                encrypted,
            });
        }
        if let Some(remaining) = remaining_candidate_scan_limit.as_mut() {
            if *remaining == 0 {
                break;
            }
            if encrypted_records.len() > *remaining {
                encrypted_records.truncate(*remaining);
            }
            *remaining = remaining.saturating_sub(encrypted_records.len());
        }

        if hnsw_ef.is_some() {
            hnsw_records.extend(encrypted_records);
            if matches!(remaining_candidate_scan_limit, Some(0)) {
                break;
            }
            let Some(offset) = scroll_result.next_page_offset else {
                break;
            };
            next_offset = Some(offset);
            continue;
        }

        if !encrypted_records.is_empty() {
            let encrypted_items = encrypted_records
                .iter()
                .map(|record| (record.point_id.clone(), record.encrypted.clone()))
                .collect::<Vec<_>>();
            let scores = match &scoring {
                CkksSidecarScoring::Nearest { query_values } => plan
                    .score_encrypted_query_batch(
                        collection_name,
                        vector_name,
                        &encrypted_items,
                        query_values,
                    )?
                    .ok_or_else(ckks_search_plan_lost_rule_error)?,
                CkksSidecarScoring::NearestResolved { query } => ckks_score_query_source_batch(
                    collection_name,
                    vector_name,
                    plan,
                    query,
                    &encrypted_items,
                )?,
                CkksSidecarScoring::StoredNearest {
                    query_point_id,
                    query_encrypted,
                } => plan
                    .score_stored_query_batch(
                        collection_name,
                        vector_name,
                        query_point_id,
                        query_encrypted,
                        &encrypted_items,
                    )?
                    .ok_or_else(ckks_search_plan_lost_rule_error)?,
                CkksSidecarScoring::NearestMmr { query, .. } => ckks_score_query_source_batch(
                    collection_name,
                    vector_name,
                    plan,
                    query,
                    &encrypted_items,
                )?,
                CkksSidecarScoring::RecommendBestScore {
                    positives,
                    negatives,
                } => {
                    let mut positive_scores = vec![f32::NEG_INFINITY; encrypted_items.len()];
                    for query_values in positives {
                        let batch_scores = plan
                            .score_encrypted_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                query_values,
                            )?
                            .ok_or_else(ckks_search_plan_lost_rule_error)?;
                        for (current, score) in positive_scores.iter_mut().zip(batch_scores) {
                            *current = current.max(score);
                        }
                    }

                    let mut negative_scores = vec![f32::NEG_INFINITY; encrypted_items.len()];
                    for query_values in negatives {
                        let batch_scores = plan
                            .score_encrypted_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                query_values,
                            )?
                            .ok_or_else(ckks_search_plan_lost_rule_error)?;
                        for (current, score) in negative_scores.iter_mut().zip(batch_scores) {
                            *current = current.max(score);
                        }
                    }

                    positive_scores
                        .into_iter()
                        .zip(negative_scores)
                        .map(|(positive, negative)| {
                            if positive > negative {
                                scaled_fast_sigmoid(positive)
                            } else {
                                -scaled_fast_sigmoid(negative)
                            }
                        })
                        .collect()
                }
                CkksSidecarScoring::RecommendAverageVectorResolved {
                    positives,
                    negatives,
                } => {
                    let mut total_scores = vec![0.0; encrypted_items.len()];
                    let positive_weight = 1.0 / positives.len() as f32;
                    for source in positives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total += score * positive_weight;
                        }
                    }
                    if !negatives.is_empty() {
                        let negative_weight = 1.0 / negatives.len() as f32;
                        for source in negatives {
                            let batch_scores = ckks_score_query_source_batch(
                                collection_name,
                                vector_name,
                                plan,
                                source,
                                &encrypted_items,
                            )?;
                            for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                                *total -= score * negative_weight;
                            }
                        }
                    }
                    total_scores
                }
                CkksSidecarScoring::RecommendBestScoreResolved {
                    positives,
                    negatives,
                } => {
                    let mut positive_scores = vec![f32::NEG_INFINITY; encrypted_items.len()];
                    for source in positives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
                        for (current, score) in positive_scores.iter_mut().zip(batch_scores) {
                            *current = current.max(score);
                        }
                    }

                    let mut negative_scores = vec![f32::NEG_INFINITY; encrypted_items.len()];
                    for source in negatives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
                        for (current, score) in negative_scores.iter_mut().zip(batch_scores) {
                            *current = current.max(score);
                        }
                    }

                    positive_scores
                        .into_iter()
                        .zip(negative_scores)
                        .map(|(positive, negative)| {
                            if positive > negative {
                                scaled_fast_sigmoid(positive)
                            } else {
                                -scaled_fast_sigmoid(negative)
                            }
                        })
                        .collect()
                }
                CkksSidecarScoring::RecommendSumScores {
                    positives,
                    negatives,
                } => {
                    let mut total_scores = vec![0.0; encrypted_items.len()];
                    for query_values in positives {
                        let batch_scores = plan
                            .score_encrypted_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                query_values,
                            )?
                            .ok_or_else(ckks_search_plan_lost_rule_error)?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total += score;
                        }
                    }
                    for query_values in negatives {
                        let batch_scores = plan
                            .score_encrypted_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                query_values,
                            )?
                            .ok_or_else(ckks_search_plan_lost_rule_error)?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total -= score;
                        }
                    }
                    total_scores
                }
                CkksSidecarScoring::RecommendSumScoresResolved {
                    positives,
                    negatives,
                } => {
                    let mut total_scores = vec![0.0; encrypted_items.len()];
                    for source in positives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total += score;
                        }
                    }
                    for source in negatives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total -= score;
                        }
                    }
                    total_scores
                }
                CkksSidecarScoring::Discover { target, pairs } => {
                    let target_scores = plan
                        .score_encrypted_query_batch(
                            collection_name,
                            vector_name,
                            &encrypted_items,
                            target,
                        )?
                        .ok_or_else(ckks_search_plan_lost_rule_error)?;
                    let mut rank_scores = vec![0i32; encrypted_items.len()];
                    for (positive, negative) in pairs {
                        let positive_scores = plan
                            .score_encrypted_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                positive,
                            )?
                            .ok_or_else(ckks_search_plan_lost_rule_error)?;
                        let negative_scores = plan
                            .score_encrypted_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                negative,
                            )?
                            .ok_or_else(ckks_search_plan_lost_rule_error)?;
                        for ((rank, positive), negative) in rank_scores
                            .iter_mut()
                            .zip(positive_scores)
                            .zip(negative_scores)
                        {
                            *rank += match positive.total_cmp(&negative) {
                                std::cmp::Ordering::Greater => 1,
                                std::cmp::Ordering::Less => -1,
                                std::cmp::Ordering::Equal => 0,
                            };
                        }
                    }
                    target_scores
                        .into_iter()
                        .zip(rank_scores)
                        .map(|(target_score, rank)| rank as f32 + scaled_fast_sigmoid(target_score))
                        .collect()
                }
                CkksSidecarScoring::DiscoverResolved { target, pairs } => {
                    let target_scores = ckks_score_query_source_batch(
                        collection_name,
                        vector_name,
                        plan,
                        target,
                        &encrypted_items,
                    )?;
                    let mut rank_scores = vec![0i32; encrypted_items.len()];
                    for (positive, negative) in pairs {
                        let positive_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            positive,
                            &encrypted_items,
                        )?;
                        let negative_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            negative,
                            &encrypted_items,
                        )?;
                        for ((rank, positive), negative) in rank_scores
                            .iter_mut()
                            .zip(positive_scores)
                            .zip(negative_scores)
                        {
                            *rank += match positive.total_cmp(&negative) {
                                std::cmp::Ordering::Greater => 1,
                                std::cmp::Ordering::Less => -1,
                                std::cmp::Ordering::Equal => 0,
                            };
                        }
                    }
                    target_scores
                        .into_iter()
                        .zip(rank_scores)
                        .map(|(target_score, rank)| rank as f32 + scaled_fast_sigmoid(target_score))
                        .collect()
                }
                CkksSidecarScoring::Context { pairs } => {
                    let mut rank_scores = vec![0i32; encrypted_items.len()];
                    for (positive, negative) in pairs {
                        let positive_scores = plan
                            .score_encrypted_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                positive,
                            )?
                            .ok_or_else(ckks_search_plan_lost_rule_error)?;
                        let negative_scores = plan
                            .score_encrypted_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                negative,
                            )?
                            .ok_or_else(ckks_search_plan_lost_rule_error)?;
                        for ((rank, positive), negative) in rank_scores
                            .iter_mut()
                            .zip(positive_scores)
                            .zip(negative_scores)
                        {
                            *rank += match positive.total_cmp(&negative) {
                                std::cmp::Ordering::Greater => 1,
                                std::cmp::Ordering::Less => -1,
                                std::cmp::Ordering::Equal => 0,
                            };
                        }
                    }
                    rank_scores.into_iter().map(|rank| rank as f32).collect()
                }
                CkksSidecarScoring::ContextResolved { pairs } => {
                    let mut rank_scores = vec![0i32; encrypted_items.len()];
                    for (positive, negative) in pairs {
                        let positive_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            positive,
                            &encrypted_items,
                        )?;
                        let negative_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            negative,
                            &encrypted_items,
                        )?;
                        for ((rank, positive), negative) in rank_scores
                            .iter_mut()
                            .zip(positive_scores)
                            .zip(negative_scores)
                        {
                            *rank += match positive.total_cmp(&negative) {
                                std::cmp::Ordering::Greater => 1,
                                std::cmp::Ordering::Less => -1,
                                std::cmp::Ordering::Equal => 0,
                            };
                        }
                    }
                    rank_scores.into_iter().map(|rank| rank as f32).collect()
                }
            };
            for (record, score) in encrypted_records.into_iter().zip(scores) {
                if !ckks_score_passes_threshold(score_order, score, score_threshold) {
                    continue;
                }
                if retain_ciphertexts_for_mmr {
                    encrypted_by_id.insert(
                        record.id,
                        (record.point_id.clone(), record.encrypted.clone()),
                    );
                }
                let scored_point = ScoredPoint {
                    id: record.id,
                    version: 0,
                    score,
                    payload: None,
                    vector: None,
                    shard_key: record.shard_key,
                    order_value: None,
                };
                match scored_by_id.entry(scored_point.id) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        if ckks_scored_point_is_better(score_order, &scored_point, entry.get()) {
                            entry.insert(scored_point);
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(scored_point);
                    }
                }
            }
        }

        let Some(offset) = scroll_result.next_page_offset else {
            break;
        };
        next_offset = Some(offset);
    }

    if let Some(hnsw_ef) = hnsw_ef {
        let hnsw_query = match &scoring {
            CkksSidecarScoring::Nearest { query_values } => {
                CkksSidecarHnswQuery::Dense(query_values)
            }
            CkksSidecarScoring::NearestResolved {
                query:
                    CkksSidecarQuerySource::ClientEncrypted {
                        collection_id,
                        vector_name: envelope_vector_name,
                        key_id,
                        rk_id,
                        rk_epoch,
                        query_nonce,
                        context_digest,
                        slots,
                        ciphertext,
                        signature_alg,
                        signature_key_id,
                        signature_b64,
                    },
            } => CkksSidecarHnswQuery::ClientEncrypted {
                collection_id,
                vector_name: envelope_vector_name,
                key_id,
                rk_id,
                rk_epoch: *rk_epoch,
                query_nonce,
                context_digest,
                slots: *slots,
                ciphertext,
                signature_alg,
                signature_key_id,
                signature_b64,
            },
            CkksSidecarScoring::StoredNearest {
                query_point_id,
                query_encrypted,
            } => CkksSidecarHnswQuery::Stored {
                query_point_id,
                query_encrypted,
            },
            _ => {
                return Err(StorageError::service_error(
                    "CKKS HNSW scroll search received a non-nearest scoring request",
                ));
            }
        };
        let hnsw_top = ckks_scored_fill_candidate_limit(offset, limit, candidate_scan_limit);
        let hnsw_points = ckks_sidecar_hnsw_search_points(
            collection_name,
            collection_crypto_id,
            vector_name,
            collection.path(),
            plan,
            &hnsw_records,
            hnsw_query,
            distance,
            score_order,
            score_threshold,
            hnsw_ef,
            hnsw_top,
        )?;

        for scored_point in hnsw_points {
            match scored_by_id.entry(scored_point.id) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    if ckks_scored_point_is_better(score_order, &scored_point, entry.get()) {
                        entry.insert(scored_point);
                    }
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(scored_point);
                }
            }
        }
    }

    if let CkksSidecarScoring::NearestMmr {
        lambda,
        candidates_limit,
        ..
    } = &scoring
    {
        let max_candidates = plan.ckks_grouped_max_candidates();
        if *candidates_limit > max_candidates {
            return Err(StorageError::bad_input(format!(
                "encrypted vector MMR may re-rank at most {max_candidates} candidates",
            )));
        }
        let mut candidates = scored_by_id.into_values().collect::<Vec<_>>();
        sort_ckks_scored_points(score_order, &mut candidates);
        let selection_limit = ckks_scored_fill_candidate_limit(0, limit, Some(candidates.len()));
        candidates.truncate((*candidates_limit).max(selection_limit));
        // Only the retained candidates need their ciphertexts from here on.
        let retained_ids = candidates
            .iter()
            .map(|candidate| candidate.id)
            .collect::<std::collections::HashSet<_>>();
        encrypted_by_id.retain(|id, _| retained_ids.contains(id));
        let mut selected = Vec::new();
        if !candidates.is_empty() && limit > 0 {
            // Each candidate's maximum similarity to the selected set is maintained
            // incrementally: every newly selected point is scored against all remaining
            // candidates in batched bridge calls, so a selection of k points costs O(k)
            // batched round trips instead of O(k^2 * candidates) single-item calls.
            let mut max_similarity = vec![f32::NEG_INFINITY; candidates.len()];
            let mut remaining = (1..candidates.len()).collect::<Vec<_>>();
            let mut newly_selected = 0usize;
            selected.push(newly_selected);
            while selected.len() < selection_limit && !remaining.is_empty() {
                if let Some((selected_point_id, selected_encrypted)) =
                    encrypted_by_id.get(&candidates[newly_selected].id)
                {
                    let scoreable = remaining
                        .iter()
                        .copied()
                        .filter(|idx| encrypted_by_id.contains_key(&candidates[*idx].id))
                        .collect::<Vec<_>>();
                    for chunk in scoreable.chunks(source_batch_max.max(1)) {
                        let batch = chunk
                            .iter()
                            .filter_map(|idx| encrypted_by_id.get(&candidates[*idx].id).cloned())
                            .collect::<Vec<_>>();
                        let scores = plan
                            .score_stored_query_batch(
                                collection_name,
                                vector_name,
                                selected_point_id,
                                selected_encrypted,
                                &batch,
                            )?
                            .ok_or_else(ckks_search_plan_lost_rule_error)?;
                        if scores.len() != chunk.len() {
                            return Err(StorageError::service_error(
                                "CKKS MMR sidecar scoring returned a mismatched score count",
                            ));
                        }
                        for (idx, similarity) in chunk.iter().zip(scores) {
                            max_similarity[*idx] = max_similarity[*idx].max(similarity);
                        }
                    }
                }
                let mut best_position = 0usize;
                let mut best_score = f32::NEG_INFINITY;
                for (position, candidate_idx) in remaining.iter().copied().enumerate() {
                    if !encrypted_by_id.contains_key(&candidates[candidate_idx].id) {
                        continue;
                    }
                    let mmr_score = *lambda * candidates[candidate_idx].score
                        - (1.0 - *lambda) * max_similarity[candidate_idx];
                    if mmr_score > best_score {
                        best_score = mmr_score;
                        best_position = position;
                    }
                }
                newly_selected = remaining.swap_remove(best_position);
                selected.push(newly_selected);
            }
        }

        let top_candidates = selected
            .into_iter()
            .filter_map(|idx| candidates.get(idx).cloned())
            .collect::<Vec<_>>();
        let top = ckks_select_and_fill_scored_points_payload_or_vectors(
            collection,
            top_candidates,
            0,
            limit,
            with_payload.unwrap_or(WithPayloadInterface::Bool(false)),
            with_vector,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc,
        )
        .await?;

        return Ok(top);
    }

    let mut scored = scored_by_id.into_values().collect::<Vec<_>>();
    sort_ckks_scored_points(score_order, &mut scored);
    ckks_select_and_fill_scored_points_payload_or_vectors(
        collection,
        scored,
        offset,
        limit,
        with_payload.unwrap_or(WithPayloadInterface::Bool(false)),
        with_vector,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await
}

fn ckks_scored_fill_candidate_limit(
    offset: usize,
    limit: usize,
    candidate_scan_limit: Option<usize>,
) -> usize {
    if limit == 0 {
        return 0;
    }

    let requested = offset.saturating_add(limit);
    let refill_slack = limit
        .saturating_mul(CKKS_SEARCH_FILL_RETRY_MULTIPLIER.saturating_sub(1))
        .max(CKKS_SEARCH_FILL_RETRY_SLACK);
    requested
        .saturating_add(refill_slack)
        .min(candidate_scan_limit.unwrap_or(usize::MAX))
}

#[allow(clippy::too_many_arguments)]
async fn ckks_select_and_fill_scored_points_payload_or_vectors(
    collection: &collection::collection::Collection,
    scored: Vec<ScoredPoint>,
    offset: usize,
    limit: usize,
    with_payload: WithPayloadInterface,
    with_vector: WithVector,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<ScoredPoint>, StorageError> {
    if scored.is_empty() || limit == 0 {
        return Ok(Vec::new());
    }

    let candidate_limit = ckks_scored_fill_candidate_limit(offset, limit, Some(scored.len()));
    let mut candidates = scored.into_iter().take(candidate_limit).collect::<Vec<_>>();
    ckks_fill_scored_points_payload_or_vectors(
        collection,
        &mut candidates,
        with_payload,
        with_vector,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await?;

    Ok(candidates.into_iter().skip(offset).take(limit).collect())
}

#[allow(clippy::too_many_arguments)]
async fn ckks_fill_scored_points_payload_or_vectors(
    collection: &collection::collection::Collection,
    points: &mut Vec<ScoredPoint>,
    with_payload: WithPayloadInterface,
    with_vector: WithVector,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<(), StorageError> {
    if points.is_empty() {
        return Ok(());
    }

    let records = collection
        .retrieve(
            PointRequestInternal {
                ids: points.iter().map(|point| point.id).collect(),
                with_payload: Some(with_payload),
                with_vector,
            },
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc,
        )
        .await?;
    ckks_hydrate_scored_points_from_records(points, records);

    Ok(())
}

fn ckks_hydrate_scored_points_from_records(
    points: &mut Vec<ScoredPoint>,
    records: Vec<RecordInternal>,
) {
    let mut records_by_id = records
        .into_iter()
        .map(|record| (record.id, record))
        .collect::<std::collections::HashMap<_, _>>();

    let mut hydrated = Vec::with_capacity(points.len());
    for mut point in std::mem::take(points) {
        if let Some(record) = records_by_id.remove(&point.id) {
            point.version = record.version;
            point.payload = record.payload;
            point.vector = record.vector;
            point.shard_key = record.shard_key.or_else(|| point.shard_key.clone());
            hydrated.push(point);
        }
    }
    *points = hydrated;
}

fn ckks_score_passes_threshold(order: Order, score: f32, score_threshold: Option<f32>) -> bool {
    score_threshold.is_none_or(|threshold| match order {
        Order::LargeBetter => score > threshold,
        Order::SmallBetter => score < threshold,
    })
}

fn ckks_scored_point_is_better(
    order: Order,
    candidate: &ScoredPoint,
    current: &ScoredPoint,
) -> bool {
    match order {
        Order::LargeBetter => ScoredPointTies(candidate) > ScoredPointTies(current),
        Order::SmallBetter => ScoredPointTies(candidate) < ScoredPointTies(current),
    }
}

fn sort_ckks_scored_points(order: Order, scored: &mut [ScoredPoint]) {
    scored.sort_unstable_by(|a, b| match order {
        Order::LargeBetter => ScoredPointTies(b).cmp(&ScoredPointTies(a)),
        Order::SmallBetter => ScoredPointTies(a).cmp(&ScoredPointTies(b)),
    });
}

fn query_vectors_as_dense_slices<'a>(
    vectors: &'a [VectorInternal],
    _vector_name: &str,
    role: &str,
) -> Result<Vec<&'a [f32]>, StorageError> {
    vectors
        .iter()
        .map(|vector| match vector {
            VectorInternal::Dense(values) => Ok(values.as_slice()),
            _ => Err(StorageError::bad_input(format!(
                "encrypted vector recommend only supports raw dense {role} examples",
            ))),
        })
        .collect()
}

fn query_context_pairs_as_dense_slices<'a>(
    pairs: &'a [ContextPair<VectorInternal>],
    _vector_name: &str,
) -> Result<Vec<(&'a [f32], &'a [f32])>, StorageError> {
    pairs
        .iter()
        .map(|pair| {
            let VectorInternal::Dense(positive) = &pair.positive else {
                return Err(StorageError::bad_input(
                    "encrypted vector discover only supports raw dense positive context examples",
                ));
            };
            let VectorInternal::Dense(negative) = &pair.negative else {
                return Err(StorageError::bad_input(
                    "encrypted vector discover only supports raw dense negative context examples",
                ));
            };
            Ok((positive.as_slice(), negative.as_slice()))
        })
        .collect()
}

fn ckks_score_query_source_batch(
    collection_name: &str,
    vector_name: &str,
    plan: &crate::common::crypto::VectorWritePlan,
    source: &CkksSidecarQuerySource<'_>,
    encrypted_items: &[(String, EncryptedCkksVector)],
) -> Result<Vec<f32>, StorageError> {
    let scores = match source {
        CkksSidecarQuerySource::Dense(query_values) => plan.score_encrypted_query_batch(
            collection_name,
            vector_name,
            encrypted_items,
            query_values,
        )?,
        CkksSidecarQuerySource::ClientEncrypted {
            collection_id,
            vector_name: envelope_vector_name,
            key_id,
            rk_id,
            rk_epoch,
            query_nonce,
            context_digest,
            slots,
            ciphertext,
            signature_alg,
            signature_key_id,
            signature_b64,
        } => plan.score_client_encrypted_query_batch(
            collection_name,
            vector_name,
            encrypted_items,
            collection_id,
            envelope_vector_name,
            key_id,
            rk_id,
            *rk_epoch,
            query_nonce,
            context_digest,
            *slots,
            ciphertext,
            signature_alg,
            signature_key_id,
            signature_b64,
        )?,
        CkksSidecarQuerySource::Stored {
            point_id,
            encrypted,
        } => plan.score_stored_query_batch(
            collection_name,
            vector_name,
            point_id,
            encrypted,
            encrypted_items,
        )?,
    };

    scores.ok_or_else(ckks_search_plan_lost_rule_error)
}

fn ckks_client_encrypted_query_source<'a>(
    vector_name: &str,
    input: &'a CkksEncryptedQueryInput,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    ckks_client_encrypted_query_source_from_parts(
        vector_name,
        input.version,
        &input.scheme,
        &input.security_profile,
        &input.collection_id,
        &input.vector_name,
        &input.key_id,
        &input.rk_id,
        input.rk_epoch,
        &input.query_nonce,
        &input.context_digest,
        input.slots,
        &input.ciphertext_sha256,
        &input.ciphertext,
        &input.signature_alg,
        &input.signature_key_id,
        &input.signature_b64,
    )
}

fn ckks_rest_client_encrypted_query_source<'a>(
    vector_name: &str,
    input: &'a api::rest::NamedCkksEncryptedQueryVector,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    ckks_client_encrypted_query_source_from_parts(
        vector_name,
        input.envelope.version,
        &input.envelope.scheme,
        &input.envelope.security_profile,
        &input.envelope.collection_id,
        &input.envelope.vector_name,
        &input.envelope.key_id,
        &input.envelope.rk_id,
        input.envelope.rk_epoch,
        &input.envelope.query_nonce,
        &input.envelope.context_digest,
        input.envelope.slots,
        &input.envelope.ciphertext_sha256,
        &input.envelope.ciphertext,
        &input.envelope.signature.alg,
        &input.envelope.signature.key_id,
        &input.envelope.signature.sig,
    )
}

fn ckks_client_encrypted_query_source_from_parts<'a>(
    vector_name: &str,
    version: u8,
    scheme: &str,
    security_profile: &str,
    collection_id: &'a str,
    envelope_vector_name: &'a str,
    key_id: &'a str,
    rk_id: &'a str,
    rk_epoch: u64,
    query_nonce_b64: &'a str,
    context_digest_b64: &'a str,
    slots: usize,
    ciphertext_sha256_b64: &str,
    ciphertext_b64: &str,
    signature_alg: &'a str,
    signature_key_id: &'a str,
    signature_b64: &'a str,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    if version != 1 {
        return Err(StorageError::bad_input(
            "client CKKS query version must be 1",
        ));
    }
    if scheme != CKKS_SCHEME {
        return Err(StorageError::bad_input(format!(
            "client CKKS query scheme must be {CKKS_SCHEME}",
        )));
    }
    if security_profile != CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50 {
        return Err(StorageError::bad_input(format!(
            "client CKKS query profile must be {CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50}",
        )));
    }
    if collection_id.is_empty() {
        return Err(StorageError::bad_input(
            "client CKKS query collection_id must not be empty",
        ));
    }
    if envelope_vector_name != vector_name {
        return Err(StorageError::bad_input(
            "client CKKS query vector_name must match request vector",
        ));
    }
    if key_id.is_empty() {
        return Err(StorageError::bad_input(
            "client CKKS query key_id must not be empty",
        ));
    }
    if rk_id.is_empty() {
        return Err(StorageError::bad_input(
            "client CKKS query rk_id must not be empty",
        ));
    }
    if rk_epoch == 0 {
        return Err(StorageError::bad_input(
            "client CKKS query rk_epoch must be greater than 0",
        ));
    }
    if query_nonce_b64.len() != 16 {
        return Err(StorageError::bad_input(
            "client CKKS query nonce must be 16 base64url characters",
        ));
    }
    let query_nonce = BASE64URL_NOPAD
        .decode(query_nonce_b64.as_bytes())
        .map_err(|_| StorageError::bad_input("client CKKS query nonce is not base64url"))?;
    if query_nonce.len() != 12 {
        return Err(StorageError::bad_input(
            "client CKKS query nonce must decode to 12 bytes",
        ));
    }
    if signature_alg != "ed25519" {
        return Err(StorageError::bad_input(
            "client CKKS query signature alg must be ed25519",
        ));
    }
    if signature_key_id.is_empty() {
        return Err(StorageError::bad_input(
            "client CKKS query signature key_id must not be empty",
        ));
    }
    if signature_b64.len() != 86 {
        return Err(StorageError::bad_input(
            "client CKKS query signature must be 86 base64url characters",
        ));
    }
    let signature = BASE64URL_NOPAD
        .decode(signature_b64.as_bytes())
        .map_err(|_| StorageError::bad_input("client CKKS query signature is not base64url"))?;
    if signature.len() != 64 {
        return Err(StorageError::bad_input(
            "client CKKS query signature must decode to 64 bytes",
        ));
    }
    if slots == 0 {
        return Err(StorageError::bad_input(
            "client CKKS query slots must be greater than 0",
        ));
    }
    if ciphertext_sha256_b64.len() != CKKS_CLIENT_QUERY_CIPHERTEXT_SHA256_B64_LEN {
        return Err(StorageError::bad_input(format!(
            "client CKKS query ciphertext_sha256 must be {CKKS_CLIENT_QUERY_CIPHERTEXT_SHA256_B64_LEN} base64url characters",
        )));
    }
    let ciphertext_sha256 = BASE64URL_NOPAD
        .decode(ciphertext_sha256_b64.as_bytes())
        .map_err(|_| {
            StorageError::bad_input("client CKKS query ciphertext_sha256 is not base64url")
        })?;
    if ciphertext_sha256.len() != 32 {
        return Err(StorageError::bad_input(
            "client CKKS query ciphertext_sha256 must decode to 32 bytes",
        ));
    }
    if context_digest_b64.len() != CKKS_CLIENT_QUERY_CONTEXT_DIGEST_B64_LEN {
        return Err(StorageError::bad_input(format!(
            "client CKKS query context digest must be {CKKS_CLIENT_QUERY_CONTEXT_DIGEST_B64_LEN} base64url characters",
        )));
    }
    let context_digest = BASE64URL_NOPAD
        .decode(context_digest_b64.as_bytes())
        .map_err(|_| {
            StorageError::bad_input("client CKKS query context digest is not base64url")
        })?;
    if context_digest.len() != 32 {
        return Err(StorageError::bad_input(
            "client CKKS query context digest must decode to 32 bytes",
        ));
    }
    if ciphertext_b64.len() > CKKS_CLIENT_QUERY_CIPHERTEXT_MAX_ENCODED_BYTES {
        return Err(StorageError::bad_input(
            "client CKKS query ciphertext exceeds maximum size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| StorageError::bad_input("client CKKS query ciphertext is not base64url"))?;
    if ciphertext.is_empty() {
        return Err(StorageError::bad_input(
            "client CKKS query ciphertext must not be empty",
        ));
    }
    if ciphertext.len() > CKKS_CLIENT_QUERY_CIPHERTEXT_MAX_BYTES {
        return Err(StorageError::bad_input(
            "client CKKS query ciphertext exceeds maximum size",
        ));
    }
    let actual_ciphertext_sha256 = Sha256::digest(&ciphertext);
    if ciphertext_sha256.as_slice() != &actual_ciphertext_sha256[..] {
        return Err(StorageError::bad_input(
            "client CKKS query ciphertext_sha256 does not match ciphertext",
        ));
    }

    Ok(CkksSidecarQuerySource::ClientEncrypted {
        collection_id,
        vector_name: envelope_vector_name,
        key_id,
        rk_id,
        rk_epoch,
        query_nonce: query_nonce_b64,
        context_digest: context_digest_b64,
        slots,
        ciphertext,
        signature_alg,
        signature_key_id,
        signature_b64,
    })
}

fn ckks_search_params_supported(params: &SearchParams) -> bool {
    params.quantization.is_none() && !params.indexed_only && params.acorn.is_none()
}

fn ckks_sidecar_hnsw_score_order_cache_tag(score_order: Order) -> &'static str {
    match score_order {
        Order::LargeBetter => "large",
        Order::SmallBetter => "small",
    }
}

fn ckks_sidecar_hnsw_distance_cache_tag(distance: Distance) -> &'static str {
    match distance {
        Distance::Cosine => "cosine",
        Distance::Euclid => "euclid",
        Distance::Dot => "dot",
        Distance::Manhattan => "manhattan",
    }
}

fn try_ckks_sidecar_hnsw_records_fingerprint(
    records: &[CkksSidecarSearchRecord],
) -> Result<String, StorageError> {
    let mut hasher = Sha256::new();
    macro_rules! hash_bytes {
        ($bytes:expr) => {{
            let bytes = $bytes;
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }};
    }

    hasher.update((records.len() as u64).to_be_bytes());
    for record in records {
        hash_ckks_sidecar_fingerprint_json(&mut hasher, &record.id, "point id")?;
        hash_bytes!(record.point_id.as_bytes());
        match &record.shard_key {
            Some(shard_key) => {
                hasher.update([1]);
                hash_ckks_sidecar_fingerprint_json(&mut hasher, shard_key, "shard key")?;
            }
            None => hasher.update([0]),
        }
        hasher.update(record.encrypted.version.to_be_bytes());
        hash_bytes!(record.encrypted.scheme.as_bytes());

        let envelope = &record.encrypted.envelope;
        hasher.update(envelope.version.to_be_bytes());
        hash_bytes!(envelope.algorithm.as_bytes());
        hash_bytes!(envelope.key_id.as_bytes());
        hash_bytes!(envelope.material_fingerprint.as_bytes());
        hash_bytes!(envelope.rk_id.as_bytes());
        match envelope.rk_epoch {
            Some(epoch) => {
                hasher.update([1]);
                hasher.update(epoch.to_be_bytes());
            }
            None => hasher.update([0]),
        }
        hash_bytes!(envelope.nonce.as_bytes());
        hash_bytes!(envelope.ciphertext.as_bytes());
    }

    let digest = hasher.finalize();
    Ok(BASE64URL_NOPAD.encode(digest.as_ref()))
}

fn hash_ckks_sidecar_fingerprint_json<T: Serialize>(
    hasher: &mut Sha256,
    value: &T,
    field_name: &str,
) -> Result<(), StorageError> {
    let serialized = serde_json::to_vec(value).map_err(|err| {
        StorageError::service_error(format!(
            "failed to serialize CKKS sidecar HNSW graph fingerprint {field_name}: {err}",
        ))
    })?;
    hasher.update((serialized.len() as u64).to_be_bytes());
    hasher.update(&serialized);
    Ok(())
}

#[cfg(test)]
fn ckks_sidecar_hnsw_records_fingerprint(records: &[CkksSidecarSearchRecord]) -> String {
    try_ckks_sidecar_hnsw_records_fingerprint(records)
        .expect("test CKKS sidecar records must serialize into fingerprint bytes")
}

#[cfg(test)]
fn ckks_sidecar_hnsw_graph_cache_file_name(key: &CkksSidecarHnswGraphCacheKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"qdrant-sec/ckks-sidecar-hnsw-graph-cache-file/v1");
    hasher.update(CKKS_SIDECAR_HNSW_GRAPH_CACHE_VERSION.to_be_bytes());
    for value in [
        key.collection_identity.as_str(),
        key.vector_name.as_str(),
        key.distance,
        key.score_order,
        key.records_fingerprint.as_str(),
    ] {
        let bytes = value.as_bytes();
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.update((key.m as u64).to_be_bytes());
    let digest = hasher.finalize();
    format!("{}.json", BASE64URL_NOPAD.encode(digest.as_ref()))
}

#[cfg(test)]
fn ckks_sidecar_hnsw_graph_cache_path(
    collection_path: &Path,
    key: &CkksSidecarHnswGraphCacheKey,
) -> PathBuf {
    collection_path
        .join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR)
        .join(ckks_sidecar_hnsw_graph_cache_file_name(key))
}

fn ckks_sidecar_hnsw_existing_cache_directory_is_safe(
    directory: &Path,
) -> Result<bool, StorageError> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => {
            return Err(StorageError::service_error(
                "failed to inspect CKKS sidecar HNSW graph cache directory",
            ));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(StorageError::service_error(
            "CKKS sidecar HNSW graph cache directory must not be a symlink",
        ));
    }
    if !metadata.is_dir() {
        return Err(StorageError::service_error(
            "CKKS sidecar HNSW graph cache directory must be a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        unsafe extern "C" {
            fn geteuid() -> u32;
        }

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StorageError::service_error(
                "CKKS sidecar HNSW graph cache directory must not be group/world accessible",
            ));
        }
        let effective_uid = unsafe { geteuid() };
        let owner = metadata.uid();
        if owner != 0 && owner != effective_uid {
            return Err(StorageError::service_error(
                "CKKS sidecar HNSW graph cache directory must be owned by root or the qdrant process user",
            ));
        }
    }

    Ok(true)
}

#[cfg(unix)]
fn ckks_sidecar_hnsw_validate_cache_file_unix_metadata(
    _path: &Path,
    metadata: &fs::Metadata,
    label: &str,
) -> Result<(), StorageError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StorageError::service_error(format!(
            "CKKS sidecar HNSW graph cache {label} must not be group/world accessible",
        )));
    }
    let effective_uid = unsafe { geteuid() };
    let owner = metadata.uid();
    if owner != 0 && owner != effective_uid {
        return Err(StorageError::service_error(format!(
            "CKKS sidecar HNSW graph cache {label} must be owned by root or the qdrant process user",
        )));
    }

    Ok(())
}

#[cfg(test)]
fn ensure_ckks_sidecar_hnsw_graph_cache_content_size(
    _path: &Path,
    len: u64,
) -> Result<(), StorageError> {
    if len > CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES {
        return Err(StorageError::service_error(
            "CKKS sidecar HNSW graph cache exceeds maximum size",
        ));
    }

    Ok(())
}

#[cfg(test)]
fn ckks_sidecar_hnsw_load_persisted_graph(
    collection_path: &Path,
    key: &CkksSidecarHnswGraphCacheKey,
    records_len: usize,
) -> Result<Option<Arc<CkksSidecarHnswGraph>>, StorageError> {
    let directory = collection_path.join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
    if !ckks_sidecar_hnsw_existing_cache_directory_is_safe(&directory)? {
        return Ok(None);
    }
    let path = directory.join(ckks_sidecar_hnsw_graph_cache_file_name(key));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(StorageError::service_error(
                "failed to inspect CKKS sidecar HNSW graph cache file",
            ));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(StorageError::service_error(
            "CKKS sidecar HNSW graph cache file must not be a symlink",
        ));
    }
    if !metadata.is_file() {
        return Err(StorageError::service_error(
            "CKKS sidecar HNSW graph cache file must be a regular file",
        ));
    }
    ensure_ckks_sidecar_hnsw_graph_cache_content_size(&path, metadata.len())?;
    #[cfg(unix)]
    ckks_sidecar_hnsw_validate_cache_file_unix_metadata(&path, &metadata, "file")?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let file = options.open(&path).map_err(|_| {
        StorageError::service_error("failed to open CKKS sidecar HNSW graph cache file")
    })?;
    let opened_metadata = file.metadata().map_err(|_| {
        StorageError::service_error("failed to inspect opened CKKS sidecar HNSW graph cache file")
    })?;
    if !opened_metadata.is_file() {
        return Err(StorageError::service_error(
            "opened CKKS sidecar HNSW graph cache file must be a regular file",
        ));
    }
    ensure_ckks_sidecar_hnsw_graph_cache_content_size(&path, opened_metadata.len())?;
    #[cfg(unix)]
    ckks_sidecar_hnsw_validate_cache_file_unix_metadata(&path, &opened_metadata, "opened file")?;

    let mut content = String::with_capacity(opened_metadata.len() as usize);
    let mut limited_file = file.take(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES + 1);
    limited_file.read_to_string(&mut content).map_err(|_| {
        StorageError::service_error("failed to read CKKS sidecar HNSW graph cache file")
    })?;
    ensure_ckks_sidecar_hnsw_graph_cache_content_size(&path, content.len() as u64)?;
    let disk: CkksSidecarHnswGraphDisk = serde_json::from_str(&content).map_err(|_| {
        StorageError::service_error("failed to parse CKKS sidecar HNSW graph cache file")
    })?;
    if disk.version != CKKS_SIDECAR_HNSW_GRAPH_CACHE_VERSION
        || disk.collection_identity != key.collection_identity
        || disk.vector_name != key.vector_name
        || disk.distance != key.distance
        || disk.score_order != key.score_order
        || disk.m != key.m
        || disk.records_fingerprint != key.records_fingerprint
    {
        return Ok(None);
    }
    if disk.links.len() != records_len {
        return Ok(None);
    }

    let Some(graph) = CkksSidecarHnswGraph::from_validated_links(disk.links) else {
        return Ok(None);
    };
    Ok(Some(Arc::new(graph)))
}

#[cfg(test)]
fn ckks_sidecar_hnsw_persist_graph(
    collection_path: &Path,
    key: &CkksSidecarHnswGraphCacheKey,
    graph: &CkksSidecarHnswGraph,
) -> Result<(), StorageError> {
    let directory = collection_path.join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
    if !ckks_sidecar_hnsw_existing_cache_directory_is_safe(&directory)? {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;

            builder.mode(0o700);
        }
        builder.create(&directory).map_err(|_| {
            StorageError::service_error("failed to create CKKS sidecar HNSW graph cache directory")
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|_| {
            StorageError::service_error(
                "failed to set CKKS sidecar HNSW graph cache directory permissions",
            )
        })?;
    }
    ckks_sidecar_hnsw_existing_cache_directory_is_safe(&directory)?;

    let path = ckks_sidecar_hnsw_graph_cache_path(collection_path, key);
    let temp_path = path.with_extension("json.tmp");
    let disk = CkksSidecarHnswGraphDisk {
        version: CKKS_SIDECAR_HNSW_GRAPH_CACHE_VERSION,
        collection_identity: key.collection_identity.clone(),
        vector_name: key.vector_name.clone(),
        distance: key.distance.to_string(),
        score_order: key.score_order.to_string(),
        m: key.m,
        records_fingerprint: key.records_fingerprint.clone(),
        links: graph.links().to_vec(),
    };
    let content = serde_json::to_vec(&disk).map_err(|_| {
        StorageError::service_error("failed to serialize CKKS sidecar HNSW graph cache")
    })?;
    ensure_ckks_sidecar_hnsw_graph_cache_content_size(&path, content.len() as u64)?;

    match fs::symlink_metadata(&temp_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StorageError::service_error(
                "CKKS sidecar HNSW graph cache temp file must not be a symlink",
            ));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(StorageError::service_error(
                "CKKS sidecar HNSW graph cache temp file must be a regular file",
            ));
        }
        Ok(metadata) => {
            #[cfg(unix)]
            ckks_sidecar_hnsw_validate_cache_file_unix_metadata(
                &temp_path,
                &metadata,
                "temp file",
            )?;
            fs::remove_file(&temp_path).map_err(|_| {
                StorageError::service_error(
                    "failed to remove stale CKKS sidecar HNSW graph cache temp file",
                )
            })?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(StorageError::service_error(
                "failed to inspect CKKS sidecar HNSW graph cache temp file",
            ));
        }
    }

    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temp_path).map_err(|_| {
        StorageError::service_error("failed to create CKKS sidecar HNSW graph cache temp file")
    })?;
    file.write_all(&content).map_err(|_| {
        StorageError::service_error("failed to write CKKS sidecar HNSW graph cache temp file")
    })?;
    file.flush().map_err(|_| {
        StorageError::service_error("failed to flush CKKS sidecar HNSW graph cache temp file")
    })?;
    file.sync_all().map_err(|_| {
        StorageError::service_error("failed to sync CKKS sidecar HNSW graph cache temp file")
    })?;
    fs::rename(&temp_path, &path).map_err(|_| {
        StorageError::service_error("failed to replace CKKS sidecar HNSW graph cache file")
    })?;
    ckks_sidecar_hnsw_prune_persisted_graphs(&directory, &path)?;
    ckks_sidecar_hnsw_sync_parent(&path).map_err(|_| {
        StorageError::service_error("failed to sync CKKS sidecar HNSW graph cache directory")
    })
}

#[cfg(test)]
fn ckks_sidecar_hnsw_prune_persisted_graphs(
    directory: &Path,
    keep_path: &Path,
) -> Result<(), StorageError> {
    struct CacheFile {
        path: PathBuf,
        len: u64,
        modified: SystemTime,
    }

    let keep_len = match fs::symlink_metadata(keep_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StorageError::service_error(
                "CKKS sidecar HNSW graph cache keep file must not be a symlink",
            ));
        }
        Ok(metadata) if metadata.is_file() => {
            #[cfg(unix)]
            ckks_sidecar_hnsw_validate_cache_file_unix_metadata(keep_path, &metadata, "keep file")?;
            metadata.len()
        }
        Ok(_) => {
            return Err(StorageError::service_error(
                "CKKS sidecar HNSW graph cache keep file must be a regular file",
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => {
            return Err(StorageError::service_error(
                "failed to inspect CKKS sidecar HNSW graph cache keep file",
            ));
        }
    };
    let mut files = Vec::new();
    let entries = fs::read_dir(directory).map_err(|_| {
        StorageError::service_error("failed to read CKKS sidecar HNSW graph cache directory")
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            StorageError::service_error(
                "failed to read CKKS sidecar HNSW graph cache directory entry",
            )
        })?;
        let path = entry.path();
        if path == keep_path
            || path.extension().and_then(|extension| extension.to_str()) != Some("json")
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| {
            StorageError::service_error("failed to inspect CKKS sidecar HNSW graph cache file")
        })?;
        if metadata.file_type().is_symlink() {
            fs::remove_file(&path).map_err(|_| {
                StorageError::service_error("failed to prune CKKS sidecar HNSW graph cache symlink")
            })?;
            ckks_sidecar_hnsw_sync_parent(&path).map_err(|_| {
                StorageError::service_error(
                    "failed to sync CKKS sidecar HNSW graph cache directory after pruning symlink",
                )
            })?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        if ckks_sidecar_hnsw_validate_cache_file_unix_metadata(&path, &metadata, "cache file")
            .is_err()
        {
            log::warn!("pruning insecure CKKS sidecar HNSW graph cache file");
            fs::remove_file(&path).map_err(|_| {
                StorageError::service_error(
                    "failed to prune insecure CKKS sidecar HNSW graph cache file",
                )
            })?;
            ckks_sidecar_hnsw_sync_parent(&path).map_err(|_| {
                StorageError::service_error("failed to sync CKKS sidecar HNSW graph cache directory after pruning insecure file")
            })?;
            continue;
        }
        files.push(CacheFile {
            path,
            len: metadata.len(),
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        });
    }

    files.sort_unstable_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.path.cmp(&right.path))
    });

    let mut kept_files = 1usize;
    let mut kept_bytes = keep_len;
    for file in files {
        let keep_file = kept_files < CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_FILES
            && kept_bytes.saturating_add(file.len) <= CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_TOTAL_BYTES;
        if keep_file {
            kept_files += 1;
            kept_bytes = kept_bytes.saturating_add(file.len);
            continue;
        }
        fs::remove_file(&file.path).map_err(|_| {
            StorageError::service_error("failed to prune CKKS sidecar HNSW graph cache file")
        })?;
        ckks_sidecar_hnsw_sync_parent(&file.path).map_err(|_| {
            StorageError::service_error(
                "failed to sync CKKS sidecar HNSW graph cache directory after pruning file",
            )
        })?;
    }

    Ok(())
}

#[cfg(unix)]
fn ckks_sidecar_hnsw_sync_parent(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let Some(parent) = path.parent() else {
        return Ok(());
    };
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(parent)?
        .sync_all()
}

#[cfg(not(unix))]
fn ckks_sidecar_hnsw_sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ckks_sidecar_score_hnsw_query_batch(
    collection_name: &str,
    vector_name: &str,
    plan: &crate::common::crypto::VectorWritePlan,
    query: CkksSidecarHnswQuery<'_>,
    encrypted_items: &[(String, EncryptedCkksVector)],
) -> Result<Vec<f32>, StorageError> {
    let scores = match query {
        CkksSidecarHnswQuery::Dense(query_values) => plan.score_encrypted_query_batch(
            collection_name,
            vector_name,
            encrypted_items,
            query_values,
        )?,
        CkksSidecarHnswQuery::ClientEncrypted {
            collection_id,
            vector_name: envelope_vector_name,
            key_id,
            rk_id,
            rk_epoch,
            query_nonce,
            context_digest,
            slots,
            ciphertext,
            signature_alg,
            signature_key_id,
            signature_b64,
        } => plan.score_client_encrypted_query_batch(
            collection_name,
            vector_name,
            encrypted_items,
            collection_id,
            envelope_vector_name,
            key_id,
            rk_id,
            rk_epoch,
            query_nonce,
            context_digest,
            slots,
            ciphertext,
            signature_alg,
            signature_key_id,
            signature_b64,
        )?,
        CkksSidecarHnswQuery::Stored {
            query_point_id,
            query_encrypted,
        } => plan.score_stored_query_batch(
            collection_name,
            vector_name,
            query_point_id,
            query_encrypted,
            encrypted_items,
        )?,
    };

    scores.ok_or_else(ckks_search_plan_lost_rule_error)
}

fn ckks_sidecar_indexed_records(
    records: &[CkksSidecarSearchRecord],
) -> Result<Vec<CkksCiphertextIndexedRecord>, StorageError> {
    records
        .iter()
        .enumerate()
        .map(|(offset, record)| {
            let point_offset = offset.try_into().map_err(|_| {
                StorageError::service_error(
                    "too many CKKS sidecar records to index in ciphertext HNSW",
                )
            })?;
            Ok(CkksCiphertextIndexedRecord::new(
                point_offset,
                record.encrypted.envelope.ciphertext.as_bytes().to_vec(),
            ))
        })
        .collect()
}

#[cfg(test)]
fn ckks_sidecar_segment_snapshots_cover_records(
    snapshots: &[CkksCiphertextSegmentIndexSnapshot],
    records: &[CkksSidecarSearchRecord],
) -> bool {
    let snapshot_records_len = snapshots
        .iter()
        .map(|snapshot| snapshot.records.len())
        .sum::<usize>();
    if snapshot_records_len != records.len() || snapshot_records_len == 0 {
        return false;
    }

    let expected = records
        .iter()
        .map(ckks_sidecar_record_identity)
        .collect::<std::collections::HashSet<_>>();
    if expected.len() != records.len() {
        return false;
    }

    let actual = snapshots
        .iter()
        .flat_map(|snapshot| {
            snapshot.records.iter().map(|record| {
                (
                    record.id,
                    record.shard_key.clone(),
                    record.point_id.clone(),
                    record.encrypted.envelope.key_id.clone(),
                    record.encrypted.envelope.material_fingerprint.clone(),
                    record.encrypted.envelope.rk_id.clone(),
                    record.encrypted.envelope.rk_epoch,
                    record.encrypted.envelope.ciphertext.clone(),
                )
            })
        })
        .collect::<std::collections::HashSet<_>>();
    expected == actual
}

#[cfg(test)]
fn ckks_sidecar_record_identity(
    record: &CkksSidecarSearchRecord,
) -> (
    PointIdType,
    Option<ShardKey>,
    String,
    String,
    String,
    String,
    Option<u64>,
    String,
) {
    (
        record.id,
        record.shard_key.clone(),
        record.point_id.clone(),
        record.encrypted.envelope.key_id.clone(),
        record.encrypted.envelope.material_fingerprint.clone(),
        record.encrypted.envelope.rk_id.clone(),
        record.encrypted.envelope.rk_epoch,
        record.encrypted.envelope.ciphertext.clone(),
    )
}

fn ckks_ciphertext_score_error_to_storage_error(
    err: CkksCiphertextScoreError<StorageError>,
) -> StorageError {
    match err {
        CkksCiphertextScoreError::ScoreCountMismatch { expected, actual } => {
            StorageError::service_error(format!(
                "CKKS ciphertext HNSW scorer returned {actual} score(s) for {expected} candidate(s)"
            ))
        }
        CkksCiphertextScoreError::Scoring(err) => err,
    }
}

#[allow(clippy::too_many_arguments)]
fn ckks_sidecar_hnsw_search_segment_snapshots(
    collection_name: &str,
    vector_name: &str,
    plan: &crate::common::crypto::VectorWritePlan,
    snapshots: &[CkksCiphertextSegmentIndexSnapshot],
    query: CkksSidecarHnswQuery<'_>,
    score_order: Order,
    score_threshold: Option<f32>,
    hnsw_ef: usize,
    top: usize,
) -> Result<Vec<ScoredPoint>, StorageError> {
    if snapshots.is_empty() || top == 0 {
        return Ok(Vec::new());
    }

    let mut scored_by_id = HashMap::<PointIdType, ScoredPoint>::new();
    for snapshot in snapshots {
        if snapshot.records.is_empty() {
            continue;
        }
        if snapshot.graph.is_optimizer_candidate_graph() {
            return Err(StorageError::service_error(
                "optimizer-candidate CKKS ciphertext graphs must be searched through the residual query-side HNSW path",
            ));
        }
        let ef = hnsw_ef.max(top).max(1).min(snapshot.records.len());
        let indexed_records = snapshot
            .records
            .iter()
            .map(|record| record.indexed_record.clone())
            .collect::<Vec<_>>();
        let Some(index) =
            CkksCiphertextVectorIndex::from_graph(indexed_records, snapshot.graph.clone())
        else {
            return Err(StorageError::service_error(
                "segment CKKS ciphertext HNSW graph did not match indexed records",
            ));
        };
        let records_by_offset = snapshot
            .records
            .iter()
            .map(|record| (record.indexed_record.point_offset, record))
            .collect::<HashMap<_, _>>();
        let hits = index
            .search_ciphertext_records(
                ef,
                top,
                score_order,
                score_threshold,
                |candidates| {
                    let encrypted_items = candidates
                        .iter()
                        .map(|candidate| {
                            let record = records_by_offset
                                .get(&candidate.point_offset)
                                .ok_or_else(|| {
                                    StorageError::service_error(format!(
                                        "segment CKKS ciphertext HNSW candidate {} is missing from snapshot records",
                                        candidate.point_offset,
                                    ))
                                })?;
                            Ok((record.point_id.clone(), record.encrypted.clone()))
                        })
                        .collect::<Result<Vec<_>, StorageError>>()?;
                    ckks_sidecar_score_hnsw_query_batch(
                        collection_name,
                        vector_name,
                        plan,
                        query,
                        &encrypted_items,
                    )
                },
            )
            .map_err(ckks_ciphertext_score_error_to_storage_error)?;

        for hit in hits {
            let Some(record) = records_by_offset.get(&hit.record.point_offset) else {
                return Err(StorageError::service_error(format!(
                    "segment CKKS ciphertext HNSW hit {} is missing from snapshot records",
                    hit.record.point_offset,
                )));
            };
            let scored_point = ScoredPoint {
                id: record.id,
                version: 0,
                score: hit.score,
                payload: None,
                vector: None,
                shard_key: record.shard_key.clone(),
                order_value: None,
            };
            match scored_by_id.entry(scored_point.id) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    if ckks_scored_point_is_better(score_order, &scored_point, entry.get()) {
                        entry.insert(scored_point);
                    }
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(scored_point);
                }
            }
        }
    }

    let mut scored = scored_by_id.into_values().collect::<Vec<_>>();
    sort_ckks_scored_points(score_order, &mut scored);
    scored.truncate(top);
    Ok(scored)
}

#[allow(clippy::too_many_arguments)]
fn ckks_sidecar_hnsw_search_points(
    collection_name: &str,
    collection_crypto_id: &str,
    vector_name: &str,
    collection_path: &Path,
    plan: &crate::common::crypto::VectorWritePlan,
    records: &[CkksSidecarSearchRecord],
    query: CkksSidecarHnswQuery<'_>,
    distance: Distance,
    score_order: Order,
    score_threshold: Option<f32>,
    hnsw_ef: usize,
    top: usize,
) -> Result<Vec<ScoredPoint>, StorageError> {
    if records.is_empty() || top == 0 {
        return Ok(Vec::new());
    }
    if records.len() == 1 {
        let encrypted_items = [(records[0].point_id.clone(), records[0].encrypted.clone())];
        let scores = ckks_sidecar_score_hnsw_query_batch(
            collection_name,
            vector_name,
            plan,
            query,
            &encrypted_items,
        )?;
        let score = scores[0];
        if !ckks_score_passes_threshold(score_order, score, score_threshold) {
            return Ok(Vec::new());
        }
        return Ok(vec![ScoredPoint {
            id: records[0].id,
            version: 0,
            score,
            payload: None,
            vector: None,
            shard_key: records[0].shard_key.clone(),
            order_value: None,
        }]);
    }

    let ef = hnsw_ef.max(top).max(1).min(records.len());
    if records.len() <= ef {
        let encrypted_items = records
            .iter()
            .map(|record| (record.point_id.clone(), record.encrypted.clone()))
            .collect::<Vec<_>>();
        let scores = ckks_sidecar_score_hnsw_query_batch(
            collection_name,
            vector_name,
            plan,
            query,
            &encrypted_items,
        )?;
        let mut scored = records
            .iter()
            .zip(scores)
            .filter_map(|(record, score)| {
                ckks_score_passes_threshold(score_order, score, score_threshold).then(|| {
                    ScoredPoint {
                        id: record.id,
                        version: 0,
                        score,
                        payload: None,
                        vector: None,
                        shard_key: record.shard_key.clone(),
                        order_value: None,
                    }
                })
            })
            .collect::<Vec<_>>();
        sort_ckks_scored_points(score_order, &mut scored);
        scored.truncate(top);
        return Ok(scored);
    }

    let m = 16.min(records.len().saturating_sub(1)).max(1);
    let cache_key = CkksSidecarHnswGraphCacheKey {
        collection_identity: collection_crypto_id.to_string(),
        vector_name: vector_name.to_string(),
        distance: ckks_sidecar_hnsw_distance_cache_tag(distance),
        score_order: ckks_sidecar_hnsw_score_order_cache_tag(score_order),
        m,
        records_fingerprint: try_ckks_sidecar_hnsw_records_fingerprint(records)?,
    };
    let graph = {
        let mut cache = CKKS_SIDECAR_HNSW_GRAPH_CACHE.lock().map_err(|_| {
            StorageError::service_error("CKKS sidecar HNSW graph cache mutex was poisoned")
        })?;
        cache.get(&cache_key)
    };
    let graph = match graph {
        Some(graph) => graph,
        None => {
            // Persisted graph cache files are only ever written by tests; production must not
            // adopt a graph that appeared in the storage directory without being built by this
            // process, so the on-disk loader is test-only and production relies on the
            // segment-native ciphertext graph or the in-memory cache.
            #[cfg(test)]
            let persisted_graph = match ckks_sidecar_hnsw_load_persisted_graph(
                collection_path,
                &cache_key,
                records.len(),
            ) {
                Ok(graph) => graph,
                Err(_) => {
                    log::warn!("Ignoring unreadable CKKS sidecar HNSW graph cache");
                    None
                }
            };
            #[cfg(not(test))]
            let persisted_graph: Option<Arc<CkksSidecarHnswGraph>> = {
                let _ = collection_path;
                None
            };
            if let Some(graph) = persisted_graph {
                let mut cache = CKKS_SIDECAR_HNSW_GRAPH_CACHE.lock().map_err(|_| {
                    StorageError::service_error("CKKS sidecar HNSW graph cache mutex was poisoned")
                })?;
                cache.insert(cache_key, graph.clone());
                graph
            } else {
                return Err(StorageError::bad_input(
                    "encrypted vector HNSW sidecar search requires an existing segment-native or persisted CKKS ciphertext graph; query-time graph build is disabled to avoid foreground pairwise CKKS scoring. Retry without hnsw_ef/exact=false to use brute-force sidecar scoring, or rebuild the encrypted vector index.",
                ));
            }
        }
    };

    let indexed_records = ckks_sidecar_indexed_records(records)?;
    let Some(index) =
        CkksCiphertextVectorIndex::from_graph(indexed_records, graph.as_ref().clone())
    else {
        return Err(StorageError::service_error(
            "CKKS ciphertext HNSW graph did not match indexed records",
        ));
    };
    let hits = index
        .search_ciphertext_records(ef, top, score_order, score_threshold, |candidates| {
            let encrypted_items = candidates
                .iter()
                .map(|candidate| {
                    let candidate = &records[candidate.point_offset as usize];
                    (candidate.point_id.clone(), candidate.encrypted.clone())
                })
                .collect::<Vec<_>>();
            ckks_sidecar_score_hnsw_query_batch(
                collection_name,
                vector_name,
                plan,
                query,
                &encrypted_items,
            )
        })
        .map_err(ckks_ciphertext_score_error_to_storage_error)?;

    Ok(hits
        .into_iter()
        .map(|hit| {
            let record = &records[hit.record.point_offset as usize];
            ScoredPoint {
                id: record.id,
                version: 0,
                score: hit.score,
                payload: None,
                vector: None,
                shard_key: record.shard_key.clone(),
                order_value: None,
            }
        })
        .collect())
}

fn encrypted_vector_from_payload(
    payload: &segment::types::Payload,
    vector_name: &str,
) -> Result<Option<EncryptedCkksVector>, StorageError> {
    let Some(sidecar) = payload
        .0
        .get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let Some(value) = sidecar.get(vector_name) else {
        return Ok(None);
    };
    let Some(marker) = value
        .as_object()
        .and_then(|object| object.get(ENCRYPTED_CKKS_VECTOR_MARKER))
    else {
        return Err(StorageError::service_error(
            "stored CKKS vector sidecar entry is malformed",
        ));
    };
    ckks_ciphertext_from_payload(payload, vector_name).map_err(|err| {
        StorageError::service_error(format!(
            "stored CKKS vector sidecar entry failed validation: {err}",
        ))
    })?;
    serde_json::from_value(marker.clone())
        .map(Some)
        .map_err(|err| {
            StorageError::service_error(format!(
                "stored CKKS vector sidecar entry failed to parse: {err}",
            ))
        })
}

fn encrypted_vector_sidecar_path() -> JsonPath {
    JsonPath {
        first_key: ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
        rest: Vec::new(),
    }
}

fn encrypted_vector_sidecar_payload_selector() -> WithPayloadInterface {
    WithPayloadInterface::Fields(vec![encrypted_vector_sidecar_path()])
}

fn encrypted_vector_sidecar_and_group_payload_selector(
    group_by: &JsonPath,
) -> WithPayloadInterface {
    WithPayloadInterface::Fields(vec![encrypted_vector_sidecar_path(), group_by.clone()])
}

#[allow(clippy::too_many_arguments)]
pub async fn do_search_point_groups(
    toc: &TableOfContent,
    collection_name: &str,
    mut request: SearchGroupsRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<GroupsResult, StorageError> {
    let encrypted_payload_read_mode = encrypted_payload_read_mode(request.with_payload.as_ref());
    preflight_private_result_oram_raw_payload_read(
        toc,
        collection_name,
        request.with_payload.as_ref(),
        "search grouped results",
        &auth,
    )
    .await?;
    preflight_payload_decrypt_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        runtime_settings,
        &auth,
    )
    .await?;
    normalize_rest_group_lookup_payload_for_read(
        &mut request.group_request.with_lookup,
        encrypted_payload_read_mode,
    );
    preflight_rest_group_lookup_private_result_oram_raw_payload_read(
        toc,
        &request.group_request.with_lookup,
        "search group lookup",
        &auth,
    )
    .await?;
    let lookup_decrypt_collection = rest_group_lookup_payload_decrypt_collection(
        &request.group_request.with_lookup,
        encrypted_payload_read_mode,
    );
    request_raw_encrypted_payload_for_collection_read(
        &mut request.with_payload,
        encrypted_payload_read_mode,
    );

    if let Some(settings) = runtime_settings
        && let Some(mut result) = try_ckks_vector_search_groups(
            toc,
            collection_name,
            &request,
            read_consistency,
            &shard_selection,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
            encrypted_payload_read_mode,
        )
        .await?
    {
        decrypt_group_hits_for_read(
            toc,
            collection_name,
            encrypted_payload_read_mode,
            &mut result,
            runtime_settings,
            &auth,
        )
        .await?;
        decrypt_group_lookup_payloads_for_read(
            toc,
            lookup_decrypt_collection.as_deref(),
            encrypted_payload_read_mode,
            &mut result,
            runtime_settings,
            &auth,
        )
        .await?;
        return Ok(result);
    }

    let with_vector = request.with_vector.clone().unwrap_or_default();
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &with_vector,
        &auth,
        "search groups",
    )
    .await?;
    ensure_encrypted_vector_group_request_is_unsupported(
        toc,
        collection_name,
        search_group_vector_name(&request.vector),
        &auth,
    )
    .await?;

    let mut result = toc
        .group(
            collection_name,
            GroupRequest::from(request),
            read_consistency,
            shard_selection,
            auth.clone(),
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
    decrypt_group_hits_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        &mut result,
        runtime_settings,
        &auth,
    )
    .await?;
    decrypt_group_lookup_payloads_for_read(
        toc,
        lookup_decrypt_collection.as_deref(),
        encrypted_payload_read_mode,
        &mut result,
        runtime_settings,
        &auth,
    )
    .await?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_search_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: &SearchGroupsRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
    encrypted_payload_read_mode: EncryptedPayloadReadMode,
) -> Result<Option<GroupsResult>, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_search_groups",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let vector_name = search_group_vector_name(&request.vector);
    if !plan.contains_vector_name(vector_name) {
        return Ok(None);
    }
    if let Some(err) = plan.private_hnsw_oram_api_required_error(vector_name) {
        return Err(err);
    }
    if request.with_vector.clone().unwrap_or_default().is_enabled() {
        return Err(StorageError::bad_input(
            "cannot return encrypted vector; CKKS vector ciphertext read path returns payload sidecar only",
        ));
    }
    ensure_group_path_does_not_touch_encrypted_crypto_selectors(
        config.params.encryption.as_ref(),
        &request.group_request.group_by,
    )?;

    let group_by = request.group_request.group_by.clone();
    if let api::rest::NamedVectorStruct::CkksEncryptedQuery(query) = &request.vector {
        let query = ckks_rest_client_encrypted_query_source(vector_name, query)?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            vector_name,
            CkksSidecarScoring::NearestResolved { query },
            request.filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &group_by,
            request.group_request.limit as usize,
            request.group_request.group_size as usize,
            request
                .with_payload
                .clone()
                .unwrap_or(WithPayloadInterface::Bool(false)),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.group_request.with_lookup.clone().map(Into::into),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    let search_request = CoreSearchRequest::from(SearchRequestInternal {
        vector: request.vector.clone(),
        filter: request.filter.clone(),
        params: request.params.clone(),
        limit: usize::MAX,
        offset: Some(0),
        with_payload: Some(encrypted_vector_sidecar_and_group_payload_selector(
            &group_by,
        )),
        with_vector: Some(WithVector::Bool(false)),
        score_threshold: request.score_threshold,
    });
    let result = ckks_vector_group_points(
        &collection,
        collection_name,
        &collection_crypto_id,
        &search_request,
        &plan,
        &group_by,
        request.group_request.limit as usize,
        request.group_request.group_size as usize,
        request
            .with_payload
            .clone()
            .unwrap_or(WithPayloadInterface::Bool(false)),
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    attach_ckks_group_lookup(
        toc,
        result,
        request.group_request.with_lookup.clone().map(Into::into),
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
        encrypted_payload_read_mode,
    )
    .await
    .map(Some)
}

fn ensure_group_path_does_not_touch_encrypted_crypto_selectors(
    encryption: Option<&CollectionEncryptionConfig>,
    group_by: &JsonPath,
) -> Result<(), StorageError> {
    let sidecar_path = JsonPath {
        first_key: ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
        rest: Vec::new(),
    };
    if group_by.compatible(&sidecar_path) {
        return Err(StorageError::bad_input(
            "cannot group by encrypted vector sidecar field; use a plaintext group field",
        ));
    }

    let Some(encryption) = encryption else {
        return Ok(());
    };

    for rule in &encryption.rules {
        match &rule.selector {
            EncryptionSelector::PayloadPaths { paths } => {
                for encrypted_path in paths {
                    let encrypted_json_path = encrypted_path.parse::<JsonPath>().map_err(|_| {
                        if encryption_rule_uses_private_result_oram(rule) {
                            StorageError::bad_input(
                                "private result ORAM payload field path is invalid",
                            )
                        } else {
                            StorageError::bad_input("encrypted payload field path is invalid")
                        }
                    })?;
                    if group_by.compatible(&encrypted_json_path) {
                        if encryption_rule_uses_private_result_oram(rule) {
                            return Err(StorageError::bad_input(
                                private_result_oram_payload_selector_overlap_message(
                                    group_by,
                                    encrypted_path,
                                ),
                            ));
                        }
                        return Err(StorageError::bad_input(format!(
                            "cannot group by encrypted payload field because it overlaps an encrypted payload selector; configure a blind index provider instead",
                        )));
                    }
                }
            }
            EncryptionSelector::MetadataKeys { keys } => {
                for metadata_key in keys {
                    let metadata_path = metadata_key.parse::<JsonPath>().map_err(|_| {
                        StorageError::bad_input("encrypted metadata field path is invalid")
                    })?;
                    if group_by.compatible(&metadata_path) {
                        return Err(StorageError::bad_input(format!(
                            "cannot group by encrypted metadata field because it overlaps an encrypted metadata selector; configure a blind index provider instead",
                        )));
                    }
                }
            }
            EncryptionSelector::VectorNames { .. } => {}
        }
    }

    Ok(())
}

fn group_ckks_search_points(
    scored: Vec<ScoredPoint>,
    group_by: &JsonPath,
    group_limit: usize,
    group_size: usize,
) -> Vec<(GroupId, Vec<ScoredPoint>)> {
    let mut groups = Vec::<(GroupId, Vec<ScoredPoint>)>::new();
    for point in scored {
        let Some(payload) = point.payload.as_ref() else {
            continue;
        };
        let values = payload
            .get_value(group_by)
            .into_iter()
            .flat_map(|value| match value {
                serde_json::Value::Array(values) => values.iter().collect(),
                value => vec![value],
            });
        for value in values {
            let Ok(group_id) = GroupId::try_from(value) else {
                continue;
            };
            if let Some((_, hits)) = groups.iter_mut().find(|(id, _)| *id == group_id) {
                if hits.len() < group_size && !hits.iter().any(|hit| hit.id == point.id) {
                    hits.push(point.clone());
                }
                continue;
            }
            if groups.len() >= group_limit {
                continue;
            }
            groups.push((group_id, vec![point.clone()]));
        }
        if groups.len() >= group_limit && groups.iter().all(|(_, hits)| hits.len() >= group_size) {
            break;
        }
    }
    groups
}

fn ckks_grouped_candidate_limit(
    group_limit: usize,
    group_size: usize,
    max_candidates: usize,
) -> Result<usize, StorageError> {
    let requested_hits = group_limit.checked_mul(group_size).ok_or_else(|| {
        StorageError::bad_input("encrypted vector grouped search request is too large")
    })?;
    if requested_hits == 0 {
        return Ok(0);
    }
    if requested_hits > max_candidates {
        return Err(StorageError::bad_input(format!(
            "encrypted vector grouped search may request at most {max_candidates} grouped hits",
        )));
    }

    Ok(requested_hits
        .saturating_mul(CKKS_GROUPED_SEARCH_CANDIDATE_OVERSAMPLING)
        .min(max_candidates)
        .max(requested_hits))
}

fn ensure_ckks_matrix_budget(
    sample_size: usize,
    limit_per_sample: usize,
) -> Result<(), StorageError> {
    if sample_size > CKKS_MATRIX_SAMPLE_MAX {
        return Err(StorageError::bad_input(format!(
            "encrypted vector matrix sample size must be at most {CKKS_MATRIX_SAMPLE_MAX}",
        )));
    }
    let score_pairs = sample_size.checked_mul(sample_size).ok_or_else(|| {
        StorageError::bad_input("encrypted vector matrix scoring budget is too large")
    })?;
    if score_pairs > CKKS_MATRIX_SCORE_PAIR_MAX {
        return Err(StorageError::bad_input(format!(
            "encrypted vector matrix scoring pairs must be at most {CKKS_MATRIX_SCORE_PAIR_MAX}",
        )));
    }
    let response_pairs = sample_size.checked_mul(limit_per_sample).ok_or_else(|| {
        StorageError::bad_input("encrypted vector matrix response budget is too large")
    })?;
    if response_pairs > CKKS_MATRIX_SCORE_PAIR_MAX {
        return Err(StorageError::bad_input(format!(
            "encrypted vector matrix response pairs must be at most {CKKS_MATRIX_SCORE_PAIR_MAX}",
        )));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_group_points(
    collection: &collection::collection::Collection,
    collection_name: &str,
    collection_crypto_id: &str,
    search_request: &CoreSearchRequest,
    plan: &crate::common::crypto::VectorWritePlan,
    group_by: &JsonPath,
    group_limit: usize,
    group_size: usize,
    with_payload: WithPayloadInterface,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<GroupsResult, StorageError> {
    let candidate_limit =
        ckks_grouped_candidate_limit(group_limit, group_size, plan.ckks_grouped_max_candidates())?;
    let mut bounded_search_request = search_request.clone();
    bounded_search_request.offset = 0;
    bounded_search_request.limit = candidate_limit;
    let scored = ckks_vector_search_points(
        collection,
        collection_name,
        collection_crypto_id,
        &bounded_search_request,
        plan,
        read_consistency,
        shard_selection,
        timeout,
        Some(candidate_limit),
        hw_measurement_acc.clone(),
    )
    .await?;

    ckks_vector_group_scored_points(
        collection,
        scored,
        group_by,
        group_limit,
        group_size,
        with_payload,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_group_points_with_scoring(
    collection: &collection::collection::Collection,
    collection_name: &str,
    collection_crypto_id: &str,
    vector_name: &str,
    scoring: CkksSidecarScoring<'_>,
    filter: Option<Filter>,
    params: Option<SearchParams>,
    score_threshold: Option<f32>,
    plan: &crate::common::crypto::VectorWritePlan,
    group_by: &JsonPath,
    group_limit: usize,
    group_size: usize,
    with_payload: WithPayloadInterface,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<GroupsResult, StorageError> {
    let candidate_limit =
        ckks_grouped_candidate_limit(group_limit, group_size, plan.ckks_grouped_max_candidates())?;
    let scored = ckks_vector_search_points_with_scoring(
        collection,
        collection_name,
        collection_crypto_id,
        vector_name,
        scoring,
        filter,
        params,
        candidate_limit,
        0,
        Some(encrypted_vector_sidecar_and_group_payload_selector(
            group_by,
        )),
        Some(WithVector::Bool(false)),
        score_threshold,
        Some(candidate_limit),
        plan,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;

    ckks_vector_group_scored_points(
        collection,
        scored,
        group_by,
        group_limit,
        group_size,
        with_payload,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_group_scored_points(
    collection: &collection::collection::Collection,
    scored: Vec<ScoredPoint>,
    group_by: &JsonPath,
    group_limit: usize,
    group_size: usize,
    with_payload: WithPayloadInterface,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<GroupsResult, StorageError> {
    let grouped = group_ckks_search_points(scored, group_by, group_limit, group_size);
    let ids = grouped
        .iter()
        .flat_map(|(_, points)| points.iter().map(|point| point.id))
        .collect::<Vec<_>>();
    let records = if ids.is_empty() {
        Vec::new()
    } else {
        collection
            .retrieve(
                PointRequestInternal {
                    ids,
                    with_payload: Some(with_payload),
                    with_vector: WithVector::Bool(false),
                },
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await?
    };
    let records_by_id = records
        .into_iter()
        .map(|record| (record.id, record))
        .collect::<std::collections::HashMap<_, _>>();

    let groups = grouped
        .into_iter()
        .map(|(id, mut hits)| {
            for hit in &mut hits {
                if let Some(record) = records_by_id.get(&hit.id) {
                    hit.payload.clone_from(&record.payload);
                    hit.vector.clone_from(&record.vector);
                    hit.shard_key = record.shard_key.clone().or_else(|| hit.shard_key.clone());
                }
            }
            PointGroup {
                hits: hits.into_iter().map(api::rest::ScoredPoint::from).collect(),
                id,
                lookup: None,
            }
        })
        .collect();

    Ok(GroupsResult { groups })
}

#[allow(clippy::too_many_arguments)]
async fn attach_ckks_group_lookup(
    toc: &TableOfContent,
    mut result: GroupsResult,
    with_lookup: Option<collection::lookup::WithLookup>,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    encrypted_payload_read_mode: EncryptedPayloadReadMode,
) -> Result<GroupsResult, StorageError> {
    let Some(with_lookup) = with_lookup else {
        return Ok(result);
    };
    let mut lookup = with_lookup;
    normalize_collection_group_lookup_payload_for_read(&mut lookup, encrypted_payload_read_mode);
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        &lookup.collection_name,
        &lookup.with_vectors.clone().unwrap_or_default(),
        auth,
        "group lookup",
    )
    .await?;
    let pseudo_ids = result
        .groups
        .iter()
        .map(|group| PseudoId::from(group.id.clone()))
        .collect::<Vec<_>>();
    let mut lookups: std::collections::HashMap<PseudoId, RecordInternal> = lookup_ids(
        lookup,
        pseudo_ids,
        |name| async move {
            let collection_pass = auth
                .check_collection_access(&name, AccessRequirements::new(), "group_lookup")
                .ok()?;
            toc.get_collection(&collection_pass).await.ok()
        },
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await?;

    for group in &mut result.groups {
        group.lookup = lookups
            .remove(&PseudoId::from(group.id.clone()))
            .map(api::rest::Record::from);
    }

    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub async fn do_recommend_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: RecommendRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let results = do_recommend_batch_points(
        toc,
        collection_name,
        vec![(request, shard_selection)],
        read_consistency,
        auth,
        timeout,
        hw_measurement_acc,
        runtime_settings,
    )
    .await?;
    results
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::service_error("Empty recommend result"))
}

#[allow(clippy::too_many_arguments)]
pub async fn do_recommend_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    mut requests: Vec<(RecommendRequestInternal, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let encrypted_payload_read_modes = requests
        .iter_mut()
        .map(|(request, _)| {
            let mode = encrypted_payload_read_mode(request.with_payload.as_ref());
            request_raw_encrypted_payload_for_collection_read(&mut request.with_payload, mode);
            mode
        })
        .collect::<Vec<_>>();
    for (request, _) in &requests {
        preflight_private_result_oram_raw_payload_read(
            toc,
            collection_name,
            request.with_payload.as_ref(),
            "recommend results",
            &auth,
        )
        .await?;
    }
    preflight_payload_decrypt_modes_for_read(
        toc,
        collection_name,
        &encrypted_payload_read_modes,
        runtime_settings,
        &auth,
    )
    .await?;

    if runtime_settings.is_none() {
        let private_hnsw_vectors =
            private_hnsw_oram_vector_names_for_collection(toc, collection_name, &auth).await?;
        for (request, _) in &requests {
            ensure_vector_name_is_not_private_hnsw_oram(
                &private_hnsw_vectors,
                &recommend_vector_name(request),
            )?;
        }
    }

    if let Some(settings) = runtime_settings
        && let Some(mut results) = try_ckks_vector_recommend_batch_points(
            toc,
            collection_name,
            &requests,
            read_consistency,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
        )
        .await?
    {
        decrypt_scored_point_batches_for_read(
            toc,
            collection_name,
            &encrypted_payload_read_modes,
            &mut results,
            runtime_settings,
            &auth,
        )
        .await?;
        return Ok(results);
    }

    for (request, _) in &requests {
        let with_vector = request.with_vector.clone().unwrap_or_default();
        ensure_with_vector_does_not_request_encrypted_vectors(
            toc,
            collection_name,
            &with_vector,
            &auth,
            "recommend",
        )
        .await?;
    }

    let mut results = toc
        .recommend_batch(
            collection_name,
            requests,
            read_consistency,
            auth.clone(),
            timeout,
            hw_measurement_acc,
        )
        .await?;
    decrypt_scored_point_batches_for_read(
        toc,
        collection_name,
        &encrypted_payload_read_modes,
        &mut results,
        runtime_settings,
        &auth,
    )
    .await?;
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_recommend_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    requests: &[(RecommendRequestInternal, ShardSelectorInternal)],
    read_consistency: Option<ReadConsistency>,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
) -> Result<Option<Vec<Vec<ScoredPoint>>>, StorageError> {
    if requests.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_recommend",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let mut has_encrypted_recommend = false;
    let mut core_requests = Vec::with_capacity(requests.len());
    enum CkksResolvedRecommendRequest<'a> {
        Plain(RecommendRequestInternal, ShardSelectorInternal),
        Core(CoreSearchRequest, ShardSelectorInternal),
        StoredNearest {
            vector_name: String,
            query_point_id: String,
            query_encrypted: EncryptedCkksVector,
            filter: Option<Filter>,
            params: Option<SearchParams>,
            limit: usize,
            offset: usize,
            with_payload: Option<WithPayloadInterface>,
            with_vector: Option<WithVector>,
            score_threshold: Option<f32>,
            shard_selection: ShardSelectorInternal,
        },
        Scoring {
            vector_name: String,
            scoring: CkksSidecarScoring<'a>,
            filter: Option<Filter>,
            params: Option<SearchParams>,
            limit: usize,
            offset: usize,
            with_payload: Option<WithPayloadInterface>,
            with_vector: Option<WithVector>,
            score_threshold: Option<f32>,
            shard_selection: ShardSelectorInternal,
        },
    }

    for (request, shard_selection) in requests {
        let vector_name = recommend_vector_name(request);
        if !plan.contains_vector_name(&vector_name) {
            core_requests.push(Some(CkksResolvedRecommendRequest::Plain(
                request.clone(),
                shard_selection.clone(),
            )));
            continue;
        }

        if let Some(err) = plan.private_hnsw_oram_api_required_error(&vector_name) {
            return Err(err);
        }
        has_encrypted_recommend = true;
        if let Some(point_id) = recommend_request_single_positive_point_id(request) {
            let query_encrypted = ckks_vector_sidecar_for_point_id(
                &collection,
                &vector_name,
                point_id,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            core_requests.push(Some(CkksResolvedRecommendRequest::StoredNearest {
                vector_name,
                query_point_id: point_id.to_string(),
                query_encrypted,
                filter: request.filter.clone(),
                params: request.params.clone(),
                limit: request.limit,
                offset: request.offset.unwrap_or_default(),
                with_payload: request.with_payload.clone(),
                with_vector: request.with_vector.clone(),
                score_threshold: None,
                shard_selection: shard_selection.clone(),
            }));
        } else if recommend_request_needs_sidecar_resolution(request) {
            let scoring = recommend_request_as_ckks_resolved_scoring(
                &collection,
                &vector_name,
                request,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            core_requests.push(Some(CkksResolvedRecommendRequest::Scoring {
                vector_name,
                scoring,
                filter: request.filter.clone(),
                params: request.params.clone(),
                limit: request.limit,
                offset: request.offset.unwrap_or_default(),
                with_payload: request.with_payload.clone(),
                with_vector: request.with_vector.clone(),
                score_threshold: request.score_threshold,
                shard_selection: shard_selection.clone(),
            }));
        } else {
            core_requests.push(Some(CkksResolvedRecommendRequest::Core(
                recommend_request_as_ckks_search_request(request, &vector_name)?,
                shard_selection.clone(),
            )));
        }
    }

    if !has_encrypted_recommend {
        return Ok(None);
    }

    let mut results = Vec::with_capacity(core_requests.len());
    for request in core_requests {
        let Some(request) = request else {
            return Err(StorageError::service_error(
                "CKKS recommend batch contained an unresolved request slot",
            ));
        };
        let result = match request {
            CkksResolvedRecommendRequest::Plain(request, shard_selection) => {
                let with_vector = request.with_vector.clone().unwrap_or_default();
                ensure_with_vector_does_not_request_encrypted_vectors(
                    toc,
                    collection_name,
                    &with_vector,
                    auth,
                    "recommend",
                )
                .await?;
                let mut plain_results = toc
                    .recommend_batch(
                        collection_name,
                        vec![(request, shard_selection)],
                        read_consistency,
                        auth.clone(),
                        timeout,
                        hw_measurement_acc.clone(),
                    )
                    .await?;
                plain_results.pop().ok_or_else(|| {
                    StorageError::service_error(
                        "plaintext recommend result missing from mixed CKKS vector batch",
                    )
                })?
            }
            CkksResolvedRecommendRequest::Core(request, shard_selection) => {
                ckks_vector_search_points(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &request,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    None,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            CkksResolvedRecommendRequest::StoredNearest {
                vector_name,
                query_point_id,
                query_encrypted,
                filter,
                params,
                limit,
                offset,
                with_payload,
                with_vector,
                score_threshold,
                shard_selection,
            } => {
                ckks_vector_search_points_with_scoring(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &vector_name,
                    CkksSidecarScoring::StoredNearest {
                        query_point_id,
                        query_encrypted,
                    },
                    filter,
                    params,
                    limit,
                    offset,
                    with_payload,
                    with_vector,
                    score_threshold,
                    None,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            CkksResolvedRecommendRequest::Scoring {
                vector_name,
                scoring,
                filter,
                params,
                limit,
                offset,
                with_payload,
                with_vector,
                score_threshold,
                shard_selection,
            } => {
                ckks_vector_search_points_with_scoring(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &vector_name,
                    scoring,
                    filter,
                    params,
                    limit,
                    offset,
                    with_payload,
                    with_vector,
                    score_threshold,
                    None,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
        };
        results.push(result);
    }

    Ok(Some(results))
}

fn recommend_request_single_positive_point_id(
    request: &RecommendRequestInternal,
) -> Option<PointIdType> {
    if request.lookup_from.is_some()
        || !request.negative.is_empty()
        || request.strategy.unwrap_or_default() != RecommendStrategy::AverageVector
        || request.positive.len() != 1
    {
        return None;
    }

    let RecommendExample::PointId(point_id) = request.positive[0] else {
        return None;
    };
    Some(point_id)
}

fn recommend_examples_contain_point_id(examples: &[RecommendExample]) -> bool {
    examples
        .iter()
        .any(|example| matches!(example, RecommendExample::PointId(_)))
}

fn recommend_request_needs_sidecar_resolution(request: &RecommendRequestInternal) -> bool {
    recommend_examples_contain_point_id(&request.positive)
        || recommend_examples_contain_point_id(&request.negative)
}

#[allow(clippy::too_many_arguments)]
async fn recommend_examples_as_ckks_query_sources<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    role: &str,
    examples: &'a [RecommendExample],
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<CkksSidecarQuerySource<'a>>, StorageError> {
    let mut sources = Vec::with_capacity(examples.len());
    for example in examples {
        sources.push(
            recommend_example_as_ckks_query_source(
                collection,
                vector_name,
                role,
                example,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?,
        );
    }
    Ok(sources)
}

#[allow(clippy::too_many_arguments)]
async fn recommend_request_as_ckks_resolved_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    request: &'a RecommendRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    if request.lookup_from.is_some() {
        return Err(StorageError::bad_input(
            "encrypted vector recommend does not support lookup_from; provide examples from the same encrypted vector sidecar",
        ));
    }
    let positives = recommend_examples_as_ckks_query_sources(
        collection,
        vector_name,
        "positive",
        &request.positive,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    let negatives = recommend_examples_as_ckks_query_sources(
        collection,
        vector_name,
        "negative",
        &request.negative,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await?;

    match request.strategy.unwrap_or_default() {
        RecommendStrategy::BestScore => Ok(CkksSidecarScoring::RecommendBestScoreResolved {
            positives,
            negatives,
        }),
        RecommendStrategy::SumScores => Ok(CkksSidecarScoring::RecommendSumScoresResolved {
            positives,
            negatives,
        }),
        RecommendStrategy::AverageVector => {
            Ok(CkksSidecarScoring::RecommendAverageVectorResolved {
                positives,
                negatives,
            })
        }
    }
}

fn recommend_request_as_ckks_search_request(
    request: &RecommendRequestInternal,
    vector_name: &str,
) -> Result<CoreSearchRequest, StorageError> {
    if request.lookup_from.is_some() {
        return Err(StorageError::bad_input(
            "encrypted vector recommend does not support lookup_from or point-id examples; provide raw dense vectors",
        ));
    }
    let positive = recommend_examples_as_dense_vectors(&request.positive, vector_name, "positive")?;
    let negative = recommend_examples_as_dense_vectors(&request.negative, vector_name, "negative")?;
    let query = match request.strategy.unwrap_or_default() {
        RecommendStrategy::AverageVector => {
            let search_vector = avg_vector_for_recommendation(
                positive.iter().map(VectorRef::from),
                negative.iter().map(VectorRef::from).peekable(),
            )
            .map_err(|_| {
                StorageError::bad_input(
                    "encrypted vector recommend average-vector conversion failed",
                )
            })?;
            QueryEnum::Nearest(NamedQuery::new(search_vector, vector_name.to_string()))
        }
        RecommendStrategy::BestScore => QueryEnum::RecommendBestScore(NamedQuery::new(
            segment::vector_storage::query::RecoQuery::new(positive, negative),
            vector_name.to_string(),
        )),
        RecommendStrategy::SumScores => QueryEnum::RecommendSumScores(NamedQuery::new(
            segment::vector_storage::query::RecoQuery::new(positive, negative),
            vector_name.to_string(),
        )),
    };

    Ok(CoreSearchRequest {
        query,
        filter: request.filter.clone(),
        params: request.params.clone(),
        limit: request.limit,
        offset: request.offset.unwrap_or_default(),
        with_payload: request.with_payload.clone(),
        with_vector: request.with_vector.clone(),
        score_threshold: request.score_threshold,
    })
}

fn recommend_examples_as_dense_vectors(
    examples: &[RecommendExample],
    _vector_name: &str,
    role: &str,
) -> Result<Vec<VectorInternal>, StorageError> {
    examples
        .iter()
        .map(|example| match example {
            RecommendExample::Dense(vector) => Ok(VectorInternal::Dense(vector.clone())),
            RecommendExample::Sparse(_) => Err(StorageError::bad_input(format!(
                "encrypted vector recommend only supports raw dense {role} examples",
            ))),
            RecommendExample::PointId(_) => Err(StorageError::bad_input(format!(
                "encrypted vector recommend cannot resolve point-id {role} examples because plaintext vectors are not stored",
            ))),
        })
        .collect()
}

fn recommend_vector_name(request: &RecommendRequestInternal) -> String {
    request
        .using
        .as_ref()
        .map(UsingVector::as_name)
        .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string())
}

#[allow(clippy::too_many_arguments)]
pub async fn do_recommend_point_groups(
    toc: &TableOfContent,
    collection_name: &str,
    mut request: RecommendGroupsRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<GroupsResult, StorageError> {
    let encrypted_payload_read_mode = encrypted_payload_read_mode(request.with_payload.as_ref());
    preflight_private_result_oram_raw_payload_read(
        toc,
        collection_name,
        request.with_payload.as_ref(),
        "recommend grouped results",
        &auth,
    )
    .await?;
    preflight_payload_decrypt_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        runtime_settings,
        &auth,
    )
    .await?;
    normalize_rest_group_lookup_payload_for_read(
        &mut request.group_request.with_lookup,
        encrypted_payload_read_mode,
    );
    preflight_rest_group_lookup_private_result_oram_raw_payload_read(
        toc,
        &request.group_request.with_lookup,
        "recommend group lookup",
        &auth,
    )
    .await?;
    let lookup_decrypt_collection = rest_group_lookup_payload_decrypt_collection(
        &request.group_request.with_lookup,
        encrypted_payload_read_mode,
    );
    request_raw_encrypted_payload_for_collection_read(
        &mut request.with_payload,
        encrypted_payload_read_mode,
    );

    if let Some(settings) = runtime_settings
        && let Some(mut result) = try_ckks_vector_recommend_groups(
            toc,
            collection_name,
            &request,
            read_consistency,
            &shard_selection,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
            encrypted_payload_read_mode,
        )
        .await?
    {
        decrypt_group_hits_for_read(
            toc,
            collection_name,
            encrypted_payload_read_mode,
            &mut result,
            runtime_settings,
            &auth,
        )
        .await?;
        decrypt_group_lookup_payloads_for_read(
            toc,
            lookup_decrypt_collection.as_deref(),
            encrypted_payload_read_mode,
            &mut result,
            runtime_settings,
            &auth,
        )
        .await?;
        return Ok(result);
    }

    let vector_name = request
        .using
        .as_ref()
        .map(UsingVector::as_name)
        .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string());
    let with_vector = request.with_vector.clone().unwrap_or_default();
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &with_vector,
        &auth,
        "recommend groups",
    )
    .await?;
    ensure_encrypted_vector_group_request_is_unsupported(toc, collection_name, &vector_name, &auth)
        .await?;

    let mut result = toc
        .group(
            collection_name,
            GroupRequest::from(request),
            read_consistency,
            shard_selection,
            auth.clone(),
            timeout,
            hw_measurement_acc,
        )
        .await?;
    decrypt_group_hits_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        &mut result,
        runtime_settings,
        &auth,
    )
    .await?;
    decrypt_group_lookup_payloads_for_read(
        toc,
        lookup_decrypt_collection.as_deref(),
        encrypted_payload_read_mode,
        &mut result,
        runtime_settings,
        &auth,
    )
    .await?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_recommend_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: &RecommendGroupsRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
    encrypted_payload_read_mode: EncryptedPayloadReadMode,
) -> Result<Option<GroupsResult>, StorageError> {
    let vector_name = request
        .using
        .as_ref()
        .map(UsingVector::as_name)
        .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string());
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_recommend_groups",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };
    if !plan.contains_vector_name(&vector_name) {
        return Ok(None);
    }
    if let Some(err) = plan.private_hnsw_oram_api_required_error(&vector_name) {
        return Err(err);
    }

    let recommend_request = RecommendRequestInternal {
        positive: request.positive.clone(),
        negative: request.negative.clone(),
        strategy: request.strategy,
        filter: request.filter.clone(),
        params: request.params.clone(),
        limit: usize::MAX,
        offset: Some(0),
        with_payload: Some(encrypted_vector_sidecar_and_group_payload_selector(
            &request.group_request.group_by,
        )),
        with_vector: Some(WithVector::Bool(false)),
        score_threshold: request.score_threshold,
        using: request.using.clone(),
        lookup_from: request.lookup_from.clone(),
    };
    if request.with_vector.clone().unwrap_or_default().is_enabled() {
        return Err(StorageError::bad_input(
            "cannot return encrypted vector; CKKS vector ciphertext read path returns payload sidecar only",
        ));
    }
    ensure_group_path_does_not_touch_encrypted_crypto_selectors(
        config.params.encryption.as_ref(),
        &request.group_request.group_by,
    )?;

    if let Some(point_id) = recommend_request_single_positive_point_id(&recommend_request) {
        let query_encrypted = ckks_vector_sidecar_for_point_id(
            &collection,
            &vector_name,
            point_id,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &vector_name,
            CkksSidecarScoring::StoredNearest {
                query_point_id: point_id.to_string(),
                query_encrypted,
            },
            recommend_request.filter.clone(),
            recommend_request.params.clone(),
            recommend_request.score_threshold,
            &plan,
            &request.group_request.group_by,
            request.group_request.limit as usize,
            request.group_request.group_size as usize,
            request
                .with_payload
                .clone()
                .unwrap_or(WithPayloadInterface::Bool(false)),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.group_request.with_lookup.clone().map(Into::into),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    if recommend_request_needs_sidecar_resolution(&recommend_request) {
        let scoring = recommend_request_as_ckks_resolved_scoring(
            &collection,
            &vector_name,
            &recommend_request,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &vector_name,
            scoring,
            recommend_request.filter.clone(),
            recommend_request.params.clone(),
            recommend_request.score_threshold,
            &plan,
            &request.group_request.group_by,
            request.group_request.limit as usize,
            request.group_request.group_size as usize,
            request
                .with_payload
                .clone()
                .unwrap_or(WithPayloadInterface::Bool(false)),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.group_request.with_lookup.clone().map(Into::into),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    let core_request = recommend_request_as_ckks_search_request(&recommend_request, &vector_name)?;
    let result = ckks_vector_group_points(
        &collection,
        collection_name,
        &collection_crypto_id,
        &core_request,
        &plan,
        &request.group_request.group_by,
        request.group_request.limit as usize,
        request.group_request.group_size as usize,
        request
            .with_payload
            .clone()
            .unwrap_or(WithPayloadInterface::Bool(false)),
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    attach_ckks_group_lookup(
        toc,
        result,
        request.group_request.with_lookup.clone().map(Into::into),
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
        encrypted_payload_read_mode,
    )
    .await
    .map(Some)
}

#[allow(clippy::too_many_arguments)]
pub async fn do_discover_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: DiscoverRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let results = do_discover_batch_points(
        toc,
        collection_name,
        vec![(request, shard_selection)],
        read_consistency,
        auth,
        timeout,
        hw_measurement_acc,
        runtime_settings,
    )
    .await?;
    results
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::service_error("Empty discover result"))
}

pub async fn do_discover_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    mut requests: Vec<(DiscoverRequestInternal, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let encrypted_payload_read_modes = requests
        .iter_mut()
        .map(|(request, _)| {
            let mode = encrypted_payload_read_mode(request.with_payload.as_ref());
            request_raw_encrypted_payload_for_collection_read(&mut request.with_payload, mode);
            mode
        })
        .collect::<Vec<_>>();
    for (request, _) in &requests {
        preflight_private_result_oram_raw_payload_read(
            toc,
            collection_name,
            request.with_payload.as_ref(),
            "discover results",
            &auth,
        )
        .await?;
    }
    preflight_payload_decrypt_modes_for_read(
        toc,
        collection_name,
        &encrypted_payload_read_modes,
        runtime_settings,
        &auth,
    )
    .await?;

    if runtime_settings.is_none() {
        let private_hnsw_vectors =
            private_hnsw_oram_vector_names_for_collection(toc, collection_name, &auth).await?;
        for (request, _) in &requests {
            ensure_vector_name_is_not_private_hnsw_oram(
                &private_hnsw_vectors,
                &discover_vector_name(request),
            )?;
        }
    }

    if let Some(settings) = runtime_settings
        && let Some(mut results) = try_ckks_vector_discover_batch_points(
            toc,
            collection_name,
            &requests,
            read_consistency,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
        )
        .await?
    {
        decrypt_scored_point_batches_for_read(
            toc,
            collection_name,
            &encrypted_payload_read_modes,
            &mut results,
            runtime_settings,
            &auth,
        )
        .await?;
        return Ok(results);
    }

    for (request, _) in &requests {
        let with_vector = request.with_vector.clone().unwrap_or_default();
        ensure_with_vector_does_not_request_encrypted_vectors(
            toc,
            collection_name,
            &with_vector,
            &auth,
            "discover",
        )
        .await?;
    }

    let mut results = toc
        .discover_batch(
            collection_name,
            requests,
            read_consistency,
            auth.clone(),
            timeout,
            hw_measurement_acc,
        )
        .await?;
    decrypt_scored_point_batches_for_read(
        toc,
        collection_name,
        &encrypted_payload_read_modes,
        &mut results,
        runtime_settings,
        &auth,
    )
    .await?;
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_discover_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    requests: &[(DiscoverRequestInternal, ShardSelectorInternal)],
    read_consistency: Option<ReadConsistency>,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
) -> Result<Option<Vec<Vec<ScoredPoint>>>, StorageError> {
    if requests.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_discover",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let mut has_encrypted_discover = false;
    let mut core_requests = Vec::with_capacity(requests.len());
    enum CkksResolvedDiscoverRequest<'a> {
        Plain(DiscoverRequestInternal, ShardSelectorInternal),
        Core(CoreSearchRequest, ShardSelectorInternal),
        Resolved {
            vector_name: String,
            scoring: CkksSidecarScoring<'a>,
            filter: Option<Filter>,
            params: Option<SearchParams>,
            limit: usize,
            offset: usize,
            with_payload: Option<WithPayloadInterface>,
            with_vector: Option<WithVector>,
            score_threshold: Option<f32>,
            shard_selection: ShardSelectorInternal,
        },
    }

    for (request, shard_selection) in requests {
        let vector_name = discover_vector_name(request);
        if !plan.contains_vector_name(&vector_name) {
            core_requests.push(Some(CkksResolvedDiscoverRequest::Plain(
                request.clone(),
                shard_selection.clone(),
            )));
            continue;
        }

        if let Some(err) = plan.private_hnsw_oram_api_required_error(&vector_name) {
            return Err(err);
        }
        has_encrypted_discover = true;
        if discover_request_needs_sidecar_resolution(request) {
            if request.lookup_from.is_some() {
                return Err(StorageError::bad_input(
                    "encrypted vector discover does not support lookup_from; provide examples from the same encrypted vector sidecar",
                ));
            }
            let scoring = discover_request_as_ckks_resolved_scoring(
                &collection,
                &vector_name,
                request,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            core_requests.push(Some(CkksResolvedDiscoverRequest::Resolved {
                vector_name,
                scoring,
                filter: request.filter.clone(),
                params: request.params.clone(),
                limit: request.limit,
                offset: request.offset.unwrap_or_default(),
                with_payload: request.with_payload.clone(),
                with_vector: request.with_vector.clone(),
                score_threshold: None,
                shard_selection: shard_selection.clone(),
            }));
        } else {
            core_requests.push(Some(CkksResolvedDiscoverRequest::Core(
                discover_request_as_ckks_search_request(request, &vector_name)?,
                shard_selection.clone(),
            )));
        }
    }

    if !has_encrypted_discover {
        return Ok(None);
    }

    let mut results = Vec::with_capacity(core_requests.len());
    for request in core_requests {
        let Some(request) = request else {
            return Err(StorageError::service_error(
                "CKKS discover batch contained an unresolved request slot",
            ));
        };
        let result = match request {
            CkksResolvedDiscoverRequest::Plain(request, shard_selection) => {
                let with_vector = request.with_vector.clone().unwrap_or_default();
                ensure_with_vector_does_not_request_encrypted_vectors(
                    toc,
                    collection_name,
                    &with_vector,
                    auth,
                    "discover",
                )
                .await?;
                let mut plain_results = toc
                    .discover_batch(
                        collection_name,
                        vec![(request, shard_selection)],
                        read_consistency,
                        auth.clone(),
                        timeout,
                        hw_measurement_acc.clone(),
                    )
                    .await?;
                plain_results.pop().ok_or_else(|| {
                    StorageError::service_error(
                        "plaintext discover result missing from mixed CKKS vector batch",
                    )
                })?
            }
            CkksResolvedDiscoverRequest::Core(request, shard_selection) => {
                ckks_vector_search_points(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &request,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    None,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            CkksResolvedDiscoverRequest::Resolved {
                vector_name,
                scoring,
                filter,
                params,
                limit,
                offset,
                with_payload,
                with_vector,
                score_threshold,
                shard_selection,
            } => {
                ckks_vector_search_points_with_scoring(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &vector_name,
                    scoring,
                    filter,
                    params,
                    limit,
                    offset,
                    with_payload,
                    with_vector,
                    score_threshold,
                    None,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
        };
        results.push(result);
    }

    Ok(Some(results))
}

fn discover_request_needs_sidecar_resolution(request: &DiscoverRequestInternal) -> bool {
    request
        .target
        .as_ref()
        .is_some_and(|target| matches!(target, RecommendExample::PointId(_)))
        || request
            .context
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|pair| {
                matches!(pair.positive, RecommendExample::PointId(_))
                    || matches!(pair.negative, RecommendExample::PointId(_))
            })
}

#[allow(clippy::too_many_arguments)]
async fn recommend_example_as_ckks_query_source<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    role: &str,
    example: &'a RecommendExample,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    match example {
        RecommendExample::Dense(values) => Ok(CkksSidecarQuerySource::Dense(values)),
        RecommendExample::PointId(point_id) => {
            let encrypted = ckks_vector_sidecar_for_point_id(
                collection,
                vector_name,
                *point_id,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await?;
            Ok(CkksSidecarQuerySource::Stored {
                point_id: point_id.to_string(),
                encrypted,
            })
        }
        RecommendExample::Sparse(_) => Err(StorageError::bad_input(format!(
            "encrypted vector discover only supports raw dense or point-id {role} examples",
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
async fn discover_request_as_ckks_resolved_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    request: &'a DiscoverRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    let Some(target) = request.target.as_ref() else {
        return Err(StorageError::bad_input(
            "encrypted vector discover requires a raw dense or point-id target vector",
        ));
    };
    let target = recommend_example_as_ckks_query_source(
        collection,
        vector_name,
        "target",
        target,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    let mut pairs = Vec::new();
    for pair in request.context.as_deref().unwrap_or_default() {
        let positive = recommend_example_as_ckks_query_source(
            collection,
            vector_name,
            "positive context",
            &pair.positive,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let negative = recommend_example_as_ckks_query_source(
            collection,
            vector_name,
            "negative context",
            &pair.negative,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        pairs.push((positive, negative));
    }

    Ok(CkksSidecarScoring::DiscoverResolved { target, pairs })
}

fn discover_request_as_ckks_search_request(
    request: &DiscoverRequestInternal,
    vector_name: &str,
) -> Result<CoreSearchRequest, StorageError> {
    if request.lookup_from.is_some() {
        return Err(StorageError::bad_input(
            "encrypted vector discover does not support lookup_from or point-id examples; provide a raw dense target vector",
        ));
    }
    let Some(target) = request.target.as_ref() else {
        return Err(StorageError::bad_input(
            "encrypted vector discover requires a raw dense target vector",
        ));
    };
    let RecommendExample::Dense(query_values) = target else {
        return Err(StorageError::bad_input(
            "encrypted vector discover cannot resolve point-id or sparse target examples because plaintext vectors are not stored",
        ));
    };
    let pairs = request
        .context
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|pair| {
            let RecommendExample::Dense(positive) = &pair.positive else {
                return Err(StorageError::bad_input(
                    "encrypted vector discover cannot resolve point-id or sparse positive context examples because plaintext vectors are not stored",
                ));
            };
            let RecommendExample::Dense(negative) = &pair.negative else {
                return Err(StorageError::bad_input(
                    "encrypted vector discover cannot resolve point-id or sparse negative context examples because plaintext vectors are not stored",
                ));
            };
            Ok(ContextPair {
                positive: VectorInternal::Dense(positive.clone()),
                negative: VectorInternal::Dense(negative.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CoreSearchRequest {
        query: QueryEnum::Discover(NamedQuery::new(
            segment::vector_storage::query::DiscoverQuery::new(
                VectorInternal::Dense(query_values.clone()),
                pairs,
            ),
            vector_name.to_string(),
        )),
        filter: request.filter.clone(),
        params: request.params.clone(),
        limit: request.limit,
        offset: request.offset.unwrap_or_default(),
        with_payload: request.with_payload.clone(),
        with_vector: request.with_vector.clone(),
        score_threshold: None,
    })
}

fn discover_vector_name(request: &DiscoverRequestInternal) -> String {
    request
        .using
        .as_ref()
        .map(UsingVector::as_name)
        .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string())
}

#[allow(clippy::too_many_arguments)]
pub async fn do_count_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: CountRequestInternal,
    read_consistency: Option<ReadConsistency>,
    timeout: Option<Duration>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CountResult, StorageError> {
    toc.count(
        collection_name,
        request,
        read_consistency,
        timeout,
        shard_selection,
        auth,
        hw_measurement_acc,
    )
    .await
}

fn encrypted_payload_read_mode(
    with_payload: Option<&WithPayloadInterface>,
) -> EncryptedPayloadReadMode {
    with_payload
        .map(WithPayloadInterface::encrypted_payload_read_mode)
        .unwrap_or(EncryptedPayloadReadMode::Raw)
}

fn group_lookup_payload_is_required(with_payload: &Option<WithPayloadInterface>) -> bool {
    with_payload
        .as_ref()
        .is_some_and(WithPayloadInterface::is_required)
}

fn group_lookup_fetch_mode_for_read(
    mode: EncryptedPayloadReadMode,
) -> Option<EncryptedPayloadReadMode> {
    match mode {
        EncryptedPayloadReadMode::Raw => None,
        EncryptedPayloadReadMode::Redacted => Some(EncryptedPayloadReadMode::Redacted),
        EncryptedPayloadReadMode::Decrypted => Some(EncryptedPayloadReadMode::Raw),
    }
}

fn normalize_lookup_payload_for_read(
    with_payload: &mut Option<WithPayloadInterface>,
    mode: EncryptedPayloadReadMode,
) {
    if !group_lookup_payload_is_required(with_payload) {
        return;
    }
    let Some(fetch_mode) = group_lookup_fetch_mode_for_read(mode) else {
        return;
    };

    *with_payload = Some(WithPayloadInterface::Encrypted(
        PayloadEncryptedReadPolicy {
            encrypted_payload: fetch_mode,
        },
    ));
}

fn normalize_rest_group_lookup_payload_for_read(
    with_lookup: &mut Option<api::rest::WithLookupInterface>,
    mode: EncryptedPayloadReadMode,
) {
    let Some(with_lookup) = with_lookup else {
        return;
    };

    match with_lookup {
        api::rest::WithLookupInterface::Collection(collection_name) => {
            if let Some(fetch_mode) = group_lookup_fetch_mode_for_read(mode) {
                *with_lookup = api::rest::WithLookupInterface::WithLookup(api::rest::WithLookup {
                    collection_name: collection_name.clone(),
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: fetch_mode,
                        },
                    )),
                    with_vectors: Some(WithVector::Bool(false)),
                });
            }
        }
        api::rest::WithLookupInterface::WithLookup(lookup) => {
            normalize_lookup_payload_for_read(&mut lookup.with_payload, mode);
        }
    }
}

fn normalize_collection_group_lookup_payload_for_read(
    lookup: &mut collection::lookup::WithLookup,
    mode: EncryptedPayloadReadMode,
) {
    normalize_lookup_payload_for_read(&mut lookup.with_payload, mode);
}

async fn preflight_rest_group_lookup_private_result_oram_raw_payload_read(
    toc: &TableOfContent,
    with_lookup: &Option<api::rest::WithLookupInterface>,
    operation: &str,
    auth: &Auth,
) -> Result<(), StorageError> {
    match with_lookup.as_ref() {
        None => Ok(()),
        Some(api::rest::WithLookupInterface::Collection(collection_name)) => {
            preflight_private_result_oram_raw_payload_read(
                toc,
                collection_name,
                Some(&WithPayloadInterface::Bool(true)),
                operation,
                auth,
            )
            .await
        }
        Some(api::rest::WithLookupInterface::WithLookup(lookup)) => {
            preflight_private_result_oram_raw_payload_read(
                toc,
                &lookup.collection_name,
                lookup.with_payload.as_ref(),
                operation,
                auth,
            )
            .await
        }
    }
}

fn rest_group_lookup_payload_decrypt_collection(
    with_lookup: &Option<api::rest::WithLookupInterface>,
    mode: EncryptedPayloadReadMode,
) -> Option<String> {
    if mode != EncryptedPayloadReadMode::Decrypted {
        return None;
    }

    match with_lookup.as_ref()? {
        api::rest::WithLookupInterface::Collection(collection_name) => {
            Some(collection_name.clone())
        }
        api::rest::WithLookupInterface::WithLookup(lookup)
            if group_lookup_payload_is_required(&lookup.with_payload) =>
        {
            Some(lookup.collection_name.clone())
        }
        api::rest::WithLookupInterface::WithLookup(_) => None,
    }
}

fn request_raw_encrypted_payload_for_collection_read(
    with_payload: &mut Option<WithPayloadInterface>,
    mode: EncryptedPayloadReadMode,
) {
    if mode != EncryptedPayloadReadMode::Decrypted {
        return;
    }

    *with_payload = Some(WithPayloadInterface::Encrypted(
        PayloadEncryptedReadPolicy {
            encrypted_payload: EncryptedPayloadReadMode::Raw,
        },
    ));
}

fn request_raw_encrypted_payload_for_required_collection_read(
    with_payload: &mut WithPayloadInterface,
    mode: EncryptedPayloadReadMode,
) {
    if mode != EncryptedPayloadReadMode::Decrypted {
        return;
    }

    *with_payload = WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
        encrypted_payload: EncryptedPayloadReadMode::Raw,
    });
}

async fn payload_decrypt_plan_for_read(
    toc: &TableOfContent,
    collection_name: &str,
    mode: EncryptedPayloadReadMode,
    runtime_settings: Option<&Settings>,
    auth: &Auth,
) -> Result<Option<PayloadWritePlan>, StorageError> {
    if mode != EncryptedPayloadReadMode::Decrypted {
        return Ok(None);
    }

    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().payload_decrypt(),
        "decrypt_payload_read",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    if collection_config.params.effective_encryption().is_none() {
        return Ok(None);
    }
    let Some(settings) = runtime_settings else {
        return Err(StorageError::bad_input(
            "encrypted payload read mode 'decrypted' requires runtime crypto settings; use 'raw' for SDK/client decryption or 'redacted'",
        ));
    };
    if settings.crypto.zero_trust_profile.as_deref()
        == Some(crate::settings::ZERO_TRUST_PROFILE_STRICT)
    {
        return Err(StorageError::bad_input(
            "encrypted payload read mode 'decrypted' is disabled by strict zero-trust profile; use raw client envelopes and decrypt in the SDK",
        ));
    }
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(StorageError::from)?;
    let plan = payload_write_plan_for_collection_with_crypto_id(
        settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )
    .map_err(|_| {
        StorageError::service_error("payload/metadata decrypt runtime is invalid for read")
    })?;

    if let Some(plan) = &plan
        && !plan.has_server_encrypt_rules()
    {
        return Err(StorageError::bad_input(
            "encrypted payload read mode 'decrypted' requires server-side payload text or metadata value AEAD rules; client-side envelopes are opaque and must be decrypted by the client SDK",
        ));
    }

    Ok(plan)
}

async fn preflight_payload_decrypt_for_read(
    toc: &TableOfContent,
    collection_name: &str,
    mode: EncryptedPayloadReadMode,
    runtime_settings: Option<&Settings>,
    auth: &Auth,
) -> Result<(), StorageError> {
    let _ =
        payload_decrypt_plan_for_read(toc, collection_name, mode, runtime_settings, auth).await?;
    Ok(())
}

async fn preflight_private_result_oram_raw_payload_read(
    toc: &TableOfContent,
    collection_name: &str,
    with_payload: Option<&WithPayloadInterface>,
    operation: &str,
    auth: &Auth,
) -> Result<(), StorageError> {
    let Some(with_payload) = with_payload else {
        return Ok(());
    };
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), operation)?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Ok(());
    };
    let Some(payload_path) =
        private_result_oram_raw_payload_read_violation(with_payload, &encryption)?
    else {
        return Ok(());
    };

    Err(private_result_oram_raw_payload_read_error(payload_path))
}

fn private_result_oram_raw_payload_read_error(payload_path: &str) -> StorageError {
    StorageError::bad_input(format!(
        "cannot read private result ORAM payload field through ordinary collection payload reads; {}",
        private_result_oram_api_required_message(payload_path),
    ))
}

fn private_result_oram_raw_payload_read_violation<'a>(
    with_payload: &WithPayloadInterface,
    encryption: &'a CollectionEncryptionConfig,
) -> Result<Option<&'a str>, StorageError> {
    if !with_payload.is_required()
        || with_payload.encrypted_payload_read_mode() == EncryptedPayloadReadMode::Redacted
    {
        return Ok(None);
    }

    for rule in encryption
        .rules
        .iter()
        .filter(|rule| encryption_rule_uses_private_result_oram(rule))
    {
        let EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
            continue;
        };
        for payload_path in paths {
            let protected_path = payload_path.parse::<JsonPath>().map_err(|_| {
                StorageError::bad_input("private result ORAM payload field path is invalid")
            })?;
            if private_result_oram_with_payload_touches_path(with_payload, &protected_path) {
                return Ok(Some(payload_path.as_str()));
            }
        }
    }

    Ok(None)
}

fn private_result_oram_with_payload_touches_path(
    with_payload: &WithPayloadInterface,
    protected_path: &JsonPath,
) -> bool {
    match with_payload {
        WithPayloadInterface::Bool(enabled) => *enabled,
        WithPayloadInterface::Encrypted(_) => true,
        WithPayloadInterface::Fields(fields) => {
            fields.iter().any(|field| field.compatible(protected_path))
        }
        WithPayloadInterface::Selector(PayloadSelector::Include(selector)) => selector
            .include
            .iter()
            .any(|field| field.compatible(protected_path)),
        WithPayloadInterface::Selector(PayloadSelector::Exclude(selector)) => !selector
            .exclude
            .iter()
            .any(|field| field.check_exclude_pattern(protected_path)),
    }
}

async fn preflight_payload_decrypt_modes_for_read(
    toc: &TableOfContent,
    collection_name: &str,
    modes: &[EncryptedPayloadReadMode],
    runtime_settings: Option<&Settings>,
    auth: &Auth,
) -> Result<(), StorageError> {
    if modes.contains(&EncryptedPayloadReadMode::Decrypted) {
        preflight_payload_decrypt_for_read(
            toc,
            collection_name,
            EncryptedPayloadReadMode::Decrypted,
            runtime_settings,
            auth,
        )
        .await?;
    }
    Ok(())
}

fn decrypt_payloads_for_read<'a>(
    _collection_name: &str,
    plan: &PayloadWritePlan,
    payloads: impl IntoIterator<Item = (PointIdType, &'a mut Payload)>,
) -> Result<(), StorageError> {
    for (point_id, payload) in payloads {
        plan.decrypt_server_payload_for_read(&point_id.to_string(), payload)
            .map_err(|_| StorageError::bad_input("payload decrypt read failed"))?;
    }

    Ok(())
}

fn decrypt_record_internal_payloads_for_read(
    collection_name: &str,
    plan: &PayloadWritePlan,
    records: &mut [RecordInternal],
) -> Result<(), StorageError> {
    decrypt_payloads_for_read(
        collection_name,
        plan,
        records.iter_mut().filter_map(|record| {
            let point_id = record.id;
            record.payload.as_mut().map(|payload| (point_id, payload))
        }),
    )
}

fn decrypt_rest_record_payloads_for_read(
    collection_name: &str,
    plan: &PayloadWritePlan,
    records: &mut [api::rest::Record],
) -> Result<(), StorageError> {
    decrypt_payloads_for_read(
        collection_name,
        plan,
        records.iter_mut().filter_map(|record| {
            let point_id = record.id;
            record.payload.as_mut().map(|payload| (point_id, payload))
        }),
    )
}

fn decrypt_scored_point_payloads_for_read(
    collection_name: &str,
    plan: &PayloadWritePlan,
    points: &mut [ScoredPoint],
) -> Result<(), StorageError> {
    decrypt_payloads_for_read(
        collection_name,
        plan,
        points.iter_mut().filter_map(|point| {
            let point_id = point.id;
            point.payload.as_mut().map(|payload| (point_id, payload))
        }),
    )
}

fn decrypt_rest_scored_point_payloads_for_read(
    collection_name: &str,
    plan: &PayloadWritePlan,
    points: &mut [api::rest::ScoredPoint],
) -> Result<(), StorageError> {
    decrypt_payloads_for_read(
        collection_name,
        plan,
        points.iter_mut().filter_map(|point| {
            let point_id = point.id;
            point.payload.as_mut().map(|payload| (point_id, payload))
        }),
    )
}

async fn decrypt_scored_point_batches_for_read(
    toc: &TableOfContent,
    collection_name: &str,
    modes: &[EncryptedPayloadReadMode],
    batches: &mut [Vec<ScoredPoint>],
    runtime_settings: Option<&Settings>,
    auth: &Auth,
) -> Result<(), StorageError> {
    if !modes.contains(&EncryptedPayloadReadMode::Decrypted) {
        return Ok(());
    }
    let Some(plan) = payload_decrypt_plan_for_read(
        toc,
        collection_name,
        EncryptedPayloadReadMode::Decrypted,
        runtime_settings,
        auth,
    )
    .await?
    else {
        return Ok(());
    };

    for (mode, points) in modes.iter().zip(batches.iter_mut()) {
        if *mode == EncryptedPayloadReadMode::Decrypted {
            decrypt_scored_point_payloads_for_read(collection_name, &plan, points)?;
        }
    }

    Ok(())
}

async fn decrypt_group_hits_for_read(
    toc: &TableOfContent,
    collection_name: &str,
    mode: EncryptedPayloadReadMode,
    result: &mut GroupsResult,
    runtime_settings: Option<&Settings>,
    auth: &Auth,
) -> Result<(), StorageError> {
    let Some(plan) =
        payload_decrypt_plan_for_read(toc, collection_name, mode, runtime_settings, auth).await?
    else {
        return Ok(());
    };

    for group in &mut result.groups {
        decrypt_rest_scored_point_payloads_for_read(collection_name, &plan, &mut group.hits)?;
    }

    Ok(())
}

async fn decrypt_group_lookup_payloads_for_read(
    toc: &TableOfContent,
    lookup_collection_name: Option<&str>,
    mode: EncryptedPayloadReadMode,
    result: &mut GroupsResult,
    runtime_settings: Option<&Settings>,
    auth: &Auth,
) -> Result<(), StorageError> {
    let Some(lookup_collection_name) = lookup_collection_name else {
        return Ok(());
    };
    let Some(plan) =
        payload_decrypt_plan_for_read(toc, lookup_collection_name, mode, runtime_settings, auth)
            .await?
    else {
        return Ok(());
    };

    decrypt_payloads_for_read(
        lookup_collection_name,
        &plan,
        result.groups.iter_mut().filter_map(|group| {
            let record = group.lookup.as_mut()?;
            let point_id = record.id;
            record.payload.as_mut().map(|payload| (point_id, payload))
        }),
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn do_get_points(
    toc: &TableOfContent,
    collection_name: &str,
    mut request: PointRequestInternal,
    read_consistency: Option<ReadConsistency>,
    timeout: Option<Duration>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<RecordInternal>, StorageError> {
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &request.with_vector,
        &auth,
        "retrieve",
    )
    .await?;

    let encrypted_payload_read_mode = encrypted_payload_read_mode(request.with_payload.as_ref());
    preflight_private_result_oram_raw_payload_read(
        toc,
        collection_name,
        request.with_payload.as_ref(),
        "retrieve",
        &auth,
    )
    .await?;
    preflight_payload_decrypt_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        runtime_settings,
        &auth,
    )
    .await?;
    request_raw_encrypted_payload_for_collection_read(
        &mut request.with_payload,
        encrypted_payload_read_mode,
    );

    let mut records = toc
        .retrieve(
            collection_name,
            request,
            read_consistency,
            timeout,
            shard_selection,
            auth.clone(),
            hw_measurement_acc,
        )
        .await?;
    if let Some(plan) = payload_decrypt_plan_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        runtime_settings,
        &auth,
    )
    .await?
    {
        decrypt_record_internal_payloads_for_read(collection_name, &plan, &mut records)?;
    }

    Ok(records)
}

#[allow(clippy::too_many_arguments)]
pub async fn do_scroll_points(
    toc: &TableOfContent,
    collection_name: &str,
    mut request: ScrollRequestInternal,
    read_consistency: Option<ReadConsistency>,
    timeout: Option<Duration>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<ScrollResult, StorageError> {
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &request.with_vector,
        &auth,
        "scroll",
    )
    .await?;

    let encrypted_payload_read_mode = encrypted_payload_read_mode(request.with_payload.as_ref());
    preflight_private_result_oram_raw_payload_read(
        toc,
        collection_name,
        request.with_payload.as_ref(),
        "scroll",
        &auth,
    )
    .await?;
    preflight_payload_decrypt_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        runtime_settings,
        &auth,
    )
    .await?;
    request_raw_encrypted_payload_for_collection_read(
        &mut request.with_payload,
        encrypted_payload_read_mode,
    );

    let mut scroll_result = toc
        .scroll(
            collection_name,
            request,
            read_consistency,
            timeout,
            shard_selection,
            auth.clone(),
            hw_measurement_acc,
        )
        .await?;
    if let Some(plan) = payload_decrypt_plan_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        runtime_settings,
        &auth,
    )
    .await?
    {
        decrypt_rest_record_payloads_for_read(collection_name, &plan, &mut scroll_result.points)?;
    }

    Ok(scroll_result)
}

async fn ensure_with_vector_does_not_request_encrypted_vectors(
    toc: &TableOfContent,
    collection_name: &str,
    with_vector: &WithVector,
    auth: &Auth,
    operation: &str,
) -> Result<(), StorageError> {
    if !with_vector.is_enabled() {
        return Ok(());
    }

    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "encrypted_vector_read_guard",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let Some(encryption) = config.params.effective_encryption() else {
        return Ok(());
    };

    match encrypted_vector_return_request(&encryption, with_vector) {
        None => Ok(()),
        Some(request) => {
            let vector_name = request.vector_name();
            if encrypted_vector_return_request_is_private_hnsw_oram(&encryption, vector_name) {
                return Err(StorageError::bad_input(format!(
                    "{} Point-level vector reads are not exposed for this provider.",
                    private_hnsw_oram_api_required_message(vector_name),
                )));
            }

            match request {
                EncryptedVectorReturnRequest::Any { .. } => Err(StorageError::bad_input(format!(
                    "cannot {operation} encrypted vectors; CKKS vector ciphertext read path returns payload sidecar only",
                ))),
                EncryptedVectorReturnRequest::Named { .. } => {
                    Err(StorageError::bad_input(format!(
                        "cannot {operation} encrypted vector; CKKS vector ciphertext read path returns payload sidecar only",
                    )))
                }
            }
        }
    }
}

fn encrypted_vector_return_request_is_private_hnsw_oram(
    encryption: &CollectionEncryptionConfig,
    vector_name: &str,
) -> bool {
    private_hnsw_oram_vector_in_encryption(encryption, vector_name)
}

fn private_hnsw_oram_vector_in_encryption(
    encryption: &CollectionEncryptionConfig,
    vector_name: &str,
) -> bool {
    encryption.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING)
            && matches!(
                &rule.selector,
                EncryptionSelector::VectorNames { names } if names.iter().any(|name| name == vector_name)
            )
    })
}

fn private_hnsw_oram_api_required_error(vector_name: &str) -> StorageError {
    StorageError::bad_input(private_hnsw_oram_api_required_message(vector_name))
}

async fn private_hnsw_oram_vector_names_for_collection(
    toc: &TableOfContent,
    collection_name: &str,
    auth: &Auth,
) -> Result<Vec<String>, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "private_hnsw_oram_vector_guard",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let Some(encryption) = config.params.effective_encryption() else {
        return Ok(Vec::new());
    };

    Ok(encryption
        .rules
        .iter()
        .filter(|rule| rule.binding.as_deref() == Some(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING))
        .flat_map(|rule| match &rule.selector {
            EncryptionSelector::VectorNames { names } => names.clone(),
            EncryptionSelector::PayloadPaths { .. } | EncryptionSelector::MetadataKeys { .. } => {
                Vec::new()
            }
        })
        .collect())
}

fn ensure_vector_name_is_not_private_hnsw_oram(
    private_hnsw_vectors: &[String],
    vector_name: &str,
) -> Result<(), StorageError> {
    if private_hnsw_vectors
        .iter()
        .any(|private_name| private_name == vector_name)
    {
        return Err(private_hnsw_oram_api_required_error(vector_name));
    }

    Ok(())
}

fn ensure_core_search_batch_does_not_use_private_hnsw_oram_vectors(
    request: &CoreSearchRequestBatch,
    private_hnsw_vectors: &[String],
) -> Result<(), StorageError> {
    for search in &request.searches {
        ensure_vector_name_is_not_private_hnsw_oram(
            private_hnsw_vectors,
            search.query.get_vector_name(),
        )?;
    }

    Ok(())
}

fn ensure_query_requests_do_not_use_private_hnsw_oram_vectors(
    requests: &[(CollectionQueryRequest, ShardSelectorInternal)],
    private_hnsw_vectors: &[String],
) -> Result<(), StorageError> {
    for (request, _) in requests {
        ensure_vector_name_is_not_private_hnsw_oram(private_hnsw_vectors, &request.using)?;

        let mut prefetches = request.prefetch.iter().collect::<Vec<_>>();
        while let Some(prefetch) = prefetches.pop() {
            ensure_vector_name_is_not_private_hnsw_oram(private_hnsw_vectors, &prefetch.using)?;
            prefetches.extend(prefetch.prefetch.iter());
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn do_query_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: CollectionQueryRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let requests = vec![(request, shard_selection)];
    let batch_res = do_query_batch_points(
        toc,
        collection_name,
        requests,
        read_consistency,
        auth,
        timeout,
        hw_measurement_acc,
        runtime_settings,
    )
    .await?;
    batch_res
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::service_error("Empty query result"))
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_sidecar_for_point_id(
    collection: &collection::collection::Collection,
    vector_name: &str,
    point_id: PointIdType,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<EncryptedCkksVector, StorageError> {
    let records = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![point_id],
                with_payload: Some(encrypted_vector_sidecar_payload_selector()),
                with_vector: WithVector::Bool(false),
            },
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc,
        )
        .await?;

    let record = records
        .into_iter()
        .find(|record| record.id == point_id)
        .ok_or_else(|| ckks_point_id_query_error("point was not found"))?;
    let payload = record
        .payload
        .as_ref()
        .ok_or_else(|| ckks_point_id_query_error("point has no payload sidecar"))?;

    encrypted_vector_from_payload(payload, vector_name)?
        .ok_or_else(|| ckks_point_id_query_error("point has no CKKS vector sidecar"))
}

fn ckks_point_id_query_error(reason: &'static str) -> StorageError {
    StorageError::bad_input(format!("encrypted vector point-id query failed: {reason}"))
}

fn ckks_search_plan_lost_rule_error() -> StorageError {
    StorageError::service_error("CKKS vector search plan lost encrypted vector rule")
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_input_as_query_source<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    role: &str,
    input: &'a VectorInputInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    match input {
        VectorInputInternal::Vector(VectorInternal::Dense(values)) => {
            Ok(CkksSidecarQuerySource::Dense(values))
        }
        VectorInputInternal::Vector(_) => Err(StorageError::bad_input(format!(
            "encrypted vector context query only supports raw dense or point-id {role} examples",
        ))),
        VectorInputInternal::InferredVector(_) => Err(StorageError::bad_input(format!(
            "encrypted vector search does not allow inference-derived {role} query vectors; use a client-encrypted CKKS query envelope or stored point-id query",
        ))),
        VectorInputInternal::CkksEncryptedQuery(input) => {
            ckks_client_encrypted_query_source(vector_name, input)
        }
        VectorInputInternal::Id(point_id) => {
            let encrypted = ckks_vector_sidecar_for_point_id(
                collection,
                vector_name,
                *point_id,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await?;
            Ok(CkksSidecarQuerySource::Stored {
                point_id: point_id.to_string(),
                encrypted,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn ckks_context_query_as_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    context: &'a segment::vector_storage::query::ContextQuery<VectorInputInternal>,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    let mut pairs = Vec::with_capacity(context.pairs.len());
    for pair in &context.pairs {
        let positive = ckks_vector_input_as_query_source(
            collection,
            vector_name,
            "positive",
            &pair.positive,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let negative = ckks_vector_input_as_query_source(
            collection,
            vector_name,
            "negative",
            &pair.negative,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        pairs.push((positive, negative));
    }

    Ok(CkksSidecarScoring::ContextResolved { pairs })
}

fn vector_inputs_contain_point_id(inputs: &[VectorInputInternal]) -> bool {
    inputs
        .iter()
        .any(|input| matches!(input, VectorInputInternal::Id(_)))
}

fn reco_query_single_positive_point_id(
    recommend: &segment::vector_storage::query::RecoQuery<VectorInputInternal>,
) -> Option<PointIdType> {
    if !recommend.negatives.is_empty() || recommend.positives.len() != 1 {
        return None;
    }
    let VectorInputInternal::Id(point_id) = recommend.positives[0] else {
        return None;
    };
    Some(point_id)
}

fn reco_query_needs_sidecar_resolution(
    recommend: &segment::vector_storage::query::RecoQuery<VectorInputInternal>,
) -> bool {
    vector_inputs_contain_point_id(&recommend.positives)
        || vector_inputs_contain_point_id(&recommend.negatives)
}

#[allow(clippy::too_many_arguments)]
async fn vector_inputs_as_ckks_query_sources<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    role: &str,
    inputs: &'a [VectorInputInternal],
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<CkksSidecarQuerySource<'a>>, StorageError> {
    let mut sources = Vec::with_capacity(inputs.len());
    for input in inputs {
        sources.push(
            ckks_vector_input_as_query_source(
                collection,
                vector_name,
                role,
                input,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?,
        );
    }
    Ok(sources)
}

#[allow(clippy::too_many_arguments)]
async fn ckks_reco_query_as_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    recommend: &'a segment::vector_storage::query::RecoQuery<VectorInputInternal>,
    strategy: RecommendStrategy,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    let positives = vector_inputs_as_ckks_query_sources(
        collection,
        vector_name,
        "positive",
        &recommend.positives,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    let negatives = vector_inputs_as_ckks_query_sources(
        collection,
        vector_name,
        "negative",
        &recommend.negatives,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await?;

    match strategy {
        RecommendStrategy::BestScore => Ok(CkksSidecarScoring::RecommendBestScoreResolved {
            positives,
            negatives,
        }),
        RecommendStrategy::SumScores => Ok(CkksSidecarScoring::RecommendSumScoresResolved {
            positives,
            negatives,
        }),
        RecommendStrategy::AverageVector => {
            Ok(CkksSidecarScoring::RecommendAverageVectorResolved {
                positives,
                negatives,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn ckks_discover_query_as_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    discover: &'a segment::vector_storage::query::DiscoverQuery<VectorInputInternal>,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    let target = ckks_vector_input_as_query_source(
        collection,
        vector_name,
        "target",
        &discover.target,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    let mut pairs = Vec::with_capacity(discover.pairs.len());
    for pair in &discover.pairs {
        let positive = ckks_vector_input_as_query_source(
            collection,
            vector_name,
            "positive context",
            &pair.positive,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let negative = ckks_vector_input_as_query_source(
            collection,
            vector_name,
            "negative context",
            &pair.negative,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        pairs.push((positive, negative));
    }

    Ok(CkksSidecarScoring::DiscoverResolved { target, pairs })
}

#[allow(clippy::too_many_arguments)]
async fn ckks_resolve_query_prefetches(
    toc: &TableOfContent,
    collection_name: &str,
    prefetches: &[CollectionPrefetch],
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let mut intermediates = Vec::with_capacity(prefetches.len());
    for prefetch in prefetches {
        let prefetch_request = CollectionQueryRequest {
            prefetch: prefetch.prefetch.clone(),
            query: prefetch.query.clone(),
            using: prefetch.using.clone(),
            filter: prefetch.filter.clone(),
            score_threshold: prefetch
                .score_threshold
                .as_ref()
                .map(|score| score.into_inner()),
            limit: prefetch.limit,
            offset: 0,
            params: prefetch.params.clone(),
            with_vector: WithVector::Bool(false),
            with_payload: WithPayloadInterface::Bool(false),
            lookup_from: prefetch.lookup_from.clone(),
        };
        intermediates.push(
            Box::pin(do_query_points(
                toc,
                collection_name,
                prefetch_request,
                read_consistency,
                shard_selection.clone(),
                auth.clone(),
                timeout,
                hw_measurement_acc.clone(),
                runtime_settings,
            ))
            .await?,
        );
    }

    Ok(intermediates)
}

fn ckks_prefetch_candidate_filter(sources: &[Vec<ScoredPoint>]) -> Option<Filter> {
    if sources.is_empty() {
        return None;
    }

    Some(
        Filter::new().with_point_ids(
            sources
                .iter()
                .flat_map(|source| source.iter().map(|point| point.id)),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn do_query_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    mut requests: Vec<(CollectionQueryRequest, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let encrypted_payload_read_modes = requests
        .iter_mut()
        .map(|(request, _)| {
            let mode = request.with_payload.encrypted_payload_read_mode();
            request_raw_encrypted_payload_for_required_collection_read(
                &mut request.with_payload,
                mode,
            );
            mode
        })
        .collect::<Vec<_>>();
    for (request, _) in &requests {
        preflight_private_result_oram_raw_payload_read(
            toc,
            collection_name,
            Some(&request.with_payload),
            "query",
            &auth,
        )
        .await?;
    }
    preflight_payload_decrypt_modes_for_read(
        toc,
        collection_name,
        &encrypted_payload_read_modes,
        runtime_settings,
        &auth,
    )
    .await?;

    if runtime_settings.is_none() {
        let private_hnsw_vectors =
            private_hnsw_oram_vector_names_for_collection(toc, collection_name, &auth).await?;
        ensure_query_requests_do_not_use_private_hnsw_oram_vectors(
            &requests,
            &private_hnsw_vectors,
        )?;
    }

    if let Some(settings) = runtime_settings {
        let collection_pass = auth.check_collection_access(
            collection_name,
            AccessRequirements::new(),
            "ckks_vector_query",
        )?;
        let collection = toc.get_collection(&collection_pass).await?;
        let config = collection.config_snapshot().await;
        let collection_crypto_id = config.stable_crypto_id(collection_name)?;
        if let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
            settings,
            collection_name,
            &collection_crypto_id,
            &config.params,
        )? {
            enum CkksResolvedQueryRequest<'a> {
                Ready(Vec<ScoredPoint>),
                Plain(CollectionQueryRequest, ShardSelectorInternal),
                Core(CoreSearchRequest, ShardSelectorInternal),
                StoredNearest {
                    vector_name: String,
                    query_point_id: String,
                    query_encrypted: EncryptedCkksVector,
                    filter: Option<Filter>,
                    params: Option<SearchParams>,
                    limit: usize,
                    offset: usize,
                    with_payload: WithPayloadInterface,
                    with_vector: WithVector,
                    score_threshold: Option<f32>,
                    shard_selection: ShardSelectorInternal,
                },
                Scoring {
                    vector_name: String,
                    scoring: CkksSidecarScoring<'a>,
                    filter: Option<Filter>,
                    params: Option<SearchParams>,
                    limit: usize,
                    offset: usize,
                    with_payload: WithPayloadInterface,
                    with_vector: WithVector,
                    score_threshold: Option<f32>,
                    shard_selection: ShardSelectorInternal,
                },
            }

            let mut has_encrypted_query = false;
            let mut core_requests = Vec::with_capacity(requests.len());

            for (request, shard_selection) in &requests {
                let root_uses_encrypted_vector = plan.contains_vector_name(&request.using);
                if let Some(err) = plan.private_hnsw_oram_api_required_error(&request.using) {
                    return Err(err);
                }
                let mut prefetches = request.prefetch.iter().collect::<Vec<_>>();
                let mut has_encrypted_prefetch = false;
                while let Some(prefetch) = prefetches.pop() {
                    if let Some(err) = plan.private_hnsw_oram_api_required_error(&prefetch.using) {
                        return Err(err);
                    }
                    if plan.contains_vector_name(&prefetch.using) {
                        has_encrypted_prefetch = true;
                    }
                    prefetches.extend(prefetch.prefetch.iter());
                }
                if has_encrypted_prefetch {
                    if let Some(Query::Fusion(fusion)) = &request.query {
                        if request.with_vector.is_enabled() {
                            return Err(StorageError::bad_input(
                                "cannot return encrypted vectors from CKKS prefetch fusion; CKKS vector ciphertext read path returns payload sidecar only",
                            ));
                        }

                        let intermediates = ckks_resolve_query_prefetches(
                            toc,
                            collection_name,
                            &request.prefetch,
                            read_consistency,
                            shard_selection,
                            &auth,
                            timeout,
                            hw_measurement_acc.clone(),
                            runtime_settings,
                        )
                        .await?;
                        let mut fused = match fusion {
                            FusionInternal::Rrf { k, weights } => {
                                let weights_slice = weights.as_ref().map(|weights| {
                                    weights.iter().map(|w| w.into_inner()).collect::<Vec<_>>()
                                });
                                ckks_rrf_scoring(
                                    intermediates,
                                    *k,
                                    weights_slice.as_deref(),
                                    "encrypted vector prefetch fusion failed",
                                )?
                            }
                            FusionInternal::Dbsf => {
                                score_fusion(intermediates, ScoreFusion::dbsf())
                            }
                        };
                        if let Some(score_threshold) = request.score_threshold {
                            fused = fused
                                .into_iter()
                                .take_while(|point| point.score >= score_threshold)
                                .collect();
                        }
                        let top = ckks_select_and_fill_scored_points_payload_or_vectors(
                            &collection,
                            fused,
                            request.offset,
                            request.limit,
                            request.with_payload.clone(),
                            WithVector::Bool(false),
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        has_encrypted_query = true;
                        core_requests.push(Some(CkksResolvedQueryRequest::Ready(top)));
                        continue;
                    }
                }

                let prefetch_candidate_filter = if has_encrypted_prefetch
                    || (root_uses_encrypted_vector && !request.prefetch.is_empty())
                {
                    let intermediates = ckks_resolve_query_prefetches(
                        toc,
                        collection_name,
                        &request.prefetch,
                        read_consistency,
                        shard_selection,
                        &auth,
                        timeout,
                        hw_measurement_acc.clone(),
                        runtime_settings,
                    )
                    .await?;
                    has_encrypted_query = true;
                    ckks_prefetch_candidate_filter(&intermediates)
                } else {
                    None
                };
                let has_prefetch_candidate_filter = prefetch_candidate_filter.is_some();
                let effective_filter =
                    Filter::merge_opts(request.filter.clone(), prefetch_candidate_filter);

                if !root_uses_encrypted_vector {
                    let mut request = request.clone();
                    if has_prefetch_candidate_filter {
                        request.prefetch.clear();
                        request.filter = effective_filter;
                    }
                    core_requests.push(Some(CkksResolvedQueryRequest::Plain(
                        request,
                        shard_selection.clone(),
                    )));
                    continue;
                }

                has_encrypted_query = true;
                if request.lookup_from.is_some() {
                    return Err(StorageError::bad_input(
                        "encrypted vector query does not support lookup_from; provide a raw dense query vector or a point id with an encrypted sidecar",
                    ));
                }
                let resolved_request = match &request.query {
                    Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::CkksEncryptedQuery(input),
                    ))) => {
                        let query = ckks_client_encrypted_query_source(&request.using, input)?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring: CkksSidecarScoring::NearestResolved { query },
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(
                        point_id,
                    )))) => {
                        let query_encrypted = ckks_vector_sidecar_for_point_id(
                            &collection,
                            &request.using,
                            *point_id,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::StoredNearest {
                            vector_name: request.using.clone(),
                            query_point_id: point_id.to_string(),
                            query_encrypted,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend)))
                        if reco_query_single_positive_point_id(recommend).is_some() =>
                    {
                        let Some(point_id) = reco_query_single_positive_point_id(recommend) else {
                            return Err(StorageError::service_error(
                                "encrypted recommend query point-id guard did not hold",
                            ));
                        };
                        let query_encrypted = ckks_vector_sidecar_for_point_id(
                            &collection,
                            &request.using,
                            point_id,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::StoredNearest {
                            vector_name: request.using.clone(),
                            query_point_id: point_id.to_string(),
                            query_encrypted,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend)))
                        if reco_query_needs_sidecar_resolution(recommend) =>
                    {
                        let scoring = ckks_reco_query_as_scoring(
                            &collection,
                            &request.using,
                            recommend,
                            RecommendStrategy::AverageVector,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::RecommendBestScore(recommend)))
                        if reco_query_needs_sidecar_resolution(recommend) =>
                    {
                        let scoring = ckks_reco_query_as_scoring(
                            &collection,
                            &request.using,
                            recommend,
                            RecommendStrategy::BestScore,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::RecommendSumScores(recommend)))
                        if reco_query_needs_sidecar_resolution(recommend) =>
                    {
                        let scoring = ckks_reco_query_as_scoring(
                            &collection,
                            &request.using,
                            recommend,
                            RecommendStrategy::SumScores,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::NearestWithMmr(nearest_with_mmr))) => {
                        let query = ckks_vector_input_as_query_source(
                            &collection,
                            &request.using,
                            "MMR nearest",
                            &nearest_with_mmr.nearest,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring: CkksSidecarScoring::NearestMmr {
                                query,
                                lambda: nearest_with_mmr
                                    .mmr
                                    .diversity
                                    .map(|diversity| 1.0 - diversity)
                                    .unwrap_or(0.5),
                                candidates_limit: nearest_with_mmr
                                    .mmr
                                    .candidates_limit
                                    .unwrap_or(request.limit),
                            },
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::Context(context))) => {
                        let scoring = ckks_context_query_as_scoring(
                            &collection,
                            &request.using,
                            context,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::Discover(discover))) => {
                        let scoring = ckks_discover_query_as_scoring(
                            &collection,
                            &request.using,
                            discover,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    _ => {
                        let query = ckks_query_as_core_query(&request.query, &request.using)?;
                        CkksResolvedQueryRequest::Core(
                            CoreSearchRequest {
                                query,
                                filter: effective_filter.clone(),
                                params: request.params.clone(),
                                limit: request.limit,
                                offset: request.offset,
                                with_payload: Some(request.with_payload.clone()),
                                with_vector: Some(request.with_vector.clone()),
                                score_threshold: request.score_threshold,
                            },
                            shard_selection.clone(),
                        )
                    }
                };

                core_requests.push(Some(resolved_request));
            }

            if has_encrypted_query {
                let mut results = Vec::with_capacity(core_requests.len());
                for request in core_requests {
                    let Some(request) = request else {
                        return Err(StorageError::service_error(
                            "CKKS query batch contained an unresolved request slot",
                        ));
                    };
                    let result = match request {
                        CkksResolvedQueryRequest::Ready(result) => result,
                        CkksResolvedQueryRequest::Plain(request, shard_selection) => {
                            ensure_with_vector_does_not_request_encrypted_vectors(
                                toc,
                                collection_name,
                                &request.with_vector,
                                &auth,
                                "query",
                            )
                            .await?;
                            let mut plain_results = toc
                                .query_batch(
                                    collection_name,
                                    vec![(request, shard_selection)],
                                    read_consistency,
                                    auth.clone(),
                                    timeout,
                                    hw_measurement_acc.clone(),
                                )
                                .await?;
                            plain_results.pop().ok_or_else(|| {
                                StorageError::service_error(
                                    "plaintext query result missing from mixed CKKS vector batch",
                                )
                            })?
                        }
                        CkksResolvedQueryRequest::Core(request, shard_selection) => {
                            ckks_vector_search_points(
                                &collection,
                                collection_name,
                                &collection_crypto_id,
                                &request,
                                &plan,
                                read_consistency,
                                &shard_selection,
                                timeout,
                                None,
                                hw_measurement_acc.clone(),
                            )
                            .await?
                        }
                        CkksResolvedQueryRequest::StoredNearest {
                            vector_name,
                            query_point_id,
                            query_encrypted,
                            filter,
                            params,
                            limit,
                            offset,
                            with_payload,
                            with_vector,
                            score_threshold,
                            shard_selection,
                        } => {
                            ckks_vector_search_points_with_scoring(
                                &collection,
                                collection_name,
                                &collection_crypto_id,
                                &vector_name,
                                CkksSidecarScoring::StoredNearest {
                                    query_point_id,
                                    query_encrypted,
                                },
                                filter,
                                params,
                                limit,
                                offset,
                                Some(with_payload),
                                Some(with_vector),
                                score_threshold,
                                None,
                                &plan,
                                read_consistency,
                                &shard_selection,
                                timeout,
                                hw_measurement_acc.clone(),
                            )
                            .await?
                        }
                        CkksResolvedQueryRequest::Scoring {
                            vector_name,
                            scoring,
                            filter,
                            params,
                            limit,
                            offset,
                            with_payload,
                            with_vector,
                            score_threshold,
                            shard_selection,
                        } => {
                            ckks_vector_search_points_with_scoring(
                                &collection,
                                collection_name,
                                &collection_crypto_id,
                                &vector_name,
                                scoring,
                                filter,
                                params,
                                limit,
                                offset,
                                Some(with_payload),
                                Some(with_vector),
                                score_threshold,
                                None,
                                &plan,
                                read_consistency,
                                &shard_selection,
                                timeout,
                                hw_measurement_acc.clone(),
                            )
                            .await?
                        }
                    };
                    results.push(result);
                }
                decrypt_scored_point_batches_for_read(
                    toc,
                    collection_name,
                    &encrypted_payload_read_modes,
                    &mut results,
                    runtime_settings,
                    &auth,
                )
                .await?;
                return Ok(results);
            }
        }
    }

    for (request, _) in &requests {
        ensure_with_vector_does_not_request_encrypted_vectors(
            toc,
            collection_name,
            &request.with_vector,
            &auth,
            "query",
        )
        .await?;
    }

    let mut results = toc
        .query_batch(
            collection_name,
            requests,
            read_consistency,
            auth.clone(),
            timeout,
            hw_measurement_acc,
        )
        .await?;
    decrypt_scored_point_batches_for_read(
        toc,
        collection_name,
        &encrypted_payload_read_modes,
        &mut results,
        runtime_settings,
        &auth,
    )
    .await?;
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
pub async fn do_query_point_groups(
    toc: &TableOfContent,
    collection_name: &str,
    mut request: CollectionQueryGroupsRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<GroupsResult, StorageError> {
    let encrypted_payload_read_mode = request.with_payload.encrypted_payload_read_mode();
    preflight_private_result_oram_raw_payload_read(
        toc,
        collection_name,
        Some(&request.with_payload),
        "query grouped results",
        &auth,
    )
    .await?;
    if let Some(lookup) = &mut request.with_lookup {
        normalize_collection_group_lookup_payload_for_read(lookup, encrypted_payload_read_mode);
        preflight_private_result_oram_raw_payload_read(
            toc,
            &lookup.collection_name,
            lookup.with_payload.as_ref(),
            "query group lookup",
            &auth,
        )
        .await?;
    }
    preflight_payload_decrypt_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        runtime_settings,
        &auth,
    )
    .await?;
    let lookup_decrypt_collection = request
        .with_lookup
        .as_ref()
        .filter(|lookup| {
            encrypted_payload_read_mode == EncryptedPayloadReadMode::Decrypted
                && group_lookup_payload_is_required(&lookup.with_payload)
        })
        .map(|lookup| lookup.collection_name.clone());
    request_raw_encrypted_payload_for_required_collection_read(
        &mut request.with_payload,
        encrypted_payload_read_mode,
    );

    if let Some(settings) = runtime_settings
        && let Some(mut result) = try_ckks_vector_query_groups(
            toc,
            collection_name,
            &request,
            read_consistency,
            &shard_selection,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
            encrypted_payload_read_mode,
        )
        .await?
    {
        decrypt_group_hits_for_read(
            toc,
            collection_name,
            encrypted_payload_read_mode,
            &mut result,
            runtime_settings,
            &auth,
        )
        .await?;
        decrypt_group_lookup_payloads_for_read(
            toc,
            lookup_decrypt_collection.as_deref(),
            encrypted_payload_read_mode,
            &mut result,
            runtime_settings,
            &auth,
        )
        .await?;
        return Ok(result);
    }

    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &request.with_vector,
        &auth,
        "query groups",
    )
    .await?;
    ensure_encrypted_vector_group_request_is_unsupported(
        toc,
        collection_name,
        &request.using,
        &auth,
    )
    .await?;
    let mut prefetches: Vec<&CollectionPrefetch> = request.prefetch.iter().collect();
    while let Some(prefetch) = prefetches.pop() {
        ensure_encrypted_vector_group_request_is_unsupported(
            toc,
            collection_name,
            &prefetch.using,
            &auth,
        )
        .await?;
        prefetches.extend(prefetch.prefetch.iter());
    }

    let mut result = toc
        .group(
            collection_name,
            GroupRequest::from(request),
            read_consistency,
            shard_selection,
            auth.clone(),
            timeout,
            hw_measurement_acc,
        )
        .await?;
    decrypt_group_hits_for_read(
        toc,
        collection_name,
        encrypted_payload_read_mode,
        &mut result,
        runtime_settings,
        &auth,
    )
    .await?;
    decrypt_group_lookup_payloads_for_read(
        toc,
        lookup_decrypt_collection.as_deref(),
        encrypted_payload_read_mode,
        &mut result,
        runtime_settings,
        &auth,
    )
    .await?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_query_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: &CollectionQueryGroupsRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
    encrypted_payload_read_mode: EncryptedPayloadReadMode,
) -> Result<Option<GroupsResult>, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_query_groups",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let mut prefetches = request.prefetch.iter().collect::<Vec<_>>();
    let mut has_encrypted_prefetch = false;
    while let Some(prefetch) = prefetches.pop() {
        if let Some(err) = plan.private_hnsw_oram_api_required_error(&prefetch.using) {
            return Err(err);
        }
        if plan.contains_vector_name(&prefetch.using) {
            has_encrypted_prefetch = true;
        }
        prefetches.extend(prefetch.prefetch.iter());
    }
    let root_uses_encrypted_vector = plan.contains_vector_name(&request.using);
    if let Some(err) = plan.private_hnsw_oram_api_required_error(&request.using) {
        return Err(err);
    }
    if has_encrypted_prefetch {
        if let Some(Query::Fusion(fusion)) = &request.query {
            if request.with_vector.is_enabled() {
                return Err(StorageError::bad_input(
                    "cannot return encrypted vectors from CKKS prefetch fusion groups; CKKS vector ciphertext read path returns payload sidecar only",
                ));
            }
            ensure_group_path_does_not_touch_encrypted_crypto_selectors(
                config.params.encryption.as_ref(),
                &request.group_by,
            )?;

            let intermediates = ckks_resolve_query_prefetches(
                toc,
                collection_name,
                &request.prefetch,
                read_consistency,
                shard_selection,
                auth,
                timeout,
                hw_measurement_acc.clone(),
                Some(runtime_settings),
            )
            .await?;
            let mut fused = match fusion {
                FusionInternal::Rrf { k, weights } => {
                    let weights_slice = weights
                        .as_ref()
                        .map(|weights| weights.iter().map(|w| w.into_inner()).collect::<Vec<_>>());
                    ckks_rrf_scoring(
                        intermediates,
                        *k,
                        weights_slice.as_deref(),
                        "encrypted vector prefetch fusion groups failed",
                    )?
                }
                FusionInternal::Dbsf => score_fusion(intermediates, ScoreFusion::dbsf()),
            };
            if let Some(score_threshold) = request.score_threshold {
                fused = fused
                    .into_iter()
                    .take_while(|point| point.score >= score_threshold)
                    .collect();
            }
            ckks_fill_scored_points_payload_or_vectors(
                &collection,
                &mut fused,
                encrypted_vector_sidecar_and_group_payload_selector(&request.group_by),
                WithVector::Bool(false),
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            let result = ckks_vector_group_scored_points(
                &collection,
                fused,
                &request.group_by,
                request.limit,
                request.group_size,
                request.with_payload.clone(),
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            return attach_ckks_group_lookup(
                toc,
                result,
                request.with_lookup.clone(),
                read_consistency,
                shard_selection,
                auth,
                timeout,
                hw_measurement_acc,
                encrypted_payload_read_mode,
            )
            .await
            .map(Some);
        }
    }

    let prefetch_candidate_filter =
        if has_encrypted_prefetch || (root_uses_encrypted_vector && !request.prefetch.is_empty()) {
            let intermediates = ckks_resolve_query_prefetches(
                toc,
                collection_name,
                &request.prefetch,
                read_consistency,
                shard_selection,
                auth,
                timeout,
                hw_measurement_acc.clone(),
                Some(runtime_settings),
            )
            .await?;
            ckks_prefetch_candidate_filter(&intermediates)
        } else {
            None
        };
    let has_prefetch_candidate_filter = prefetch_candidate_filter.is_some();
    let effective_filter = Filter::merge_opts(request.filter.clone(), prefetch_candidate_filter);

    if !root_uses_encrypted_vector {
        if has_prefetch_candidate_filter {
            let request = CollectionQueryGroupsRequest {
                prefetch: Vec::new(),
                query: request.query.clone(),
                using: request.using.clone(),
                filter: effective_filter,
                params: request.params.clone(),
                score_threshold: request.score_threshold,
                with_vector: request.with_vector.clone(),
                with_payload: request.with_payload.clone(),
                lookup_from: request.lookup_from.clone(),
                group_by: request.group_by.clone(),
                group_size: request.group_size,
                limit: request.limit,
                with_lookup: request.with_lookup.clone(),
            };
            ensure_group_path_does_not_touch_encrypted_crypto_selectors(
                config.params.encryption.as_ref(),
                &request.group_by,
            )?;
            return toc
                .group(
                    collection_name,
                    GroupRequest::from(request),
                    read_consistency,
                    shard_selection.clone(),
                    auth.clone(),
                    timeout,
                    hw_measurement_acc,
                )
                .await
                .map(Some);
        }
        return Ok(None);
    }
    if request.lookup_from.is_some() {
        return Err(StorageError::bad_input(
            "encrypted vector query groups do not support lookup_from; provide a plaintext dense query vector",
        ));
    }
    ensure_group_path_does_not_touch_encrypted_crypto_selectors(
        config.params.encryption.as_ref(),
        &request.group_by,
    )?;

    if let Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend))) = &request.query
        && let Some(point_id) = reco_query_single_positive_point_id(recommend)
    {
        let query_encrypted = ckks_vector_sidecar_for_point_id(
            &collection,
            &request.using,
            point_id,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            CkksSidecarScoring::StoredNearest {
                query_point_id: point_id.to_string(),
                query_encrypted,
            },
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend))) = &request.query
        && reco_query_needs_sidecar_resolution(recommend)
    {
        let scoring = ckks_reco_query_as_scoring(
            &collection,
            &request.using,
            recommend,
            RecommendStrategy::AverageVector,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::RecommendBestScore(recommend))) = &request.query
        && reco_query_needs_sidecar_resolution(recommend)
    {
        let scoring = ckks_reco_query_as_scoring(
            &collection,
            &request.using,
            recommend,
            RecommendStrategy::BestScore,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::RecommendSumScores(recommend))) = &request.query
        && reco_query_needs_sidecar_resolution(recommend)
    {
        let scoring = ckks_reco_query_as_scoring(
            &collection,
            &request.using,
            recommend,
            RecommendStrategy::SumScores,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::Discover(discover))) = &request.query {
        let scoring = ckks_discover_query_as_scoring(
            &collection,
            &request.using,
            discover,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::Context(context))) = &request.query {
        let scoring = ckks_context_query_as_scoring(
            &collection,
            &request.using,
            context,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::CkksEncryptedQuery(
        input,
    )))) = &request.query
    {
        let query = ckks_client_encrypted_query_source(&request.using, input)?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            CkksSidecarScoring::NearestResolved { query },
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(point_id)))) =
        &request.query
    {
        let query_encrypted = ckks_vector_sidecar_for_point_id(
            &collection,
            &request.using,
            *point_id,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            CkksSidecarScoring::StoredNearest {
                query_point_id: point_id.to_string(),
                query_encrypted,
            },
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::NearestWithMmr(nearest_with_mmr))) = &request.query {
        let query = ckks_vector_input_as_query_source(
            &collection,
            &request.using,
            "MMR nearest",
            &nearest_with_mmr.nearest,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            CkksSidecarScoring::NearestMmr {
                query,
                lambda: nearest_with_mmr
                    .mmr
                    .diversity
                    .map(|diversity| 1.0 - diversity)
                    .unwrap_or(0.5),
                candidates_limit: nearest_with_mmr
                    .mmr
                    .candidates_limit
                    .unwrap_or(request.limit),
            },
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            encrypted_payload_read_mode,
        )
        .await
        .map(Some);
    }

    let search_request = CoreSearchRequest {
        query: ckks_query_as_core_query(&request.query, &request.using)?,
        filter: effective_filter.clone(),
        params: request.params.clone(),
        limit: usize::MAX,
        offset: 0,
        with_payload: Some(encrypted_vector_sidecar_and_group_payload_selector(
            &request.group_by,
        )),
        with_vector: Some(WithVector::Bool(false)),
        score_threshold: request.score_threshold,
    };
    let result = ckks_vector_group_points(
        &collection,
        collection_name,
        &collection_crypto_id,
        &search_request,
        &plan,
        &request.group_by,
        request.limit,
        request.group_size,
        request.with_payload.clone(),
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    attach_ckks_group_lookup(
        toc,
        result,
        request.with_lookup.clone(),
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
        encrypted_payload_read_mode,
    )
    .await
    .map(Some)
}

fn ckks_query_as_core_query(
    query: &Option<Query>,
    vector_name: &str,
) -> Result<QueryEnum, StorageError> {
    match query {
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Vector(
            VectorInternal::Dense(query_values),
        )))) => Ok(QueryEnum::Nearest(NamedQuery::new(
            VectorInternal::Dense(query_values.clone()),
            vector_name.to_string(),
        ))),
        Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend))) => {
            ckks_recommend_query_as_dense_search_vector(recommend, vector_name).map(|values| {
                QueryEnum::Nearest(NamedQuery::new(
                    VectorInternal::Dense(values),
                    vector_name.to_string(),
                ))
            })
        }
        Some(Query::Vector(VectorQuery::RecommendBestScore(recommend))) => {
            ckks_recommend_query_as_core_recommend(recommend, vector_name).map(|query| {
                QueryEnum::RecommendBestScore(NamedQuery::new(query, vector_name.to_string()))
            })
        }
        Some(Query::Vector(VectorQuery::RecommendSumScores(recommend))) => {
            ckks_recommend_query_as_core_recommend(recommend, vector_name).map(|query| {
                QueryEnum::RecommendSumScores(NamedQuery::new(query, vector_name.to_string()))
            })
        }
        Some(Query::Vector(VectorQuery::Discover(discover))) => {
            ckks_discover_query_as_core_discover(discover, vector_name)
                .map(|query| QueryEnum::Discover(NamedQuery::new(query, vector_name.to_string())))
        }
        Some(Query::Vector(VectorQuery::Context(context))) => {
            ckks_context_query_as_core_context(context, vector_name)
                .map(|query| QueryEnum::Context(NamedQuery::new(query, vector_name.to_string())))
        }
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(_)))) => {
            Err(StorageError::bad_input(
                "encrypted vector query cannot resolve point-id query vectors because plaintext vectors are not stored",
            ))
        }
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::CkksEncryptedQuery(_)))) => {
            Err(StorageError::bad_input(
                "encrypted vector client CKKS query requires CKKS sidecar scoring",
            ))
        }
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Vector(_)))) => Err(
            StorageError::bad_input("encrypted vector search only supports dense query vectors"),
        ),
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::InferredVector(_)))) => {
            Err(StorageError::bad_input(format!(
                "encrypted vector search does not allow inference-derived query vectors; use a client-encrypted CKKS query envelope or stored point-id query",
            )))
        }
        _ => Err(StorageError::bad_input(
            "encrypted vector query only supports nearest-neighbor dense query, raw-dense recommend, raw-dense discover, or raw-dense context",
        )),
    }
}

fn ckks_recommend_query_as_dense_search_vector(
    recommend: &segment::vector_storage::query::RecoQuery<VectorInputInternal>,
    vector_name: &str,
) -> Result<Vec<f32>, StorageError> {
    let positive = vector_inputs_as_dense_vectors(&recommend.positives, vector_name, "positive")?;
    let negative = vector_inputs_as_dense_vectors(&recommend.negatives, vector_name, "negative")?;
    let search_vector = avg_vector_for_recommendation(
        positive.iter().map(VectorRef::from),
        negative.iter().map(VectorRef::from).peekable(),
    )
    .map_err(|_| {
        StorageError::bad_input("encrypted vector query recommend average-vector conversion failed")
    })?;
    let VectorInternal::Dense(query_values) = search_vector else {
        return Err(StorageError::service_error(
            "CKKS sidecar recommend query conversion produced non-dense query",
        ));
    };
    Ok(query_values)
}

fn ckks_rrf_scoring(
    intermediates: Vec<Vec<ScoredPoint>>,
    k: usize,
    weights: Option<&[f32]>,
    message: &'static str,
) -> Result<Vec<ScoredPoint>, StorageError> {
    rrf_scoring(intermediates, k, weights).map_err(|_| StorageError::bad_input(message))
}

fn vector_inputs_as_dense_vectors(
    inputs: &[VectorInputInternal],
    _vector_name: &str,
    role: &str,
) -> Result<Vec<VectorInternal>, StorageError> {
    inputs
        .iter()
        .map(|input| match input {
            VectorInputInternal::Vector(VectorInternal::Dense(vector)) => {
                Ok(VectorInternal::Dense(vector.clone()))
            }
            VectorInputInternal::Vector(_) => Err(StorageError::bad_input(format!(
                "encrypted vector query only supports raw dense {role} examples",
            ))),
            VectorInputInternal::InferredVector(_) => Err(StorageError::bad_input(format!(
                "encrypted vector query does not allow inference-derived {role} examples",
            ))),
            VectorInputInternal::Id(_) => Err(StorageError::bad_input(format!(
                "encrypted vector query cannot resolve point-id {role} examples because plaintext vectors are not stored",
            ))),
            VectorInputInternal::CkksEncryptedQuery(_) => Err(StorageError::bad_input(format!(
                "encrypted vector query does not support client CKKS encrypted {role} examples in recommend/discover/context inputs",
            ))),
        })
        .collect()
}

fn ckks_recommend_query_as_core_recommend(
    recommend: &segment::vector_storage::query::RecoQuery<VectorInputInternal>,
    vector_name: &str,
) -> Result<segment::vector_storage::query::RecoQuery<VectorInternal>, StorageError> {
    let positive = vector_inputs_as_dense_vectors(&recommend.positives, vector_name, "positive")?;
    let negative = vector_inputs_as_dense_vectors(&recommend.negatives, vector_name, "negative")?;
    Ok(segment::vector_storage::query::RecoQuery::new(
        positive, negative,
    ))
}

fn ckks_discover_query_as_core_discover(
    discover: &segment::vector_storage::query::DiscoverQuery<VectorInputInternal>,
    _vector_name: &str,
) -> Result<segment::vector_storage::query::DiscoverQuery<VectorInternal>, StorageError> {
    let target = match &discover.target {
        VectorInputInternal::Vector(VectorInternal::Dense(target)) => target,
        VectorInputInternal::InferredVector(_) => {
            return Err(StorageError::bad_input(format!(
                "encrypted vector discover does not allow inference-derived target examples",
            )));
        }
        _ => {
            return Err(StorageError::bad_input(
                "encrypted vector discover cannot resolve point-id or non-dense target examples because plaintext vectors are not stored",
            ));
        }
    };
    let pairs = discover
        .pairs
        .iter()
        .map(|pair| {
            let positive = match &pair.positive {
                VectorInputInternal::Vector(VectorInternal::Dense(positive)) => positive,
                VectorInputInternal::InferredVector(_) => {
                    return Err(StorageError::bad_input(format!(
                        "encrypted vector discover does not allow inference-derived positive context examples",
                    )));
                }
                _ => {
                    return Err(StorageError::bad_input(
                        "encrypted vector discover cannot resolve point-id or non-dense positive context examples because plaintext vectors are not stored",
                    ));
                }
            };
            let negative = match &pair.negative {
                VectorInputInternal::Vector(VectorInternal::Dense(negative)) => negative,
                VectorInputInternal::InferredVector(_) => {
                    return Err(StorageError::bad_input(format!(
                        "encrypted vector discover does not allow inference-derived negative context examples",
                    )));
                }
                _ => {
                    return Err(StorageError::bad_input(
                        "encrypted vector discover cannot resolve point-id or non-dense negative context examples because plaintext vectors are not stored",
                    ));
                }
            };
            Ok(ContextPair {
                positive: VectorInternal::Dense(positive.clone()),
                negative: VectorInternal::Dense(negative.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(segment::vector_storage::query::DiscoverQuery::new(
        VectorInternal::Dense(target.clone()),
        pairs,
    ))
}

fn ckks_context_query_as_core_context(
    context: &segment::vector_storage::query::ContextQuery<VectorInputInternal>,
    _vector_name: &str,
) -> Result<segment::vector_storage::query::ContextQuery<VectorInternal>, StorageError> {
    let pairs = context
        .pairs
        .iter()
        .map(|pair| {
            let positive = match &pair.positive {
                VectorInputInternal::Vector(VectorInternal::Dense(positive)) => positive,
                VectorInputInternal::InferredVector(_) => {
                    return Err(StorageError::bad_input(format!(
                        "encrypted vector context query does not allow inference-derived positive examples",
                    )));
                }
                _ => {
                    return Err(StorageError::bad_input(
                        "encrypted vector context query cannot resolve point-id or non-dense positive examples because plaintext vectors are not stored",
                    ));
                }
            };
            let negative = match &pair.negative {
                VectorInputInternal::Vector(VectorInternal::Dense(negative)) => negative,
                VectorInputInternal::InferredVector(_) => {
                    return Err(StorageError::bad_input(format!(
                        "encrypted vector context query does not allow inference-derived negative examples",
                    )));
                }
                _ => {
                    return Err(StorageError::bad_input(
                        "encrypted vector context query cannot resolve point-id or non-dense negative examples because plaintext vectors are not stored",
                    ));
                }
            };
            Ok(ContextPair {
                positive: VectorInternal::Dense(positive.clone()),
                negative: VectorInternal::Dense(negative.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(segment::vector_storage::query::ContextQuery::new(pairs))
}

fn search_group_vector_name(vector: &api::rest::NamedVectorStruct) -> &str {
    match vector {
        api::rest::NamedVectorStruct::Default(_) => DEFAULT_VECTOR_NAME,
        api::rest::NamedVectorStruct::CkksEncryptedQuery(vector) => {
            vector.name.as_deref().unwrap_or(DEFAULT_VECTOR_NAME)
        }
        api::rest::NamedVectorStruct::Dense(vector) => &vector.name,
        api::rest::NamedVectorStruct::Sparse(vector) => &vector.name,
    }
}

async fn ensure_encrypted_vector_group_request_is_unsupported(
    toc: &TableOfContent,
    collection_name: &str,
    vector_name: &str,
    auth: &Auth,
) -> Result<(), StorageError> {
    ensure_encrypted_vector_name_is_unsupported(
        toc,
        collection_name,
        vector_name,
        auth,
        "group by search over",
        "runtime OpenFHE settings are required for CKKS sidecar grouped search",
    )
    .await
}

async fn ensure_encrypted_vector_name_is_unsupported(
    toc: &TableOfContent,
    collection_name: &str,
    vector_name: &str,
    auth: &Auth,
    operation: &str,
    reason: &str,
) -> Result<(), StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "encrypted_vector_operation_guard",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    if let Some(encryption) = config.params.effective_encryption() {
        for rule in &encryption.rules {
            let EncryptionSelector::VectorNames { names } = &rule.selector else {
                continue;
            };
            if names.iter().any(|name| name == vector_name) {
                if private_hnsw_oram_vector_in_encryption(&encryption, vector_name) {
                    return Err(private_hnsw_oram_api_required_error(vector_name));
                }
                return Err(StorageError::bad_input(format!(
                    "cannot {operation} encrypted vector; {reason}",
                )));
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn do_search_points_matrix(
    toc: &TableOfContent,
    collection_name: &str,
    request: CollectionSearchMatrixRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<CollectionSearchMatrixResponse, StorageError> {
    if let Some(settings) = runtime_settings {
        let collection_pass = auth.check_collection_access(
            collection_name,
            AccessRequirements::new(),
            "ckks_vector_search_matrix",
        )?;
        let collection = toc.get_collection(&collection_pass).await?;
        let config = collection.config_snapshot().await;
        let collection_crypto_id = config.stable_crypto_id(collection_name)?;
        if let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
            settings,
            collection_name,
            &collection_crypto_id,
            &config.params,
        )? && plan.contains_vector_name(&request.using)
        {
            if let Some(err) = plan.private_hnsw_oram_api_required_error(&request.using) {
                return Err(err);
            }
            return ckks_vector_search_points_matrix(
                &collection,
                collection_name,
                &request,
                &plan,
                read_consistency,
                &shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await;
        }
    }

    ensure_encrypted_vector_name_is_unsupported(
        toc,
        collection_name,
        &request.using,
        &auth,
        "search matrix using",
        "runtime OpenFHE settings are required for CKKS sidecar matrix search",
    )
    .await?;

    toc.search_points_matrix(
        collection_name,
        request,
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_search_points_matrix(
    collection: &collection::collection::Collection,
    collection_name: &str,
    request: &CollectionSearchMatrixRequest,
    plan: &crate::common::crypto::VectorWritePlan,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CollectionSearchMatrixResponse, StorageError> {
    if request.sample_size == 0 || request.limit_per_sample == 0 {
        return Ok(CollectionSearchMatrixResponse::default());
    }
    ensure_ckks_matrix_budget(request.sample_size, request.limit_per_sample)?;

    let vector_name = request.using.as_str();
    let distance = plan
        .distance_for_vector(vector_name)
        .ok_or_else(ckks_search_plan_lost_rule_error)?;
    let score_order = distance.distance_order();
    let mut sampled = Vec::with_capacity(request.sample_size);

    let sampled_points = collection
        .query(
            ShardQueryRequest {
                prefetches: Vec::new(),
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: request.filter.clone(),
                score_threshold: None,
                limit: request.sample_size,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: encrypted_vector_sidecar_payload_selector(),
            },
            read_consistency,
            shard_selection.clone(),
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;

    for record in sampled_points {
        let Some(payload) = record.payload.as_ref() else {
            continue;
        };
        let Some(encrypted) = encrypted_vector_from_payload(payload, vector_name)? else {
            continue;
        };
        sampled.push(CkksSidecarSearchRecord {
            id: record.id,
            shard_key: record.shard_key,
            point_id: record.id.to_string(),
            encrypted,
        });
    }

    if sampled.len() < 2 {
        return Ok(CollectionSearchMatrixResponse::default());
    }

    sampled.sort_unstable_by_key(|record| record.id);
    let sample_ids = sampled.iter().map(|record| record.id).collect::<Vec<_>>();
    let encrypted_items = sampled
        .iter()
        .map(|record| (record.point_id.clone(), record.encrypted.clone()))
        .collect::<Vec<_>>();
    let mut nearests = Vec::with_capacity(sampled.len());

    for query in &sampled {
        let scores = plan
            .score_stored_query_batch(
                collection_name,
                vector_name,
                &query.point_id,
                &query.encrypted,
                &encrypted_items,
            )?
            .ok_or_else(ckks_search_plan_lost_rule_error)?;
        let mut scored = sampled
            .iter()
            .zip(scores)
            .filter_map(|(record, score)| {
                (record.id != query.id).then(|| ScoredPoint {
                    id: record.id,
                    version: 0,
                    score,
                    payload: None,
                    vector: None,
                    shard_key: record.shard_key.clone(),
                    order_value: None,
                })
            })
            .collect::<Vec<_>>();
        sort_ckks_scored_points(score_order, &mut scored);
        scored.truncate(request.limit_per_sample);
        nearests.push(scored);
    }

    let version_ids = nearests
        .iter()
        .flat_map(|nearest| nearest.iter().map(|point| point.id))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !version_ids.is_empty() {
        let records = collection
            .retrieve(
                PointRequestInternal {
                    ids: version_ids,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: WithVector::Bool(false),
                },
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await?;
        let versions_by_id = records
            .into_iter()
            .map(|record| (record.id, record.version))
            .collect::<HashMap<_, _>>();
        for scored in nearests.iter_mut().flatten() {
            if let Some(version) = versions_by_id.get(&scored.id) {
                scored.version = *version;
            }
        }
    }

    Ok(CollectionSearchMatrixResponse {
        sample_ids,
        nearests,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use collection::collection::ckks_search::{
        CkksCiphertextSegmentIndexSnapshot, CkksCiphertextSegmentSearchRecord,
    };
    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector,
    };
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::operations::verification::new_unchecked_verification_pass;
    use common::types::PointOffsetType;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use segment::types::Distance;
    use serde_json::json;
    use storage::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreateCollection, CreateCollectionOperation,
    };
    use storage::dispatcher::Dispatcher;
    use storage::rbac::Access;
    use uuid::Uuid;

    use super::*;
    use crate::common::private_hnsw_wire_fixture::{
        COLLECTION_NAME, PrivateHnswRouteWireFixture, VECTOR_NAME, create_private_hnsw_collection,
        create_private_hnsw_collection_with_private_result_oram, test_dispatcher,
    };
    use crate::settings::{
        CryptoBackendConfig, CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings,
    };

    #[test]
    fn ckks_internal_sidecar_payload_selectors_are_narrow() {
        let protected_result_payload = "document.body".parse::<JsonPath>().unwrap();

        let sidecar_selector = encrypted_vector_sidecar_payload_selector();
        let WithPayloadInterface::Fields(sidecar_fields) = sidecar_selector else {
            panic!("CKKS sidecar lookup must not request the full payload");
        };
        assert_eq!(sidecar_fields.len(), 1);
        assert_eq!(sidecar_fields[0].first_key, ENCRYPTED_VECTOR_SIDECAR_FIELD);
        assert!(sidecar_fields[0].rest.is_empty());
        assert!(
            !sidecar_fields
                .iter()
                .any(|field| field.compatible(&protected_result_payload))
        );

        let group_by = "document.title".parse::<JsonPath>().unwrap();
        let group_selector = encrypted_vector_sidecar_and_group_payload_selector(&group_by);
        let WithPayloadInterface::Fields(group_fields) = group_selector else {
            panic!("CKKS grouped sidecar lookup must not request the full payload");
        };
        assert_eq!(group_fields.len(), 2);
        assert_eq!(group_fields[0].first_key, ENCRYPTED_VECTOR_SIDECAR_FIELD);
        assert_eq!(group_fields[1], group_by);
        assert!(
            !group_fields
                .iter()
                .any(|field| field.compatible(&protected_result_payload))
        );
    }

    fn scored_point(id: u64, score: f32) -> ScoredPoint {
        ScoredPoint {
            id: id.into(),
            version: 0,
            score,
            payload: None,
            vector: None,
            shard_key: None,
            order_value: None,
        }
    }

    fn scored_point_with_payload(id: u64, score: f32, payload: serde_json::Value) -> ScoredPoint {
        let mut point = scored_point(id, score);
        point.payload = Some(segment::types::Payload(
            payload.as_object().unwrap().clone(),
        ));
        point
    }

    fn valid_query_signature_b64() -> String {
        BASE64URL_NOPAD.encode(&[4_u8; 64])
    }

    fn valid_query_nonce_b64() -> String {
        BASE64URL_NOPAD.encode(&[7_u8; 12])
    }

    async fn create_plain_lookup_target_collection(dispatcher: &Dispatcher) {
        dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::CreateCollection(
                    CreateCollectionOperation::new(
                        "plain_docs".to_string(),
                        CreateCollection {
                            vectors: VectorsConfig::Multi(BTreeMap::from([(
                                "plain".to_string(),
                                VectorParamsBuilder::new(2, Distance::Euclid).build(),
                            )])),
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
                            uuid: Some(Uuid::new_v4()),
                            metadata: None,
                        },
                    )
                    .unwrap(),
                ),
                Auth::new_internal(Access::full("private HNSW lookup source test")),
                None,
            )
            .await
            .unwrap();
    }

    fn assert_private_hnsw_api_required_storage_error(err: &StorageError) {
        match err {
            StorageError::BadInput { description } => {
                assert_private_hnsw_api_required_message(description)
            }
            other => panic!("expected private HNSW API required BadInput, got {other:?}"),
        }
    }

    fn assert_private_hnsw_api_required_message(message: &str) {
        assert!(
            message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER),
            "{message}"
        );
        assert!(
            message.contains("/private-hnsw/{vector}/session"),
            "{message}"
        );
        assert!(!message.contains(VECTOR_NAME), "{message}");
        for alias in [
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_hashes.bin",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "client_state_ciphertexts_sha256.bin",
            "client_state_ciphertexts_sha256.json",
            "encrypted_client_state_snapshot.bin",
            "encrypted_client_state_snapshot.json",
            "encrypted_client_state_snapshots.json",
            "encrypted.client.state",
            "encrypted.client.state.json",
            "encrypted.client.state.snapshot",
            "encrypted.client.state.snapshot.json",
            "encrypted.client.state.snapshots.json",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_hashes.bin",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "encrypted_client_state_ciphertexts_sha256.bin",
            "encrypted_client_state_ciphertexts_sha256.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
            "state_ciphertexts_sha256.bin",
            "state_ciphertexts_sha256.json",
            "client.state.snapshot",
            "client.state.snapshot.json",
            "client.state.snapshots.json",
            "token.map.backup",
            "token.map.backup.json",
            "token.position.map.backup",
            "token.position.map.backup.json",
        ] {
            assert!(!message.contains(alias), "{message}");
        }
        assert!(!message.contains("CKKS vector ciphertext"), "{message}");
    }

    #[test]
    fn private_hnsw_oram_query_paths_require_client_led_session() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();

            let err = do_query_points(
                &toc,
                COLLECTION_NAME,
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                    ))),
                    using: VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);

            let err = do_query_points(
                &toc,
                COLLECTION_NAME,
                CollectionQueryRequest {
                    prefetch: vec![CollectionPrefetch {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                        ))),
                        using: VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        params: None,
                        lookup_from: None,
                    }],
                    query: Some(Query::Fusion(FusionInternal::Dbsf)),
                    using: "plain".to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
        });
    }

    #[test]
    fn private_hnsw_oram_lookup_source_requires_client_led_session() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            create_plain_lookup_target_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();

            let err = do_query_points(
                &toc,
                "plain_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Id(0.into()),
                    ))),
                    using: "plain".to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: Some(api::rest::LookupLocation {
                        collection: COLLECTION_NAME.to_string(),
                        vector: Some(VECTOR_NAME.to_string()),
                        shard_key: None,
                    }),
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("Point"), "{err}");

            let err = do_recommend_points(
                &toc,
                "plain_docs",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::PointId(0.into())],
                    negative: Vec::new(),
                    strategy: Some(RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(UsingVector::Name("plain".to_string())),
                    lookup_from: Some(api::rest::LookupLocation {
                        collection: COLLECTION_NAME.to_string(),
                        vector: Some(VECTOR_NAME.to_string()),
                        shard_key: None,
                    }),
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("Point"), "{err}");

            let err = do_discover_points(
                &toc,
                "plain_docs",
                DiscoverRequestInternal {
                    target: Some(RecommendExample::PointId(0.into())),
                    context: None,
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    using: Some(UsingVector::Name("plain".to_string())),
                    lookup_from: Some(api::rest::LookupLocation {
                        collection: COLLECTION_NAME.to_string(),
                        vector: Some(VECTOR_NAME.to_string()),
                        shard_key: None,
                    }),
                },
                None,
                ShardSelectorInternal::All,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("Point"), "{err}");
        });
    }

    #[test]
    fn private_hnsw_oram_group_lookup_source_requires_client_led_session() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            create_plain_lookup_target_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();
            let group_by = "group".parse::<JsonPath>().unwrap();

            let err = do_query_point_groups(
                &toc,
                "plain_docs",
                CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Id(0.into()),
                    ))),
                    using: "plain".to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: Some(api::rest::LookupLocation {
                        collection: COLLECTION_NAME.to_string(),
                        vector: Some(VECTOR_NAME.to_string()),
                        shard_key: None,
                    }),
                    group_by: group_by.clone(),
                    group_size: 1,
                    limit: 1,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("Point"), "{err}");

            let err = do_recommend_point_groups(
                &toc,
                "plain_docs",
                RecommendGroupsRequestInternal {
                    positive: vec![RecommendExample::PointId(0.into())],
                    negative: Vec::new(),
                    strategy: Some(RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(UsingVector::Name("plain".to_string())),
                    lookup_from: Some(api::rest::LookupLocation {
                        collection: COLLECTION_NAME.to_string(),
                        vector: Some(VECTOR_NAME.to_string()),
                        shard_key: None,
                    }),
                    group_request: api::rest::BaseGroupRequest {
                        group_by,
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("Point"), "{err}");
        });
    }

    #[test]
    fn private_hnsw_oram_context_and_mmr_require_client_led_session() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();

            let err = do_query_points(
                &toc,
                COLLECTION_NAME,
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Context(
                        segment::vector_storage::query::ContextQuery::new(vec![ContextPair {
                            positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                1.0, 0.0,
                            ])),
                            negative: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                0.0, 1.0,
                            ])),
                        }]),
                    ))),
                    using: VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);

            let err = do_query_points(
                &toc,
                COLLECTION_NAME,
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::NearestWithMmr(NearestWithMmr {
                        nearest: VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                        mmr: Mmr {
                            diversity: Some(0.25),
                            candidates_limit: Some(8),
                        },
                    }))),
                    using: VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
        });
    }

    #[test]
    fn private_hnsw_oram_legacy_and_batch_search_require_client_led_session() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();

            let err = do_search_points(
                &toc,
                COLLECTION_NAME,
                SearchRequestInternal {
                    vector: api::rest::NamedVectorStruct::Dense(
                        segment::data_types::vectors::NamedVector {
                            name: VECTOR_NAME.to_string(),
                            vector: vec![1.0, 0.0],
                        },
                    ),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);

            let err = do_search_batch_points(
                &toc,
                COLLECTION_NAME,
                vec![(
                    CoreSearchRequest {
                        query: QueryEnum::Nearest(NamedQuery::new(
                            VectorInternal::Dense(vec![1.0, 0.0]),
                            VECTOR_NAME.to_string(),
                        )),
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: 0,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                    },
                    ShardSelectorInternal::All,
                )],
                None,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
        });
    }

    #[test]
    fn private_hnsw_oram_no_runtime_paths_require_client_led_session() {
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();
            let collection_pass = auth
                .check_collection_access(COLLECTION_NAME, AccessRequirements::new(), "test")
                .unwrap();
            let private_hnsw_collection = toc.get_collection(&collection_pass).await.unwrap();

            let err = do_query_points(
                &toc,
                COLLECTION_NAME,
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                    ))),
                    using: VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("runtime CKKS"), "{err}");
            assert!(!err.to_string().contains("runtime OpenFHE"), "{err}");

            let err = private_hnsw_collection
                .query(
                    ShardQueryRequest {
                        prefetches: Vec::new(),
                        query: Some(ScoringQuery::Vector(QueryEnum::Nearest(NamedQuery::new(
                            VectorInternal::Dense(vec![1.0, 0.0]),
                            VECTOR_NAME.to_string(),
                        )))),
                        filter: None,
                        score_threshold: None,
                        limit: 0,
                        offset: 0,
                        params: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(false),
                    },
                    None,
                    ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap_err();

            let message = err.to_string();
            assert_private_hnsw_api_required_message(&message);
            assert!(!message.contains("runtime CKKS"), "{message}");
            assert!(!message.contains("runtime OpenFHE"), "{message}");

            let err = do_search_points(
                &toc,
                COLLECTION_NAME,
                SearchRequestInternal {
                    vector: api::rest::NamedVectorStruct::Dense(
                        segment::data_types::vectors::NamedVector {
                            name: VECTOR_NAME.to_string(),
                            vector: vec![1.0, 0.0],
                        },
                    ),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("runtime CKKS"), "{err}");
            assert!(!err.to_string().contains("runtime OpenFHE"), "{err}");

            let err = private_hnsw_collection
                .core_search_batch(
                    CoreSearchRequestBatch {
                        searches: vec![CoreSearchRequest {
                            query: QueryEnum::Nearest(NamedQuery::new(
                                VectorInternal::Dense(vec![1.0, 0.0]),
                                VECTOR_NAME.to_string(),
                            )),
                            filter: None,
                            params: None,
                            limit: 0,
                            offset: 0,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            score_threshold: None,
                        }],
                    },
                    None,
                    ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap_err();

            let message = err.to_string();
            assert_private_hnsw_api_required_message(&message);
            assert!(!message.contains("runtime CKKS"), "{message}");
            assert!(!message.contains("runtime OpenFHE"), "{message}");

            let err = do_recommend_points(
                &toc,
                COLLECTION_NAME,
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![1.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(UsingVector::Name(VECTOR_NAME.to_string())),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("runtime CKKS"), "{err}");
            assert!(!err.to_string().contains("runtime OpenFHE"), "{err}");

            let err = do_discover_points(
                &toc,
                COLLECTION_NAME,
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![1.0, 0.0])),
                    context: None,
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    using: Some(UsingVector::Name(VECTOR_NAME.to_string())),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("runtime CKKS"), "{err}");
            assert!(!err.to_string().contains("runtime OpenFHE"), "{err}");

            let err = do_search_points_matrix(
                &toc,
                COLLECTION_NAME,
                CollectionSearchMatrixRequest {
                    sample_size: 2,
                    limit_per_sample: 1,
                    filter: None,
                    using: VECTOR_NAME.to_string(),
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("runtime CKKS"), "{err}");
            assert!(!err.to_string().contains("runtime OpenFHE"), "{err}");

            let group_by = "group".parse::<JsonPath>().unwrap();
            let err = do_search_point_groups(
                &toc,
                COLLECTION_NAME,
                SearchGroupsRequestInternal {
                    vector: api::rest::NamedVectorStruct::Dense(
                        segment::data_types::vectors::NamedVector {
                            name: VECTOR_NAME.to_string(),
                            vector: vec![1.0, 0.0],
                        },
                    ),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: api::rest::BaseGroupRequest {
                        group_by: group_by.clone(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("runtime CKKS"), "{err}");
            assert!(!err.to_string().contains("runtime OpenFHE"), "{err}");

            let err = do_query_point_groups(
                &toc,
                COLLECTION_NAME,
                CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                    ))),
                    using: VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by,
                    group_size: 1,
                    limit: 1,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("runtime CKKS"), "{err}");
            assert!(!err.to_string().contains("runtime OpenFHE"), "{err}");
        });
    }

    #[test]
    fn private_hnsw_oram_vector_reads_use_private_session_error() {
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();

            let err = do_get_points(
                &toc,
                COLLECTION_NAME,
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: WithVector::Selector(vec![VECTOR_NAME.to_string()]),
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("retrieve"), "{err}");

            let err = do_scroll_points(
                &toc,
                COLLECTION_NAME,
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: WithVector::Bool(true),
                    order_by: None,
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
            assert!(!err.to_string().contains("scroll"), "{err}");
        });
    }

    #[test]
    fn private_hnsw_oram_search_matrix_requires_client_led_session() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();
            let collection_pass = auth
                .check_collection_access(COLLECTION_NAME, AccessRequirements::new(), "test")
                .unwrap();
            let private_hnsw_collection = toc.get_collection(&collection_pass).await.unwrap();

            let err = do_search_points_matrix(
                &toc,
                COLLECTION_NAME,
                CollectionSearchMatrixRequest {
                    sample_size: 2,
                    limit_per_sample: 1,
                    filter: None,
                    using: VECTOR_NAME.to_string(),
                },
                None,
                ShardSelectorInternal::All,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);

            let err = private_hnsw_collection
                .search_points_matrix(
                    CollectionSearchMatrixRequest {
                        sample_size: 0,
                        limit_per_sample: 0,
                        filter: None,
                        using: VECTOR_NAME.to_string(),
                    },
                    ShardSelectorInternal::All,
                    None,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap_err();

            assert_private_hnsw_api_required_message(&err.to_string());
        });
    }

    #[test]
    fn private_hnsw_oram_recommend_and_discover_require_client_led_session() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();
            let collection_pass = auth
                .check_collection_access(COLLECTION_NAME, AccessRequirements::new(), "test")
                .unwrap();
            let private_hnsw_collection = toc.get_collection(&collection_pass).await.unwrap();

            let err = do_recommend_points(
                &toc,
                COLLECTION_NAME,
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![1.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(UsingVector::Name(VECTOR_NAME.to_string())),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);

            let err = collection::recommendations::recommend_by(
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![1.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 0,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(UsingVector::Name(VECTOR_NAME.to_string())),
                    lookup_from: None,
                },
                private_hnsw_collection.as_ref(),
                |_| async { None },
                None,
                ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::disposable(),
            )
            .await
            .map_err(StorageError::from)
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);

            let err = do_discover_points(
                &toc,
                COLLECTION_NAME,
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![1.0, 0.0])),
                    context: None,
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    using: Some(UsingVector::Name(VECTOR_NAME.to_string())),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);

            let err = collection::discovery::discover(
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![1.0, 0.0])),
                    context: None,
                    filter: None,
                    params: None,
                    limit: 0,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    using: Some(UsingVector::Name(VECTOR_NAME.to_string())),
                    lookup_from: None,
                },
                private_hnsw_collection.as_ref(),
                |_| async { None },
                None,
                ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::disposable(),
            )
            .await
            .map_err(StorageError::from)
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
        });
    }

    #[test]
    fn private_hnsw_oram_group_paths_require_client_led_session() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("For test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();
            let group_by = "group".parse::<JsonPath>().unwrap();

            let err = do_search_point_groups(
                &toc,
                COLLECTION_NAME,
                SearchGroupsRequestInternal {
                    vector: api::rest::NamedVectorStruct::Dense(
                        segment::data_types::vectors::NamedVector {
                            name: VECTOR_NAME.to_string(),
                            vector: vec![1.0, 0.0],
                        },
                    ),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: api::rest::BaseGroupRequest {
                        group_by: group_by.clone(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);

            let err = do_query_point_groups(
                &toc,
                COLLECTION_NAME,
                CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                    ))),
                    using: VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by,
                    group_size: 1,
                    limit: 1,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();

            assert_private_hnsw_api_required_storage_error(&err);
        });
    }

    #[test]
    fn ckks_score_query_source_batch_forwards_query_rk_id_not_key_id() {
        let bridge_dir = tempfile::Builder::new()
            .prefix("qdrant-sec-query-rk-bridge-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let bridge_path = bridge_dir.path().join("openfhe-bridge");
        let bridge_bytes = b"#!/bin/sh\nexit 0\n";
        std::fs::write(&bridge_path, bridge_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut dir_permissions = std::fs::metadata(bridge_dir.path()).unwrap().permissions();
            dir_permissions.set_mode(0o700);
            std::fs::set_permissions(bridge_dir.path(), dir_permissions).unwrap();

            let mut permissions = std::fs::metadata(&bridge_path).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&bridge_path, permissions).unwrap();
        }
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let signature_key_id = "tenant-a:query-signing-v1";
        let query_key_id = "tenant-a:vector";
        let query_rk_id = "tenant-a/vector-v1";
        let query_rk_epoch = 1;
        let query_nonce = valid_query_nonce_b64();
        let encrypted_query = b"client-query-ciphertext".to_vec();
        let public_material =
            qdrant_sec::CkksPublicMaterial::new(b"openfhe context", b"openfhe public key").unwrap();
        let context_digest =
            public_material.digest_for(&qdrant_sec::CkksParameters::openfhe_default_128_bit());
        let signature_message = crate::common::crypto::ckks_client_query_signature_message(
            "docs-crypto-id",
            "embedding",
            query_key_id,
            query_rk_id,
            query_rk_epoch,
            &query_nonce,
            &context_digest,
            2,
            &encrypted_query,
            "ed25519",
            signature_key_id,
        );
        let signature_b64 = BASE64URL_NOPAD.encode(key_pair.sign(&signature_message).as_ref());
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: qdrant_sec::VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            query_rk_id.to_string(),
                        )]),
                        backend_ref: Some("openfhe_local".to_string()),
                        options: json!({
                            "key_id": query_key_id,
                            "material_fingerprint_id": "tenant-a/vector@v1",
                            "profile": qdrant_sec::CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                            "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                            "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                            "score_plaintext_output_tcb_ack": "qdrant-sec-ckks-score-output-tcb-v1",
                            "signature_public_keys": {
                                signature_key_id: BASE64URL_NOPAD.encode(key_pair.public_key().as_ref()),
                            },
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    query_rk_id.to_string(),
                    CryptoMaterialConfig {
                        kind: "symmetric_key_32".to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[8_u8; 32])),
                        rk_epoch: Some(query_rk_epoch),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    CryptoBackendConfig {
                        kind: "process".to_string(),
                        program: Some(bridge_path.to_string_lossy().to_string()),
                        sha256_b64: Some(BASE64URL_NOPAD.encode(&Sha256::digest(bridge_bytes))),
                        ..CryptoBackendConfig::default()
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            vectors: collection::operations::types::VectorsConfig::Multi(BTreeMap::from([(
                "embedding".to_string(),
                VectorParamsBuilder::new(2, Distance::Dot).build(),
            )])),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some(query_key_id.to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some(qdrant_sec::VECTOR_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            "docs-crypto-id",
            &params,
        )
        .unwrap()
        .unwrap();
        let source = CkksSidecarQuerySource::ClientEncrypted {
            collection_id: "docs-crypto-id",
            vector_name: "embedding",
            key_id: query_key_id,
            rk_id: query_rk_id,
            rk_epoch: query_rk_epoch,
            query_nonce: &query_nonce,
            context_digest: &context_digest,
            slots: 2,
            ciphertext: encrypted_query,
            signature_alg: "ed25519",
            signature_key_id,
            signature_b64: &signature_b64,
        };

        let scores =
            ckks_score_query_source_batch("docs", "embedding", &plan, &source, &[]).unwrap();

        assert!(scores.is_empty());
    }

    #[test]
    fn ckks_client_encrypted_query_source_rejects_oversized_fixed_fields() {
        let context_digest = BASE64URL_NOPAD.encode(&[3_u8; 32]);
        let valid_ciphertext_bytes = b"ciphertext";
        let valid_ciphertext = BASE64URL_NOPAD.encode(valid_ciphertext_bytes);
        let valid_ciphertext_sha256 =
            BASE64URL_NOPAD.encode(&Sha256::digest(valid_ciphertext_bytes));
        let valid_signature = valid_query_signature_b64();
        let valid_nonce = valid_query_nonce_b64();

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id",
            "embedding",
            "tenant-a:vector",
            "tenant-a/vector-v1",
            1,
            &valid_nonce,
            &"A".repeat(CKKS_CLIENT_QUERY_CONTEXT_DIGEST_B64_LEN + 1),
            2,
            &valid_ciphertext_sha256,
            &valid_ciphertext,
            "ed25519",
            "tenant-a:query-signing-v1",
            &valid_signature,
        ) {
            Ok(_) => panic!("oversized context digest must be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("context digest"));

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id",
            "embedding",
            "tenant-a:vector",
            "tenant-a/vector-v1",
            1,
            &valid_nonce,
            &context_digest,
            2,
            &valid_ciphertext_sha256,
            &"A".repeat(CKKS_CLIENT_QUERY_CIPHERTEXT_MAX_ENCODED_BYTES + 1),
            "ed25519",
            "tenant-a:query-signing-v1",
            &valid_signature,
        ) {
            Ok(_) => panic!("oversized ciphertext must be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("maximum size"));
    }

    #[test]
    fn ckks_client_encrypted_query_source_rejects_ciphertext_hash_mismatch() {
        let valid_signature = valid_query_signature_b64();
        let valid_nonce = valid_query_nonce_b64();
        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id",
            "embedding",
            "tenant-a:vector",
            "tenant-a/vector-v1",
            1,
            &valid_nonce,
            &BASE64URL_NOPAD.encode(&[3_u8; 32]),
            2,
            &BASE64URL_NOPAD.encode(&Sha256::digest(b"other-ciphertext")),
            &BASE64URL_NOPAD.encode(b"ciphertext"),
            "ed25519",
            "tenant-a:query-signing-v1",
            &valid_signature,
        ) {
            Ok(_) => panic!("ciphertext hash mismatch must fail before bridge scoring"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("ciphertext_sha256"));
    }

    #[test]
    fn ckks_client_encrypted_query_source_errors_redact_request_vector_name() {
        let valid_signature = valid_query_signature_b64();
        let valid_nonce = valid_query_nonce_b64();
        let valid_context_digest = BASE64URL_NOPAD.encode(&[3_u8; 32]);
        let ciphertext = BASE64URL_NOPAD.encode(b"ciphertext");
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(b"ciphertext"));
        let mismatched_ciphertext_sha256 =
            BASE64URL_NOPAD.encode(&Sha256::digest(b"other-ciphertext"));
        let invalid_nonce = "!!client-secret!".to_string();
        let invalid_signature = "!".repeat(86);
        let invalid_ciphertext_sha256 = "!".repeat(CKKS_CLIENT_QUERY_CIPHERTEXT_SHA256_B64_LEN);
        let invalid_context_digest = "!".repeat(CKKS_CLIENT_QUERY_CONTEXT_DIGEST_B64_LEN);
        let invalid_ciphertext = "client-query-ciphertext-secret!".to_string();
        let forbidden = vec![
            "embedding-sensitive-sentinel",
            "docs-crypto-id-sensitive-sentinel",
            "tenant-a:vector-sensitive-sentinel",
            "tenant-a/vector-v1-sensitive-sentinel",
            "tenant-a:vector-sensitive-wrong",
            "tenant-a/vector-v1-sensitive-wrong",
            "tenant-a:query-signing-sensitive-sentinel",
            invalid_nonce.as_str(),
            invalid_signature.as_str(),
            invalid_ciphertext_sha256.as_str(),
            invalid_context_digest.as_str(),
            invalid_ciphertext.as_str(),
        ];
        let assert_redacted = |err: StorageError, expected: &str| {
            let rendered = err.to_string();
            assert!(
                rendered.contains(expected),
                "unexpected validation error: {rendered}",
            );
            for leaked in &forbidden {
                assert!(
                    !rendered.contains(leaked),
                    "client CKKS query validation error leaked {leaked}: {rendered}",
                );
            }
        };

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding-sensitive-sentinel",
            2,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id-sensitive-sentinel",
            "embedding-sensitive-sentinel",
            "tenant-a:vector-sensitive-sentinel",
            "tenant-a/vector-v1-sensitive-sentinel",
            1,
            &valid_nonce,
            &valid_context_digest,
            2,
            &mismatched_ciphertext_sha256,
            &ciphertext,
            "ed25519",
            "tenant-a:query-signing-sensitive-sentinel",
            &valid_signature,
        ) {
            Ok(_) => panic!("invalid client CKKS query version must be rejected"),
            Err(err) => err,
        };
        assert_redacted(err, "client CKKS query version");

        let cases = [
            (
                "nonce",
                "embedding-sensitive-sentinel",
                "tenant-a:vector-sensitive-sentinel",
                "tenant-a/vector-v1-sensitive-sentinel",
                invalid_nonce.as_str(),
                valid_context_digest.as_str(),
                ciphertext_sha256.as_str(),
                ciphertext.as_str(),
                "tenant-a:query-signing-sensitive-sentinel",
                valid_signature.as_str(),
            ),
            (
                "signature is not base64url",
                "embedding-sensitive-sentinel",
                "tenant-a:vector-sensitive-sentinel",
                "tenant-a/vector-v1-sensitive-sentinel",
                valid_nonce.as_str(),
                valid_context_digest.as_str(),
                ciphertext_sha256.as_str(),
                ciphertext.as_str(),
                "tenant-a:query-signing-sensitive-sentinel",
                invalid_signature.as_str(),
            ),
            (
                "ciphertext_sha256 is not base64url",
                "embedding-sensitive-sentinel",
                "tenant-a:vector-sensitive-sentinel",
                "tenant-a/vector-v1-sensitive-sentinel",
                valid_nonce.as_str(),
                valid_context_digest.as_str(),
                invalid_ciphertext_sha256.as_str(),
                ciphertext.as_str(),
                "tenant-a:query-signing-sensitive-sentinel",
                valid_signature.as_str(),
            ),
            (
                "context digest is not base64url",
                "embedding-sensitive-sentinel",
                "tenant-a:vector-sensitive-sentinel",
                "tenant-a/vector-v1-sensitive-sentinel",
                valid_nonce.as_str(),
                invalid_context_digest.as_str(),
                ciphertext_sha256.as_str(),
                ciphertext.as_str(),
                "tenant-a:query-signing-sensitive-sentinel",
                valid_signature.as_str(),
            ),
            (
                "ciphertext is not base64url",
                "embedding-sensitive-sentinel",
                "tenant-a:vector-sensitive-sentinel",
                "tenant-a/vector-v1-sensitive-sentinel",
                valid_nonce.as_str(),
                valid_context_digest.as_str(),
                ciphertext_sha256.as_str(),
                invalid_ciphertext.as_str(),
                "tenant-a:query-signing-sensitive-sentinel",
                valid_signature.as_str(),
            ),
        ];
        for (
            expected,
            request_vector_name,
            key_id,
            rk_id,
            query_nonce,
            context_digest,
            ciphertext_sha256,
            ciphertext,
            signature_key_id,
            signature,
        ) in cases
        {
            let err = match ckks_client_encrypted_query_source_from_parts(
                request_vector_name,
                1,
                CKKS_SCHEME,
                CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                "docs-crypto-id-sensitive-sentinel",
                "embedding-sensitive-sentinel",
                key_id,
                rk_id,
                1,
                query_nonce,
                context_digest,
                2,
                ciphertext_sha256,
                ciphertext,
                "ed25519",
                signature_key_id,
                signature,
            ) {
                Ok(_) => panic!("invalid client CKKS query base64 input must be rejected"),
                Err(err) => err,
            };
            assert_redacted(err, expected);
        }

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding-sensitive-sentinel",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id-sensitive-sentinel",
            "embedding-sensitive-sentinel",
            "tenant-a:vector-sensitive-wrong",
            "tenant-a/vector-v1-sensitive-wrong",
            1,
            &valid_nonce,
            &valid_context_digest,
            2,
            &mismatched_ciphertext_sha256,
            &ciphertext,
            "ed25519",
            "tenant-a:query-signing-sensitive-sentinel",
            &valid_signature,
        ) {
            Ok(_) => panic!("ciphertext hash mismatch must fail before bridge scoring"),
            Err(err) => err,
        };
        assert_redacted(err, "ciphertext_sha256");
    }

    #[test]
    fn ckks_client_encrypted_query_source_rejects_missing_lineage() {
        let context_digest = BASE64URL_NOPAD.encode(&[3_u8; 32]);
        let ciphertext = BASE64URL_NOPAD.encode(b"ciphertext");
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(b"ciphertext"));
        let valid_signature = valid_query_signature_b64();
        let valid_nonce = valid_query_nonce_b64();

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "",
            "embedding",
            "tenant-a:vector",
            "tenant-a/vector-v1",
            1,
            &valid_nonce,
            &context_digest,
            2,
            &ciphertext_sha256,
            &ciphertext,
            "ed25519",
            "tenant-a:query-signing-v1",
            &valid_signature,
        ) {
            Ok(_) => panic!("client encrypted query collection identity must be required"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("collection_id"));

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id",
            "other-vector",
            "tenant-a:vector",
            "tenant-a/vector-v1",
            1,
            &valid_nonce,
            &context_digest,
            2,
            &ciphertext_sha256,
            &ciphertext,
            "ed25519",
            "tenant-a:query-signing-v1",
            &valid_signature,
        ) {
            Ok(_) => panic!("client encrypted query vector name must match the requested vector"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("vector_name"));

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id",
            "embedding",
            "",
            "tenant-a/vector-v1",
            1,
            &valid_nonce,
            &context_digest,
            2,
            &ciphertext_sha256,
            &ciphertext,
            "ed25519",
            "tenant-a:query-signing-v1",
            &valid_signature,
        ) {
            Ok(_) => panic!("client encrypted query key id must be required"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("key_id"));

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id",
            "embedding",
            "tenant-a:vector",
            "",
            1,
            &valid_nonce,
            &context_digest,
            2,
            &ciphertext_sha256,
            &ciphertext,
            "ed25519",
            "tenant-a:query-signing-v1",
            &valid_signature,
        ) {
            Ok(_) => panic!("client encrypted query RK id must be required"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("rk_id"));

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id",
            "embedding",
            "tenant-a:vector",
            "tenant-a/vector-v1",
            0,
            &valid_nonce,
            &context_digest,
            2,
            &ciphertext_sha256,
            &ciphertext,
            "ed25519",
            "tenant-a:query-signing-v1",
            &valid_signature,
        ) {
            Ok(_) => panic!("client encrypted query RK epoch must be required"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("rk_epoch"));

        let err = match ckks_client_encrypted_query_source_from_parts(
            "embedding",
            1,
            CKKS_SCHEME,
            CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
            "docs-crypto-id",
            "embedding",
            "tenant-a:vector",
            "tenant-a/vector-v1",
            1,
            &BASE64URL_NOPAD.encode(&[7_u8; 11]),
            &context_digest,
            2,
            &ciphertext_sha256,
            &ciphertext,
            "ed25519",
            "tenant-a:query-signing-v1",
            &valid_signature,
        ) {
            Ok(_) => panic!("client encrypted query nonce must be required"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("nonce"));
    }

    #[test]
    fn ckks_query_rejects_inference_derived_vector_inputs() {
        let err = ckks_query_as_core_query(
            &Some(Query::Vector(VectorQuery::Nearest(
                VectorInputInternal::InferredVector(VectorInternal::Dense(vec![0.1, 0.2])),
            ))),
            "embedding",
        )
        .expect_err("CKKS encrypted vector queries must reject inference-derived plaintext");

        assert!(matches!(
            err,
            StorageError::BadInput { ref description }
                if description.contains("inference-derived query vectors")
                    && !description.contains("embedding")
        ));

        let err = ckks_recommend_query_as_core_recommend(
            &segment::vector_storage::query::RecoQuery::new(
                vec![VectorInputInternal::InferredVector(VectorInternal::Dense(
                    vec![0.1, 0.2],
                ))],
                Vec::new(),
            ),
            "embedding",
        )
        .expect_err("CKKS recommend must reject inference-derived plaintext");

        assert!(matches!(
            err,
            StorageError::BadInput { ref description }
                if description.contains("inference-derived positive examples")
                    && !description.contains("embedding")
        ));

        let err = ckks_discover_query_as_core_discover(
            &segment::vector_storage::query::DiscoverQuery::new(
                VectorInputInternal::InferredVector(VectorInternal::Dense(vec![0.1, 0.2])),
                vec![ContextPair {
                    positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![0.3, 0.4])),
                    negative: VectorInputInternal::Vector(VectorInternal::Dense(vec![0.5, 0.6])),
                }],
            ),
            "embedding",
        )
        .expect_err("CKKS discover must reject inference-derived target plaintext");

        assert!(matches!(
            err,
            StorageError::BadInput { ref description }
                if description.contains("inference-derived target examples")
                    && !description.contains("embedding")
        ));

        let err = ckks_discover_query_as_core_discover(
            &segment::vector_storage::query::DiscoverQuery::new(
                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                vec![ContextPair {
                    positive: VectorInputInternal::InferredVector(VectorInternal::Dense(vec![
                        0.3, 0.4,
                    ])),
                    negative: VectorInputInternal::Vector(VectorInternal::Dense(vec![0.5, 0.6])),
                }],
            ),
            "embedding",
        )
        .expect_err("CKKS discover must reject inference-derived context plaintext");

        assert!(matches!(
            err,
            StorageError::BadInput { ref description }
                if description.contains("inference-derived positive context examples")
                    && !description.contains("embedding")
        ));

        let err = ckks_context_query_as_core_context(
            &segment::vector_storage::query::ContextQuery::new(vec![ContextPair {
                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                negative: VectorInputInternal::InferredVector(VectorInternal::Dense(vec![
                    0.3, 0.4,
                ])),
            }]),
            "embedding",
        )
        .expect_err("CKKS context must reject inference-derived pair plaintext");

        assert!(matches!(
            err,
            StorageError::BadInput { ref description }
                if description.contains("inference-derived negative examples")
                    && !description.contains("embedding")
        ));
    }

    #[test]
    fn ckks_recommend_average_errors_do_not_reflect_vector_shape_detail() {
        let err = recommend_request_as_ckks_search_request(
            &RecommendRequestInternal {
                positive: Vec::new(),
                negative: Vec::new(),
                strategy: Some(RecommendStrategy::AverageVector),
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                score_threshold: None,
                using: Some(UsingVector::Name("embedding".to_string())),
                lookup_from: None,
            },
            "embedding",
        )
        .expect_err("empty examples must fail average-vector conversion");

        assert!(matches!(
            err,
            StorageError::BadInput { ref description }
                if description == "encrypted vector recommend average-vector conversion failed"
                    && !description.contains("embedding")
                    && !description.contains("dimension")
                    && !description.contains("positive")
        ));

        let err = ckks_recommend_query_as_dense_search_vector(
            &segment::vector_storage::query::RecoQuery::new(Vec::new(), Vec::new()),
            "embedding",
        )
        .expect_err("empty examples must fail query average-vector conversion");

        assert!(matches!(
            err,
            StorageError::BadInput { ref description }
                if description == "encrypted vector query recommend average-vector conversion failed"
                    && !description.contains("embedding")
                    && !description.contains("dimension")
                    && !description.contains("positive")
        ));
    }

    #[test]
    fn ckks_rrf_fusion_errors_do_not_reflect_weight_counts() {
        let err = ckks_rrf_scoring(
            vec![vec![scored_point(1, 1.0)], vec![scored_point(2, 1.0)]],
            60,
            Some(&[1.0]),
            "encrypted vector prefetch fusion failed",
        )
        .expect_err("RRF weight count mismatch must fail");

        assert!(matches!(
            err,
            StorageError::BadInput { ref description }
                if description == "encrypted vector prefetch fusion failed"
                    && !description.contains("got")
                    && !description.contains("expected")
                    && !description.contains("1")
                    && !description.contains("2")
        ));
    }

    #[test]
    fn ckks_query_rejects_unsupported_vector_input_shapes_without_vector_name() {
        let assert_redacted = |err: StorageError, expected: &str| {
            let rendered = err.to_string();
            assert!(
                rendered.contains(expected),
                "unexpected validation error: {rendered}",
            );
            assert!(
                !rendered.contains("embedding"),
                "validation error leaked vector name: {rendered}",
            );
        };

        let err = ckks_query_as_core_query(
            &Some(Query::Vector(VectorQuery::Nearest(
                VectorInputInternal::Id(1.into()),
            ))),
            "embedding",
        )
        .expect_err("CKKS query must reject point-id nearest inputs without plaintext vectors");
        assert_redacted(err, "point-id query vectors");

        let err = ckks_query_as_core_query(&None, "embedding")
            .expect_err("CKKS query must reject unsupported query shapes");
        assert_redacted(err, "only supports nearest-neighbor dense query");

        let err = vector_inputs_as_dense_vectors(
            &[VectorInputInternal::Id(1.into())],
            "embedding",
            "positive",
        )
        .expect_err("CKKS recommend must reject point-id examples without plaintext vectors");
        assert_redacted(err, "point-id positive examples");

        let err = ckks_discover_query_as_core_discover(
            &segment::vector_storage::query::DiscoverQuery::new(
                VectorInputInternal::Id(1.into()),
                vec![ContextPair {
                    positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![0.3, 0.4])),
                    negative: VectorInputInternal::Vector(VectorInternal::Dense(vec![0.5, 0.6])),
                }],
            ),
            "embedding",
        )
        .expect_err("CKKS discover must reject point-id target without plaintext vectors");
        assert_redacted(err, "point-id or non-dense target examples");

        let err = ckks_context_query_as_core_context(
            &segment::vector_storage::query::ContextQuery::new(vec![ContextPair {
                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                negative: VectorInputInternal::Id(1.into()),
            }]),
            "embedding",
        )
        .expect_err("CKKS context must reject point-id context examples without plaintext vectors");
        assert_redacted(err, "point-id or non-dense negative examples");
    }

    #[test]
    fn ckks_fill_drops_scored_points_missing_from_retrieve_results() {
        let mut points = vec![scored_point(1, 9.0), scored_point(2, 8.0)];
        points[0].shard_key = Some(ShardKey::from("stale-shard"));
        let payload = json!({ "body": "kept" });
        let records = vec![RecordInternal {
            id: 2.into(),
            version: 42,
            payload: Some(Payload(payload.as_object().unwrap().clone())),
            vector: None,
            shard_key: Some(ShardKey::from("tenant-b")),
            order_value: None,
        }];

        ckks_hydrate_scored_points_from_records(&mut points, records);

        assert_eq!(points.len(), 1);
        assert_eq!(points[0].id, 2.into());
        assert_eq!(points[0].version, 42);
        assert_eq!(points[0].payload.as_ref().unwrap().0["body"], "kept");
        assert_eq!(points[0].shard_key, Some(ShardKey::from("tenant-b")));
    }

    #[test]
    fn ckks_fill_candidate_limit_adds_bounded_refill_slack() {
        let requested = 7;
        let candidate_limit = ckks_scored_fill_candidate_limit(2, 5, None);
        assert_eq!(candidate_limit, requested + CKKS_SEARCH_FILL_RETRY_SLACK);

        assert_eq!(ckks_scored_fill_candidate_limit(2, 5, Some(9)), 9);
        assert_eq!(ckks_scored_fill_candidate_limit(2, 0, None), 0);

        let large_limit = 64;
        assert_eq!(
            ckks_scored_fill_candidate_limit(0, large_limit, None),
            large_limit * CKKS_SEARCH_FILL_RETRY_MULTIPLIER,
        );
    }

    #[test]
    fn ckks_fill_can_refill_top_k_from_extra_candidates() {
        let candidate_limit = ckks_scored_fill_candidate_limit(0, 2, Some(3));
        assert_eq!(candidate_limit, 3);

        let mut candidates = vec![
            scored_point(1, 9.0),
            scored_point(2, 8.0),
            scored_point(3, 7.0),
        ]
        .into_iter()
        .take(candidate_limit)
        .collect::<Vec<_>>();
        let records = vec![
            RecordInternal {
                id: 2.into(),
                version: 42,
                payload: None,
                vector: None,
                shard_key: None,
                order_value: None,
            },
            RecordInternal {
                id: 3.into(),
                version: 43,
                payload: None,
                vector: None,
                shard_key: None,
                order_value: None,
            },
        ];

        ckks_hydrate_scored_points_from_records(&mut candidates, records);
        let top = candidates.into_iter().take(2).collect::<Vec<_>>();

        assert_eq!(
            top.iter().map(|point| point.id).collect::<Vec<_>>(),
            vec![2.into(), 3.into()],
        );
        assert_eq!(top[0].version, 42);
        assert_eq!(top[1].version, 43);
    }

    #[test]
    fn ckks_sidecar_search_uses_distance_order_for_ranking() {
        let mut dot = vec![scored_point(1, 9.0), scored_point(2, 4.0)];
        sort_ckks_scored_points(Distance::Dot.distance_order(), &mut dot);
        assert_eq!(dot[0].id, 1.into());
        assert_eq!(dot[1].id, 2.into());

        let mut euclid = vec![scored_point(1, 9.0), scored_point(2, 4.0)];
        sort_ckks_scored_points(Distance::Euclid.distance_order(), &mut euclid);
        assert_eq!(euclid[0].id, 2.into());
        assert_eq!(euclid[1].id, 1.into());
    }

    #[test]
    fn ckks_sidecar_search_uses_distance_order_for_thresholds() {
        assert!(ckks_score_passes_threshold(
            Distance::Dot.distance_order(),
            9.0,
            Some(5.0)
        ));
        assert!(!ckks_score_passes_threshold(
            Distance::Dot.distance_order(),
            4.0,
            Some(5.0)
        ));

        assert!(ckks_score_passes_threshold(
            Distance::Euclid.distance_order(),
            4.0,
            Some(5.0)
        ));
        assert!(!ckks_score_passes_threshold(
            Distance::Euclid.distance_order(),
            9.0,
            Some(5.0)
        ));
    }

    #[test]
    fn ckks_sidecar_search_replaces_duplicates_using_distance_order() {
        assert!(ckks_scored_point_is_better(
            Distance::Dot.distance_order(),
            &scored_point(1, 9.0),
            &scored_point(1, 4.0),
        ));
        assert!(ckks_scored_point_is_better(
            Distance::Euclid.distance_order(),
            &scored_point(1, 4.0),
            &scored_point(1, 9.0),
        ));
    }

    #[test]
    fn ckks_sidecar_search_rejects_unsupported_search_params() {
        let exact_params = SearchParams {
            exact: true,
            ..SearchParams::default()
        };
        assert!(ckks_search_params_supported(&exact_params));

        let hnsw_params = SearchParams {
            hnsw_ef: Some(128),
            ..SearchParams::default()
        };
        assert!(ckks_search_params_supported(&hnsw_params));

        let indexed_only_params = SearchParams {
            indexed_only: true,
            ..SearchParams::default()
        };
        assert!(!ckks_search_params_supported(&indexed_only_params));

        let quantization_params = SearchParams {
            quantization: Some(segment::types::QuantizationSearchParams::default()),
            ..SearchParams::default()
        };
        assert!(!ckks_search_params_supported(&quantization_params));

        let acorn_params = SearchParams {
            acorn: Some(segment::types::AcornSearchParams::default()),
            ..SearchParams::default()
        };
        assert!(!ckks_search_params_supported(&acorn_params));
    }

    fn ckks_sidecar_test_record(point_id: u64, ciphertext: &str) -> CkksSidecarSearchRecord {
        CkksSidecarSearchRecord {
            id: point_id.into(),
            shard_key: None,
            point_id: point_id.to_string(),
            encrypted: EncryptedCkksVector {
                version: 1,
                scheme: qdrant_sec::CKKS_SCHEME.to_string(),
                envelope: qdrant_sec::EncryptedEnvelope {
                    version: 1,
                    algorithm: "AES-256-GCM".to_string(),
                    key_id: "test-key".to_string(),
                    material_fingerprint: "test-material".to_string(),
                    rk_id: "test-rk".to_string(),
                    rk_epoch: Some(1),
                    nonce: "AAAAAAAAAAAAAAAA".to_string(),
                    ciphertext: ciphertext.to_string(),
                },
            },
        }
    }

    fn ckks_sidecar_test_segment_record(
        point_id: u64,
        ciphertext: &str,
    ) -> CkksCiphertextSegmentSearchRecord {
        let record = ckks_sidecar_test_record(point_id, ciphertext);
        CkksCiphertextSegmentSearchRecord {
            id: record.id,
            shard_key: record.shard_key,
            point_id: record.point_id,
            indexed_record: CkksCiphertextIndexedRecord {
                point_offset: point_id as PointOffsetType,
                ciphertext: ciphertext.as_bytes().to_vec(),
                sidecar_identity: format!("sidecar-{point_id}").into_bytes(),
            },
            encrypted: record.encrypted,
        }
    }

    #[test]
    fn ckks_sidecar_segment_search_rejects_optimizer_candidate_graph_snapshots() {
        let err = ckks_sidecar_hnsw_search_segment_snapshots(
            "test",
            "embedding",
            &crate::common::crypto::VectorWritePlan::empty_for_test(),
            &[CkksCiphertextSegmentIndexSnapshot {
                records: vec![
                    ckks_sidecar_test_segment_record(0, "ciphertext-a"),
                    ckks_sidecar_test_segment_record(1, "ciphertext-b"),
                ],
                graph: CkksCiphertextHnswGraph::build_optimizer_candidate_graph(2, 16),
            }],
            CkksSidecarHnswQuery::Dense(&[1.0, 0.0]),
            Distance::Dot.distance_order(),
            None,
            1,
            1,
        )
        .expect_err("optimizer-candidate segment graphs must not be searched as indexed HNSW");

        assert!(
            err.to_string()
                .contains("optimizer-candidate CKKS ciphertext graphs"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_records_fingerprint_tracks_ciphertext_changes() {
        let first = ckks_sidecar_hnsw_records_fingerprint(&[
            ckks_sidecar_test_record(1, "ciphertext-a"),
            ckks_sidecar_test_record(2, "ciphertext-b"),
        ]);
        let changed = ckks_sidecar_hnsw_records_fingerprint(&[
            ckks_sidecar_test_record(1, "ciphertext-a"),
            ckks_sidecar_test_record(2, "ciphertext-c"),
        ]);

        assert_ne!(first, changed);
    }

    #[test]
    fn ckks_sidecar_hnsw_records_fingerprint_tracks_resource_key_identity_changes() {
        let first =
            ckks_sidecar_hnsw_records_fingerprint(&[ckks_sidecar_test_record(1, "ciphertext-a")]);

        let mut changed_rk_id = ckks_sidecar_test_record(1, "ciphertext-a");
        changed_rk_id.encrypted.envelope.rk_id = "test-rk-v2".to_string();
        let changed_rk_id = ckks_sidecar_hnsw_records_fingerprint(&[changed_rk_id]);

        let mut changed_rk_epoch = ckks_sidecar_test_record(1, "ciphertext-a");
        changed_rk_epoch.encrypted.envelope.rk_epoch = Some(2);
        let changed_rk_epoch = ckks_sidecar_hnsw_records_fingerprint(&[changed_rk_epoch]);

        assert_ne!(first, changed_rk_id);
        assert_ne!(first, changed_rk_epoch);
    }

    #[test]
    fn ckks_sidecar_hnsw_records_fingerprint_tracks_point_identity_changes() {
        let first = ckks_sidecar_hnsw_records_fingerprint(&[
            ckks_sidecar_test_record(1, "ciphertext-a"),
            ckks_sidecar_test_record(2, "ciphertext-b"),
        ]);
        let changed = ckks_sidecar_hnsw_records_fingerprint(&[
            ckks_sidecar_test_record(1, "ciphertext-a"),
            ckks_sidecar_test_record(3, "ciphertext-b"),
        ]);

        assert_ne!(first, changed);
    }

    #[test]
    fn ckks_sidecar_hnsw_records_fingerprint_tracks_scored_point_id_identity() {
        let first =
            ckks_sidecar_hnsw_records_fingerprint(&[ckks_sidecar_test_record(1, "ciphertext-a")]);
        let mut changed = ckks_sidecar_test_record(1, "ciphertext-a");
        changed.id = 2.into();
        let changed = ckks_sidecar_hnsw_records_fingerprint(&[changed]);

        assert_ne!(first, changed);
    }

    #[test]
    fn ckks_sidecar_hnsw_records_fingerprint_tracks_shard_key_identity() {
        let without_shard =
            ckks_sidecar_hnsw_records_fingerprint(&[ckks_sidecar_test_record(1, "ciphertext-a")]);
        let mut keyword_shard = ckks_sidecar_test_record(1, "ciphertext-a");
        keyword_shard.shard_key = Some(ShardKey::from("tenant-a"));
        let keyword = ckks_sidecar_hnsw_records_fingerprint(std::slice::from_ref(&keyword_shard));
        let mut numeric_shard = ckks_sidecar_test_record(1, "ciphertext-a");
        numeric_shard.shard_key = Some(ShardKey::from(7_u64));
        let numeric = ckks_sidecar_hnsw_records_fingerprint(&[numeric_shard]);

        assert_ne!(without_shard, keyword);
        assert_ne!(keyword, numeric);
    }

    #[test]
    fn ckks_sidecar_hnsw_records_fingerprint_tracks_record_order() {
        let first = ckks_sidecar_hnsw_records_fingerprint(&[
            ckks_sidecar_test_record(1, "ciphertext-a"),
            ckks_sidecar_test_record(2, "ciphertext-b"),
        ]);
        let reordered = ckks_sidecar_hnsw_records_fingerprint(&[
            ckks_sidecar_test_record(2, "ciphertext-b"),
            ckks_sidecar_test_record(1, "ciphertext-a"),
        ]);

        assert_ne!(first, reordered);
    }

    #[test]
    fn ckks_sidecar_hnsw_records_fingerprint_tracks_resource_key_metadata() {
        let first =
            ckks_sidecar_hnsw_records_fingerprint(&[ckks_sidecar_test_record(1, "ciphertext-a")]);
        let mut rotated = ckks_sidecar_test_record(1, "ciphertext-a");
        rotated.encrypted.envelope.key_id = "test-key-v2".to_string();
        rotated.encrypted.envelope.material_fingerprint = "test-material-v2".to_string();
        rotated.encrypted.envelope.rk_id = "test-rk-v2".to_string();
        rotated.encrypted.envelope.rk_epoch = Some(2);
        let changed = ckks_sidecar_hnsw_records_fingerprint(&[rotated]);

        assert_ne!(first, changed);
    }

    #[test]
    fn ckks_sidecar_hnsw_records_fingerprint_tracks_envelope_header_metadata() {
        let first =
            ckks_sidecar_hnsw_records_fingerprint(&[ckks_sidecar_test_record(1, "ciphertext-a")]);

        let mut changed_scheme = ckks_sidecar_test_record(1, "ciphertext-a");
        changed_scheme.encrypted.scheme = "other-scheme".to_string();
        assert_ne!(
            first,
            ckks_sidecar_hnsw_records_fingerprint(&[changed_scheme])
        );

        let mut changed_algorithm = ckks_sidecar_test_record(1, "ciphertext-a");
        changed_algorithm.encrypted.envelope.algorithm = "other-algorithm".to_string();
        assert_ne!(
            first,
            ckks_sidecar_hnsw_records_fingerprint(&[changed_algorithm])
        );

        let mut changed_nonce = ckks_sidecar_test_record(1, "ciphertext-a");
        changed_nonce.encrypted.envelope.nonce = "BBBBBBBBBBBBBBBB".to_string();
        assert_ne!(
            first,
            ckks_sidecar_hnsw_records_fingerprint(&[changed_nonce])
        );
    }

    #[test]
    fn ckks_sidecar_segment_snapshots_must_cover_scroll_records() {
        let first = ckks_sidecar_test_record(1, "ciphertext-a");
        let second = ckks_sidecar_test_record(2, "ciphertext-b");
        let snapshots = vec![ckks_sidecar_test_segment_snapshot(vec![
            first.clone(),
            second.clone(),
        ])];

        assert!(ckks_sidecar_segment_snapshots_cover_records(
            &snapshots,
            &[first.clone(), second.clone()],
        ));
        assert!(!ckks_sidecar_segment_snapshots_cover_records(
            &snapshots,
            &[first],
        ));

        let mut changed = second;
        changed.encrypted.envelope.rk_epoch = Some(2);
        assert!(!ckks_sidecar_segment_snapshots_cover_records(
            &snapshots,
            &[ckks_sidecar_test_record(1, "ciphertext-a"), changed],
        ));

        let mut stale_ciphertext = ckks_sidecar_test_record(2, "ciphertext-b");
        stale_ciphertext.encrypted.envelope.ciphertext = "ciphertext-c".to_string();
        assert!(!ckks_sidecar_segment_snapshots_cover_records(
            &snapshots,
            &[
                ckks_sidecar_test_record(1, "ciphertext-a"),
                stale_ciphertext
            ],
        ));

        let mut stale_shard_key = ckks_sidecar_test_record(2, "ciphertext-b");
        stale_shard_key.shard_key = Some(ShardKey::from("tenant-b"));
        assert!(
            !ckks_sidecar_segment_snapshots_cover_records(
                &snapshots,
                &[ckks_sidecar_test_record(1, "ciphertext-a"), stale_shard_key],
            ),
            "segment-native CKKS index snapshots must not be reused across shard-key identity changes",
        );
    }

    #[test]
    fn encrypted_vector_from_payload_validates_sidecar_metadata() {
        let payload = json!({
            "$qdrant_sec_vectors": {
                "embedding-sensitive-sentinel": {
                    "$qdrant_sec_ckks_vector": {
                        "version": 1,
                        "scheme": "openfhe-ckks",
                        "envelope": {
                            "version": 1,
                            "algorithm": "AES-256-GCM",
                            "key_id": "tenant-a:vector-sensitive-sentinel",
                            "material_fingerprint": "tenant-a/vector-sensitive-sentinel@v1",
                            "rk_id": "tenant-a/vector-rk-sensitive-sentinel@v1",
                            "rk_epoch": 1,
                            "nonce": "AAAAAAAAAAAAAAAA",
                            "ciphertext": "short-sensitive-sentinel!"
                        }
                    }
                }
            }
        });
        let payload = Payload(payload.as_object().unwrap().clone());

        let err = encrypted_vector_from_payload(&payload, "embedding-sensitive-sentinel")
            .expect_err("common query sidecar scan must reject malformed ciphertext metadata");
        let rendered = err.to_string();
        assert!(
            rendered.contains("failed validation"),
            "unexpected error: {err:?}",
        );
        for leaked in [
            "embedding-sensitive-sentinel",
            "tenant-a:vector-sensitive-sentinel",
            "tenant-a/vector-sensitive-sentinel@v1",
            "tenant-a/vector-rk-sensitive-sentinel@v1",
            "short-sensitive-sentinel",
        ] {
            assert!(
                !rendered.contains(leaked),
                "stored CKKS vector sidecar validation error leaked {leaked}: {rendered}",
            );
        }
    }

    #[test]
    fn ckks_sidecar_hnsw_cache_miss_does_not_build_graph_on_query_path() {
        let dir = tempfile::tempdir().unwrap();
        let records = vec![
            ckks_sidecar_test_record(10, "ciphertext-a"),
            ckks_sidecar_test_record(11, "ciphertext-b"),
            ckks_sidecar_test_record(12, "ciphertext-c"),
        ];

        let err = ckks_sidecar_hnsw_search_points(
            "test",
            "cache-miss-no-query-build",
            "embedding",
            dir.path(),
            &crate::common::crypto::VectorWritePlan::empty_for_test(),
            &records,
            CkksSidecarHnswQuery::Dense(&[1.0, 0.0]),
            Distance::Dot,
            Distance::Dot.distance_order(),
            None,
            1,
            1,
        )
        .expect_err("query-time CKKS graph cache miss must fail fast");

        let rendered = format!("{err}");
        assert!(
            rendered.contains("query-time graph build is disabled"),
            "unexpected error: {err}",
        );
        assert!(
            !rendered.contains("embedding"),
            "HNSW cache miss error leaked vector name: {err}",
        );
    }

    fn ckks_sidecar_test_segment_snapshot(
        records: Vec<CkksSidecarSearchRecord>,
    ) -> CkksCiphertextSegmentIndexSnapshot {
        let indexed_records = records
            .iter()
            .enumerate()
            .map(|(idx, record)| {
                CkksCiphertextIndexedRecord::new(
                    idx as _,
                    record.encrypted.envelope.ciphertext.as_bytes().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        let graph = CkksCiphertextHnswGraph::build_optimizer_candidate_graph(records.len(), 2);
        let records = records
            .into_iter()
            .zip(indexed_records)
            .map(
                |(record, indexed_record)| CkksCiphertextSegmentSearchRecord {
                    id: record.id,
                    shard_key: record.shard_key,
                    point_id: record.point_id,
                    indexed_record,
                    encrypted: record.encrypted,
                },
            )
            .collect();

        CkksCiphertextSegmentIndexSnapshot { records, graph }
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_key_uses_collection_identity() {
        let first = CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid-a".to_string(),
            vector_name: "vector".to_string(),
            distance: "dot",
            score_order: "large",
            m: 16,
            records_fingerprint: "fingerprint-a".to_string(),
        };
        let second = CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid-b".to_string(),
            ..first.clone()
        };

        assert_ne!(
            ckks_sidecar_hnsw_graph_cache_file_name(&first),
            ckks_sidecar_hnsw_graph_cache_file_name(&second),
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_key_uses_distance_metric() {
        let dot = CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid".to_string(),
            vector_name: "vector".to_string(),
            distance: "dot",
            score_order: "large",
            m: 16,
            records_fingerprint: "fingerprint-a".to_string(),
        };
        let cosine = CkksSidecarHnswGraphCacheKey {
            distance: "cosine",
            ..dot.clone()
        };

        assert_ne!(
            ckks_sidecar_hnsw_graph_cache_file_name(&dot),
            ckks_sidecar_hnsw_graph_cache_file_name(&cosine),
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_key_uses_vector_name() {
        let first = CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid".to_string(),
            vector_name: "embedding".to_string(),
            distance: "dot",
            score_order: "large",
            m: 16,
            records_fingerprint: "fingerprint-a".to_string(),
        };
        let second = CkksSidecarHnswGraphCacheKey {
            vector_name: "image".to_string(),
            ..first.clone()
        };

        assert_ne!(
            ckks_sidecar_hnsw_graph_cache_file_name(&first),
            ckks_sidecar_hnsw_graph_cache_file_name(&second),
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_key_uses_score_order() {
        let large_better = CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid".to_string(),
            vector_name: "vector".to_string(),
            distance: "dot",
            score_order: "large",
            m: 16,
            records_fingerprint: "fingerprint-a".to_string(),
        };
        let small_better = CkksSidecarHnswGraphCacheKey {
            score_order: "small",
            ..large_better.clone()
        };

        assert_ne!(
            ckks_sidecar_hnsw_graph_cache_file_name(&large_better),
            ckks_sidecar_hnsw_graph_cache_file_name(&small_better),
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_key_uses_graph_degree() {
        let first = CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid".to_string(),
            vector_name: "vector".to_string(),
            distance: "dot",
            score_order: "large",
            m: 16,
            records_fingerprint: "fingerprint-a".to_string(),
        };
        let second = CkksSidecarHnswGraphCacheKey {
            m: 32,
            ..first.clone()
        };

        assert_ne!(
            ckks_sidecar_hnsw_graph_cache_file_name(&first),
            ckks_sidecar_hnsw_graph_cache_file_name(&second),
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_key_uses_records_fingerprint() {
        let first = CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid".to_string(),
            vector_name: "vector".to_string(),
            distance: "dot",
            score_order: "large",
            m: 16,
            records_fingerprint: "fingerprint-a".to_string(),
        };
        let second = CkksSidecarHnswGraphCacheKey {
            records_fingerprint: "fingerprint-b".to_string(),
            ..first.clone()
        };

        assert_ne!(
            ckks_sidecar_hnsw_graph_cache_file_name(&first),
            ckks_sidecar_hnsw_graph_cache_file_name(&second),
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_evicts_old_entries() {
        let mut cache = CkksSidecarHnswGraphCache::default();
        let original_key = ckks_sidecar_test_graph_cache_key("original");
        let original_graph = Arc::new(ckks_sidecar_test_graph(vec![vec![1], vec![0]]));
        cache.insert(original_key.clone(), original_graph.clone());
        assert!(Arc::ptr_eq(
            &cache.get(&original_key).unwrap(),
            &original_graph
        ));

        for idx in 0..CKKS_SIDECAR_HNSW_GRAPH_CACHE_CAPACITY {
            cache.insert(
                ckks_sidecar_test_graph_cache_key(format!("fresh-{idx}")),
                Arc::new(ckks_sidecar_test_graph(Vec::new())),
            );
        }

        assert!(cache.get(&original_key).is_none());
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_invalidates_collection_vector_entries() {
        let mut cache = CkksSidecarHnswGraphCache::default();
        let target_key = ckks_sidecar_test_graph_cache_key("target");
        let same_collection_other_vector_key = CkksSidecarHnswGraphCacheKey {
            vector_name: "other".to_string(),
            records_fingerprint: "other-vector".to_string(),
            ..target_key.clone()
        };
        let other_collection_key = CkksSidecarHnswGraphCacheKey {
            collection_identity: "other-collection".to_string(),
            records_fingerprint: "other-collection".to_string(),
            ..target_key.clone()
        };

        for key in [
            target_key.clone(),
            same_collection_other_vector_key.clone(),
            other_collection_key.clone(),
        ] {
            cache.insert(key, Arc::new(ckks_sidecar_test_graph(Vec::new())));
        }

        cache.invalidate_collection_vectors("collection-uuid", &["vector".to_string()]);

        assert!(cache.get(&target_key).is_none());
        assert!(cache.get(&same_collection_other_vector_key).is_some());
        assert!(cache.get(&other_collection_key).is_some());
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_invalidates_matching_persisted_entries() {
        let dir = tempfile::tempdir().unwrap();
        let target_key = ckks_sidecar_test_graph_cache_key("target");
        let same_collection_other_vector_key = CkksSidecarHnswGraphCacheKey {
            vector_name: "other".to_string(),
            records_fingerprint: "other-vector".to_string(),
            ..target_key.clone()
        };
        let other_collection_key = CkksSidecarHnswGraphCacheKey {
            collection_identity: "other-collection".to_string(),
            records_fingerprint: "other-collection".to_string(),
            ..target_key.clone()
        };

        let target_path = write_ckks_sidecar_test_graph_disk(
            dir.path(),
            &target_key,
            &ckks_sidecar_test_graph_disk(&target_key, vec![vec![1], vec![0]]),
        );
        let same_collection_other_vector_path = write_ckks_sidecar_test_graph_disk(
            dir.path(),
            &same_collection_other_vector_key,
            &ckks_sidecar_test_graph_disk(
                &same_collection_other_vector_key,
                vec![vec![1], vec![0]],
            ),
        );
        let other_collection_path = write_ckks_sidecar_test_graph_disk(
            dir.path(),
            &other_collection_key,
            &ckks_sidecar_test_graph_disk(&other_collection_key, vec![vec![1], vec![0]]),
        );

        invalidate_ckks_sidecar_hnsw_graph_cache_for_collection_path(
            dir.path(),
            "collection-uuid",
            &["vector".to_string()],
        )
        .unwrap();

        assert!(!target_path.exists());
        assert!(same_collection_other_vector_path.exists());
        assert!(other_collection_path.exists());
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_invalidates_malformed_persisted_entries() {
        let dir = tempfile::tempdir().unwrap();
        let target_key = ckks_sidecar_test_graph_cache_key("malformed-target");
        let target_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &target_key);
        let directory = target_path.parent().unwrap();
        std::fs::create_dir_all(directory).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(directory);
        std::fs::write(&target_path, b"not-json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        invalidate_ckks_sidecar_hnsw_graph_cache_for_collection_path(
            dir.path(),
            "collection-uuid",
            &["vector".to_string()],
        )
        .unwrap();

        assert!(
            !target_path.exists(),
            "malformed persisted sidecar graph cache should not survive mutation invalidation",
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_invalidates_oversized_persisted_entries() {
        let dir = tempfile::tempdir().unwrap();
        let target_key = ckks_sidecar_test_graph_cache_key("oversized-target");
        let target_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &target_key);
        let directory = target_path.parent().unwrap();
        std::fs::create_dir_all(directory).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(directory);
        let file = std::fs::File::create(&target_path).unwrap();
        file.set_len(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES + 1)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        invalidate_ckks_sidecar_hnsw_graph_cache_for_collection_path(
            dir.path(),
            "collection-uuid",
            &["vector".to_string()],
        )
        .unwrap();

        assert!(
            !target_path.exists(),
            "oversized persisted sidecar graph cache should not survive mutation invalidation",
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_rejects_oversized_serialized_content() {
        let path = Path::new("ckks-sidecar-cache.json");
        ensure_ckks_sidecar_hnsw_graph_cache_content_size(
            path,
            CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES,
        )
        .unwrap();
        let err = ensure_ckks_sidecar_hnsw_graph_cache_content_size(
            path,
            CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES + 1,
        )
        .expect_err("oversized persisted graph cache content must fail before write");

        assert!(format!("{err}").contains("exceeds maximum size"));
    }

    fn ckks_sidecar_test_graph_cache_key(
        records_fingerprint: impl Into<String>,
    ) -> CkksSidecarHnswGraphCacheKey {
        CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid".to_string(),
            vector_name: "vector".to_string(),
            distance: "dot",
            score_order: "large",
            m: 16,
            records_fingerprint: records_fingerprint.into(),
        }
    }

    fn ckks_sidecar_test_graph(links: Vec<Vec<usize>>) -> CkksSidecarHnswGraph {
        CkksSidecarHnswGraph::from_validated_links(links).unwrap()
    }

    fn ckks_sidecar_test_graph_disk(
        key: &CkksSidecarHnswGraphCacheKey,
        links: Vec<Vec<usize>>,
    ) -> CkksSidecarHnswGraphDisk {
        CkksSidecarHnswGraphDisk {
            version: CKKS_SIDECAR_HNSW_GRAPH_CACHE_VERSION,
            collection_identity: key.collection_identity.clone(),
            vector_name: key.vector_name.clone(),
            distance: key.distance.to_string(),
            score_order: key.score_order.to_string(),
            m: key.m,
            records_fingerprint: key.records_fingerprint.clone(),
            links,
        }
    }

    fn set_ckks_sidecar_test_private_directory_permissions(directory: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn write_ckks_sidecar_test_graph_disk(
        collection_path: &Path,
        key: &CkksSidecarHnswGraphCacheKey,
        disk: &CkksSidecarHnswGraphDisk,
    ) -> PathBuf {
        let path = ckks_sidecar_hnsw_graph_cache_path(collection_path, key);
        let directory = path.parent().unwrap();
        std::fs::create_dir_all(directory).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(directory);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        let mut file = options.open(&path).unwrap();
        file.write_all(&serde_json::to_vec(disk).unwrap()).unwrap();
        path
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_roundtrips_by_cache_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let graph = ckks_sidecar_test_graph(vec![vec![1], vec![0, 2], vec![1]]);

        ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let cache_dir = dir.path().join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
            let mode = std::fs::metadata(cache_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        let loaded = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 3)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.links(), graph.links());

        let stale_key = CkksSidecarHnswGraphCacheKey {
            records_fingerprint: "fingerprint-b".to_string(),
            ..key
        };
        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &stale_key, 3)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_metadata_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let mut disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1], vec![0]]);
        disk.collection_identity = "other-collection-uuid".to_string();
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_distance_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let mut disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1], vec![0]]);
        disk.distance = "cosine".to_string();
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_cache_metadata_mismatches() {
        let mismatches = [
            (
                "cache version",
                Box::new(|disk: &mut CkksSidecarHnswGraphDisk| {
                    disk.version += 1;
                }) as Box<dyn Fn(&mut CkksSidecarHnswGraphDisk)>,
            ),
            (
                "vector name",
                Box::new(|disk: &mut CkksSidecarHnswGraphDisk| {
                    disk.vector_name = "other-vector".to_string();
                }),
            ),
            (
                "score order",
                Box::new(|disk: &mut CkksSidecarHnswGraphDisk| {
                    disk.score_order = "small".to_string();
                }),
            ),
            (
                "graph degree",
                Box::new(|disk: &mut CkksSidecarHnswGraphDisk| {
                    disk.m += 1;
                }),
            ),
            (
                "records fingerprint",
                Box::new(|disk: &mut CkksSidecarHnswGraphDisk| {
                    disk.records_fingerprint = "other-fingerprint".to_string();
                }),
            ),
        ];

        for (label, mutate) in mismatches {
            let dir = tempfile::tempdir().unwrap();
            let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
            let mut disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1], vec![0]]);
            mutate(&mut disk);
            write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

            assert!(
                ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                    .unwrap()
                    .is_none(),
                "persisted graph with {label} mismatch must not be reused",
            );
        }
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_out_of_range_links() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![2], vec![0]]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_asymmetric_links() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1], Vec::new()]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_duplicate_links() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1, 1], vec![0]]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_self_loops() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![0, 1], vec![0]]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_disconnected_links() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1], vec![0], Vec::new()]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 3)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_malformed_cache_file() {
        let dir = tempfile::Builder::new()
            .prefix("ckks-cache-path-sentinel-")
            .tempdir()
            .unwrap();
        let key = ckks_sidecar_test_graph_cache_key("malformed");
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_directory = cache_path.parent().unwrap();
        std::fs::create_dir_all(cache_directory).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_directory);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        let mut file = options.open(&cache_path).unwrap();
        file.write_all(b"{not-json").unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 0).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("failed to parse CKKS sidecar HNSW graph cache"));
        assert!(
            !rendered.contains("ckks-cache-path-sentinel"),
            "persisted graph cache error leaked storage path: {rendered}",
        );
        assert!(
            !rendered.contains("collection-uuid") && !rendered.contains("vector"),
            "persisted graph cache error leaked cache key identifiers: {rendered}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_symlink_cache_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_directory = cache_path.parent().unwrap();
        std::fs::create_dir_all(cache_directory).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_directory);
        let target_path = dir.path().join("target.json");
        std::fs::write(&target_path, "{}").unwrap();
        symlink(&target_path, &cache_path).unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 0).unwrap_err();
        assert!(format!("{err}").contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_symlink_cache_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let target_dir = dir.path().join("target-cache-dir");
        std::fs::create_dir(&target_dir).unwrap();
        symlink(
            &target_dir,
            dir.path().join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR),
        )
        .unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 0).unwrap_err();
        assert!(format!("{err}").contains("cache directory"));
        assert!(format!("{err}").contains("must not be a symlink"));

        let graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        let err = ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap_err();
        assert!(format!("{err}").contains("cache directory"));
        assert!(format!("{err}").contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_group_accessible_cache_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let cache_dir = dir.path().join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
        std::fs::create_dir(&cache_dir).unwrap();
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o750)).unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 0).unwrap_err();
        assert!(format!("{err}").contains("cache directory"));
        assert!(format!("{err}").contains("must not be group/world accessible"));

        let graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        let err = ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap_err();
        assert!(format!("{err}").contains("cache directory"));
        assert!(format!("{err}").contains("must not be group/world accessible"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_group_accessible_cache_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap();
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 1).unwrap_err();
        assert!(format!("{err}").contains("must not be group/world accessible"));
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_oversized_cache_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_directory = cache_path.parent().unwrap();
        std::fs::create_dir_all(cache_directory).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_directory);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        let file = options.open(&cache_path).unwrap();
        file.set_len(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES + 1)
            .unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 0).unwrap_err();
        assert!(format!("{err}").contains("exceeds maximum size"));
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prunes_old_cache_files() {
        let dir = tempfile::tempdir().unwrap();
        let graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        let mut newest_key = None;
        for idx in 0..(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_FILES + 5) {
            let key = ckks_sidecar_test_graph_cache_key(format!("fingerprint-{idx}"));
            ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap();
            newest_key = Some(key);
        }

        let cache_dir = dir.path().join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
        let cache_files = std::fs::read_dir(cache_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("json")
            })
            .count();
        assert!(cache_files <= CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_FILES);

        let newest_key = newest_key.unwrap();
        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &newest_key, 1)
                .unwrap()
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prune_rejects_symlink_keep_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("keep");
        let keep_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_dir = keep_path.parent().unwrap();
        std::fs::create_dir_all(cache_dir).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_dir);
        let target_path = dir.path().join("target.json");
        std::fs::write(&target_path, "{}").unwrap();
        symlink(&target_path, &keep_path).unwrap();

        let err = ckks_sidecar_hnsw_prune_persisted_graphs(cache_dir, &keep_path).unwrap_err();
        assert!(format!("{err}").contains("keep file"));
        assert!(format!("{err}").contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prune_rejects_group_accessible_keep_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("keep-permissions");
        let graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap();
        let keep_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_dir = keep_path.parent().unwrap();
        std::fs::set_permissions(&keep_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let err = ckks_sidecar_hnsw_prune_persisted_graphs(cache_dir, &keep_path).unwrap_err();
        assert!(format!("{err}").contains("keep file"));
        assert!(format!("{err}").contains("must not be group/world accessible"));
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prune_rejects_non_regular_keep_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("keep-directory");
        let keep_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_dir = keep_path.parent().unwrap();
        std::fs::create_dir_all(&keep_path).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_dir);

        let err = ckks_sidecar_hnsw_prune_persisted_graphs(cache_dir, &keep_path).unwrap_err();
        assert!(format!("{err}").contains("keep file"));
        assert!(format!("{err}").contains("must be a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prune_removes_stale_symlink_cache_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let keep_key = ckks_sidecar_test_graph_cache_key("keep");
        let graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        ckks_sidecar_hnsw_persist_graph(dir.path(), &keep_key, &graph).unwrap();
        let keep_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &keep_key);
        let cache_dir = keep_path.parent().unwrap();

        let stale_key = ckks_sidecar_test_graph_cache_key("stale-symlink");
        let stale_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &stale_key);
        let target_path = dir.path().join("target.json");
        std::fs::write(&target_path, "{}").unwrap();
        symlink(&target_path, &stale_path).unwrap();

        ckks_sidecar_hnsw_prune_persisted_graphs(cache_dir, &keep_path).unwrap();
        assert!(!stale_path.exists());
        assert!(keep_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prune_removes_insecure_stale_cache_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let keep_key = ckks_sidecar_test_graph_cache_key("keep");
        let graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        ckks_sidecar_hnsw_persist_graph(dir.path(), &keep_key, &graph).unwrap();
        let keep_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &keep_key);
        let cache_dir = keep_path.parent().unwrap();

        let stale_key = ckks_sidecar_test_graph_cache_key("stale-permissions");
        let stale_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &stale_key);
        let disk = ckks_sidecar_test_graph_disk(&stale_key, vec![Vec::new()]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &stale_key, &disk);
        std::fs::set_permissions(&stale_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        ckks_sidecar_hnsw_prune_persisted_graphs(cache_dir, &keep_path).unwrap();
        assert!(!stale_path.exists());
        assert!(keep_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_symlink_temp_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("temp-symlink");
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_dir = cache_path.parent().unwrap();
        std::fs::create_dir_all(cache_dir).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_dir);
        let temp_path = cache_path.with_extension("json.tmp");
        let target_path = dir.path().join("target.tmp");
        std::fs::write(&target_path, "{}").unwrap();
        symlink(&target_path, &temp_path).unwrap();

        let graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        let err = ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap_err();
        assert!(format!("{err}").contains("temp file"));
        assert!(format!("{err}").contains("must not be a symlink"));
        assert!(!cache_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_group_accessible_temp_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("temp-permissions");
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_dir = cache_path.parent().unwrap();
        std::fs::create_dir_all(cache_dir).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_dir);
        let temp_path = cache_path.with_extension("json.tmp");
        std::fs::write(&temp_path, "{}").unwrap();
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        let err = ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap_err();
        assert!(format!("{err}").contains("temp file"));
        assert!(format!("{err}").contains("must not be group/world accessible"));
        assert!(!cache_path.exists());
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prunes_by_total_size() {
        let dir = tempfile::tempdir().unwrap();
        let keep_key = ckks_sidecar_test_graph_cache_key("keep");
        let keep_graph = ckks_sidecar_test_graph(vec![Vec::new()]);
        ckks_sidecar_hnsw_persist_graph(dir.path(), &keep_key, &keep_graph).unwrap();
        let cache_dir = dir.path().join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
        let keep_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &keep_key);

        for idx in 0..4 {
            let old_key = ckks_sidecar_test_graph_cache_key(format!("old-{idx}"));
            let old_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &old_key);
            let old_directory = old_path.parent().unwrap();
            std::fs::create_dir_all(old_directory).unwrap();
            set_ckks_sidecar_test_private_directory_permissions(old_directory);
            let mut options = std::fs::OpenOptions::new();
            options.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;

                options.mode(0o600);
            }
            let file = options.open(&old_path).unwrap();
            file.set_len(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_TOTAL_BYTES / 2)
                .unwrap();
        }

        ckks_sidecar_hnsw_prune_persisted_graphs(&cache_dir, &keep_path).unwrap();
        let total_bytes = std::fs::read_dir(cache_dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.metadata().unwrap().len())
            .sum::<u64>();
        assert!(total_bytes <= CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_TOTAL_BYTES);
        assert!(keep_path.exists());
    }

    #[test]
    fn ckks_sidecar_grouping_uses_ranked_group_order_and_size() {
        let group_by = "group".parse::<JsonPath>().unwrap();
        let groups = group_ckks_search_points(
            vec![
                scored_point_with_payload(1, 9.0, json!({ "group": "a" })),
                scored_point_with_payload(2, 8.0, json!({ "group": "a" })),
                scored_point_with_payload(3, 7.0, json!({ "group": "b" })),
                scored_point_with_payload(4, 6.0, json!({ "group": "c" })),
            ],
            &group_by,
            2,
            1,
        );

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0, GroupId::from("a"));
        assert_eq!(groups[0].1.len(), 1);
        assert_eq!(groups[0].1[0].id, 1.into());
        assert_eq!(groups[1].0, GroupId::from("b"));
        assert_eq!(groups[1].1[0].id, 3.into());
    }

    #[test]
    fn ckks_sidecar_grouped_candidate_limit_is_bounded() {
        let max_candidates = crate::settings::default_ckks_grouped_max_candidates();
        assert_eq!(
            ckks_grouped_candidate_limit(1, 1, max_candidates).unwrap(),
            32
        );
        assert_eq!(
            ckks_grouped_candidate_limit(64, 2, max_candidates).unwrap(),
            4096
        );
        assert_eq!(
            ckks_grouped_candidate_limit(0, 10, max_candidates).unwrap(),
            0
        );
        assert_eq!(ckks_grouped_candidate_limit(5, 2, 16).unwrap(), 16);

        let err = ckks_grouped_candidate_limit(max_candidates + 1, 1, max_candidates)
            .expect_err("grouped requests larger than the CKKS candidate budget must fail");
        assert!(
            format!("{err}").contains("at most"),
            "unexpected error: {err}",
        );

        let err = ckks_grouped_candidate_limit(usize::MAX, 2, max_candidates)
            .expect_err("overflowing grouped requests must fail");
        assert!(
            format!("{err}").contains("too large"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn ckks_sidecar_scoring_source_batches_counts_expensive_sources() {
        let source = vec![0.0_f32, 1.0];
        let positives = (0..20).map(|_| source.as_slice()).collect::<Vec<_>>();
        let negatives = (0..13).map(|_| source.as_slice()).collect::<Vec<_>>();
        let scoring = CkksSidecarScoring::RecommendSumScores {
            positives,
            negatives,
        };
        assert_eq!(
            ckks_sidecar_scoring_source_batches(&scoring),
            crate::settings::default_ckks_scoring_source_batch_max() + 1,
        );

        let pairs = (0..16)
            .map(|_| (source.as_slice(), source.as_slice()))
            .collect::<Vec<_>>();
        let scoring = CkksSidecarScoring::Discover {
            target: source.as_slice(),
            pairs,
        };
        assert_eq!(
            ckks_sidecar_scoring_source_batches(&scoring),
            crate::settings::default_ckks_scoring_source_batch_max() + 1,
        );

        let scoring = CkksSidecarScoring::Nearest {
            query_values: source.as_slice(),
        };
        assert_eq!(ckks_sidecar_scoring_source_batches(&scoring), 1);
    }

    #[test]
    fn ckks_search_plan_lost_rule_error_redacts_vector_name() {
        let err = ckks_search_plan_lost_rule_error();
        let rendered = err.to_string();
        assert!(rendered.contains("CKKS vector search plan lost encrypted vector rule"));
        assert!(!rendered.contains("embedding"));
        assert!(!rendered.contains("encrypted vector '"));
    }

    #[test]
    fn ckks_client_query_nonce_replay_cache_rejects_recent_reuse() {
        clear_ckks_client_query_nonce_replay_cache_for_tests();
        let plan = crate::common::crypto::VectorWritePlan::empty_for_test();

        record_ckks_client_query_nonce(
            "collection-uuid",
            "embedding",
            "tenant-a:key",
            "tenant-a/rk",
            3,
            "AAAAAAAAAAAAAAAA",
            "tenant-a/signing",
            &plan,
        )
        .unwrap();

        let err = record_ckks_client_query_nonce(
            "collection-uuid",
            "embedding",
            "tenant-a:key",
            "tenant-a/rk",
            3,
            "AAAAAAAAAAAAAAAA",
            "tenant-a/signing",
            &plan,
        )
        .expect_err("same signed query nonce must not be accepted twice");
        assert!(
            format!("{err}").contains("already used recently"),
            "unexpected error: {err}",
        );
        for leaked in [
            "collection-uuid",
            "embedding",
            "tenant-a:key",
            "tenant-a/rk",
            "tenant-a/signing",
        ] {
            assert!(
                !format!("{err}").contains(leaked),
                "replay error leaked sensitive query nonce lineage field {leaked}: {err}",
            );
        }

        record_ckks_client_query_nonce(
            "collection-uuid",
            "embedding",
            "tenant-a:key",
            "tenant-a/rk",
            3,
            "AAAAAAAAAAAAAAAB",
            "tenant-a/signing",
            &plan,
        )
        .unwrap();
    }

    #[test]
    fn ckks_point_id_query_error_redacts_identifiers() {
        let rendered = format!(
            "{}",
            ckks_point_id_query_error("point has no CKKS vector sidecar")
        );

        assert!(rendered.contains("point-id query failed"));
        assert!(rendered.contains("CKKS vector sidecar"));
        for leaked in [
            "embedding-sensitive-sentinel",
            "collection-sensitive-sentinel",
            "point-id-sensitive-sentinel",
            "123456789",
        ] {
            assert!(
                !rendered.contains(leaked),
                "point-id query error leaked identifier {leaked}: {rendered}",
            );
        }
    }

    #[test]
    fn ckks_client_query_nonce_replay_cache_rejects_same_nonce_across_signers() {
        clear_ckks_client_query_nonce_replay_cache_for_tests();
        let plan = crate::common::crypto::VectorWritePlan::empty_for_test();

        record_ckks_client_query_nonce(
            "collection-uuid",
            "embedding",
            "tenant-a:key",
            "tenant-a/rk",
            3,
            "BBBBBBBBBBBBBBBB",
            "tenant-a/signing-a",
            &plan,
        )
        .unwrap();

        let err = record_ckks_client_query_nonce(
            "collection-uuid",
            "embedding",
            "tenant-a:key",
            "tenant-a/rk",
            3,
            "BBBBBBBBBBBBBBBB",
            "tenant-a/signing-b",
            &plan,
        )
        .expect_err("same query nonce under the same CKKS key lineage must be single-use");

        assert!(
            format!("{err}").contains("already used recently"),
            "unexpected error: {err}",
        );
        for leaked in [
            "collection-uuid",
            "embedding",
            "tenant-a:key",
            "tenant-a/rk",
            "tenant-a/signing-a",
            "tenant-a/signing-b",
        ] {
            assert!(
                !format!("{err}").contains(leaked),
                "replay error leaked sensitive query nonce lineage field {leaked}: {err}",
            );
        }
    }

    #[test]
    fn ckks_matrix_budget_rejects_quadratic_scoring_cost() {
        ensure_ckks_matrix_budget(CKKS_MATRIX_SAMPLE_MAX, 1).unwrap();
        ensure_ckks_matrix_budget(1, CKKS_MATRIX_SCORE_PAIR_MAX).unwrap();

        let err = ensure_ckks_matrix_budget(CKKS_MATRIX_SAMPLE_MAX + 1, 1)
            .expect_err("sample above matrix budget must fail");
        assert!(
            format!("{err}").contains("sample size"),
            "unexpected error: {err}",
        );

        let err = ensure_ckks_matrix_budget(CKKS_MATRIX_SAMPLE_MAX, CKKS_MATRIX_SAMPLE_MAX + 1)
            .expect_err("response pairs above matrix budget must fail");
        assert!(
            format!("{err}").contains("response pairs"),
            "unexpected error: {err}",
        );

        let err =
            ensure_ckks_matrix_budget(usize::MAX, 2).expect_err("overflowing sample must fail");
        assert!(
            format!("{err}").contains("sample size"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn ckks_sidecar_grouping_allows_plain_group_path() {
        let group_by = "group".parse::<JsonPath>().unwrap();
        ensure_group_path_does_not_touch_encrypted_crypto_selectors(None, &group_by).unwrap();
    }

    #[test]
    fn ckks_sidecar_grouping_rejects_sidecar_group_paths() {
        for group_by in [
            "\"$qdrant_sec_vectors\"",
            "\"$qdrant_sec_vectors\".embedding",
        ] {
            let group_by = group_by.parse::<JsonPath>().unwrap();
            let err = ensure_group_path_does_not_touch_encrypted_crypto_selectors(None, &group_by)
                .expect_err("grouping by encrypted vector sidecar path must fail");
            let message = format!("{err}");

            assert!(
                message.contains("cannot group by encrypted vector sidecar field")
                    && !message.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD),
                "unexpected error: {err}",
            );
        }
    }

    #[test]
    fn ckks_sidecar_grouping_rejects_encrypted_payload_and_metadata_paths() {
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:docs".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 3,
            migration_state: CryptoMigrationState::Active,
            rules: vec![
                EncryptionRuleRef {
                    id: "body".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["document.body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: None,
                },
                EncryptionRuleRef {
                    id: "metadata".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec!["meta.owner".to_string()],
                    },
                    instance: "docs_metadata_v1".to_string(),
                    binding: Some("metadata-value/v1".to_string()),
                },
            ],
        };

        for (group_by, expected) in [
            ("document", "cannot group by encrypted payload field"),
            (
                "document.body.keyword",
                "cannot group by encrypted payload field",
            ),
            ("meta.owner", "cannot group by encrypted metadata field"),
            ("meta.owner.raw", "cannot group by encrypted metadata field"),
        ] {
            let group_by = group_by.parse::<JsonPath>().unwrap();
            let err = ensure_group_path_does_not_touch_encrypted_crypto_selectors(
                Some(&encryption),
                &group_by,
            )
            .expect_err("CKKS grouping by encrypted payload or metadata paths must fail");
            let message = format!("{err}");
            assert!(
                message.contains(expected),
                "unexpected error for {group_by}: {err}",
            );
            assert!(!message.contains("document.body"), "{message}");
            assert!(!message.contains("meta.owner"), "{message}");
        }
    }

    #[test]
    fn private_result_oram_grouping_rejects_payload_paths_with_session_api_message() {
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:result-private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "private_result_payload".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["document.body".to_string()],
                },
                instance: "docs_private_result_oram_v1".to_string(),
                binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
            }],
        };

        for group_by in ["document", "document.body", "document.body.lang"] {
            let group_by = group_by.parse::<JsonPath>().unwrap();
            let err = ensure_group_path_does_not_touch_encrypted_crypto_selectors(
                Some(&encryption),
                &group_by,
            )
            .expect_err("private result ORAM grouping must fail closed");
            let message = err.to_string();
            assert!(
                message.contains("cannot use private result ORAM payload field"),
                "unexpected error for {group_by}: {err}",
            );
            assert!(
                message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                "unexpected error for {group_by}: {err}",
            );
            assert!(
                message.contains("/private-result-oram/session"),
                "unexpected error for {group_by}: {err}",
            );
            assert!(
                !message.contains("document.body"),
                "unexpected error for {group_by}: {err}",
            );
            assert!(
                !message.contains("configure a blind index provider"),
                "unexpected error for {group_by}: {err}",
            );
        }
    }

    const PRIVATE_RESULT_ORAM_PAYLOAD_ALIAS_SENTINELS: &[&str] = &[
        "clientState",
        "clientStates",
        "client_state",
        "client_states",
        "clientStateBackup",
        "clientStateBackups",
        "client_state_backup",
        "client_state_backups",
        "clientStateSnapshot",
        "clientStateSnapshots",
        "client.state.snapshot",
        "client.state.snapshot.json",
        "client.state.snapshots.json",
        "client_state_snapshot",
        "client_state_snapshots",
        "clientStateCiphertext",
        "clientStateCiphertextHash",
        "clientStateCiphertextHashes",
        "clientStateCiphertextSha256",
        "clientStateCiphertextsSha256",
        "client_state_ciphertext",
        "client_state_ciphertext_hash",
        "client_state_ciphertext_hash.bin",
        "client_state_ciphertext_hash.json",
        "client_state_ciphertext_hashes",
        "client_state_ciphertext_hashes.bin",
        "client_state_ciphertext_hashes.json",
        "client_state_ciphertext_sha256",
        "client_state_ciphertext_sha256.bin",
        "client_state_ciphertext_sha256.json",
        "client_state_ciphertexts_sha256",
        "client_state_ciphertexts_sha256.bin",
        "client_state_ciphertexts_sha256.json",
        "encryptedClientStateBackup",
        "encryptedClientStateBackups",
        "encryptedClientState",
        "encryptedClientStates",
        "encrypted.client.state",
        "encrypted.client.state.json",
        "encrypted.client.state.snapshot",
        "encrypted.client.state.snapshot.json",
        "encrypted.client.state.snapshots.json",
        "encrypted_client_states",
        "encrypted_client_state_backups",
        "encryptedClientStateSnapshot",
        "encryptedClientStateSnapshots",
        "encrypted_client_state_snapshot",
        "encrypted_client_state_snapshot.bin",
        "encrypted_client_state_snapshot.json",
        "encrypted_client_state_snapshots",
        "encrypted_client_state_snapshots.json",
        "encryptedClientStateCiphertext",
        "encryptedClientStateCiphertextHash",
        "encryptedClientStateCiphertextHashes",
        "encryptedClientStateCiphertextSha256",
        "encryptedClientStateCiphertextsSha256",
        "encrypted_client_state",
        "encrypted_client_state_backup",
        "encrypted_client_state_ciphertexts",
        "encrypted_client_state_ciphertext",
        "encrypted_client_state_ciphertext_hash",
        "encrypted_client_state_ciphertext_hash.bin",
        "encrypted_client_state_ciphertext_hash.json",
        "encrypted_client_state_ciphertext_hashes",
        "encrypted_client_state_ciphertext_hashes.bin",
        "encrypted_client_state_ciphertext_hashes.json",
        "encrypted_client_state_ciphertext_sha256",
        "encrypted_client_state_ciphertext_sha256.bin",
        "encrypted_client_state_ciphertext_sha256.json",
        "encrypted_client_state_ciphertexts_sha256",
        "encrypted_client_state_ciphertexts_sha256.bin",
        "encrypted_client_state_ciphertexts_sha256.json",
        "oramPositionMap",
        "oramPositionMaps",
        "oramPositionMapBackup",
        "oramPositionMapBackups",
        "oramPositionMapSnapshot",
        "oramPositionMapSnapshots",
        "oram_position_map",
        "oram_position_maps",
        "oram_position_map_backup",
        "oram_position_map_backups",
        "oram_position_map_snapshot",
        "oram_position_map_snapshots",
        "positionMap",
        "positionMaps",
        "positionMapBackup",
        "positionMapBackups",
        "positionMapSnapshot",
        "positionMapSnapshots",
        "position_map",
        "position_maps",
        "position_map_backup",
        "position_map_backups",
        "position_map_snapshot",
        "position_map_snapshots",
        "stash",
        "stashBackup",
        "stashBackups",
        "stashSnapshot",
        "stashSnapshots",
        "stash_backup",
        "stash_backups",
        "stash_snapshot",
        "stash_snapshots",
        "stateCiphertext",
        "stateCiphertexts",
        "stateCiphertextHash",
        "stateCiphertextHashes",
        "stateCiphertextSha256",
        "stateCiphertextsSha256",
        "state_ciphertext",
        "state_ciphertexts",
        "state_ciphertext_hash",
        "state_ciphertext_hash.bin",
        "state_ciphertext_hash.json",
        "state_ciphertext_hashes",
        "state_ciphertext_hashes.bin",
        "state_ciphertext_hashes.json",
        "state_ciphertext_sha256",
        "state_ciphertext_sha256.bin",
        "state_ciphertext_sha256.json",
        "state_ciphertexts_sha256",
        "state_ciphertexts_sha256.bin",
        "state_ciphertexts_sha256.json",
        "tokenMap",
        "tokenMaps",
        "tokenMapBackup",
        "tokenMapBackups",
        "token.map.backup",
        "token.map.backup.json",
        "token.map.backups",
        "token.map.backups.json",
        "tokenMapSnapshot",
        "tokenMapSnapshots",
        "token_map",
        "token_maps",
        "token.maps",
        "token_map_backup",
        "token_map_backups",
        "token_map_snapshot",
        "token.map.snapshot",
        "token_map_snapshots",
        "token.map.snapshots",
        "tokenPositionMap",
        "tokenPositionMaps",
        "tokenPositionMapBackup",
        "tokenPositionMapBackups",
        "token.position.map.backup",
        "token.position.map.backup.json",
        "token.position.map.backups",
        "token.position.map.backups.json",
        "tokenPositionMapSnapshot",
        "tokenPositionMapSnapshots",
        "token_position_map",
        "token_position_maps",
        "token.position.maps",
        "token_position_map_backup",
        "token_position_map_backups",
        "token_position_map_snapshot",
        "token.position.map.snapshot",
        "token_position_map_snapshots",
        "token.position.map.snapshots",
    ];

    #[test]
    fn private_result_oram_grouping_redacts_backup_alias_payload_path() {
        for &payload_path in PRIVATE_RESULT_ORAM_PAYLOAD_ALIAS_SENTINELS {
            let encryption = CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:result-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "private_result_payload".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec![payload_path.to_string()],
                    },
                    instance: "docs_private_result_oram_v1".to_string(),
                    binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
                }],
            };
            let group_by = payload_path.parse::<JsonPath>().unwrap();

            let err = ensure_group_path_does_not_touch_encrypted_crypto_selectors(
                Some(&encryption),
                &group_by,
            )
            .expect_err("private result ORAM grouping must fail closed without alias leaks");
            let message = err.to_string();

            assert!(message.contains("cannot use private result ORAM payload field"));
            assert!(message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
            assert!(message.contains("/private-result-oram/session"));
            assert!(!message.contains(payload_path), "{message}");
            for &sentinel in PRIVATE_RESULT_ORAM_PAYLOAD_ALIAS_SENTINELS {
                assert!(!message.contains(sentinel), "{message}");
            }
            assert!(!message.contains("configure a blind index provider"));
        }
    }

    #[test]
    fn private_result_oram_grouping_invalid_payload_path_error_is_sanitized() {
        let secret_path = "document.body[private-result-group-secret";
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:result-private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "private_result_payload".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec![secret_path.to_string()],
                },
                instance: "docs_private_result_oram_v1".to_string(),
                binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
            }],
        };
        let group_by = "document".parse::<JsonPath>().unwrap();

        let err = ensure_group_path_does_not_touch_encrypted_crypto_selectors(
            Some(&encryption),
            &group_by,
        )
        .expect_err("invalid private result ORAM selector must fail closed")
        .to_string();

        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-group-secret"), "{err}");
        assert!(!err.contains("JsonPath"), "{err}");
    }

    #[test]
    fn private_result_oram_rest_group_lookup_preflight_rejects_raw_or_decrypted_payload_reads() {
        let (_temp, dispatcher) = test_dispatcher();
        let auth = Auth::new_internal(Access::full("private result ORAM group lookup test"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(&dispatcher).await;
            let pass = new_unchecked_verification_pass();
            let toc = dispatcher.toc(&auth, &pass).clone();

            let collection_lookup = Some(api::rest::WithLookupInterface::Collection(
                COLLECTION_NAME.to_string(),
            ));
            let err = preflight_rest_group_lookup_private_result_oram_raw_payload_read(
                &toc,
                &collection_lookup,
                "search group lookup",
                &auth,
            )
            .await
            .expect_err(
                "collection shorthand lookup must fail closed for raw private result payload",
            );
            let message = err.to_string();
            assert!(
                message.contains("cannot read private result ORAM payload field"),
                "{message}"
            );
            assert!(!message.contains("search group lookup"), "{message}");
            assert!(message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
            assert!(message.contains("/private-result-oram/session"));
            assert!(!message.contains("body"), "{message}");

            let explicit_raw_lookup = Some(api::rest::WithLookupInterface::WithLookup(
                api::rest::WithLookup {
                    collection_name: COLLECTION_NAME.to_string(),
                    with_payload: Some(WithPayloadInterface::Fields(vec![
                        "body.lang".parse().unwrap(),
                    ])),
                    with_vectors: Some(WithVector::Bool(false)),
                },
            ));
            let err = preflight_rest_group_lookup_private_result_oram_raw_payload_read(
                &toc,
                &explicit_raw_lookup,
                "recommend group lookup",
                &auth,
            )
            .await
            .expect_err("explicit lookup payload path must fail closed for private result payload");
            let message = err.to_string();
            assert!(
                message.contains("cannot read private result ORAM payload field"),
                "{message}"
            );
            assert!(!message.contains("recommend group lookup"), "{message}");
            assert!(message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
            assert!(message.contains("/private-result-oram/session"));
            assert!(!message.contains("body.lang"), "{message}");
            assert!(!message.contains("body"), "{message}");

            let explicit_decrypted_lookup = Some(api::rest::WithLookupInterface::WithLookup(
                api::rest::WithLookup {
                    collection_name: COLLECTION_NAME.to_string(),
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vectors: Some(WithVector::Bool(false)),
                },
            ));
            let err = preflight_rest_group_lookup_private_result_oram_raw_payload_read(
                &toc,
                &explicit_decrypted_lookup,
                "query group lookup",
                &auth,
            )
            .await
            .expect_err(
                "decrypted lookup payload mode must fail closed for private result payload",
            );
            let message = err.to_string();
            assert!(
                message.contains("cannot read private result ORAM payload field"),
                "{message}"
            );
            assert!(!message.contains("query group lookup"), "{message}");
            assert!(message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
            assert!(message.contains("/private-result-oram/session"));
            assert!(
                !message.contains("requires runtime crypto settings"),
                "{message}"
            );
            assert!(!message.contains("payload decrypt"), "{message}");

            for allowed_lookup in [
                None,
                Some(api::rest::WithLookupInterface::WithLookup(
                    api::rest::WithLookup {
                        collection_name: COLLECTION_NAME.to_string(),
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vectors: Some(WithVector::Bool(false)),
                    },
                )),
                Some(api::rest::WithLookupInterface::WithLookup(
                    api::rest::WithLookup {
                        collection_name: COLLECTION_NAME.to_string(),
                        with_payload: Some(WithPayloadInterface::Encrypted(
                            PayloadEncryptedReadPolicy {
                                encrypted_payload: EncryptedPayloadReadMode::Redacted,
                            },
                        )),
                        with_vectors: Some(WithVector::Bool(false)),
                    },
                )),
            ] {
                preflight_rest_group_lookup_private_result_oram_raw_payload_read(
                    &toc,
                    &allowed_lookup,
                    "query group lookup",
                    &auth,
                )
                .await
                .unwrap();
            }
        });
    }

    #[test]
    fn private_result_oram_raw_payload_read_selector_matrix_matches_collection_guard() {
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:result-private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "private_result_payload".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["document.body".to_string()],
                },
                instance: "docs_private_result_oram_v1".to_string(),
                binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
            }],
        };
        let protected_path = "document.body".parse::<JsonPath>().unwrap();

        let raw_read_cases = [
            WithPayloadInterface::Bool(true),
            WithPayloadInterface::Fields(vec!["document".parse().unwrap()]),
            WithPayloadInterface::Fields(vec!["document.body".parse().unwrap()]),
            WithPayloadInterface::Fields(vec!["document.body.lang".parse().unwrap()]),
            WithPayloadInterface::Selector(PayloadSelector::Include(
                segment::types::PayloadSelectorInclude::new(vec!["document".parse().unwrap()]),
            )),
            WithPayloadInterface::Selector(PayloadSelector::Include(
                segment::types::PayloadSelectorInclude::new(vec![
                    "document.body.lang".parse().unwrap(),
                ]),
            )),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(
                segment::types::PayloadSelectorExclude::new(vec![
                    "document.title".parse().unwrap(),
                ]),
            )),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(
                segment::types::PayloadSelectorExclude::new(vec![
                    "document.body.lang".parse().unwrap(),
                ]),
            )),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(
                segment::types::PayloadSelectorExclude::new(Vec::new()),
            )),
            WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                encrypted_payload: EncryptedPayloadReadMode::Raw,
            }),
            WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                encrypted_payload: EncryptedPayloadReadMode::Decrypted,
            }),
        ];

        for with_payload in raw_read_cases {
            let violation =
                private_result_oram_raw_payload_read_violation(&with_payload, &encryption).unwrap();

            assert_eq!(violation, Some("document.body"));
            assert!(private_result_oram_with_payload_touches_path(
                &with_payload,
                &protected_path
            ));
        }

        let allowed_cases = [
            WithPayloadInterface::Bool(false),
            WithPayloadInterface::Fields(vec!["document.title".parse().unwrap()]),
            WithPayloadInterface::Selector(PayloadSelector::Include(
                segment::types::PayloadSelectorInclude::new(vec![
                    "document.title".parse().unwrap(),
                ]),
            )),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(
                segment::types::PayloadSelectorExclude::new(vec!["document".parse().unwrap()]),
            )),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(
                segment::types::PayloadSelectorExclude::new(vec!["document.body".parse().unwrap()]),
            )),
            WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                encrypted_payload: EncryptedPayloadReadMode::Redacted,
            }),
        ];

        for with_payload in allowed_cases {
            let violation =
                private_result_oram_raw_payload_read_violation(&with_payload, &encryption).unwrap();

            assert_eq!(violation, None);
        }
    }

    #[test]
    fn private_result_oram_raw_payload_read_invalid_path_error_is_sanitized() {
        let secret_path = "document.body[private-result-query-secret";
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:result-private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "private_result_payload".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec![secret_path.to_string()],
                },
                instance: "docs_private_result_oram_v1".to_string(),
                binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
            }],
        };

        let err = private_result_oram_raw_payload_read_violation(
            &WithPayloadInterface::Bool(true),
            &encryption,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-query-secret"), "{err}");
        assert!(!err.contains("JsonPath"), "{err}");
    }

    #[test]
    fn private_result_oram_raw_payload_read_errors_redact_path_for_collection_read_operations() {
        for operation in [
            "search",
            "search grouped results",
            "search group lookup",
            "search results",
            "recommend results",
            "recommend grouped results",
            "recommend group lookup",
            "discover results",
            "context results",
            "retrieve",
            "scroll",
            "query",
            "query grouped results",
            "query group lookup",
            "private-result-read-operation-sentinel",
        ] {
            let message = private_result_oram_raw_payload_read_error("document.body").to_string();

            assert!(
                message.contains("cannot read private result ORAM payload field"),
                "{message}"
            );
            assert!(!message.contains(operation), "{message}");
            assert!(
                message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                "{message}"
            );
            assert!(
                message.contains("/private-result-oram/session"),
                "{message}"
            );
            assert!(
                message.contains("ordinary collection payload reads"),
                "{message}"
            );
            assert!(!message.contains("document.body"), "{message}");
            assert!(!message.contains("document"), "{message}");
            assert!(!message.contains("body"), "{message}");
        }

        for &payload_path in PRIVATE_RESULT_ORAM_PAYLOAD_ALIAS_SENTINELS {
            let message = private_result_oram_raw_payload_read_error(payload_path).to_string();
            assert!(
                message.contains("cannot read private result ORAM payload field"),
                "{message}"
            );
            assert!(message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
            assert!(message.contains("/private-result-oram/session"));
            assert!(message.contains("ordinary collection payload reads"));
            assert!(!message.contains(payload_path), "{message}");
            for &sentinel in PRIVATE_RESULT_ORAM_PAYLOAD_ALIAS_SENTINELS {
                assert!(!message.contains(sentinel), "{message}");
            }
        }
    }
}
