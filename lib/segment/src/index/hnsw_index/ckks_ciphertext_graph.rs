use std::cmp::Ordering;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, io};

use common::counter::hardware_counter::HardwareCounterCell;
use common::types::{PointOffsetType, ScoredPointOffset, TelemetryDetail};
use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};

use crate::common::operation_error::{OperationError, OperationResult};
use crate::data_types::query_context::VectorQueryContext;
use crate::data_types::vectors::{QueryVector, VectorRef};
use crate::id_tracker::IdTracker;
use crate::index::struct_payload_index::StructPayloadIndex;
use crate::index::{PayloadIndex, VectorIndex};
use crate::telemetry::VectorIndexSearchesTelemetry;
use crate::types::{Filter, Order, Payload, SearchParams};

const CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION: u8 = 2;
const CKKS_CIPHERTEXT_HNSW_GRAPH_FILE: &str = "ckks_ciphertext_hnsw_graph.json";
const CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES: u64 = 512 * 1024 * 1024;
const CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE: usize = 512;
const CKKS_CIPHERTEXT_SIDECAR_MAX_BYTES: usize = 16 * 1024 * 1024;
const CKKS_CIPHERTEXT_SIDECAR_MAX_ENCODED_BYTES: usize =
    (CKKS_CIPHERTEXT_SIDECAR_MAX_BYTES + 2) / 3 * 4;
const CKKS_CIPHERTEXT_SIDECAR_NONCE_B64_LEN: usize = 16;
pub const CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD: &str = "$qdrant_sec_vectors";
pub const CKKS_VECTOR_SIDECAR_MARKER: &str = "$qdrant_sec_ckks_vector";

#[derive(Clone)]
pub struct CkksCiphertextHnswGraph {
    links: Arc<Vec<Vec<usize>>>,
    max_degree: usize,
    kind: CkksCiphertextHnswGraphKind,
}

impl std::fmt::Debug for CkksCiphertextHnswGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksCiphertextHnswGraph")
            .field("node_count", &"[redacted]")
            .field("max_degree", &"[redacted]")
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone)]
pub struct CkksCiphertextHnswIndex<C> {
    records: Arc<Vec<C>>,
    graph: CkksCiphertextHnswGraph,
}

impl<C> std::fmt::Debug for CkksCiphertextHnswIndex<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksCiphertextHnswIndex")
            .field("record_count", &"[redacted]")
            .field("graph", &self.graph)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct CkksCiphertextHnswHit {
    pub point_index: usize,
    pub score: f32,
}

impl std::fmt::Debug for CkksCiphertextHnswHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksCiphertextHnswHit")
            .field("point_index", &"[redacted]")
            .field("score", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct CkksCiphertextHnswRecordHit<'a, C> {
    pub point_index: usize,
    pub record: &'a C,
    pub score: f32,
}

impl<C> std::fmt::Debug for CkksCiphertextHnswRecordHit<'_, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksCiphertextHnswRecordHit")
            .field("point_index", &"[redacted]")
            .field("record", &"[redacted]")
            .field("score", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CkksCiphertextIndexedRecord {
    pub point_offset: PointOffsetType,
    pub ciphertext: Vec<u8>,
    pub sidecar_identity: Vec<u8>,
}

impl std::fmt::Debug for CkksCiphertextIndexedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksCiphertextIndexedRecord")
            .field("point_offset", &"[redacted]")
            .field("ciphertext_len", &"[redacted]")
            .field("sidecar_identity_len", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CkksCiphertextHnswGraphKind {
    Similarity,
    OptimizerCandidate,
}

#[derive(Clone)]
pub struct CkksCiphertextVectorIndex {
    index: CkksCiphertextHnswIndex<CkksCiphertextIndexedRecord>,
    graph_file: Option<PathBuf>,
}

impl std::fmt::Debug for CkksCiphertextVectorIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksCiphertextVectorIndex")
            .field("index", &self.index)
            .field(
                "graph_file",
                &self.graph_file.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

#[derive(PartialEq)]
pub enum CkksCiphertextVectorIndexBuildError<E> {
    DuplicatePointOffset,
    ScoreCountMismatch { expected: usize, actual: usize },
    Scoring(E),
}

impl<E> std::fmt::Debug for CkksCiphertextVectorIndexBuildError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicatePointOffset => f.write_str("DuplicatePointOffset"),
            Self::ScoreCountMismatch { .. } => f
                .debug_struct("ScoreCountMismatch")
                .field("expected", &"[redacted]")
                .field("actual", &"[redacted]")
                .finish(),
            Self::Scoring(_) => f.debug_tuple("Scoring").field(&"[redacted]").finish(),
        }
    }
}

#[derive(PartialEq)]
pub enum CkksCiphertextScoreError<E> {
    ScoreCountMismatch { expected: usize, actual: usize },
    Scoring(E),
}

impl<E> std::fmt::Debug for CkksCiphertextScoreError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScoreCountMismatch { .. } => f
                .debug_struct("ScoreCountMismatch")
                .field("expected", &"[redacted]")
                .field("actual", &"[redacted]")
                .finish(),
            Self::Scoring(_) => f.debug_tuple("Scoring").field(&"[redacted]").finish(),
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CkksCiphertextHnswGraphFile {
    version: u8,
    graph_kind: CkksCiphertextHnswGraphKind,
    record_count: usize,
    records_digest: String,
    #[serde(default)]
    max_degree: Option<usize>,
    links: Vec<Vec<usize>>,
}

impl CkksCiphertextHnswGraph {
    pub fn from_validated_links(links: Vec<Vec<usize>>) -> Option<Self> {
        Self::from_validated_links_with_kind(links, CkksCiphertextHnswGraphKind::Similarity)
    }

    fn from_validated_links_with_kind(
        links: Vec<Vec<usize>>,
        kind: CkksCiphertextHnswGraphKind,
    ) -> Option<Self> {
        let max_degree = links.iter().map(Vec::len).max().unwrap_or(0);
        if max_degree <= CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE
            && links_have_valid_neighbors(&links)
            && links_are_reciprocal(&links)
            && links_are_connected(&links)
        {
            Some(Self {
                links: Arc::new(links),
                max_degree,
                kind,
            })
        } else {
            None
        }
    }

    pub fn links(&self) -> &[Vec<usize>] {
        self.links.as_ref()
    }

    pub fn max_degree(&self) -> usize {
        self.max_degree
    }

    pub fn kind(&self) -> CkksCiphertextHnswGraphKind {
        self.kind
    }

    pub fn is_optimizer_candidate_graph(&self) -> bool {
        self.kind == CkksCiphertextHnswGraphKind::OptimizerCandidate
    }

    pub fn links_are_reciprocal(links: &[Vec<usize>]) -> bool {
        links_are_reciprocal(links)
    }

    pub fn links_are_connected(links: &[Vec<usize>]) -> bool {
        links_are_connected(links)
    }

    pub fn add_bounded_undirected_link(
        links: &mut [Vec<usize>],
        first: usize,
        second: usize,
        max_degree: usize,
    ) {
        add_bounded_undirected_link(links, first, second, max_degree);
    }

    pub fn add_connectivity_backbone(links: &mut [Vec<usize>]) {
        add_connectivity_backbone(links);
    }

    pub fn build<E>(
        points_len: usize,
        m: usize,
        score_order: Order,
        mut score_previous_points: impl FnMut(usize) -> Result<Vec<f32>, E>,
    ) -> Result<Self, CkksCiphertextScoreError<E>> {
        let mut links = vec![Vec::<usize>::new(); points_len];
        if points_len == 0 {
            return Ok(Self {
                links: Arc::new(links),
                max_degree: 0,
                kind: CkksCiphertextHnswGraphKind::Similarity,
            });
        }

        let max_degree = pre_backbone_max_degree(m);
        for idx in 1..points_len {
            let scores = score_previous_points(idx).map_err(CkksCiphertextScoreError::Scoring)?;
            if scores.len() != idx {
                return Err(CkksCiphertextScoreError::ScoreCountMismatch {
                    expected: idx,
                    actual: scores.len(),
                });
            }
            let mut neighbors = scores
                .into_iter()
                .enumerate()
                .map(|(point_index, score)| CkksCiphertextHnswHit { point_index, score })
                .collect::<Vec<_>>();
            sort_hits(score_order, &mut neighbors);
            for neighbor in neighbors.into_iter().take(m) {
                add_bounded_undirected_link(&mut links, idx, neighbor.point_index, max_degree);
            }
        }

        add_connectivity_backbone(&mut links);
        let max_degree = links.iter().map(Vec::len).max().unwrap_or(0);
        Ok(Self {
            links: Arc::new(links),
            max_degree,
            kind: CkksCiphertextHnswGraphKind::Similarity,
        })
    }

    pub fn build_optimizer_candidate_graph(points_len: usize, m: usize) -> Self {
        let mut links = vec![Vec::<usize>::new(); points_len];
        if points_len == 0 {
            return Self {
                links: Arc::new(links),
                max_degree: 0,
                kind: CkksCiphertextHnswGraphKind::OptimizerCandidate,
            };
        }

        // Segment optimization does not own an OpenFHE scoring runtime. Build a
        // deterministic connected candidate graph here; query-time CKKS search
        // still scores visited ciphertext candidates through the runtime bridge.
        let max_degree = pre_backbone_max_degree(m);
        for idx in 1..points_len {
            let first_candidate = idx.saturating_sub(m.max(1));
            for candidate in first_candidate..idx {
                add_bounded_undirected_link(&mut links, idx, candidate, max_degree);
            }
        }

        add_connectivity_backbone(&mut links);
        let max_degree = links.iter().map(Vec::len).max().unwrap_or(0);
        Self {
            links: Arc::new(links),
            max_degree,
            kind: CkksCiphertextHnswGraphKind::OptimizerCandidate,
        }
    }

    pub fn search<E>(
        &self,
        ef: usize,
        top: usize,
        score_order: Order,
        score_threshold: Option<f32>,
        mut score_candidates: impl FnMut(&[usize]) -> Result<Vec<f32>, E>,
    ) -> Result<Vec<CkksCiphertextHnswHit>, CkksCiphertextScoreError<E>> {
        let links = self.links();
        if links.is_empty() || top == 0 {
            return Ok(Vec::new());
        }

        let mut visited = vec![false; links.len()];
        let mut frontier = vec![0usize];
        let mut scored = Vec::<CkksCiphertextHnswHit>::new();
        let score_budget = ef.max(top).max(1).min(links.len());
        let mut scored_candidates = 0usize;

        while !frontier.is_empty() && scored_candidates < score_budget {
            frontier.sort_unstable();
            frontier.dedup();
            frontier.retain(|candidate| {
                let fresh = !visited[*candidate];
                visited[*candidate] = true;
                fresh
            });
            if frontier.is_empty() {
                break;
            }
            let remaining_budget = score_budget.saturating_sub(scored_candidates);
            frontier.truncate(remaining_budget);

            let scores = score_candidates(&frontier).map_err(CkksCiphertextScoreError::Scoring)?;
            if scores.len() != frontier.len() {
                return Err(CkksCiphertextScoreError::ScoreCountMismatch {
                    expected: frontier.len(),
                    actual: scores.len(),
                });
            }
            let mut batch = frontier
                .into_iter()
                .zip(scores)
                .map(|(point_index, score)| CkksCiphertextHnswHit { point_index, score })
                .collect::<Vec<_>>();
            scored_candidates = scored_candidates.saturating_add(batch.len());
            sort_hits(score_order, &mut batch);

            frontier = Vec::new();
            for hit in batch {
                if score_passes_threshold(score_order, hit.score, score_threshold) {
                    scored.push(hit);
                }
                for neighbor in &links[hit.point_index] {
                    if !visited[*neighbor] {
                        frontier.push(*neighbor);
                    }
                }
                if scored.len() >= top && scored_candidates >= score_budget {
                    break;
                }
            }
        }

        sort_hits(score_order, &mut scored);
        scored.truncate(top);
        Ok(scored)
    }
}

impl CkksCiphertextIndexedRecord {
    pub fn new(point_offset: PointOffsetType, ciphertext: Vec<u8>) -> Self {
        Self {
            point_offset,
            sidecar_identity: ciphertext.clone(),
            ciphertext,
        }
    }

    pub fn new_with_sidecar_identity(
        point_offset: PointOffsetType,
        ciphertext: Vec<u8>,
        sidecar_identity: Vec<u8>,
    ) -> Self {
        Self {
            point_offset,
            ciphertext,
            sidecar_identity,
        }
    }
}

impl CkksCiphertextVectorIndex {
    pub fn graph_file_path(directory: impl AsRef<Path>) -> PathBuf {
        directory.as_ref().join(CKKS_CIPHERTEXT_HNSW_GRAPH_FILE)
    }

    pub fn from_graph(
        records: Vec<CkksCiphertextIndexedRecord>,
        graph: CkksCiphertextHnswGraph,
    ) -> Option<Self> {
        if !ckks_ciphertext_records_have_unique_offsets(&records) {
            return None;
        }

        CkksCiphertextHnswIndex::from_graph(records, graph).map(|index| Self {
            index,
            graph_file: None,
        })
    }

    pub fn build<E>(
        records: Vec<CkksCiphertextIndexedRecord>,
        m: usize,
        score_order: Order,
        score_previous_records: impl FnMut(
            &CkksCiphertextIndexedRecord,
            &[&CkksCiphertextIndexedRecord],
        ) -> Result<Vec<f32>, E>,
    ) -> Result<Self, CkksCiphertextVectorIndexBuildError<E>> {
        if !ckks_ciphertext_records_have_unique_offsets(&records) {
            return Err(CkksCiphertextVectorIndexBuildError::DuplicatePointOffset);
        }

        Ok(Self {
            index: CkksCiphertextHnswIndex::build(records, m, score_order, score_previous_records)
                .map_err(|err| match err {
                    CkksCiphertextScoreError::ScoreCountMismatch { expected, actual } => {
                        CkksCiphertextVectorIndexBuildError::ScoreCountMismatch { expected, actual }
                    }
                    CkksCiphertextScoreError::Scoring(err) => {
                        CkksCiphertextVectorIndexBuildError::Scoring(err)
                    }
                })?,
            graph_file: None,
        })
    }

    pub fn build_optimizer_candidate_graph(
        records: Vec<CkksCiphertextIndexedRecord>,
        m: usize,
    ) -> OperationResult<Self> {
        let graph = CkksCiphertextHnswGraph::build_optimizer_candidate_graph(records.len(), m);
        Self::from_graph(records, graph).ok_or_else(|| {
            OperationError::service_error(
                "CKKS ciphertext HNSW candidate graph records must have unique point offsets",
            )
        })
    }

    pub fn open_graph_file(
        records: Vec<CkksCiphertextIndexedRecord>,
        path: impl AsRef<Path>,
    ) -> OperationResult<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }

        let bytes = read_graph_file(path).map_err(|err| {
            OperationError::service_error(format!(
                "failed to read CKKS ciphertext HNSW graph file: {err}",
            ))
        })?;
        let graph_file: CkksCiphertextHnswGraphFile =
            serde_json::from_slice(&bytes).map_err(|err| {
                OperationError::service_error(format!(
                    "failed to parse CKKS ciphertext HNSW graph file: {err}",
                ))
            })?;

        if graph_file.version != CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION {
            return Err(OperationError::service_error(format!(
                "unsupported CKKS ciphertext HNSW graph file version {}",
                graph_file.version,
            )));
        }
        if graph_file.record_count != records.len() {
            return Ok(None);
        }
        let expected_records_digest = ckks_ciphertext_records_digest(&records);
        if graph_file.records_digest != expected_records_digest {
            return Ok(None);
        }
        let Some(max_degree) = graph_file.max_degree else {
            return Ok(None);
        };
        if max_degree > CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE {
            return Ok(None);
        }
        if graph_file
            .links
            .iter()
            .any(|neighbors| neighbors.len() > max_degree)
        {
            return Ok(None);
        }
        let Some(graph) = CkksCiphertextHnswGraph::from_validated_links_with_kind(
            graph_file.links,
            graph_file.graph_kind,
        ) else {
            return Ok(None);
        };
        let Some(mut index) = Self::from_graph(records, graph) else {
            return Ok(None);
        };
        index.graph_file = Some(path.to_path_buf());
        Ok(Some(index))
    }

    pub fn persist_graph_file(&mut self, path: impl AsRef<Path>) -> OperationResult<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                OperationError::service_error(format!(
                    "failed to create CKKS ciphertext HNSW graph directory: {err}",
                ))
            })?;
        }
        let graph_file = CkksCiphertextHnswGraphFile {
            version: CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION,
            graph_kind: self.index.graph().kind(),
            record_count: self.index.records().len(),
            records_digest: ckks_ciphertext_records_digest(self.index.records()),
            max_degree: Some(self.index.graph().max_degree()),
            links: self.index.graph().links().to_vec(),
        };
        let bytes = serde_json::to_vec(&graph_file).map_err(|err| {
            OperationError::service_error(format!(
                "failed to serialize CKKS ciphertext HNSW graph file: {err}",
            ))
        })?;
        if bytes.len() as u64 > CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES {
            return Err(OperationError::service_error(
                "CKKS ciphertext HNSW graph file exceeds maximum size",
            ));
        }
        write_graph_file(path, &bytes).map_err(|err| {
            OperationError::service_error(format!(
                "failed to write CKKS ciphertext HNSW graph file: {err}",
            ))
        })?;
        self.graph_file = Some(path.to_path_buf());
        Ok(())
    }

    pub fn search_ciphertext<E>(
        &self,
        ef: usize,
        top: usize,
        score_order: Order,
        score_threshold: Option<f32>,
        score_records: impl FnMut(&[&CkksCiphertextIndexedRecord]) -> Result<Vec<f32>, E>,
    ) -> Result<Vec<ScoredPointOffset>, CkksCiphertextScoreError<E>> {
        let hits =
            self.search_ciphertext_records(ef, top, score_order, score_threshold, score_records)?;

        Ok(hits
            .into_iter()
            .map(|hit| ScoredPointOffset {
                idx: hit.record.point_offset,
                score: hit.score,
            })
            .collect())
    }

    pub fn search_ciphertext_records<E>(
        &self,
        ef: usize,
        top: usize,
        score_order: Order,
        score_threshold: Option<f32>,
        score_records: impl FnMut(&[&CkksCiphertextIndexedRecord]) -> Result<Vec<f32>, E>,
    ) -> Result<
        Vec<CkksCiphertextHnswRecordHit<'_, CkksCiphertextIndexedRecord>>,
        CkksCiphertextScoreError<E>,
    > {
        self.index
            .search(ef, top, score_order, score_threshold, score_records)
    }

    pub fn graph(&self) -> &CkksCiphertextHnswGraph {
        self.index.graph()
    }

    pub fn records(&self) -> &[CkksCiphertextIndexedRecord] {
        self.index.records()
    }
}

pub fn ckks_ciphertext_records_from_payload_index(
    id_tracker: &dyn IdTracker,
    payload_index: &StructPayloadIndex,
    vector_name: &str,
    hw_counter: &HardwareCounterCell,
) -> OperationResult<Vec<CkksCiphertextIndexedRecord>> {
    let mut records = Vec::new();
    for point_offset in id_tracker.point_mappings().iter_internal() {
        let payload = payload_index.get_payload_sequential(point_offset, hw_counter)?;
        if let Some(record) =
            ckks_ciphertext_indexed_record_from_payload(point_offset, &payload, vector_name)?
        {
            records.push(record);
        }
    }
    Ok(records)
}

pub fn ckks_ciphertext_indexed_record_from_payload(
    point_offset: PointOffsetType,
    payload: &Payload,
    vector_name: &str,
) -> OperationResult<Option<CkksCiphertextIndexedRecord>> {
    let Some(ciphertext) = ckks_ciphertext_from_payload(payload, vector_name)? else {
        return Ok(None);
    };
    let Some(sidecar_identity) =
        ckks_ciphertext_sidecar_identity_from_payload(payload, vector_name)?
    else {
        return Ok(None);
    };
    Ok(Some(
        CkksCiphertextIndexedRecord::new_with_sidecar_identity(
            point_offset,
            ciphertext.as_bytes().to_vec(),
            sidecar_identity,
        ),
    ))
}

pub fn ckks_ciphertext_from_payload<'a>(
    payload: &'a Payload,
    vector_name: &str,
) -> OperationResult<Option<&'a str>> {
    let Some(sidecar) = payload
        .0
        .get(CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD)
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let Some(value) = sidecar.get(vector_name) else {
        return Ok(None);
    };
    let Some(marker) = value
        .as_object()
        .and_then(|object| object.get(CKKS_VECTOR_SIDECAR_MARKER))
    else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry is malformed",
        ));
    };
    let Some(marker) = marker.as_object() else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry is malformed",
        ));
    };
    if marker
        .keys()
        .find(|key| !matches!(key.as_str(), "version" | "scheme" | "envelope"))
        .is_some()
    {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has unsupported metadata field",
        ));
    }
    if marker.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has unsupported version",
        ));
    }
    if marker.get("scheme").and_then(serde_json::Value::as_str) != Some("openfhe-ckks") {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has unsupported scheme",
        ));
    }
    let Some(envelope) = marker
        .get("envelope")
        .and_then(serde_json::Value::as_object)
    else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry is missing envelope",
        ));
    };
    if envelope
        .keys()
        .find(|key| {
            !matches!(
                key.as_str(),
                "version"
                    | "algorithm"
                    | "key_id"
                    | "material_fingerprint"
                    | "rk_id"
                    | "rk_epoch"
                    | "nonce"
                    | "ciphertext"
            )
        })
        .is_some()
    {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has unsupported envelope field",
        ));
    }
    if envelope.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has unsupported envelope version",
        ));
    }
    if envelope
        .get("algorithm")
        .and_then(serde_json::Value::as_str)
        != Some("AES-256-GCM")
    {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has unsupported envelope algorithm",
        ));
    }
    for required_field in ["key_id", "material_fingerprint", "rk_id", "nonce"] {
        if envelope
            .get(required_field)
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(OperationError::service_error(format!(
                "stored CKKS vector sidecar entry is missing {required_field}",
            )));
        }
    }
    let Some(nonce) = envelope.get("nonce").and_then(serde_json::Value::as_str) else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry is missing nonce",
        ));
    };
    if nonce.len() != CKKS_CIPHERTEXT_SIDECAR_NONCE_B64_LEN {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has invalid nonce",
        ));
    }
    let nonce = BASE64URL_NOPAD.decode(nonce.as_bytes()).map_err(|_| {
        OperationError::service_error("stored CKKS vector sidecar entry has invalid nonce")
    })?;
    if nonce.len() != 12 {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has invalid nonce",
        ));
    }
    if envelope
        .get("rk_epoch")
        .and_then(serde_json::Value::as_u64)
        .is_none()
    {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry is missing rk_epoch",
        ));
    }
    let Some(ciphertext) = envelope
        .get("ciphertext")
        .and_then(serde_json::Value::as_str)
    else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry is missing ciphertext",
        ));
    };
    if ciphertext.is_empty() {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has empty ciphertext",
        ));
    }
    if ciphertext.len() > CKKS_CIPHERTEXT_SIDECAR_MAX_ENCODED_BYTES {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry exceeds maximum ciphertext size",
        ));
    }
    let ciphertext_bytes = BASE64URL_NOPAD.decode(ciphertext.as_bytes()).map_err(|_| {
        OperationError::service_error("stored CKKS vector sidecar entry has invalid ciphertext")
    })?;
    if ciphertext_bytes.len() > CKKS_CIPHERTEXT_SIDECAR_MAX_BYTES {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry exceeds maximum ciphertext size",
        ));
    }
    if ciphertext_bytes.len() < 16 {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has invalid ciphertext",
        ));
    }
    Ok(Some(ciphertext))
}

fn ckks_ciphertext_sidecar_identity_from_payload(
    payload: &Payload,
    vector_name: &str,
) -> OperationResult<Option<Vec<u8>>> {
    let Some(ciphertext) = ckks_ciphertext_from_payload(payload, vector_name)? else {
        return Ok(None);
    };
    let Some(marker) = payload
        .0
        .get(CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD)
        .and_then(serde_json::Value::as_object)
        .and_then(|sidecar| sidecar.get(vector_name))
        .and_then(serde_json::Value::as_object)
        .and_then(|value| value.get(CKKS_VECTOR_SIDECAR_MARKER))
        .and_then(serde_json::Value::as_object)
    else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry is malformed",
        ));
    };
    let Some(envelope) = marker
        .get("envelope")
        .and_then(serde_json::Value::as_object)
    else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry is missing envelope",
        ));
    };

    let mut digest = Sha256::new();
    digest.update(b"qdrant-sec/ckks-ciphertext-sidecar-identity/v1");
    update_digest_str(&mut digest, vector_name);
    let Some(marker_version) = marker.get("version").and_then(serde_json::Value::as_u64) else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has unsupported version",
        ));
    };
    update_digest_u64(&mut digest, marker_version);
    let Some(marker_scheme) = marker.get("scheme").and_then(serde_json::Value::as_str) else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has unsupported scheme",
        ));
    };
    update_digest_str(&mut digest, marker_scheme);
    let Some(envelope_version) = envelope.get("version").and_then(serde_json::Value::as_u64) else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry has unsupported envelope version",
        ));
    };
    update_digest_u64(&mut digest, envelope_version);
    for field in [
        "algorithm",
        "key_id",
        "material_fingerprint",
        "rk_id",
        "nonce",
    ] {
        let Some(value) = envelope.get(field).and_then(serde_json::Value::as_str) else {
            return Err(OperationError::service_error(format!(
                "stored CKKS vector sidecar entry is missing {field}",
            )));
        };
        update_digest_str(&mut digest, value);
    }
    let Some(rk_epoch) = envelope.get("rk_epoch").and_then(serde_json::Value::as_u64) else {
        return Err(OperationError::service_error(
            "stored CKKS vector sidecar entry is missing rk_epoch",
        ));
    };
    update_digest_u64(&mut digest, rk_epoch);
    update_digest_str(&mut digest, ciphertext);
    Ok(Some(digest.finalize().to_vec()))
}

impl<C> CkksCiphertextHnswIndex<C> {
    pub fn from_graph(records: Vec<C>, graph: CkksCiphertextHnswGraph) -> Option<Self> {
        (records.len() == graph.links().len()).then(|| Self {
            records: Arc::new(records),
            graph,
        })
    }

    pub fn build<E>(
        records: Vec<C>,
        m: usize,
        score_order: Order,
        mut score_previous_records: impl FnMut(&C, &[&C]) -> Result<Vec<f32>, E>,
    ) -> Result<Self, CkksCiphertextScoreError<E>> {
        let graph = CkksCiphertextHnswGraph::build(records.len(), m, score_order, |idx| {
            let candidates = records[..idx].iter().collect::<Vec<_>>();
            score_previous_records(&records[idx], &candidates)
        })?;

        Ok(Self {
            records: Arc::new(records),
            graph,
        })
    }

    pub fn records(&self) -> &[C] {
        self.records.as_ref()
    }

    pub fn graph(&self) -> &CkksCiphertextHnswGraph {
        &self.graph
    }

    pub fn search<E>(
        &self,
        ef: usize,
        top: usize,
        score_order: Order,
        score_threshold: Option<f32>,
        mut score_records: impl FnMut(&[&C]) -> Result<Vec<f32>, E>,
    ) -> Result<Vec<CkksCiphertextHnswRecordHit<'_, C>>, CkksCiphertextScoreError<E>> {
        let hits = self
            .graph
            .search(ef, top, score_order, score_threshold, |candidates| {
                let records = candidates
                    .iter()
                    .map(|candidate| &self.records[*candidate])
                    .collect::<Vec<_>>();
                score_records(&records)
            })?;

        Ok(hits
            .into_iter()
            .map(|hit| CkksCiphertextHnswRecordHit {
                point_index: hit.point_index,
                record: &self.records[hit.point_index],
                score: hit.score,
            })
            .collect())
    }
}

impl VectorIndex for CkksCiphertextVectorIndex {
    fn search(
        &self,
        vectors: &[&QueryVector],
        _filter: Option<&Filter>,
        _top: usize,
        _params: Option<&SearchParams>,
        _query_context: &VectorQueryContext,
    ) -> OperationResult<Vec<Vec<ScoredPointOffset>>> {
        Err(OperationError::validation_error(format!(
            "CKKS ciphertext HNSW index does not accept plaintext QueryVector search requests; received {} query vector(s)",
            vectors.len(),
        )))
    }

    fn get_telemetry_data(&self, _detail: TelemetryDetail) -> VectorIndexSearchesTelemetry {
        VectorIndexSearchesTelemetry::default()
    }

    fn files(&self) -> Vec<PathBuf> {
        self.graph_file.iter().cloned().collect()
    }

    fn immutable_files(&self) -> Vec<PathBuf> {
        self.files()
    }

    fn indexed_vector_count(&self) -> usize {
        self.index.records().len()
    }

    fn size_of_searchable_vectors_in_bytes(&self) -> usize {
        self.index
            .records()
            .iter()
            .map(|record| record.ciphertext.len())
            .sum()
    }

    fn update_vector(
        &mut self,
        _id: PointOffsetType,
        _vector: Option<VectorRef>,
        _hw_counter: &HardwareCounterCell,
    ) -> OperationResult<()> {
        Err(OperationError::validation_error(
            "CKKS ciphertext HNSW index cannot be updated with plaintext vectors",
        ))
    }
}

fn add_bounded_undirected_link(
    links: &mut [Vec<usize>],
    first: usize,
    second: usize,
    max_degree: usize,
) {
    if first == second {
        return;
    }
    add_bounded_directed_link(links, first, second, max_degree);
    add_bounded_directed_link(links, second, first, max_degree);
}

fn add_bounded_directed_link(links: &mut [Vec<usize>], from: usize, to: usize, max_degree: usize) {
    let removed = {
        let neighbors = &mut links[from];
        if neighbors.contains(&to) {
            return;
        }
        neighbors.push(to);
        if neighbors.len() <= max_degree {
            return;
        }
        neighbors.remove(0)
    };
    links[removed].retain(|neighbor| *neighbor != from);
}

fn add_unbounded_undirected_link(links: &mut [Vec<usize>], first: usize, second: usize) {
    if first == second {
        return;
    }
    if !links[first].contains(&second) {
        links[first].push(second);
    }
    if !links[second].contains(&first) {
        links[second].push(first);
    }
}

fn add_connectivity_backbone(links: &mut [Vec<usize>]) {
    for idx in 1..links.len() {
        add_unbounded_undirected_link(links, idx - 1, idx);
    }
}

fn pre_backbone_max_degree(m: usize) -> usize {
    m.saturating_mul(2)
        .max(1)
        .min(CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE.saturating_sub(2))
}

fn write_graph_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary_path = path.with_extension("json.tmp");
    write_private_graph_file(&temporary_path, bytes)?;
    fs::rename(&temporary_path, path)?;
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    sync_graph_parent_directory(path)?;
    Ok(())
}

fn read_graph_file(path: &Path) -> io::Result<Vec<u8>> {
    validate_private_graph_parent(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "graph file must be a regular non-symlink file",
        ));
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "graph file must be a regular non-symlink file",
        ));
    }
    if metadata.len() > CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "graph file is too large: {} bytes exceeds {} bytes",
                metadata.len(),
                CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES
            ),
        ));
    }
    validate_private_graph_file_metadata(path, &metadata)?;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "opened graph file must be a regular file",
        ));
    }
    if opened_metadata.len() > CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "graph file is too large: {} bytes exceeds {} bytes",
                opened_metadata.len(),
                CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES
            ),
        ));
    }
    validate_private_graph_file_metadata(path, &opened_metadata)?;

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    let mut limited_file = file.take(CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES + 1);
    limited_file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "graph file is too large: {} bytes exceeds {} bytes",
                bytes.len(),
                CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES
            ),
        ));
    }
    Ok(bytes)
}

fn write_private_graph_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    validate_private_graph_parent(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "graph file must not be a symlink",
        ));
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(path, PermissionsExt::from_mode(0o600))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

fn validate_private_graph_file_metadata(_path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "graph file must not be group/world accessible",
            ));
        }

        let owner = metadata.uid();
        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if owner != 0 && owner != effective_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "graph file must be owned by root or the Qdrant process user",
            ));
        }
    }

    Ok(())
}

fn validate_private_graph_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = nix::unistd::Uid::effective().as_raw();
        let direct_parent = path.parent();
        let mut parent = direct_parent;
        while let Some(directory) = parent {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "graph file parent must be a directory",
                ));
            }
            let owner = metadata.uid();
            if owner != 0 && owner != effective_uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "graph file parent must be owned by root or the Qdrant process user",
                ));
            }
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 {
                let sticky_ancestor = Some(directory) != direct_parent && mode & 0o1000 != 0;
                if sticky_ancestor {
                    parent = directory.parent();
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "graph file parent must not be group/world writable",
                ));
            }
            parent = directory.parent();
        }
    }

    Ok(())
}

fn sync_graph_parent_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let Some(parent) = path.parent() else {
            return Ok(());
        };
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(parent)?;
        directory.sync_all()?;
    }

    Ok(())
}

fn ckks_ciphertext_records_digest(records: &[CkksCiphertextIndexedRecord]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"qdrant-sec/ckks-ciphertext-hnsw-records/v1");
    for record in records {
        digest.update(record.point_offset.to_le_bytes());
        digest.update((record.sidecar_identity.len() as u64).to_le_bytes());
        digest.update(&record.sidecar_identity);
    }
    BASE64URL_NOPAD.encode(&digest.finalize())
}

fn update_digest_str(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value.as_bytes());
}

fn update_digest_u64(digest: &mut Sha256, value: u64) {
    digest.update(value.to_le_bytes());
}

fn ckks_ciphertext_records_have_unique_offsets(records: &[CkksCiphertextIndexedRecord]) -> bool {
    let mut point_offsets = records
        .iter()
        .map(|record| record.point_offset)
        .collect::<Vec<_>>();
    point_offsets.sort_unstable();
    !point_offsets
        .windows(2)
        .any(|window| window[0] == window[1])
}

fn links_have_valid_neighbors(links: &[Vec<usize>]) -> bool {
    links.iter().enumerate().all(|(from, neighbors)| {
        let mut unique_neighbors = std::collections::HashSet::with_capacity(neighbors.len());
        neighbors.iter().all(|neighbor| {
            *neighbor < links.len() && *neighbor != from && unique_neighbors.insert(*neighbor)
        })
    })
}

fn links_are_reciprocal(links: &[Vec<usize>]) -> bool {
    links.iter().enumerate().all(|(from, neighbors)| {
        neighbors
            .iter()
            .all(|neighbor| links[*neighbor].iter().any(|candidate| *candidate == from))
    })
}

fn links_are_connected(links: &[Vec<usize>]) -> bool {
    if links.is_empty() {
        return true;
    }

    let mut visited = vec![false; links.len()];
    let mut stack = vec![0usize];
    while let Some(idx) = stack.pop() {
        if visited[idx] {
            continue;
        }
        visited[idx] = true;
        for neighbor in &links[idx] {
            if !visited[*neighbor] {
                stack.push(*neighbor);
            }
        }
    }

    visited.into_iter().all(|seen| seen)
}

fn score_passes_threshold(order: Order, score: f32, score_threshold: Option<f32>) -> bool {
    score_threshold.is_none_or(|threshold| match order {
        Order::LargeBetter => score > threshold,
        Order::SmallBetter => score < threshold,
    })
}

fn sort_hits(order: Order, hits: &mut [CkksCiphertextHnswHit]) {
    hits.sort_unstable_by(|first, second| compare_hits(order, first, second));
}

fn compare_hits(
    order: Order,
    first: &CkksCiphertextHnswHit,
    second: &CkksCiphertextHnswHit,
) -> Ordering {
    let score_order = first
        .score
        .total_cmp(&second.score)
        .then_with(|| first.point_index.cmp(&second.point_index));
    match order {
        Order::LargeBetter => score_order.reverse(),
        Order::SmallBetter => score_order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::vector_index_base::VectorIndexEnum;

    fn graph_test_directory() -> tempfile::TempDir {
        // macOS exposes its default temporary directory through a symlinked ancestor.
        tempfile::Builder::new()
            .prefix("ckks-graph-path-sentinel-")
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap()
    }

    #[test]
    fn ckks_ciphertext_debug_redacts_graph_records_and_scores() {
        let record = CkksCiphertextIndexedRecord::new_with_sidecar_identity(
            12_345,
            b"CKKS-CIPHERTEXT-SENTINEL".to_vec(),
            b"CKKS-SIDECAR-SENTINEL".to_vec(),
        );
        let other_record =
            CkksCiphertextIndexedRecord::new(12_346, b"CKKS-OTHER-SENTINEL".to_vec());
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]])
            .expect("test graph must be valid");
        let index = CkksCiphertextHnswIndex::from_graph(
            vec![record.clone(), other_record.clone()],
            graph.clone(),
        )
        .expect("test index must match graph size");
        let vector_index = CkksCiphertextVectorIndex::from_graph(
            vec![record.clone(), other_record],
            graph.clone(),
        )
        .expect("test vector index must match graph size");
        let hit = CkksCiphertextHnswHit {
            point_index: 7,
            score: 42.125,
        };
        let record_hit = CkksCiphertextHnswRecordHit {
            point_index: 7,
            record: &record,
            score: 42.125,
        };

        for rendered in [
            format!("{record:?}"),
            format!("{graph:?}"),
            format!("{index:?}"),
            format!("{vector_index:?}"),
            format!("{hit:?}"),
            format!("{record_hit:?}"),
        ] {
            assert!(rendered.contains("[redacted]"), "{rendered}");
            assert!(!rendered.contains("CKKS-CIPHERTEXT-SENTINEL"), "{rendered}");
            assert!(!rendered.contains("CKKS-SIDECAR-SENTINEL"), "{rendered}");
            assert!(!rendered.contains("CKKS-OTHER-SENTINEL"), "{rendered}");
            assert!(!rendered.contains("12345"), "{rendered}");
            assert!(!rendered.contains("point_index: 7"), "{rendered}");
            assert!(!rendered.contains("42.125"), "{rendered}");
        }
    }

    #[test]
    fn ckks_ciphertext_error_debug_redacts_scoring_details() {
        let build_scoring = CkksCiphertextVectorIndexBuildError::Scoring(
            "CKKS-BUILD-SCORING-ERROR-SENTINEL".to_string(),
        );
        let build_count = CkksCiphertextVectorIndexBuildError::<String>::ScoreCountMismatch {
            expected: 777,
            actual: 333,
        };
        let score_scoring =
            CkksCiphertextScoreError::Scoring("CKKS-SCORE-ERROR-SENTINEL".to_string());
        let score_count = CkksCiphertextScoreError::<String>::ScoreCountMismatch {
            expected: 777,
            actual: 333,
        };

        for rendered in [
            format!("{build_scoring:?}"),
            format!("{build_count:?}"),
            format!("{score_scoring:?}"),
            format!("{score_count:?}"),
        ] {
            assert!(rendered.contains("[redacted]"), "{rendered}");
            assert!(
                !rendered.contains("CKKS-BUILD-SCORING-ERROR-SENTINEL"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("CKKS-SCORE-ERROR-SENTINEL"),
                "{rendered}"
            );
            assert!(!rendered.contains("777"), "{rendered}");
            assert!(!rendered.contains("333"), "{rendered}");
        }
    }

    #[test]
    fn bounded_links_remain_reciprocal_when_pruned() {
        let mut links = vec![Vec::<usize>::new(); 4];
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 1, 0, 2);
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 2, 0, 2);
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 3, 0, 2);

        assert_eq!(links[0], vec![2, 3]);
        assert!(!links[1].contains(&0));
        assert!(!links[0].contains(&1));
        assert!(links[2].contains(&0));
        assert!(links[3].contains(&0));
        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(&links));
    }

    #[test]
    fn connectivity_backbone_restores_pruned_graph() {
        let mut links = vec![Vec::<usize>::new(); 4];
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 1, 0, 2);
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 2, 0, 2);
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 3, 0, 2);

        assert!(!CkksCiphertextHnswGraph::links_are_connected(&links));
        CkksCiphertextHnswGraph::add_connectivity_backbone(&mut links);

        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(&links));
        assert!(CkksCiphertextHnswGraph::links_are_connected(&links));
    }

    #[test]
    fn rejects_invalid_cached_links() {
        assert!(CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], Vec::new()]).is_none());
        assert!(CkksCiphertextHnswGraph::from_validated_links(vec![vec![2], vec![0]]).is_none());
        assert!(CkksCiphertextHnswGraph::from_validated_links(vec![vec![0], Vec::new()]).is_none());
    }

    #[test]
    fn builds_graph_from_ciphertext_pairwise_scores() {
        let values = [0.0_f32, 0.2, 0.8, 1.0];
        let graph = CkksCiphertextHnswGraph::build(
            values.len(),
            1,
            Order::SmallBetter,
            |idx| -> Result<Vec<f32>, std::convert::Infallible> {
                Ok((0..idx)
                    .map(|candidate| (values[idx] - values[candidate]).abs())
                    .collect())
            },
        )
        .unwrap();

        assert_eq!(graph.kind(), CkksCiphertextHnswGraphKind::Similarity);
        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(graph.links()));
        assert!(CkksCiphertextHnswGraph::links_are_connected(graph.links()));
        assert!(graph.links()[1].contains(&0));
        assert!(graph.links()[2].contains(&1));
        assert!(graph.links()[3].contains(&2));
    }

    #[test]
    fn builds_optimizer_candidate_graph_without_scoring_runtime() {
        let graph = CkksCiphertextHnswGraph::build_optimizer_candidate_graph(5, 2);

        assert_eq!(
            graph.kind(),
            CkksCiphertextHnswGraphKind::OptimizerCandidate
        );
        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(graph.links()));
        assert!(CkksCiphertextHnswGraph::links_are_connected(graph.links()));
        assert!(graph.links()[0].contains(&1));
        assert!(graph.links()[4].contains(&3));
    }

    #[test]
    fn built_graphs_respect_max_degree_after_connectivity_backbone() {
        let graph = CkksCiphertextHnswGraph::build(
            CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE + 4,
            usize::MAX,
            Order::SmallBetter,
            |idx| -> Result<Vec<f32>, std::convert::Infallible> {
                Ok((0..idx).map(|candidate| (idx - candidate) as f32).collect())
            },
        )
        .unwrap();

        assert!(
            graph.max_degree() <= CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE,
            "similarity graph degree {} exceeded max {}",
            graph.max_degree(),
            CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE
        );
        assert!(CkksCiphertextHnswGraph::from_validated_links(graph.links().to_vec()).is_some());

        let candidate_graph = CkksCiphertextHnswGraph::build_optimizer_candidate_graph(
            CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE + 4,
            usize::MAX,
        );

        assert!(
            candidate_graph.max_degree() <= CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE,
            "candidate graph degree {} exceeded max {}",
            candidate_graph.max_degree(),
            CKKS_CIPHERTEXT_HNSW_GRAPH_MAX_DEGREE
        );
        assert!(
            CkksCiphertextHnswGraph::from_validated_links(candidate_graph.links().to_vec())
                .is_some()
        );
    }

    #[test]
    fn searches_graph_with_query_scorer() {
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![
            vec![1],
            vec![0, 2],
            vec![1, 3],
            vec![2],
        ])
        .unwrap();
        let values = [0.0_f32, 0.2, 0.8, 1.0];
        let query = 0.9_f32;

        let results = graph
            .search(
                4,
                2,
                Order::SmallBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| (query - values[*candidate]).abs())
                        .collect())
                },
            )
            .unwrap();

        assert_eq!(
            results
                .iter()
                .map(|hit| hit.point_index)
                .collect::<Vec<_>>(),
            vec![2, 3],
        );
    }

    #[test]
    fn search_counts_threshold_filtered_candidates_against_ef_budget() {
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![
            vec![1],
            vec![0, 2],
            vec![1, 3],
            vec![2],
        ])
        .unwrap();
        let mut scored_candidates = 0usize;

        let results = graph
            .search(
                2,
                2,
                Order::SmallBetter,
                Some(-1.0),
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    scored_candidates += candidates.len();
                    Ok(vec![1.0; candidates.len()])
                },
            )
            .unwrap();

        assert!(results.is_empty());
        assert_eq!(
            scored_candidates, 2,
            "threshold-filtered candidates must still consume the ef scoring budget",
        );
    }

    #[test]
    fn search_truncates_high_degree_frontier_to_remaining_ef_budget() {
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![
            vec![1, 2, 3, 4],
            vec![0],
            vec![0],
            vec![0],
            vec![0],
        ])
        .unwrap();
        let mut max_batch = 0usize;
        let mut scored_candidates = 0usize;

        let _results = graph
            .search(
                2,
                2,
                Order::LargeBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    max_batch = max_batch.max(candidates.len());
                    scored_candidates += candidates.len();
                    Ok(vec![1.0; candidates.len()])
                },
            )
            .unwrap();

        assert_eq!(scored_candidates, 2);
        assert!(
            max_batch <= 1,
            "high-degree frontier batches must be truncated before bridge scoring",
        );
    }

    #[test]
    fn index_rejects_graph_record_count_mismatch() {
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap();

        assert!(CkksCiphertextHnswIndex::from_graph(vec!["a"], graph).is_none());
    }

    #[test]
    fn ciphertext_vector_index_rejects_duplicate_record_offsets() {
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap();

        assert!(
            CkksCiphertextVectorIndex::from_graph(
                vec![
                    CkksCiphertextIndexedRecord::new(7, b"ciphertext-a".to_vec()),
                    CkksCiphertextIndexedRecord::new(7, b"ciphertext-b".to_vec()),
                ],
                graph,
            )
            .is_none()
        );
    }

    #[test]
    fn index_builds_and_searches_ciphertext_records() {
        #[derive(Clone, Debug, PartialEq)]
        struct CiphertextRecord {
            ciphertext: &'static str,
            clear_fixture: f32,
        }

        let records = vec![
            CiphertextRecord {
                ciphertext: "ct-0",
                clear_fixture: 0.0,
            },
            CiphertextRecord {
                ciphertext: "ct-1",
                clear_fixture: 0.2,
            },
            CiphertextRecord {
                ciphertext: "ct-2",
                clear_fixture: 0.8,
            },
            CiphertextRecord {
                ciphertext: "ct-3",
                clear_fixture: 1.0,
            },
        ];
        let index = CkksCiphertextHnswIndex::build(
            records,
            1,
            Order::SmallBetter,
            |record, candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                assert!(record.ciphertext.starts_with("ct-"));
                Ok(candidates
                    .iter()
                    .map(|candidate| (record.clear_fixture - candidate.clear_fixture).abs())
                    .collect())
            },
        )
        .unwrap();

        let query = 0.9_f32;
        let results = index
            .search(
                4,
                2,
                Order::SmallBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| {
                            assert!(candidate.ciphertext.starts_with("ct-"));
                            (query - candidate.clear_fixture).abs()
                        })
                        .collect())
                },
            )
            .unwrap();

        assert_eq!(
            results
                .iter()
                .map(|hit| (hit.point_index, hit.record.ciphertext))
                .collect::<Vec<_>>(),
            vec![(2, "ct-2"), (3, "ct-3")],
        );
        assert!(CkksCiphertextHnswGraph::links_are_connected(
            index.graph().links()
        ));
    }

    #[test]
    fn vector_index_enum_exposes_ciphertext_hnsw_stats() {
        let index = CkksCiphertextVectorIndex::build(
            vec![
                CkksCiphertextIndexedRecord::new(10, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(11, b"ciphertext-b".to_vec()),
            ],
            1,
            Order::LargeBetter,
            |record, candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                Ok(candidates
                    .iter()
                    .map(|candidate| {
                        if record.ciphertext > candidate.ciphertext {
                            1.0
                        } else {
                            0.0
                        }
                    })
                    .collect())
            },
        )
        .unwrap();

        let results = index
            .search_ciphertext(
                2,
                1,
                Order::LargeBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| {
                            if candidate.ciphertext == b"ciphertext-b" {
                                10.0
                            } else {
                                1.0
                            }
                        })
                        .collect())
                },
            )
            .unwrap();
        assert_eq!(
            results,
            vec![ScoredPointOffset {
                idx: 11,
                score: 10.0
            }]
        );

        let enum_index = VectorIndexEnum::CkksCiphertextHnsw(index);
        assert!(enum_index.is_index());
        assert!(!enum_index.is_on_disk());
        assert_eq!(enum_index.indexed_vectors(), 2);
        assert_eq!(VectorIndex::indexed_vector_count(&enum_index), 2);
        assert_eq!(
            VectorIndex::size_of_searchable_vectors_in_bytes(&enum_index),
            b"ciphertext-a".len() + b"ciphertext-b".len(),
        );
        enum_index.populate().unwrap();
        enum_index.clear_cache().unwrap();
    }

    #[test]
    fn vector_index_builds_optimizer_candidate_graph() {
        let index = CkksCiphertextVectorIndex::build_optimizer_candidate_graph(
            vec![
                CkksCiphertextIndexedRecord::new(10, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(11, b"ciphertext-b".to_vec()),
                CkksCiphertextIndexedRecord::new(12, b"ciphertext-c".to_vec()),
            ],
            2,
        )
        .unwrap();

        assert_eq!(index.indexed_vector_count(), 3);
        assert_eq!(index.records()[1].point_offset, 11);
        assert_eq!(index.records()[1].ciphertext, b"ciphertext-b");
        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(
            index.graph().links()
        ));
        assert!(CkksCiphertextHnswGraph::links_are_connected(
            index.graph().links()
        ));
    }

    #[test]
    fn vector_index_rejects_duplicate_optimizer_candidate_record_offsets() {
        let err = CkksCiphertextVectorIndex::build_optimizer_candidate_graph(
            vec![
                CkksCiphertextIndexedRecord::new(10, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(10, b"ciphertext-b".to_vec()),
            ],
            1,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("unique point offsets"),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn ciphertext_vector_index_rejects_plaintext_vector_index_search_api() {
        let index = CkksCiphertextVectorIndex::build_optimizer_candidate_graph(
            vec![CkksCiphertextIndexedRecord::new(
                10,
                b"ciphertext-a".to_vec(),
            )],
            1,
        )
        .unwrap();
        let query = QueryVector::Nearest(crate::data_types::vectors::VectorInternal::Dense(vec![
            0.1, 0.2,
        ]));

        let err = VectorIndex::search(
            &index,
            &[&query],
            None,
            1,
            None,
            &VectorQueryContext::default(),
        )
        .expect_err("ciphertext index must reject plaintext VectorIndex search API");

        assert!(
            err.to_string()
                .contains("does not accept plaintext QueryVector search requests"),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn ciphertext_vector_index_rejects_plaintext_vector_update_api() {
        let mut index = CkksCiphertextVectorIndex::build_optimizer_candidate_graph(
            vec![CkksCiphertextIndexedRecord::new(
                10,
                b"ciphertext-a".to_vec(),
            )],
            1,
        )
        .unwrap();
        let vector = vec![1.0];

        let err = index
            .update_vector(
                10,
                Some(VectorRef::from(&vector)),
                &HardwareCounterCell::disposable(),
            )
            .expect_err("ciphertext index must reject plaintext vector updates");
        assert!(
            err.to_string()
                .contains("cannot be updated with plaintext vectors"),
            "unexpected error: {err:?}",
        );

        let err = index
            .update_vector(10, None, &HardwareCounterCell::disposable())
            .expect_err("ciphertext index must reject plaintext vector deletions");
        assert!(
            err.to_string()
                .contains("cannot be updated with plaintext vectors"),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn ciphertext_vector_index_can_reopen_from_valid_graph() {
        let records = vec![
            CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
            CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
        ];
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]])
            .expect("valid reciprocal graph");

        let index = CkksCiphertextVectorIndex::from_graph(records, graph)
            .expect("record count matches graph nodes");

        let results = index
            .search_ciphertext(
                2,
                1,
                Order::LargeBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| {
                            if candidate.point_offset == 1 {
                                3.0
                            } else {
                                1.0
                            }
                        })
                        .collect())
                },
            )
            .unwrap();

        assert_eq!(results[0].idx, 1);
        assert_eq!(results[0].score, 3.0);
    }

    #[test]
    fn ciphertext_vector_index_build_rejects_duplicate_record_offsets() {
        let err = CkksCiphertextVectorIndex::build(
            vec![
                CkksCiphertextIndexedRecord::new(9, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(9, b"ciphertext-b".to_vec()),
            ],
            1,
            Order::LargeBetter,
            |_record, _candidates| -> Result<Vec<f32>, std::convert::Infallible> { Ok(Vec::new()) },
        )
        .expect_err("build must reject duplicate point offsets");

        assert_eq!(
            err,
            CkksCiphertextVectorIndexBuildError::DuplicatePointOffset,
        );
    }

    #[test]
    fn ciphertext_vector_index_build_rejects_score_count_mismatch() {
        let err = CkksCiphertextVectorIndex::build(
            vec![
                CkksCiphertextIndexedRecord::new(7, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(8, b"ciphertext-b".to_vec()),
            ],
            1,
            Order::LargeBetter,
            |_record, _candidates| -> Result<Vec<f32>, std::convert::Infallible> { Ok(Vec::new()) },
        )
        .expect_err("build must reject bridge score count mismatch");

        assert_eq!(
            err,
            CkksCiphertextVectorIndexBuildError::ScoreCountMismatch {
                expected: 1,
                actual: 0,
            },
        );
    }

    #[test]
    fn ciphertext_vector_index_exposes_segment_record_hits() {
        let graph =
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0, 2], vec![1]])
                .expect("valid reciprocal graph");
        let index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(42, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(43, b"ciphertext-b".to_vec()),
                CkksCiphertextIndexedRecord::new(44, b"ciphertext-c".to_vec()),
            ],
            graph,
        )
        .expect("record count matches graph nodes");

        let hits = index
            .search_ciphertext_records(
                3,
                2,
                Order::LargeBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| match candidate.point_offset {
                            42 => 0.1,
                            43 => 0.9,
                            44 => 0.7,
                            other => panic!("unexpected candidate offset {other}"),
                        })
                        .collect())
                },
            )
            .unwrap();

        assert_eq!(
            hits.iter()
                .map(|hit| (hit.point_index, hit.record.point_offset, hit.score))
                .collect::<Vec<_>>(),
            vec![(1, 43, 0.9), (2, 44, 0.7)],
        );
        assert_eq!(hits[0].record.ciphertext, b"ciphertext-b");
    }

    #[test]
    fn ciphertext_vector_index_search_rejects_score_count_mismatch() {
        let graph =
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0, 2], vec![1]])
                .expect("valid reciprocal graph");
        let index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(42, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(43, b"ciphertext-b".to_vec()),
                CkksCiphertextIndexedRecord::new(44, b"ciphertext-c".to_vec()),
            ],
            graph,
        )
        .expect("record count matches graph nodes");

        let err = index
            .search_ciphertext_records(
                3,
                2,
                Order::LargeBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(vec![1.0; candidates.len().saturating_sub(1)])
                },
            )
            .expect_err("search must reject bridge score count mismatch");

        assert_eq!(
            err,
            CkksCiphertextScoreError::ScoreCountMismatch {
                expected: 1,
                actual: 0,
            },
        );
    }

    #[test]
    fn ciphertext_vector_index_persists_graph_as_index_file() {
        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::build(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            1,
            Order::LargeBetter,
            |record, candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                Ok(candidates
                    .iter()
                    .map(|candidate| {
                        if record.ciphertext > candidate.ciphertext {
                            1.0
                        } else {
                            0.0
                        }
                    })
                    .collect())
            },
        )
        .unwrap();

        index.persist_graph_file(&graph_file).unwrap();

        assert_eq!(index.files(), vec![graph_file.clone()]);
        assert_eq!(index.immutable_files(), vec![graph_file.clone()]);
        assert!(graph_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&graph_file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let reopened = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap()
        .expect("persisted graph should reopen");

        assert_eq!(reopened.files(), vec![graph_file]);
        assert_eq!(reopened.immutable_files(), reopened.files());
        assert_eq!(reopened.graph().links(), index.graph().links());
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_group_accessible_graph_file() {
        use std::os::unix::fs::PermissionsExt;

        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();
        index.persist_graph_file(&graph_file).unwrap();
        std::fs::set_permissions(&graph_file, PermissionsExt::from_mode(0o640)).unwrap();

        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(err.to_string().contains("group/world accessible"));
        assert_ciphertext_graph_file_error_redacts_paths(&err);
    }

    #[test]
    fn ciphertext_vector_index_rejects_oversized_graph_file() {
        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&graph_file)
            .unwrap();
        file.set_len(CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES + 1)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&graph_file, PermissionsExt::from_mode(0o600)).unwrap();
        }

        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(err.to_string().contains("graph file is too large"));
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_graph_symlink_on_open() {
        use std::os::unix::fs::symlink;

        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let target_file = directory.path().join("graph-target");
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();
        index.persist_graph_file(&target_file).unwrap();
        symlink(&target_file, &graph_file).unwrap();

        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(err.to_string().contains("regular non-symlink file"));
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_temp_graph_symlink_on_persist() {
        use std::os::unix::fs::symlink;

        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let temp_graph_file = graph_file.with_extension("json.tmp");
        let external_file = directory.path().join("external-target");
        std::fs::write(&external_file, b"do-not-overwrite").unwrap();
        symlink(&external_file, &temp_graph_file).unwrap();

        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();

        let err = index.persist_graph_file(&graph_file).unwrap_err();

        assert!(err.to_string().contains("must not be a symlink"));
        assert_eq!(std::fs::read(&external_file).unwrap(), b"do-not-overwrite");
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_writable_graph_parent() {
        use std::os::unix::fs::PermissionsExt;

        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();

        std::fs::set_permissions(directory.path(), PermissionsExt::from_mode(0o777)).unwrap();
        let err = index.persist_graph_file(&graph_file).unwrap_err();
        assert!(err.to_string().contains("must not be group/world writable"));
        assert_ciphertext_graph_file_error_redacts_paths(&err);

        std::fs::set_permissions(directory.path(), PermissionsExt::from_mode(0o700)).unwrap();
        index.persist_graph_file(&graph_file).unwrap();

        std::fs::set_permissions(directory.path(), PermissionsExt::from_mode(0o777)).unwrap();
        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(err.to_string().contains("must not be group/world writable"));
        assert_ciphertext_graph_file_error_redacts_paths(&err);
        std::fs::set_permissions(directory.path(), PermissionsExt::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_writable_graph_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let directory = graph_test_directory();
        let ancestor = directory.path().join("writable-ancestor");
        let direct_parent = ancestor.join("graph-parent");
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::create_dir(&direct_parent).unwrap();
        std::fs::set_permissions(&ancestor, PermissionsExt::from_mode(0o722)).unwrap();
        std::fs::set_permissions(&direct_parent, PermissionsExt::from_mode(0o700)).unwrap();

        let graph_file = CkksCiphertextVectorIndex::graph_file_path(&direct_parent);
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();

        let err = index.persist_graph_file(&graph_file).unwrap_err();
        assert!(err.to_string().contains("must not be group/world writable"));

        std::fs::set_permissions(&ancestor, PermissionsExt::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_symlink_graph_parent() {
        use std::os::unix::fs::symlink;

        let directory = graph_test_directory();
        let real_parent = directory.path().join("real-parent");
        let symlink_parent = directory.path().join("symlink-parent");
        std::fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &symlink_parent).unwrap();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(&symlink_parent);

        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();

        let err = index.persist_graph_file(&graph_file).unwrap_err();
        assert!(err.to_string().contains("must be a directory"));
        assert_ciphertext_graph_file_error_redacts_paths(&err);

        let real_graph_file = CkksCiphertextVectorIndex::graph_file_path(&real_parent);
        index.persist_graph_file(&real_graph_file).unwrap();
        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be a directory"));
        assert_ciphertext_graph_file_error_redacts_paths(&err);
    }

    #[test]
    fn ciphertext_vector_index_ignores_graph_record_count_mismatch_on_open() {
        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();
        index.persist_graph_file(&graph_file).unwrap();

        let reopened = CkksCiphertextVectorIndex::open_graph_file(
            vec![CkksCiphertextIndexedRecord::new(
                0,
                b"ciphertext-a".to_vec(),
            )],
            &graph_file,
        )
        .unwrap();

        assert!(
            reopened.is_none(),
            "record-count mismatches should trigger rebuild/fallback instead of hard-failing",
        );
    }

    #[test]
    fn ciphertext_vector_index_rejects_graph_version_mismatch_on_open() {
        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let graph = CkksCiphertextHnswGraphFile {
            version: CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION + 1,
            graph_kind: CkksCiphertextHnswGraphKind::Similarity,
            record_count: 2,
            records_digest: ckks_ciphertext_records_digest(&[
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ]),
            max_degree: Some(1),
            links: vec![vec![1], vec![0]],
        };
        write_graph_file(&graph_file, &serde_json::to_vec(&graph).unwrap()).unwrap();

        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("unsupported CKKS ciphertext HNSW graph file version")
        );
        assert_ciphertext_graph_file_error_redacts_paths(&err);
    }

    #[test]
    fn ciphertext_vector_index_rejects_graph_unknown_fields_on_open() {
        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let graph = serde_json::json!({
            "version": CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION,
            "graph_kind": "similarity",
            "record_count": 2,
            "records_digest": ckks_ciphertext_records_digest(&[
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ]),
            "max_degree": 1,
            "links": [[1], [0]],
            "untrusted_cache_metadata": "must not be ignored",
        });
        write_graph_file(&graph_file, &serde_json::to_vec(&graph).unwrap()).unwrap();

        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("failed to parse"),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn ciphertext_vector_index_ignores_graph_records_digest_mismatch_on_open() {
        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();
        index.persist_graph_file(&graph_file).unwrap();

        let reopened = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
            ],
            &graph_file,
        )
        .unwrap();

        assert!(
            reopened.is_none(),
            "record digest mismatch should trigger rebuild/fallback instead of hard-failing",
        );

        let reopened = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-c".to_vec()),
            ],
            &graph_file,
        )
        .unwrap();

        assert!(
            reopened.is_none(),
            "ciphertext digest mismatch should trigger rebuild/fallback instead of hard-failing",
        );
    }

    #[test]
    fn ciphertext_vector_index_digest_tracks_full_sidecar_identity() {
        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![CkksCiphertextIndexedRecord::new_with_sidecar_identity(
                0,
                b"same-ciphertext".to_vec(),
                b"rk-epoch-1".to_vec(),
            )],
            CkksCiphertextHnswGraph::from_validated_links(vec![Vec::new()]).unwrap(),
        )
        .unwrap();
        index.persist_graph_file(&graph_file).unwrap();

        let reopened = CkksCiphertextVectorIndex::open_graph_file(
            vec![CkksCiphertextIndexedRecord::new_with_sidecar_identity(
                0,
                b"same-ciphertext".to_vec(),
                b"rk-epoch-2".to_vec(),
            )],
            &graph_file,
        )
        .unwrap();

        assert!(
            reopened.is_none(),
            "sidecar identity changes must invalidate graph files even when ciphertext bytes match",
        );
    }

    #[test]
    fn ciphertext_vector_index_ignores_invalid_graph_links_on_open() {
        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let invalid_graph = CkksCiphertextHnswGraphFile {
            version: CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION,
            graph_kind: CkksCiphertextHnswGraphKind::Similarity,
            record_count: 3,
            records_digest: ckks_ciphertext_records_digest(&[
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
                CkksCiphertextIndexedRecord::new(2, b"ciphertext-c".to_vec()),
            ]),
            max_degree: Some(1),
            links: vec![vec![1], vec![], vec![]],
        };
        write_graph_file(&graph_file, &serde_json::to_vec(&invalid_graph).unwrap()).unwrap();

        let reopened = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
                CkksCiphertextIndexedRecord::new(2, b"ciphertext-c".to_vec()),
            ],
            &graph_file,
        )
        .unwrap();

        assert!(
            reopened.is_none(),
            "invalid graph links should trigger rebuild/fallback instead of hard-failing",
        );
    }

    #[test]
    fn ciphertext_vector_index_ignores_graph_degree_above_persisted_limit_on_open() {
        let directory = graph_test_directory();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let records = vec![
            CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
            CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            CkksCiphertextIndexedRecord::new(2, b"ciphertext-c".to_vec()),
        ];
        let invalid_graph = CkksCiphertextHnswGraphFile {
            version: CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION,
            graph_kind: CkksCiphertextHnswGraphKind::Similarity,
            record_count: records.len(),
            records_digest: ckks_ciphertext_records_digest(&records),
            max_degree: Some(1),
            links: vec![vec![1, 2], vec![0, 2], vec![0, 1]],
        };
        write_graph_file(&graph_file, &serde_json::to_vec(&invalid_graph).unwrap()).unwrap();

        let reopened = CkksCiphertextVectorIndex::open_graph_file(records, &graph_file).unwrap();

        assert!(
            reopened.is_none(),
            "graph degree above persisted max_degree must trigger rebuild/fallback",
        );
    }

    #[test]
    fn ciphertext_record_extractor_reads_sidecar_ciphertext() {
        let payload = Payload(
            serde_json::from_value(serde_json::json!({
                CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD: {
                    "embedding": {
                        CKKS_VECTOR_SIDECAR_MARKER: {
                            "version": 1,
                            "scheme": "openfhe-ckks",
                            "envelope": {
                                "version": 1,
                                "algorithm": "AES-256-GCM",
                                "key_id": "tenant-a:vector",
                                "material_fingerprint": "tenant-a/vector@v1",
                                "rk_id": "tenant-a/vector-rk@v1",
                                "rk_epoch": 1,
                                "nonce": "AAAAAAAAAAAAAAAA",
                                "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
                            }
                        }
                    }
                }
            }))
            .unwrap(),
        );

        assert_eq!(
            ckks_ciphertext_from_payload(&payload, "embedding").unwrap(),
            Some("AAAAAAAAAAAAAAAAAAAAAA"),
        );
        assert_eq!(
            ckks_ciphertext_from_payload(&payload, "other").unwrap(),
            None
        );
    }

    #[test]
    fn ciphertext_record_extractor_rejects_malformed_sidecar() {
        let payload = Payload(
            serde_json::from_value(serde_json::json!({
                CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD: {
                    "embedding-sensitive-sentinel": { "not_the_marker": {} }
                }
            }))
            .unwrap(),
        );

        let err =
            ckks_ciphertext_from_payload(&payload, "embedding-sensitive-sentinel").unwrap_err();
        assert!(err.to_string().contains("malformed"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);
    }

    #[test]
    fn ciphertext_record_extractor_rejects_unsupported_marker_metadata() {
        let payload_with_marker = |marker: serde_json::Value| {
            Payload(
                serde_json::from_value(serde_json::json!({
                    CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD: {
                        "embedding-sensitive-sentinel": {
                            CKKS_VECTOR_SIDECAR_MARKER: marker
                        }
                    }
                }))
                .unwrap(),
            )
        };

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 2,
                "scheme": "openfhe-ckks",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported version"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "other-scheme",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported scheme"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "openfhe-ckks",
                "unexpected-sensitive-sentinel": true,
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-128-GCM",
                    "key_id": "tenant-a:vector",
                    "material_fingerprint": "tenant-a/vector@v1",
                    "rk_id": "tenant-a/vector-rk@v1",
                    "rk_epoch": 1,
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported metadata field"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "openfhe-ckks",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a:vector",
                    "material_fingerprint": "tenant-a/vector@v1",
                    "rk_id": "tenant-a/vector-rk@v1",
                    "rk_epoch": 1,
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                    "unexpected-sensitive-sentinel": true
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported envelope field"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "openfhe-ckks",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a:vector",
                    "material_fingerprint": "tenant-a/vector@v1",
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing rk_id"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "openfhe-ckks",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a:vector",
                    "material_fingerprint": "tenant-a/vector@v1",
                    "rk_id": "tenant-a/vector-rk@v1",
                    "rk_epoch": 1,
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": ""
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty ciphertext"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let oversized_ciphertext = "A".repeat(CKKS_CIPHERTEXT_SIDECAR_MAX_ENCODED_BYTES + 1);
        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "openfhe-ckks",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a:vector",
                    "material_fingerprint": "tenant-a/vector@v1",
                    "rk_id": "tenant-a/vector-rk@v1",
                    "rk_epoch": 1,
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": oversized_ciphertext
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("maximum ciphertext size"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "openfhe-ckks",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a:vector",
                    "material_fingerprint": "tenant-a/vector@v1",
                    "rk_id": "tenant-a/vector-rk@v1",
                    "rk_epoch": 1,
                    "nonce": "not-base64url-sensitive-sentinel",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid nonce"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "openfhe-ckks",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a:vector",
                    "material_fingerprint": "tenant-a/vector@v1",
                    "rk_id": "tenant-a/vector-rk@v1",
                    "rk_epoch": 1,
                    "nonce": "A".repeat(CKKS_CIPHERTEXT_SIDECAR_NONCE_B64_LEN + 1),
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid nonce"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "openfhe-ckks",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a:vector",
                    "material_fingerprint": "tenant-a/vector@v1",
                    "rk_id": "tenant-a/vector-rk@v1",
                    "rk_epoch": 1,
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "too-short-sensitive-sentinel!"
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid ciphertext"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);

        let err = ckks_ciphertext_from_payload(
            &payload_with_marker(serde_json::json!({
                "version": 1,
                "scheme": "openfhe-ckks",
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-128-GCM",
                    "key_id": "tenant-a:vector",
                    "material_fingerprint": "tenant-a/vector@v1",
                    "rk_id": "tenant-a/vector-rk@v1",
                    "rk_epoch": 1,
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
                }
            })),
            "embedding-sensitive-sentinel",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported envelope algorithm"));
        assert_ckks_sidecar_payload_error_redacts_sensitive_fields(&err);
    }

    fn assert_ckks_sidecar_payload_error_redacts_sensitive_fields(err: &OperationError) {
        let rendered = err.to_string();
        for leaked in [
            "embedding-sensitive-sentinel",
            "unexpected-sensitive-sentinel",
            "tenant-a:vector",
            "tenant-a/vector@v1",
            "tenant-a/vector-rk@v1",
            "not-base64url-sensitive-sentinel",
            "too-short-sensitive-sentinel",
        ] {
            assert!(
                !rendered.contains(leaked),
                "stored CKKS sidecar payload error leaked sensitive field {leaked}: {rendered}",
            );
        }
    }

    fn assert_ciphertext_graph_file_error_redacts_paths(err: &OperationError) {
        let rendered = err.to_string();
        for leaked in [
            "ckks-graph-path-sentinel",
            "writable-ancestor",
            "graph-parent",
            "real-parent",
            "symlink-parent",
            CKKS_CIPHERTEXT_HNSW_GRAPH_FILE,
        ] {
            assert!(
                !rendered.contains(leaked),
                "CKKS ciphertext graph file error leaked path component {leaked}: {rendered}",
            );
        }
    }
}
