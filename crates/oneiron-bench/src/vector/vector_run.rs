//! Vector bench execution, measurement, and gate evaluation.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use oneiron::{EdgeKind, EntityId, TimeRange, Vault, VaultConfig};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

use super::vector_config::{BENCH_EMBEDDING_MODEL, BENCH_ENTITY_TYPE, QUERY_PERTURBATION_SCALE};
use super::vector_report::print_report;
use super::{
    BenchSettings, CONTRACT_EF_CONSTRUCTION, CONTRACT_EF_SEARCH, CONTRACT_M_MAX_0,
    MENTIONS_EDGE_WEIGHT, SEARCH_LIMIT, TARGET_RECALL_AT_10, parse_args,
};

// ─── Measurements ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LatencyStats {
    pub(crate) count: usize,
    pub(crate) p50_ms: f64,
    pub(crate) p90_ms: f64,
    pub(crate) p99_ms: f64,
    pub(crate) mean_ms: f64,
}

impl LatencyStats {
    fn from_samples(mut samples: Vec<f64>) -> Self {
        assert!(
            !samples.is_empty(),
            "latency stats need at least one sample"
        );
        samples.sort_by(f64::total_cmp);
        let mean_ms = samples.iter().sum::<f64>() / samples.len() as f64;
        Self {
            count: samples.len(),
            p50_ms: percentile(&samples, 50.0),
            p90_ms: percentile(&samples, 90.0),
            p99_ms: percentile(&samples, 99.0),
            mean_ms,
        }
    }
}

/// Nearest-rank percentile over an ascending-sorted, non-empty slice.
pub(crate) fn percentile(sorted: &[f64], pct: f64) -> f64 {
    assert!(!sorted.is_empty(), "percentile over empty samples");
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SearchMeasure {
    pub(crate) latency: LatencyStats,
    pub(crate) recall: f64,
    /// Effective k for the recall denominator: `min(10, live)`.
    pub(crate) recall_k: usize,
    /// Structural contract violations (wrong hit count, non-live hit).
    /// Non-empty ⇒ the run fails regardless of flags.
    pub(crate) violations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ChurnMeasure {
    pub(crate) churned: usize,
    pub(crate) live_after: usize,
    pub(crate) op_latency: LatencyStats,
    pub(crate) search: SearchMeasure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RamReport {
    /// `n × dim × 4` — the logical float32 vector payload. The future
    /// binary-quantization fairness baseline.
    pub(crate) vectors_raw_bytes: u64,
    /// Allocated disk size of `data.mdb` after the build phase.
    pub(crate) data_mdb_disk_bytes: Option<u64>,
    /// Best-effort process RSS after the build phase.
    pub(crate) process_rss_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct VectorBenchReport {
    pub(crate) settings: BenchSettings,
    pub(crate) insert_new: LatencyStats,
    pub(crate) ram: RamReport,
    pub(crate) baseline: SearchMeasure,
    pub(crate) refresh: Option<ChurnMeasure>,
    pub(crate) delete: Option<ChurnMeasure>,
}

impl VectorBenchReport {
    /// All structural violations across phases.
    fn violations(&self) -> Vec<&str> {
        self.search_measures()
            .into_iter()
            .flat_map(|(_, measure)| measure.violations.iter().map(String::as_str))
            .collect()
    }

    /// `(phase label, measure)` pairs for every search phase that ran.
    fn search_measures(&self) -> Vec<(&'static str, &SearchMeasure)> {
        let mut measures = vec![("baseline", &self.baseline)];
        if let Some(refresh) = &self.refresh {
            measures.push(("refresh-churn", &refresh.search));
        }
        if let Some(delete) = &self.delete {
            measures.push(("delete-churn", &delete.search));
        }
        measures
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────

pub(crate) fn run(args: &[String]) -> ExitCode {
    let settings = match parse_args(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vector: {e}");
            eprintln!(
                "usage: oneiron-bench vector [--n 1k|10k] [--dim 1024|4096] [--seed N]\n\
                 \x20                          [--queries N] [--churn none|refresh|delete|both]\n\
                 \x20                          [--churn-pct 1..99] [--churn-ops N]\n\
                 \x20                          [--no-recall-assert]"
            );
            return ExitCode::FAILURE;
        }
    };

    let report = match run_bench(&settings) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vector bench failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    print_report(&report);
    evaluate_gates(&report)
}

fn evaluate_gates(report: &VectorBenchReport) -> ExitCode {
    let mut failed = false;

    let violations = report.violations();
    if !violations.is_empty() {
        for violation in &violations {
            eprintln!("[violation] {violation}");
        }
        eprintln!(
            "result: FAIL ({} structural violation(s))",
            violations.len()
        );
        failed = true;
    }

    if report.settings.assert_recall {
        for (label, measure) in report.search_measures() {
            if measure.recall <= TARGET_RECALL_AT_10 {
                eprintln!(
                    "[recall gate] {label}: recall@{} = {:.4} <= {TARGET_RECALL_AT_10} \
                     (ARCH-0019: Recall@10 > 90% vs brute-force baseline)",
                    measure.recall_k, measure.recall
                );
                failed = true;
            }
        }
    }

    if failed {
        println!("result: FAIL");
        ExitCode::FAILURE
    } else {
        println!("result: PASS");
        ExitCode::SUCCESS
    }
}

// ─── Bench core ──────────────────────────────────────────────────────────

pub(crate) fn run_bench(settings: &BenchSettings) -> Result<VectorBenchReport, String> {
    if settings.n < SEARCH_LIMIT {
        return Err(format!("n must be >= {SEARCH_LIMIT}, got {}", settings.n));
    }
    let mut rng = StdRng::seed_from_u64(settings.seed);

    // Deterministic stream order: corpus → queries → refresh selection →
    // refresh vectors → delete selection.
    let corpus = gen_corpus(&mut rng, settings.n, settings.dim);
    let queries = gen_queries(&mut rng, &corpus, settings.queries);

    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let vault = Vault::open(dir.path(), bench_config(settings.n, settings.dim))
        .map_err(|e| format!("vault open: {e}"))?;

    // [build] new-node inserts — entity + vector + edge in ONE write txn,
    // matching the contract row "Insert (entity + vector + edges) — single
    // write txn". Entity i carries a `mentions` chain edge to entity i-1.
    let mut live: BTreeMap<EntityId, Vec<f32>> = BTreeMap::new();
    let mut insert_samples = Vec::with_capacity(corpus.len());
    for (i, (id, vector)) in corpus.iter().enumerate() {
        let timestamp = (i + 1) as u64;
        let started = Instant::now();
        let mut batch = vault
            .batch()
            .put(
                id,
                BENCH_ENTITY_TYPE,
                TimeRange {
                    start: timestamp,
                    end: timestamp,
                },
                timestamp,
                b"vector-bench",
            )
            .vector(id, vector);
        if i > 0 {
            batch = batch.edge(
                id,
                EdgeKind::Mentions,
                &corpus[i - 1].0,
                MENTIONS_EDGE_WEIGHT,
            );
        }
        batch
            .commit()
            .map_err(|e| format!("insert {i} ({}): {e}", id.to_hex()))?;
        insert_samples.push(elapsed_ms(started));
        live.insert(*id, vector.clone());
    }
    let insert_new = LatencyStats::from_samples(insert_samples);

    let ram = ram_at_index(dir.path(), settings.n, settings.dim);

    // [baseline]
    let baseline = measure_search(&vault, &queries, &live)?;

    // [refresh-churn] re-put X% with fresh vectors (HNSW refresh path).
    let refresh = if settings.churn.runs_refresh() {
        let count = churn_count(live.len(), settings.churn_pct, settings.churn_ops);
        let ids = select_churn_ids(&mut rng, &live, count);
        let mut samples = Vec::with_capacity(ids.len());
        for id in &ids {
            let vector = gen_vector(&mut rng, settings.dim);
            let started = Instant::now();
            vault
                .put_vector(id, &vector)
                .map_err(|e| format!("refresh {}: {e}", id.to_hex()))?;
            samples.push(elapsed_ms(started));
            live.insert(*id, vector);
        }
        Some(ChurnMeasure {
            churned: ids.len(),
            live_after: live.len(),
            op_latency: LatencyStats::from_samples(samples),
            search: measure_search(&vault, &queries, &live)?,
        })
    } else {
        None
    };

    // [delete-churn] hard-delete X% of the (post-refresh) live set. The
    // post-delete search measure fails closed if any deleted ID resurfaces.
    let delete = if settings.churn.runs_delete() {
        let count = churn_count(live.len(), settings.churn_pct, settings.churn_ops);
        let ids = select_churn_ids(&mut rng, &live, count);
        let mut samples = Vec::with_capacity(ids.len());
        for id in &ids {
            let started = Instant::now();
            let existed = vault
                .delete_entity(id)
                .map_err(|e| format!("delete {}: {e}", id.to_hex()))?;
            samples.push(elapsed_ms(started));
            if !existed {
                return Err(format!(
                    "delete {}: entity vanished before delete-churn",
                    id.to_hex()
                ));
            }
            live.remove(id);
        }
        Some(ChurnMeasure {
            churned: ids.len(),
            live_after: live.len(),
            op_latency: LatencyStats::from_samples(samples),
            search: measure_search(&vault, &queries, &live)?,
        })
    } else {
        None
    };

    Ok(VectorBenchReport {
        settings: settings.clone(),
        insert_new,
        ram,
        baseline,
        refresh,
        delete,
    })
}

/// Vault config pinned to the ARCH-0019 HNSW parameter table.
pub(super) fn bench_config(n: usize, dim: usize) -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.dimensions = dim;
    cfg.embedding_model = Some(BENCH_EMBEDDING_MODEL.to_owned());
    cfg.map_size = compute_map_size(n, dim);
    cfg.max_readers = 16;
    cfg.hnsw.m_max_0 = CONTRACT_M_MAX_0;
    cfg.hnsw.ef_construction = CONTRACT_EF_CONSTRUCTION;
    cfg.hnsw.ef_search = CONTRACT_EF_SEARCH;
    cfg
}

/// Map size: 6× the raw vector payload (neighbor lists, entities, edges,
/// LMDB copy-on-write churn, delete receipts) + 512 MiB floor, rounded up
/// to a 1 MiB boundary (LMDB requires a page-size multiple). The file is
/// sparse; this is virtual reservation, not RSS.
fn compute_map_size(n: usize, dim: usize) -> usize {
    const MIB: usize = 1024 * 1024;
    let raw = n
        .saturating_mul(dim)
        .saturating_mul(4)
        .saturating_mul(6)
        .saturating_add(512 * MIB);
    raw.div_ceil(MIB).saturating_mul(MIB)
}

pub(super) fn gen_corpus(rng: &mut StdRng, n: usize, dim: usize) -> Vec<(EntityId, Vec<f32>)> {
    (0..n)
        .map(|_| (gen_entity_id(rng), gen_vector(rng, dim)))
        .collect()
}

fn gen_entity_id(rng: &mut StdRng) -> EntityId {
    loop {
        let mut bytes = [0_u8; 16];
        rng.fill(&mut bytes);
        // Reserved sentinel patterns (all-zero / all-0xFF / [type, 0xFF×15])
        // are rejected by `from_bytes`; astronomically unlikely — retry.
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
    }
}

fn gen_vector(rng: &mut StdRng, dim: usize) -> Vec<f32> {
    (0..dim).map(|_| rng.gen_range(-1.0_f32..1.0)).collect()
}

/// Queries are perturbed corpus vectors: query q is anchored on corpus index
/// `q * n / count` plus seeded noise, modeling a query embedding near a
/// stored document embedding.
pub(super) fn gen_queries(
    rng: &mut StdRng,
    corpus: &[(EntityId, Vec<f32>)],
    count: usize,
) -> Vec<Vec<f32>> {
    (0..count)
        .map(|q| {
            let base = &corpus[(q * corpus.len()) / count].1;
            base.iter()
                .map(|v| v + QUERY_PERTURBATION_SCALE * rng.gen_range(-1.0_f32..1.0))
                .collect()
        })
        .collect()
}

/// Number of churn operations: `pct`% of the live set (min 1), unless an
/// absolute `--churn-ops` override is given; always clamped to the live set.
pub(crate) fn churn_count(live_len: usize, pct: u32, ops: Option<usize>) -> usize {
    let from_pct = ((live_len as u64 * u64::from(pct)) / 100).max(1) as usize;
    ops.unwrap_or(from_pct).min(live_len)
}

/// Deterministically selects `count` of the live IDs: live keys are iterated
/// in BTreeMap (byte) order, shuffled by the seeded stream, then truncated.
pub(super) fn select_churn_ids(
    rng: &mut StdRng,
    live: &BTreeMap<EntityId, Vec<f32>>,
    count: usize,
) -> Vec<EntityId> {
    let mut ids: Vec<EntityId> = live.keys().copied().collect();
    ids.shuffle(rng);
    ids.truncate(count);
    ids
}

/// One warmup pass, then a measured pass: per-query latency of
/// `search_vector(q, 10)` plus recall@10 against an independent float32
/// brute-force ranking over the bench's own ground-truth copy of the live
/// vectors (NOT the engine's opinion of what it stored).
fn measure_search(
    vault: &Vault,
    queries: &[Vec<f32>],
    live: &BTreeMap<EntityId, Vec<f32>>,
) -> Result<SearchMeasure, String> {
    let k = SEARCH_LIMIT.min(live.len());
    for query in queries {
        vault
            .search_vector(query, SEARCH_LIMIT)
            .map_err(|e| format!("warmup search: {e}"))?;
    }

    let mut samples = Vec::with_capacity(queries.len());
    let mut recall_sum = 0.0_f64;
    let mut violations = Vec::new();
    for (qi, query) in queries.iter().enumerate() {
        let started = Instant::now();
        let hits = vault
            .search_vector(query, SEARCH_LIMIT)
            .map_err(|e| format!("search {qi}: {e}"))?;
        samples.push(elapsed_ms(started));

        if hits.len() != k {
            violations.push(format!("query {qi}: expected {k} hits, got {}", hits.len()));
        }
        let ann: HashSet<EntityId> = hits.iter().map(|hit| hit.id).collect();
        for id in &ann {
            if !live.contains_key(id) {
                violations.push(format!(
                    "query {qi}: hit {} is not live (tombstone leak)",
                    id.to_hex()
                ));
            }
        }

        let brute = brute_force_top_k(live, query, k);
        let overlap = brute.iter().filter(|id| ann.contains(id)).count();
        recall_sum += overlap as f64 / k as f64;
    }

    Ok(SearchMeasure {
        latency: LatencyStats::from_samples(samples),
        recall: recall_sum / queries.len() as f64,
        recall_k: k,
        violations,
    })
}

/// Float32 brute-force top-k by cosine distance, ties broken by ID bytes.
/// Independent reference implementation — sequential f32 accumulation, no
/// engine code.
pub(crate) fn brute_force_top_k(
    live: &BTreeMap<EntityId, Vec<f32>>,
    query: &[f32],
    k: usize,
) -> Vec<EntityId> {
    let mut scored: Vec<(EntityId, f32)> = live
        .iter()
        .map(|(id, vector)| (*id, cosine_distance_f32(query, vector)))
        .collect();
    scored.sort_by(|a, b| {
        a.1.total_cmp(&b.1)
            .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
    });
    scored.into_iter().take(k).map(|(id, _)| id).collect()
}

/// `1 − dot(a,b) / (‖a‖ × ‖b‖)` in sequential float32 (ARCH-0019 distance
/// definition).
pub(crate) fn cosine_distance_f32(a: &[f32], b: &[f32]) -> f32 {
    assert_eq!(a.len(), b.len(), "dimension mismatch in brute force");
    let mut dot = 0.0_f32;
    let mut norm_a = 0.0_f32;
    let mut norm_b = 0.0_f32;
    for (x, y) in a.iter().zip(b) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        return 1.0;
    }
    1.0 - dot / denom
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1e3
}

// ─── RAM-at-index ────────────────────────────────────────────────────────

fn ram_at_index(vault_dir: &Path, n: usize, dim: usize) -> RamReport {
    RamReport {
        vectors_raw_bytes: (n as u64) * (dim as u64) * 4,
        data_mdb_disk_bytes: data_mdb_disk_bytes(vault_dir),
        process_rss_bytes: process_rss_bytes(),
    }
}

/// Allocated (not sparse-apparent) size of `data.mdb`.
fn data_mdb_disk_bytes(vault_dir: &Path) -> Option<u64> {
    let meta = std::fs::metadata(vault_dir.join("data.mdb")).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(meta.blocks() * 512)
    }
    #[cfg(not(unix))]
    {
        Some(meta.len())
    }
}

/// Best-effort process RSS. `None` when unavailable — reported as such,
/// never guessed.
fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
        let kib: u64 = line
            .trim_start_matches("VmRSS:")
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()?;
        Some(kib * 1024)
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p"])
            .arg(std::process::id().to_string())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let kib: u64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
        Some(kib * 1024)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}
