//! `vector` subcommand — ARCH-0019 §perf vector benchmark harness (ONE-1120).
//!
//! Contract (ARCH-0019 "oneiron-db benchmark targets",
//! `core/oneiron-arch-0019-oneiron-db-v1`):
//!
//! * Vector search top-10: `< 5ms p50` — "Flat NSW, ef=128".
//! * Recall@10: `> 90%` — "vs brute-force baseline" (float32).
//! * Insert (entity + vector + edges): `< 1ms` — "Single write txn".
//! * Operating point: 10K vault; 1024-dim (device) / 4096-dim (cloud).
//! * HNSW parameters: `m_max_0 = 64`, `ef_construction = 200`,
//!   `ef_search = 128`.
//!
//! Latency / insert targets are GOALS: the harness reports measured values
//! against the target rows but never fails the process on a miss. Recall@10
//! is a hard gate by default (`--no-recall-assert` opts out). Structural
//! invariants always fail closed: every ANN result set must contain exactly
//! `min(10, live)` hits and every hit must be a live (non-deleted) entity —
//! a deleted ID resurfacing after delete-churn is a tombstone leak and fails
//! the run regardless of flags.
//!
//! Determinism: the corpus, query set, churn selections, and churn
//! replacement vectors are all drawn from a single `StdRng` stream seeded by
//! `--seed` (default 42), in a fixed order (corpus IDs+vectors → queries →
//! refresh selection → refresh vectors → delete selection). Same seed ⇒ same
//! corpus ⇒ same recall numbers on a given build. The harness contains no
//! arch-specific code; it runs unchanged on aarch64 (NEON), x86_64
//! (AVX2/scalar), and any other target the engine compiles for.
//!
//! RAM-at-index is reported (raw f32 vector bytes, `data.mdb` disk usage,
//! best-effort process RSS) as the fairness baseline for any future
//! binary-quantization comparison — measurement only, no BQ here.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use oneiron::{EdgeKind, EntityId, TimeRange, Vault, VaultConfig};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

// ─── ARCH-0019 contract literals ─────────────────────────────────────────
// "oneiron-db benchmark targets" table + "HNSW parameters" table.

/// "Vector search top-10 — < 5ms p50 — oneiron-db target; Flat NSW, ef=128".
pub(crate) const TARGET_SEARCH_TOP10_P50_MS: f64 = 5.0;
/// "Insert (entity + vector + edges) — < 1ms — Single write txn".
pub(crate) const TARGET_INSERT_P50_MS: f64 = 1.0;
/// "Recall@10 — > 90% — vs brute-force baseline".
pub(crate) const TARGET_RECALL_AT_10: f64 = 0.90;
/// "ef_search — 128 — Beam width during search".
pub(crate) const CONTRACT_EF_SEARCH: usize = 128;
/// "ef_construction — 200 — Beam width during insert".
pub(crate) const CONTRACT_EF_CONSTRUCTION: usize = 200;
/// "m_max_0 — 64 — Neighbours per node (layer 0)".
pub(crate) const CONTRACT_M_MAX_0: usize = 64;
/// Top-10: the contract's search and recall rows are both @10.
pub(crate) const SEARCH_LIMIT: usize = 10;
/// "mentions — 0.6" from the ARCH-0019 PPR edge-kind weight table; used for
/// the chain edge included in each new-node insert txn so the measured op is
/// the contract row's "entity + vector + edges" single write txn.
pub(crate) const MENTIONS_EDGE_WEIGHT: f32 = 0.6;

const DEFAULT_N: usize = 10_000;
const DEFAULT_DIM: usize = 1024;
const DEFAULT_SEED: u64 = 42;
const DEFAULT_QUERY_COUNT: usize = 100;
const DEFAULT_CHURN_PCT: u32 = 10;
const BENCH_ENTITY_TYPE: u8 = 1;
const BENCH_EMBEDDING_MODEL: &str = "bench-vector-harness";
/// Query = corpus vector + perturbation × this scale (models a query
/// embedding landing near a stored document embedding).
const QUERY_PERTURBATION_SCALE: f32 = 0.1;

// ─── CLI ─────────────────────────────────────────────────────────────────

/// Churn phases to run after the baseline measurement. `Both` runs refresh
/// first, then delete on the post-refresh vault (cumulative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChurnMode {
    None,
    Refresh,
    Delete,
    Both,
}

impl ChurnMode {
    const fn runs_refresh(self) -> bool {
        matches!(self, Self::Refresh | Self::Both)
    }

    const fn runs_delete(self) -> bool {
        matches!(self, Self::Delete | Self::Both)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Refresh => "refresh",
            Self::Delete => "delete",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BenchSettings {
    pub(crate) n: usize,
    pub(crate) dim: usize,
    pub(crate) seed: u64,
    pub(crate) queries: usize,
    pub(crate) churn: ChurnMode,
    pub(crate) churn_pct: u32,
    pub(crate) assert_recall: bool,
}

impl Default for BenchSettings {
    fn default() -> Self {
        Self {
            n: DEFAULT_N,
            dim: DEFAULT_DIM,
            seed: DEFAULT_SEED,
            queries: DEFAULT_QUERY_COUNT,
            churn: ChurnMode::Both,
            churn_pct: DEFAULT_CHURN_PCT,
            assert_recall: true,
        }
    }
}

/// Parses `vector` subcommand flags. CLI surface pins the ticket's presets:
/// `--n` ∈ {1k, 10k}, `--dim` ∈ {1024, 4096} — anything else is rejected
/// (fail closed); tests drive arbitrary sizes through [`BenchSettings`]
/// directly.
pub(crate) fn parse_args(args: &[String]) -> Result<BenchSettings, String> {
    let mut settings = BenchSettings::default();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value_for = |name: &str| {
            iter.next()
                .map(String::as_str)
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match flag.as_str() {
            "--n" => {
                let value = value_for("--n")?;
                settings.n = if value.eq_ignore_ascii_case("1k") {
                    1_000
                } else if value.eq_ignore_ascii_case("10k") {
                    10_000
                } else {
                    return Err(format!("--n must be 1k or 10k, got `{value}`"));
                };
            }
            "--dim" => {
                let value = value_for("--dim")?;
                settings.dim = match value {
                    "1024" => 1024,
                    "4096" => 4096,
                    other => {
                        return Err(format!("--dim must be 1024 or 4096, got `{other}`"));
                    }
                };
            }
            "--seed" => {
                let value = value_for("--seed")?;
                settings.seed = value
                    .parse()
                    .map_err(|_| format!("--seed must be a u64, got `{value}`"))?;
            }
            "--queries" => {
                let value = value_for("--queries")?;
                settings.queries = value.parse().ok().filter(|q| *q > 0).ok_or_else(|| {
                    format!("--queries must be a positive integer, got `{value}`")
                })?;
            }
            "--churn" => {
                let value = value_for("--churn")?;
                settings.churn = match value {
                    "none" => ChurnMode::None,
                    "refresh" => ChurnMode::Refresh,
                    "delete" => ChurnMode::Delete,
                    "both" => ChurnMode::Both,
                    other => {
                        return Err(format!(
                            "--churn must be none|refresh|delete|both, got `{other}`"
                        ));
                    }
                };
            }
            "--churn-pct" => {
                let value = value_for("--churn-pct")?;
                settings.churn_pct = value
                    .parse()
                    .ok()
                    .filter(|p| (1..=99).contains(p))
                    .ok_or_else(|| format!("--churn-pct must be in 1..=99, got `{value}`"))?;
            }
            "--no-recall-assert" => settings.assert_recall = false,
            other => return Err(format!("unknown vector flag: `{other}`")),
        }
    }
    Ok(settings)
}

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
                 \x20                          [--churn-pct 1..99] [--no-recall-assert]"
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
        let ids = select_churn_ids(&mut rng, &live, settings.churn_pct);
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
        let ids = select_churn_ids(&mut rng, &live, settings.churn_pct);
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
fn bench_config(n: usize, dim: usize) -> VaultConfig {
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

fn gen_corpus(rng: &mut StdRng, n: usize, dim: usize) -> Vec<(EntityId, Vec<f32>)> {
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
fn gen_queries(rng: &mut StdRng, corpus: &[(EntityId, Vec<f32>)], count: usize) -> Vec<Vec<f32>> {
    (0..count)
        .map(|q| {
            let base = &corpus[(q * corpus.len()) / count].1;
            base.iter()
                .map(|v| v + QUERY_PERTURBATION_SCALE * rng.gen_range(-1.0_f32..1.0))
                .collect()
        })
        .collect()
}

/// Deterministically selects `pct`% (min 1) of the live IDs: live keys are
/// iterated in BTreeMap (byte) order, shuffled by the seeded stream, then
/// truncated.
fn select_churn_ids(
    rng: &mut StdRng,
    live: &BTreeMap<EntityId, Vec<f32>>,
    pct: u32,
) -> Vec<EntityId> {
    let mut ids: Vec<EntityId> = live.keys().copied().collect();
    ids.shuffle(rng);
    let count = ((live.len() as u64 * u64::from(pct)) / 100).max(1) as usize;
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

// ─── Reporting ───────────────────────────────────────────────────────────

fn print_report(report: &VectorBenchReport) {
    let s = &report.settings;
    println!("== vector bench (ONE-1120) ==");
    println!(
        "contract: ARCH-0019 §perf — vector top-10 < {TARGET_SEARCH_TOP10_P50_MS}ms p50 \
         (Flat NSW, ef={CONTRACT_EF_SEARCH}); recall@10 > {TARGET_RECALL_AT_10} vs f32 brute \
         force; insert (entity+vector+edges) < {TARGET_INSERT_P50_MS}ms single txn"
    );
    println!(
        "params: n={} dim={} seed={} queries={} churn={} churn-pct={}%",
        s.n,
        s.dim,
        s.seed,
        s.queries,
        s.churn.as_str(),
        s.churn_pct
    );
    println!(
        "hnsw: m_max_0={CONTRACT_M_MAX_0} ef_construction={CONTRACT_EF_CONSTRUCTION} \
         ef_search={CONTRACT_EF_SEARCH}"
    );

    println!("\n[build: new-node inserts]");
    print_latency(
        "insert new-node",
        &report.insert_new,
        Some(TARGET_INSERT_P50_MS),
    );
    println!("  {}", format_ram(&report.ram, s.n, s.dim));

    println!("\n[baseline]");
    print_search_measure(&report.baseline);

    if let Some(refresh) = &report.refresh {
        println!(
            "\n[refresh-churn: re-put {} nodes ({}%), live={}]",
            refresh.churned, s.churn_pct, refresh.live_after
        );
        print_latency(
            "insert refresh ",
            &refresh.op_latency,
            Some(TARGET_INSERT_P50_MS),
        );
        print_search_measure(&refresh.search);
    }

    if let Some(delete) = &report.delete {
        println!(
            "\n[delete-churn: delete {} nodes ({}%), live={}]",
            delete.churned, s.churn_pct, delete.live_after
        );
        print_latency("delete         ", &delete.op_latency, None);
        print_search_measure(&delete.search);
    }
    println!();
}

fn print_latency(label: &str, stats: &LatencyStats, target_p50_ms: Option<f64>) {
    let target = match target_p50_ms {
        Some(t) => {
            let verdict = if stats.p50_ms < t { "ok" } else { "MISS" };
            format!(" — target < {t}ms p50: {verdict} (goal, not asserted)")
        }
        None => String::new(),
    };
    println!(
        "  {label}: p50={:.3}ms p90={:.3}ms p99={:.3}ms mean={:.3}ms ({} ops){target}",
        stats.p50_ms, stats.p90_ms, stats.p99_ms, stats.mean_ms, stats.count
    );
}

fn print_search_measure(measure: &SearchMeasure) {
    print_latency(
        "search top-10  ",
        &measure.latency,
        Some(TARGET_SEARCH_TOP10_P50_MS),
    );
    let verdict = if measure.recall > TARGET_RECALL_AT_10 {
        "ok"
    } else {
        "FAIL"
    };
    println!(
        "  recall@{}: {:.4} — target > {TARGET_RECALL_AT_10}: {verdict}",
        measure.recall_k, measure.recall
    );
    for violation in &measure.violations {
        println!("  [violation] {violation}");
    }
}

fn format_ram(ram: &RamReport, n: usize, dim: usize) -> String {
    let disk = ram
        .data_mdb_disk_bytes
        .map_or_else(|| "unavailable".to_owned(), format_mib);
    let rss = ram
        .process_rss_bytes
        .map_or_else(|| "unavailable".to_owned(), format_mib);
    format!(
        "ram-at-index: vectors-raw={} ({n} × {dim} × 4 B f32) data.mdb-disk={disk} \
         process-rss={rss}",
        format_mib(ram.vectors_raw_bytes)
    )
}

fn format_mib(bytes: u64) -> String {
    format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::HnswConfig;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The bench pins the LITERAL ARCH-0019 values. A plausible-but-wrong
    /// edit (e.g. ef_search 100, target 10ms) must fail here.
    #[test]
    fn contract_literals_pinned() {
        assert_eq!(TARGET_SEARCH_TOP10_P50_MS, 5.0);
        assert_eq!(TARGET_INSERT_P50_MS, 1.0);
        assert_eq!(TARGET_RECALL_AT_10, 0.90);
        assert_eq!(CONTRACT_EF_SEARCH, 128);
        assert_eq!(CONTRACT_EF_CONSTRUCTION, 200);
        assert_eq!(CONTRACT_M_MAX_0, 64);
        assert_eq!(SEARCH_LIMIT, 10);
        assert_eq!(MENTIONS_EDGE_WEIGHT, 0.6);
    }

    /// The harness config must match the contract table, and the engine's
    /// own default must agree with ARCH-0019 — if either drifts, this fails.
    #[test]
    fn bench_config_matches_contract_and_engine_default() {
        let cfg = bench_config(10_000, 1024);
        assert_eq!(cfg.hnsw.ef_search, 128);
        assert_eq!(cfg.hnsw.ef_construction, 200);
        assert_eq!(cfg.hnsw.m_max_0, 64);
        assert_eq!(cfg.dimensions, 1024);
        assert!(cfg.embedding_model.is_some());

        let engine_default = HnswConfig::default();
        assert_eq!(
            engine_default.ef_search, 128,
            "engine default drifted from ARCH-0019"
        );
        assert_eq!(
            engine_default.ef_construction, 200,
            "engine default drifted from ARCH-0019"
        );
        assert_eq!(
            engine_default.m_max_0, 64,
            "engine default drifted from ARCH-0019"
        );
    }

    #[test]
    fn parse_args_defaults_to_contract_operating_point() {
        let settings = parse_args(&[]).expect("defaults parse");
        assert_eq!(settings.n, 10_000);
        assert_eq!(settings.dim, 1024);
        assert_eq!(settings.seed, 42);
        assert_eq!(settings.queries, 100);
        assert_eq!(settings.churn, ChurnMode::Both);
        assert_eq!(settings.churn_pct, 10);
        assert!(settings.assert_recall);
    }

    #[test]
    fn parse_args_accepts_presets() {
        let settings = parse_args(&args(&[
            "--n",
            "1k",
            "--dim",
            "4096",
            "--seed",
            "7",
            "--queries",
            "25",
            "--churn",
            "refresh",
            "--churn-pct",
            "25",
            "--no-recall-assert",
        ]))
        .expect("flags parse");
        assert_eq!(settings.n, 1_000);
        assert_eq!(settings.dim, 4096);
        assert_eq!(settings.seed, 7);
        assert_eq!(settings.queries, 25);
        assert_eq!(settings.churn, ChurnMode::Refresh);
        assert_eq!(settings.churn_pct, 25);
        assert!(!settings.assert_recall);
    }

    /// Fail closed: only the ticket's presets are accepted.
    #[test]
    fn parse_args_rejects_off_contract_values() {
        assert!(parse_args(&args(&["--n", "5k"])).is_err());
        assert!(parse_args(&args(&["--n", "100"])).is_err());
        assert!(parse_args(&args(&["--dim", "512"])).is_err());
        assert!(parse_args(&args(&["--dim", "1536"])).is_err());
        assert!(parse_args(&args(&["--churn", "bogus"])).is_err());
        assert!(parse_args(&args(&["--churn-pct", "0"])).is_err());
        assert!(parse_args(&args(&["--churn-pct", "100"])).is_err());
        assert!(parse_args(&args(&["--queries", "0"])).is_err());
        assert!(parse_args(&args(&["--seed"])).is_err());
        assert!(parse_args(&args(&["--frobnicate"])).is_err());
    }

    #[test]
    fn corpus_and_queries_are_seed_deterministic() {
        let mut rng_a = StdRng::seed_from_u64(42);
        let corpus_a = gen_corpus(&mut rng_a, 32, 8);
        let queries_a = gen_queries(&mut rng_a, &corpus_a, 5);

        let mut rng_b = StdRng::seed_from_u64(42);
        let corpus_b = gen_corpus(&mut rng_b, 32, 8);
        let queries_b = gen_queries(&mut rng_b, &corpus_b, 5);

        assert_eq!(corpus_a, corpus_b);
        assert_eq!(queries_a, queries_b);

        let mut rng_c = StdRng::seed_from_u64(43);
        let corpus_c = gen_corpus(&mut rng_c, 32, 8);
        assert_ne!(corpus_a, corpus_c, "different seed must change the corpus");
    }

    #[test]
    fn percentile_is_nearest_rank() {
        let sorted: Vec<f64> = (1..=10).map(|v| f64::from(v) * 10.0).collect();
        assert_eq!(percentile(&sorted, 50.0), 50.0);
        assert_eq!(percentile(&sorted, 90.0), 90.0);
        assert_eq!(percentile(&sorted, 99.0), 100.0);
        assert_eq!(percentile(&[7.5], 50.0), 7.5);
        assert_eq!(percentile(&[7.5], 99.0), 7.5);
    }

    #[test]
    fn brute_force_top_k_known_answer() {
        let ids: Vec<EntityId> = (1_u8..=4)
            .map(|b| EntityId::from_bytes([b; 16]).expect("id"))
            .collect();
        let mut live = BTreeMap::new();
        live.insert(ids[0], vec![1.0_f32, 0.0]); // dist 0.0 to query
        live.insert(ids[1], vec![0.9_f32, 0.1]); // dist ~0.0062
        live.insert(ids[2], vec![0.0_f32, 1.0]); // dist 1.0
        live.insert(ids[3], vec![-1.0_f32, 0.0]); // dist 2.0

        let top2 = brute_force_top_k(&live, &[1.0, 0.0], 2);
        assert_eq!(top2, vec![ids[0], ids[1]]);

        let top3 = brute_force_top_k(&live, &[1.0, 0.0], 3);
        assert_eq!(top3, vec![ids[0], ids[1], ids[2]]);
    }

    #[test]
    fn cosine_distance_literal_values() {
        assert_eq!(cosine_distance_f32(&[1.0, 0.0], &[1.0, 0.0]), 0.0);
        assert_eq!(cosine_distance_f32(&[1.0, 0.0], &[0.0, 1.0]), 1.0);
        assert_eq!(cosine_distance_f32(&[1.0, 0.0], &[-1.0, 0.0]), 2.0);
        // Zero vector fails closed to max distance, never NaN.
        assert_eq!(cosine_distance_f32(&[0.0, 0.0], &[1.0, 0.0]), 1.0);
    }

    #[test]
    fn churn_selection_is_deterministic_and_sized() {
        let mut live = BTreeMap::new();
        for b in 1_u8..=100 {
            live.insert(EntityId::from_bytes([b; 16]).expect("id"), vec![0.0_f32; 4]);
        }
        let mut rng_a = StdRng::seed_from_u64(9);
        let mut rng_b = StdRng::seed_from_u64(9);
        let picked_a = select_churn_ids(&mut rng_a, &live, 10);
        let picked_b = select_churn_ids(&mut rng_b, &live, 10);
        assert_eq!(picked_a, picked_b);
        assert_eq!(picked_a.len(), 10);
        assert_eq!(select_churn_ids(&mut rng_a, &live, 1).len(), 1);
        // min-1 floor: 1% of 10 entities rounds to 0 but must churn 1.
        let mut small = BTreeMap::new();
        for b in 1_u8..=10 {
            small.insert(EntityId::from_bytes([b; 16]).expect("id"), vec![0.0_f32; 4]);
        }
        assert_eq!(select_churn_ids(&mut rng_a, &small, 1).len(), 1);
    }

    /// End-to-end at a tiny operating point (n=100 < ef_search=128, so the
    /// search beam covers the whole graph): recall must be exactly 1.0 in
    /// every phase, churn counts must match, and the post-delete phase must
    /// produce zero structural violations (no tombstone leaks).
    #[test]
    fn run_bench_tiny_end_to_end() {
        let settings = BenchSettings {
            n: 100,
            dim: 16,
            seed: 42,
            queries: 20,
            churn: ChurnMode::Both,
            churn_pct: 10,
            assert_recall: true,
        };
        let report = run_bench(&settings).expect("tiny bench run");

        assert_eq!(report.insert_new.count, 100);
        assert_eq!(report.baseline.recall_k, 10);
        assert!(report.baseline.violations.is_empty());
        assert_eq!(report.baseline.recall, 1.0);

        let refresh = report.refresh.as_ref().expect("refresh phase ran");
        assert_eq!(refresh.churned, 10);
        assert_eq!(refresh.live_after, 100);
        assert!(refresh.search.violations.is_empty());
        assert_eq!(refresh.search.recall, 1.0);

        let delete = report.delete.as_ref().expect("delete phase ran");
        assert_eq!(delete.churned, 10);
        assert_eq!(delete.live_after, 90);
        assert!(delete.search.violations.is_empty());
        assert_eq!(delete.search.recall, 1.0);

        assert_eq!(report.ram.vectors_raw_bytes, 100 * 16 * 4);
        assert!(report.ram.data_mdb_disk_bytes.is_some_and(|b| b > 0));
    }

    /// Same seed ⇒ identical recall in every phase across two full runs
    /// (fresh vault each time) — the determinism contract of AC4.
    #[test]
    fn run_bench_is_deterministic_across_runs() {
        let settings = BenchSettings {
            n: 100,
            dim: 16,
            seed: 7,
            queries: 10,
            churn: ChurnMode::Both,
            churn_pct: 20,
            assert_recall: true,
        };
        let a = run_bench(&settings).expect("run a");
        let b = run_bench(&settings).expect("run b");

        assert_eq!(a.baseline.recall, b.baseline.recall);
        assert_eq!(
            a.refresh.as_ref().map(|c| c.search.recall),
            b.refresh.as_ref().map(|c| c.search.recall)
        );
        assert_eq!(
            a.delete.as_ref().map(|c| c.search.recall),
            b.delete.as_ref().map(|c| c.search.recall)
        );
        assert_eq!(
            a.delete.as_ref().map(|c| c.live_after),
            b.delete.as_ref().map(|c| c.live_after)
        );
    }

    #[test]
    fn run_bench_rejects_n_below_search_limit() {
        let settings = BenchSettings {
            n: 5,
            dim: 8,
            seed: 1,
            queries: 1,
            churn: ChurnMode::None,
            churn_pct: 10,
            assert_recall: true,
        };
        assert!(run_bench(&settings).is_err());
    }
}
