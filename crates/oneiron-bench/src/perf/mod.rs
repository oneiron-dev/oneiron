//! `perf` subcommand — ONE-1579 performance bench harness.
//!
//! This is BEAM's SIBLING, not its successor. ONEIRON-ARCH-0042 keeps accuracy
//! and cost; this harness answers the separate question "does the engine hold
//! up". Its results live BESIDE the BEAM report and are never folded into a
//! BEAM score — there is no composite number anywhere in the output, and every
//! axis carries its own evidence kind, sample count and fail-closed cells.
//!
//! Commands:
//!
//! * `oneiron-bench perf run --plan <JSON> --out <JSON>` — run a plan and
//!   write the report.
//! * `oneiron-bench perf smoke` — run the bundled synthetic smoke. Always
//!   marked `synthetic_smoke` and explicitly non-publishable.
//! * `oneiron-bench perf wake-child ...` — harness-internal. Spawned BY the
//!   wake and ready-children probes as their ready child; not a user command.
//!
//! The eight axes, each reported separately:
//!
//! 1. Warm and cold recall/latency as two disjoint sample sets (never one
//!    average, never a merged percentile).
//! 2. Wake latency measured by the parent's completed TCP `accept`. Log text
//!    is never read — children run with all standard streams discarded.
//! 3. The concurrent-session curve against ONE vault. A full run must walk
//!    exactly `[1, 10, 100, 300]`; omitting or reordering it is an invalid plan.
//! 4. RSS across exactly ten ready child processes, each holding an open vault.
//!    The ARCH-0023b 50 MB per-vault budget rides along as a comparison slot.
//! 5. Gated-write commits/s and error counts through `ClaimCandidate` +
//!    `WriteEnvelope` + `BatchBuilder::claim_candidate`/`commit`, with the gate
//!    ledger read back to confirm one decision per commit.
//! 6. F32 / F16 / Int8Sq / `BinaryPrefixRescore` precision rows — BENCH
//!    representations only. Engine storage is untouched and the engine persist
//!    path stays f16.
//! 7. Real-traffic cache hit rates per listed rung, from bench-owned JSONL
//!    events. `vault.rs` and `ppr.rs` retrieval internals are not instrumented.
//! 8. A descriptive NVMe sequential/random fsync row. Missing hardware stays
//!    explicitly missing.
//!
//! Fail-closed rules the code enforces rather than merely documents: a full run
//! below the >=1000-doc / >=100-query floor reports not-applicable latency
//! cells instead of numbers; a full run below >=1000 warmup / >=10000 measured
//! gated writes is an invalid plan; a speedup is emitted only when BOTH sides
//! were measured wall-clock in the same run, and is otherwise omitted; a full
//! run refuses any cache event that is not real traffic; and a listed cache
//! rung with no admissible event is `not_ready`, never `0`.

pub(crate) mod external;
pub(crate) mod precision;
pub(crate) mod report;
pub(crate) mod workloads;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use oneiron::Vault;
use serde::{Deserialize, Serialize};

use external::{NvmeFsyncAxis, NvmeProbe, Provenance, ProvenanceInputs, describe_nvme_fsync};
use precision::{PrecisionAxis, PrecisionCandidate, default_binary_prefix_breadth};
use report::{
    BEAM_RELATIONSHIP, EvidenceKind, FULL_RUN_MIN_GATED_WRITE_MEASURED,
    FULL_RUN_MIN_GATED_WRITE_WARMUP, FULL_RUN_MIN_INDEXED_DOCS, FULL_RUN_MIN_QUERIES,
    GatedWriteAxis, PERF_REPORT_SCHEMA, PerfReport, REQUIRED_FULL_SESSION_CURVE,
    REQUIRED_READY_CHILDREN, RecallLatencyAxis, ResidentMemoryAxis, RunMode, SCORING_POLICY,
    SessionsAxis, WakeAxis,
};
use workloads::{
    CacheAxis, ChildCommandPlan, ChildSettings, Corpus, generate_corpus, index_corpus,
    measure_cold, measure_gated_writes, measure_resident_memory, measure_session_curve,
    measure_wake, measure_warm, perf_vault_config,
};

/// Plan schema id. A plan that does not name it is refused.
pub(crate) const PERF_PLAN_SCHEMA: &str = "oneiron.bench.perf_plan.v1";
/// Reason stamped on every synthetic smoke report.
const SMOKE_NON_PUBLISHABLE_REASON: &str = "synthetic smoke over bundled under-floor fixtures: it proves the harness emits every axis, \
     and is never a publishable performance result";
/// Reason stamped on a full run that nonetheless sat below a floor.
const UNDER_FLOOR_REASON: &str = "the run sat below a full-run floor, so its latency cells are not-applicable rather than \
     numbers and the report is not publishable";

const SMOKE_PLAN_FIXTURE_NAME: &str = "perf_smoke.plan.json";
const SMOKE_CACHE_FIXTURE_NAME: &str = "perf_smoke.cache.jsonl";
const SMOKE_PLAN_FIXTURE: &str = include_str!("../../fixtures/perf_smoke.plan.json");
const SMOKE_CACHE_FIXTURE: &str = include_str!("../../fixtures/perf_smoke.cache.jsonl");
const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures");

// ─── plan ────────────────────────────────────────────────────────────────

/// Which contract a plan is asking to be held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PlanMode {
    Full,
    SyntheticSmoke,
}

impl PlanMode {
    const fn run_mode(self) -> RunMode {
        match self {
            Self::Full => RunMode::Full,
            Self::SyntheticSmoke => RunMode::SyntheticSmoke,
        }
    }

    const fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::Full => EvidenceKind::MeasuredWallClock,
            Self::SyntheticSmoke => EvidenceKind::SyntheticSmoke,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorpusPlan {
    pub(crate) indexed_docs: usize,
    pub(crate) queries: usize,
    pub(crate) k: usize,
    pub(crate) dimensions: usize,
    pub(crate) warm_passes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionsPlan {
    pub(crate) curve: Vec<usize>,
    pub(crate) queries_per_session: usize,
}

impl SessionsPlan {
    fn max_sessions(&self) -> usize {
        self.curve.iter().copied().max().unwrap_or(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WakePlan {
    pub(crate) samples: usize,
    pub(crate) timeout_ms: u64,
    pub(crate) hold_ms: u64,
    /// The program a full run spawns as its ready child. Absent means the
    /// harness spawns its own `perf wake-child` process.
    #[serde(default)]
    pub(crate) child: Option<ChildCommandPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentMemoryPlan {
    pub(crate) ready_children: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatedWritePlan {
    pub(crate) warmup: usize,
    pub(crate) measured: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrecisionPlan {
    pub(crate) candidates: Vec<PrecisionCandidate>,
    /// Defaults to `4 * k` (40 at the contract k=10) and is always recorded.
    #[serde(default)]
    pub(crate) binary_prefix_breadth: Option<usize>,
}

impl PrecisionPlan {
    fn breadth(&self, k: usize) -> usize {
        self.binary_prefix_breadth
            .unwrap_or_else(|| default_binary_prefix_breadth(k))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachePlan {
    /// Only rungs that actually exist for this run. A rung with no rows must
    /// be OMITTED from the plan rather than listed and zeroed.
    pub(crate) rungs: Vec<String>,
    /// JSONL cache-event stream, resolved relative to the plan file.
    #[serde(default)]
    pub(crate) events_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NvmePlan {
    pub(crate) sequential_ops: usize,
    pub(crate) random_ops: usize,
    pub(crate) block_bytes: usize,
}

impl NvmePlan {
    const fn probe(self, seed: u64) -> NvmeProbe {
        NvmeProbe {
            sequential_ops: self.sequential_ops,
            random_ops: self.random_ops,
            block_bytes: self.block_bytes,
            seed,
        }
    }
}

/// One performance-bench plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PerfPlan {
    pub(crate) schema: String,
    pub(crate) label: String,
    pub(crate) mode: PlanMode,
    pub(crate) seed: u64,
    pub(crate) corpus: CorpusPlan,
    pub(crate) sessions: SessionsPlan,
    pub(crate) wake: WakePlan,
    pub(crate) resident_memory: ResidentMemoryPlan,
    pub(crate) gated_writes: GatedWritePlan,
    pub(crate) precision: PrecisionPlan,
    pub(crate) cache: CachePlan,
    pub(crate) nvme: NvmePlan,
}

/// Why a plan was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum PlanError {
    #[error("plan schema `{found}` is not `oneiron.bench.perf_plan.v1`")]
    Schema { found: String },
    #[error("the concurrent-session curve must be non-empty and carry no zero-session point")]
    EmptySessionCurve,
    #[error(
        "a full run must walk exactly the concurrent-session curve {expected:?} against one \
         vault; `{found:?}` omits or reorders it and is not a valid full-run plan"
    )]
    SessionCurve {
        expected: Vec<usize>,
        found: Vec<usize>,
    },
    #[error(
        "a full run needs >=1000 indexed docs and >=100 queries for latency/recall; the plan asks \
         for {indexed_docs} docs and {queries} queries"
    )]
    LatencyFloor { indexed_docs: usize, queries: usize },
    #[error(
        "a full run needs >=1000 warmup and >=10000 measured gated writes; the plan asks for \
         {warmup} warmup and {measured} measured"
    )]
    GatedWriteFloor { warmup: usize, measured: usize },
    #[error(
        "the resident-memory axis is defined at exactly {expected} ready children, not {found}"
    )]
    ReadyChildren { expected: usize, found: usize },
    #[error(
        "the precision axis needs exactly the four candidates f32, f16, int8_sq and \
         binary_prefix_rescore, got {found:?}"
    )]
    PrecisionCandidates { found: Vec<String> },
    #[error("the plan must list at least one cache rung, or the cache axis has nothing to report")]
    EmptyCacheRungs,
    #[error("cache rung `{rung}` is listed more than once")]
    DuplicateCacheRung { rung: String },
    #[error("a full run must name a real-traffic cache event stream (`cache.events_path`)")]
    MissingCacheEvents,
    #[error("`{field}` must be greater than zero")]
    NonPositive { field: &'static str },
}

impl PerfPlan {
    /// Fail-closed plan admission. A full run is held to every floor; a
    /// synthetic smoke may use smaller fixtures but still has to be coherent.
    pub(crate) fn validate(&self) -> Result<(), PlanError> {
        if self.schema != PERF_PLAN_SCHEMA {
            return Err(PlanError::Schema {
                found: self.schema.clone(),
            });
        }
        self.validate_shape()?;
        self.validate_precision()?;
        self.validate_cache()?;
        if self.resident_memory.ready_children != REQUIRED_READY_CHILDREN {
            return Err(PlanError::ReadyChildren {
                expected: REQUIRED_READY_CHILDREN,
                found: self.resident_memory.ready_children,
            });
        }
        if self.mode == PlanMode::Full {
            self.validate_full_run()?;
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), PlanError> {
        for (field, value) in [
            ("corpus.indexed_docs", self.corpus.indexed_docs),
            ("corpus.queries", self.corpus.queries),
            ("corpus.k", self.corpus.k),
            ("corpus.dimensions", self.corpus.dimensions),
            (
                "sessions.queries_per_session",
                self.sessions.queries_per_session,
            ),
            ("wake.samples", self.wake.samples),
            ("gated_writes.measured", self.gated_writes.measured),
            ("nvme.block_bytes", self.nvme.block_bytes),
        ] {
            if value == 0 {
                return Err(PlanError::NonPositive { field });
            }
        }
        if self.wake.timeout_ms == 0 {
            return Err(PlanError::NonPositive {
                field: "wake.timeout_ms",
            });
        }
        if self.sessions.curve.is_empty() || self.sessions.curve.contains(&0) {
            return Err(PlanError::EmptySessionCurve);
        }
        Ok(())
    }

    fn validate_precision(&self) -> Result<(), PlanError> {
        if self.precision.candidates.as_slice() != PrecisionCandidate::ALL.as_slice() {
            return Err(PlanError::PrecisionCandidates {
                found: self
                    .precision
                    .candidates
                    .iter()
                    .map(|candidate| candidate.as_str().to_owned())
                    .collect(),
            });
        }
        Ok(())
    }

    fn validate_cache(&self) -> Result<(), PlanError> {
        if self.cache.rungs.is_empty() {
            return Err(PlanError::EmptyCacheRungs);
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.cache.rungs.len());
        for rung in &self.cache.rungs {
            if seen.contains(&rung.as_str()) {
                return Err(PlanError::DuplicateCacheRung { rung: rung.clone() });
            }
            seen.push(rung.as_str());
        }
        Ok(())
    }

    fn validate_full_run(&self) -> Result<(), PlanError> {
        if self.sessions.curve.as_slice() != REQUIRED_FULL_SESSION_CURVE.as_slice() {
            return Err(PlanError::SessionCurve {
                expected: REQUIRED_FULL_SESSION_CURVE.to_vec(),
                found: self.sessions.curve.clone(),
            });
        }
        if self.corpus.indexed_docs < FULL_RUN_MIN_INDEXED_DOCS
            || self.corpus.queries < FULL_RUN_MIN_QUERIES
        {
            return Err(PlanError::LatencyFloor {
                indexed_docs: self.corpus.indexed_docs,
                queries: self.corpus.queries,
            });
        }
        if self.gated_writes.warmup < FULL_RUN_MIN_GATED_WRITE_WARMUP
            || self.gated_writes.measured < FULL_RUN_MIN_GATED_WRITE_MEASURED
        {
            return Err(PlanError::GatedWriteFloor {
                warmup: self.gated_writes.warmup,
                measured: self.gated_writes.measured,
            });
        }
        if self.cache.events_path.is_none() {
            return Err(PlanError::MissingCacheEvents);
        }
        Ok(())
    }

    fn child_settings(&self) -> ChildSettings {
        ChildSettings {
            samples: self.wake.samples,
            timeout_ms: self.wake.timeout_ms,
            hold_ms: self.wake.hold_ms,
            child: self.wake.child.clone(),
        }
    }
}

// ─── run ─────────────────────────────────────────────────────────────────

/// Everything one run needs, already read off disk (or out of the fixtures).
struct RunInputs {
    plan: PerfPlan,
    plan_bytes: Vec<u8>,
    plan_source: String,
    cache_events: String,
    cache_source: String,
}

/// The measured axes, before they are wrapped in provenance and emitted.
struct MeasuredAxes {
    recall_latency: RecallLatencyAxis,
    wake: WakeAxis,
    sessions: SessionsAxis,
    resident_memory: ResidentMemoryAxis,
    gated_writes: GatedWriteAxis,
    precision: PrecisionAxis,
    cache: CacheAxis,
    nvme_fsync: NvmeFsyncAxis,
}

fn execute(inputs: &RunInputs) -> Result<PerfReport, String> {
    inputs.plan.validate().map_err(|error| error.to_string())?;
    let plan = &inputs.plan;
    let mode = plan.mode.run_mode();
    let evidence = plan.mode.evidence_kind();
    let corpus = generate_corpus(
        plan.seed,
        plan.corpus.indexed_docs,
        plan.corpus.queries,
        plan.corpus.dimensions,
    )?;

    let root = tempfile::tempdir().map_err(|error| format!("perf tempdir failed: {error}"))?;
    let vault_dir = root.path().join("vault");
    std::fs::create_dir_all(&vault_dir)
        .map_err(|error| format!("perf vault dir failed: {error}"))?;
    let config = perf_vault_config(plan.corpus.indexed_docs, plan.sessions.max_sessions());
    {
        let builder = Vault::open(&vault_dir, config.clone())
            .map_err(|error| format!("perf vault open failed: {error}"))?;
        index_corpus(&builder, &corpus)?;
    }

    // COLD first, on a handle that has served nothing: no pre-seed, no warm,
    // no replay before the measurement window.
    let vault = Arc::new(
        Vault::open(&vault_dir, config)
            .map_err(|error| format!("perf vault reopen failed: {error}"))?,
    );
    let cold = measure_cold(&vault, &corpus, plan.corpus.k);
    let warm = measure_warm(&vault, &corpus, plan.corpus.k, plan.corpus.warm_passes);
    let recall_latency = RecallLatencyAxis::new(
        plan.corpus.k,
        plan.corpus.indexed_docs,
        plan.corpus.queries,
        cold,
        warm,
        evidence,
    );
    let axes = measure_remaining_axes(inputs, &corpus, &vault, root.path(), recall_latency)?;
    Ok(finish(inputs, mode, axes, &corpus.hash, &vault_dir))
}

/// Everything except the warm/cold sets, which the caller measures first so
/// the cold window is genuinely the first thing the vault handle serves.
fn measure_remaining_axes(
    inputs: &RunInputs,
    corpus: &Corpus,
    vault: &Arc<Vault>,
    root: &Path,
    recall_latency: RecallLatencyAxis,
) -> Result<MeasuredAxes, String> {
    let plan = &inputs.plan;
    let mode = plan.mode.run_mode();
    let evidence = plan.mode.evidence_kind();
    let child_settings = plan.child_settings();
    let curve = measure_session_curve(
        vault,
        corpus,
        plan.corpus.k,
        &plan.sessions.curve,
        plan.sessions.queries_per_session,
    );
    let wake = measure_wake(&root.join("wake"), &child_settings, evidence);
    let resident_memory = measure_resident_memory(
        &root.join("ready"),
        &child_settings,
        plan.resident_memory.ready_children,
        evidence,
    );
    let gated_writes = measure_gated_writes(
        vault,
        plan.gated_writes.warmup,
        plan.gated_writes.measured,
        evidence,
    )?;
    let breadth = plan.precision.breadth(plan.corpus.k);
    let precision = precision::evaluate(
        &corpus.vectors,
        &corpus.query_vectors,
        plan.corpus.k,
        breadth,
        evidence,
    );
    let cache = CacheAxis::ingest(mode, &plan.cache.rungs, &inputs.cache_events)
        .map_err(|error| error.to_string())?;
    Ok(MeasuredAxes {
        recall_latency,
        wake,
        sessions: SessionsAxis {
            vaults: 1,
            required_full_curve: REQUIRED_FULL_SESSION_CURVE,
            requested_curve: plan.sessions.curve.clone(),
            exact_full_curve: plan.sessions.curve.as_slice()
                == REQUIRED_FULL_SESSION_CURVE.as_slice(),
            curve,
            evidence_kind: evidence,
            note: SESSIONS_NOTE,
        },
        resident_memory,
        gated_writes,
        precision,
        cache,
        // The descriptive fsync probe writes its own scratch file at the run
        // root rather than inside the live vault directory; same mount, same
        // device, no interference with the open LMDB environment.
        nvme_fsync: describe_nvme_fsync(root, plan.nvme.probe(plan.seed)),
    })
}

const SESSIONS_NOTE: &str = "all sessions run concurrently against ONE open vault; each query is \
     `Vault::search_text_with_telemetry`, so the measured cost includes the engine's own \
     best-effort retrieval-telemetry persistence exactly as a real caller pays it";

/// Assembles the emitted report and applies the full-run floor rewrite.
fn finish(
    inputs: &RunInputs,
    mode: RunMode,
    mut axes: MeasuredAxes,
    corpus_hash: &str,
    vault_dir: &Path,
) -> PerfReport {
    if mode.is_full() {
        axes.recall_latency.enforce_full_run_floor();
    }
    let publishable = mode.is_full()
        && axes.recall_latency.meets_full_run_floor
        && axes.gated_writes.meets_full_run_floor;
    let non_publishable_reason = if publishable {
        None
    } else if mode.is_full() {
        Some(UNDER_FLOOR_REASON.to_owned())
    } else {
        Some(SMOKE_NON_PUBLISHABLE_REASON.to_owned())
    };
    let provenance = Provenance::collect(ProvenanceInputs {
        plan_hash: blake3::hash(&inputs.plan_bytes).to_hex().to_string(),
        corpus_hash: corpus_hash.to_owned(),
        seed: inputs.plan.seed,
        sample_counts: sample_counts(&axes),
        evidence_kind: inputs.plan.mode.evidence_kind(),
        plan_source: format!(
            "plan={}; cache_events={}",
            inputs.plan_source, inputs.cache_source
        ),
        measured_path: vault_dir.to_path_buf(),
    });
    PerfReport {
        schema: PERF_REPORT_SCHEMA,
        mode,
        publishable,
        non_publishable_reason,
        scoring_policy: SCORING_POLICY,
        beam_relationship: BEAM_RELATIONSHIP,
        plan_label: inputs.plan.label.clone(),
        provenance,
        recall_latency: axes.recall_latency,
        wake: axes.wake,
        sessions: axes.sessions,
        resident_memory: axes.resident_memory,
        gated_writes: axes.gated_writes,
        precision: axes.precision,
        cache: axes.cache,
        nvme_fsync: axes.nvme_fsync,
    }
}

fn sample_counts(axes: &MeasuredAxes) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    counts.insert("cold_queries".to_owned(), axes.recall_latency.cold.samples);
    counts.insert("warm_queries".to_owned(), axes.recall_latency.warm.samples);
    counts.insert("wake_probes".to_owned(), axes.wake.samples);
    counts.insert("session_curve_points".to_owned(), axes.sessions.curve.len());
    counts.insert(
        "ready_children".to_owned(),
        axes.resident_memory.ready_children_observed,
    );
    counts.insert(
        "gated_write_commits".to_owned(),
        axes.gated_writes.measured_commits,
    );
    counts.insert("precision_rows".to_owned(), axes.precision.rows.len());
    counts.insert("cache_events".to_owned(), axes.cache.events_admitted);
    counts.insert(
        "nvme_fsync_ops".to_owned(),
        axes.nvme_fsync.sequential_ops + axes.nvme_fsync.random_ops,
    );
    counts
}

// ─── entry points ────────────────────────────────────────────────────────

/// `perf` dispatch.
pub(crate) fn run(args: &[String]) -> ExitCode {
    match args {
        [] => {
            print_help();
            ExitCode::SUCCESS
        }
        [first, ..] if is_help(first) => {
            print_help();
            ExitCode::SUCCESS
        }
        [sub, rest @ ..] if sub == "run" => finish_command(run_plan(rest)),
        [sub, rest @ ..] if sub == "smoke" => {
            if rest.is_empty() {
                finish_command(run_smoke_command())
            } else {
                eprintln!("perf smoke takes no arguments, got: {rest:?}");
                ExitCode::FAILURE
            }
        }
        [sub, rest @ ..] if sub == "wake-child" => workloads::run_wake_child(rest),
        [sub, ..] => {
            eprintln!("unknown perf subcommand: {sub}");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn is_help(argument: &str) -> bool {
    matches!(argument, "--help" | "-h" | "help")
}

fn finish_command(outcome: Result<(), String>) -> ExitCode {
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("perf: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "usage: oneiron-bench perf <subcommand>\n\
         \n\
         subcommands:\n\
           run --plan <JSON> --out <JSON>   run a perf plan and write the report\n\
           smoke                            run the bundled synthetic smoke; the report is\n\
                                            always marked synthetic_smoke and explicitly\n\
                                            non-publishable\n\
           wake-child --ready-addr <ADDR> [--vault <DIR>] [--hold-ms <N>]\n\
                                            harness-internal ready child, spawned by the wake\n\
                                            and ready-children probes; not a user command\n\
         \n\
         the report emits eight axes side by side and never collapses them into one\n\
         score: warm/cold recall as separate sample sets, TCP-accept wake latency,\n\
         the [1, 10, 100, 300] concurrent-session curve against one vault, RSS across\n\
         exactly ten ready children, gated-write commits/s with one gate decision per\n\
         commit, F32/F16/Int8Sq/BinaryPrefixRescore precision rows (bench\n\
         representations only; engine storage is unchanged and persist stays f16),\n\
         real-traffic cache hit rates per listed rung, and a descriptive NVMe fsync\n\
         row. Accuracy and cost stay BEAM-owned."
    );
}

fn run_plan(args: &[String]) -> Result<(), String> {
    let (plan_path, out_path) = parse_run_args(args)?;
    let plan_bytes = std::fs::read(&plan_path)
        .map_err(|error| format!("could not read plan `{}`: {error}", plan_path.display()))?;
    let plan: PerfPlan = serde_json::from_slice(&plan_bytes)
        .map_err(|error| format!("plan `{}` is not valid: {error}", plan_path.display()))?;
    plan.validate().map_err(|error| error.to_string())?;

    let (cache_events, cache_source) = read_cache_events(&plan, &plan_path)?;
    let inputs = RunInputs {
        plan,
        plan_bytes,
        plan_source: plan_path.display().to_string(),
        cache_events,
        cache_source,
    };
    let report = execute(&inputs)?;
    let rendered = emit(&report)?;
    std::fs::write(&out_path, rendered)
        .map_err(|error| format!("could not write `{}`: {error}", out_path.display()))?;
    print_summary(&report);
    println!("report written to {}", out_path.display());
    Ok(())
}

fn parse_run_args(args: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let mut plan = None;
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("`{flag}` needs a value"))?;
        match flag {
            "--plan" => plan = Some(PathBuf::from(value)),
            "--out" => out = Some(PathBuf::from(value)),
            other => return Err(format!("unknown `perf run` flag `{other}`")),
        }
        index += 2;
    }
    let plan = plan.ok_or_else(|| "`perf run` requires --plan <JSON>".to_owned())?;
    let out = out.ok_or_else(|| "`perf run` requires --out <JSON>".to_owned())?;
    Ok((plan, out))
}

fn read_cache_events(plan: &PerfPlan, plan_path: &Path) -> Result<(String, String), String> {
    let Some(relative) = &plan.cache.events_path else {
        return Ok((
            String::new(),
            "none (the plan named no cache-event stream)".to_owned(),
        ));
    };
    let base = plan_path.parent().unwrap_or_else(|| Path::new("."));
    let resolved = base.join(relative);
    let contents = std::fs::read_to_string(&resolved).map_err(|error| {
        format!(
            "could not read cache events `{}`: {error}",
            resolved.display()
        )
    })?;
    Ok((contents, resolved.display().to_string()))
}

fn run_smoke_command() -> Result<(), String> {
    let report = smoke_report()?;
    let rendered = emit(&report)?;
    print_summary(&report);
    println!("{rendered}");
    Ok(())
}

/// Runs the bundled synthetic smoke and returns its report.
pub(crate) fn smoke_report() -> Result<PerfReport, String> {
    let (plan_text, plan_source) = load_fixture(SMOKE_PLAN_FIXTURE_NAME, SMOKE_PLAN_FIXTURE);
    let (cache_events, cache_source) = load_fixture(SMOKE_CACHE_FIXTURE_NAME, SMOKE_CACHE_FIXTURE);
    let plan: PerfPlan = serde_json::from_str(&plan_text)
        .map_err(|error| format!("the bundled smoke plan is not valid: {error}"))?;
    if plan.mode != PlanMode::SyntheticSmoke {
        return Err("the bundled smoke plan must declare mode `synthetic_smoke`".to_owned());
    }
    let inputs = RunInputs {
        plan,
        plan_bytes: plan_text.into_bytes(),
        plan_source,
        cache_events,
        cache_source,
    };
    execute(&inputs)
}

fn load_fixture(name: &str, embedded: &'static str) -> (String, String) {
    let path = Path::new(FIXTURE_DIR).join(name);
    match std::fs::read_to_string(&path) {
        Ok(contents) => (contents, format!("filesystem:{}", path.display())),
        Err(_) => (embedded.to_owned(), format!("embedded:{name}")),
    }
}

/// Renders the report, refusing to emit one that dropped an axis or a
/// provenance field.
fn emit(report: &PerfReport) -> Result<String, String> {
    let value = serde_json::to_value(report)
        .map_err(|error| format!("the perf report could not be rendered: {error}"))?;
    let missing_axes = report::missing_axes(&value);
    if !missing_axes.is_empty() {
        return Err(format!("the perf report is missing axes: {missing_axes:?}"));
    }
    let missing_provenance = report::missing_provenance_fields(&value);
    if !missing_provenance.is_empty() {
        return Err(format!(
            "the perf report is missing provenance: {missing_provenance:?}"
        ));
    }
    serde_json::to_string_pretty(&value)
        .map_err(|error| format!("the perf report could not be serialized: {error}"))
}

fn print_summary(report: &PerfReport) {
    println!("== oneiron perf bench (ONE-1579) ==");
    println!(
        "mode: {} | publishable: {} | plan: {}",
        report.mode.as_str(),
        report.publishable,
        report.plan_label
    );
    if let Some(reason) = &report.non_publishable_reason {
        println!("non-publishable: {reason}");
    }
    println!("{}", report.scoring_policy);
    for (axis, measured) in [
        (
            "cold recall/latency",
            report.recall_latency.cold.latency_ms.is_measured(),
        ),
        (
            "warm recall/latency",
            report.recall_latency.warm.latency_ms.is_measured(),
        ),
        (
            "wake (tcp accept)",
            report.wake.spawn_to_ready_ms.is_measured(),
        ),
        (
            "ten ready children rss",
            report.resident_memory.total_child_rss_bytes.is_measured(),
        ),
        (
            "gated writes",
            report.gated_writes.commits_per_second.is_measured(),
        ),
        (
            "nvme fsync (descriptive)",
            report.nvme_fsync.sequential_fsync_ms.is_measured(),
        ),
    ] {
        let state = if measured { "measured" } else { "not measured" };
        println!("  {axis}: {state}");
    }
    println!(
        "  sessions: {:?} against {} vault(s)",
        report.sessions.requested_curve, report.sessions.vaults
    );
    println!(
        "  precision rows: {} (binary prefix breadth {})",
        report.precision.rows.len(),
        report.precision.binary_prefix_breadth
    );
    println!("  cache rungs: {:?}", report.cache.rungs_listed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_plan_fixture() -> PerfPlan {
        PerfPlan {
            schema: PERF_PLAN_SCHEMA.to_owned(),
            label: "full-run fixture".to_owned(),
            mode: PlanMode::Full,
            seed: 1579,
            corpus: CorpusPlan {
                indexed_docs: FULL_RUN_MIN_INDEXED_DOCS,
                queries: FULL_RUN_MIN_QUERIES,
                k: 10,
                dimensions: 256,
                warm_passes: 2,
            },
            sessions: SessionsPlan {
                curve: REQUIRED_FULL_SESSION_CURVE.to_vec(),
                queries_per_session: 20,
            },
            wake: WakePlan {
                samples: 5,
                timeout_ms: 20_000,
                hold_ms: 30_000,
                child: None,
            },
            resident_memory: ResidentMemoryPlan {
                ready_children: REQUIRED_READY_CHILDREN,
            },
            gated_writes: GatedWritePlan {
                warmup: FULL_RUN_MIN_GATED_WRITE_WARMUP,
                measured: FULL_RUN_MIN_GATED_WRITE_MEASURED,
            },
            precision: PrecisionPlan {
                candidates: PrecisionCandidate::ALL.to_vec(),
                binary_prefix_breadth: None,
            },
            cache: CachePlan {
                rungs: vec!["embedding".to_owned(), "posting_list".to_owned()],
                events_path: Some("cache.jsonl".to_owned()),
            },
            nvme: NvmePlan {
                sequential_ops: 64,
                random_ops: 64,
                block_bytes: 4096,
            },
        }
    }

    /// A full run is defined at exactly `[1, 10, 100, 300]`. Omitting a rung,
    /// reordering it, padding it or emptying it are all invalid full-run
    /// plans; a synthetic smoke may use a smaller curve.
    #[test]
    fn perf_plan_requires_exact_full_scale_curve() {
        full_plan_fixture()
            .validate()
            .expect("the exact curve validates");

        for broken in [
            vec![1, 10, 100],
            vec![1, 10, 300],
            vec![1, 10, 300, 100],
            vec![300, 100, 10, 1],
            vec![1, 10, 100, 300, 1000],
            vec![1, 10, 100, 200],
        ] {
            let mut plan = full_plan_fixture();
            plan.sessions.curve = broken.clone();
            let error = plan
                .validate()
                .expect_err("a full run must refuse a curve that is not exactly [1,10,100,300]");
            match error {
                PlanError::SessionCurve { expected, found } => {
                    assert_eq!(expected.as_slice(), REQUIRED_FULL_SESSION_CURVE.as_slice());
                    assert_eq!(found, broken);
                }
                other => panic!("expected a session-curve refusal for {broken:?}, got {other}"),
            }
        }

        let mut empty = full_plan_fixture();
        empty.sessions.curve = Vec::new();
        assert_eq!(
            empty.validate().expect_err("an empty curve is refused"),
            PlanError::EmptySessionCurve
        );

        // The smoke contract is explicitly allowed smaller fixtures.
        let mut smoke = full_plan_fixture();
        smoke.mode = PlanMode::SyntheticSmoke;
        smoke.sessions.curve = vec![1, 4];
        smoke.corpus.indexed_docs = 48;
        smoke.corpus.queries = 8;
        smoke.gated_writes = GatedWritePlan {
            warmup: 2,
            measured: 6,
        };
        smoke.cache.events_path = None;
        smoke
            .validate()
            .expect("a synthetic smoke may use smaller fixtures");
    }

    #[test]
    fn full_run_floors_and_axis_shape_are_enforced() {
        let mut under = full_plan_fixture();
        under.corpus.indexed_docs = 999;
        assert!(matches!(
            under.validate(),
            Err(PlanError::LatencyFloor { .. })
        ));

        let mut writes = full_plan_fixture();
        writes.gated_writes.measured = 9_999;
        assert!(matches!(
            writes.validate(),
            Err(PlanError::GatedWriteFloor { .. })
        ));

        let mut children = full_plan_fixture();
        children.resident_memory.ready_children = 9;
        assert!(matches!(
            children.validate(),
            Err(PlanError::ReadyChildren { .. })
        ));

        let mut candidates = full_plan_fixture();
        candidates.precision.candidates = vec![PrecisionCandidate::F32, PrecisionCandidate::F16];
        assert!(matches!(
            candidates.validate(),
            Err(PlanError::PrecisionCandidates { .. })
        ));

        let mut rungs = full_plan_fixture();
        rungs.cache.rungs = vec!["embedding".to_owned(), "embedding".to_owned()];
        assert!(matches!(
            rungs.validate(),
            Err(PlanError::DuplicateCacheRung { .. })
        ));

        let mut events = full_plan_fixture();
        events.cache.events_path = None;
        assert_eq!(
            events.validate().expect_err("a full run needs real events"),
            PlanError::MissingCacheEvents
        );

        let mut schema = full_plan_fixture();
        schema.schema = "something.else".to_owned();
        assert!(matches!(schema.validate(), Err(PlanError::Schema { .. })));
    }

    #[test]
    fn the_bundled_smoke_plan_parses_and_validates() {
        let (text, _) = load_fixture(SMOKE_PLAN_FIXTURE_NAME, SMOKE_PLAN_FIXTURE);
        let plan: PerfPlan = serde_json::from_str(&text).expect("the smoke plan parses");
        assert_eq!(plan.mode, PlanMode::SyntheticSmoke);
        assert_eq!(
            plan.resident_memory.ready_children, REQUIRED_READY_CHILDREN,
            "the RSS axis is defined at exactly ten ready children even for a smoke"
        );
        assert_eq!(
            plan.precision.candidates.as_slice(),
            PrecisionCandidate::ALL.as_slice()
        );
        plan.validate().expect("the bundled smoke plan validates");
    }

    /// The smoke must run end to end against its bundled fixtures and emit
    /// every axis and every provenance field, marked synthetic and explicitly
    /// non-publishable.
    #[test]
    fn perf_smoke_emits_every_axis() {
        let report = smoke_report().expect("the bundled smoke runs");

        assert_eq!(report.mode, RunMode::SyntheticSmoke);
        assert!(!report.publishable, "a smoke is never publishable");
        assert_eq!(
            report.non_publishable_reason.as_deref(),
            Some(SMOKE_NON_PUBLISHABLE_REASON)
        );
        assert_eq!(report.schema, PERF_REPORT_SCHEMA);

        let value = serde_json::to_value(&report).expect("the report renders");
        assert!(
            report::missing_axes(&value).is_empty(),
            "the smoke dropped axes: {:?}",
            report::missing_axes(&value)
        );
        assert!(
            report::missing_provenance_fields(&value).is_empty(),
            "the smoke dropped provenance: {:?}",
            report::missing_provenance_fields(&value)
        );

        // Axis 1: two separate populations.
        assert_eq!(report.recall_latency.cold.label, "cold");
        assert_eq!(report.recall_latency.warm.label, "warm");
        assert!(report.recall_latency.cold.latency_ms.is_measured());
        assert!(report.recall_latency.warm.latency_ms.is_measured());
        assert!(!report.recall_latency.meets_full_run_floor);

        // Axis 2: readiness is the TCP accept, whatever the outcome.
        assert_eq!(
            report.wake.readiness_signal,
            report::ReadinessSignal::TcpAccept
        );

        // Axis 3: the curve actually ran.
        assert!(!report.sessions.curve.is_empty());
        assert_eq!(report.sessions.vaults, 1);
        assert_eq!(
            report.sessions.required_full_curve,
            REQUIRED_FULL_SESSION_CURVE
        );

        // Axis 4: the axis is defined at ten ready children.
        assert_eq!(
            report.resident_memory.required_ready_children,
            REQUIRED_READY_CHILDREN
        );
        assert_eq!(report.resident_memory.arch_0023b_per_vault_budget_mb, 50);

        // Axis 5: one gate decision per commit.
        assert!(report.gated_writes.measured_commits > 0);
        assert_eq!(
            report.gated_writes.gate_decisions_recorded, report.gated_writes.measured_commits,
            "one gate decision per commit"
        );

        // Axis 6: four rows, breadth recorded, engine storage untouched.
        assert_eq!(report.precision.rows.len(), 4);
        assert!(report.precision.bench_representations_only);
        assert_eq!(report.precision.engine_persist_representation, "f16");
        assert_eq!(
            report.precision.binary_prefix_breadth,
            default_binary_prefix_breadth(report.precision.k)
        );

        // Axis 7: rungs come from the plan; a silent rung is not_ready.
        assert!(!report.cache.rows.is_empty());
        for row in &report.cache.rows {
            if row.events == 0 {
                assert!(
                    matches!(row.hit_rate, report::Cell::NotReady { .. }),
                    "silent rung `{}` must be not_ready, never 0",
                    row.rung
                );
            }
        }

        // Axis 8: descriptive, and never a fake zero.
        assert!(report.nvme_fsync.descriptive_only);
        assert!(matches!(report.nvme_fsync.status, "measured" | "not_ready"));

        // No collapsed score anywhere.
        let object = value.as_object().expect("report object");
        for forbidden in ["score", "overall_score", "composite", "beam_score"] {
            assert!(
                !object.contains_key(forbidden),
                "{forbidden} must not exist"
            );
        }
        assert!(emit(&report).is_ok());
    }
}
