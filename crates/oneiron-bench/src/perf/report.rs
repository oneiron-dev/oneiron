//! ONE-1579 performance-bench report shapes.
//!
//! The perf harness is the SIBLING of BEAM, not a replacement for it: BEAM
//! keeps accuracy and cost, this report answers "does the engine hold up".
//! Nothing here ever collapses accuracy, latency and cost into one number —
//! there is deliberately no composite score field, and every axis is emitted
//! as its own object with its own evidence kind and sample counts.
//!
//! Two shapes carry the fail-closed contract:
//!
//! * [`Cell`] — every numeric slot is `measured` / `not_applicable` /
//!   `not_ready`. A missing measurement is never rendered as `0`.
//! * [`Ratio`] — a speedup is only ever emitted when BOTH sides were measured
//!   wall-clock in this run. When a baseline was not measured the field is
//!   absent from the JSON entirely (`Option` + `skip_serializing_if`), so no
//!   simulated, injected or authored denominator can reach a reader.

use std::collections::BTreeMap;

use serde::Serialize;

/// Report envelope schema id.
pub(crate) const PERF_REPORT_SCHEMA: &str = "oneiron.bench.perf_report.v1";

/// ARCH-0042-sibling contract: the exact concurrent-session curve a full run
/// must walk against ONE vault. Omitting or reordering it invalidates the plan.
pub(crate) const REQUIRED_FULL_SESSION_CURVE: [usize; 4] = [1, 10, 100, 300];
/// RAM/RSS axis is defined at exactly ten ready child processes / active vaults.
pub(crate) const REQUIRED_READY_CHILDREN: usize = 10;
/// Full-run latency/recall floor: indexed documents.
pub(crate) const FULL_RUN_MIN_INDEXED_DOCS: usize = 1_000;
/// Full-run latency/recall floor: distinct queries.
pub(crate) const FULL_RUN_MIN_QUERIES: usize = 100;
/// Full-run gated-write floor: unmeasured warmup commits.
pub(crate) const FULL_RUN_MIN_GATED_WRITE_WARMUP: usize = 1_000;
/// Full-run gated-write floor: measured commits.
pub(crate) const FULL_RUN_MIN_GATED_WRITE_MEASURED: usize = 10_000;
/// ARCH-0023b per-vault RAM budget, carried as a COMPARISON SLOT only. The
/// measurement itself is the ten ready children below it, never this number.
pub(crate) const ARCH_0023B_PER_VAULT_BUDGET_MB: u64 = 50;

/// Every axis the report must emit, in report order.
pub(crate) const AXES: [&str; 8] = [
    "recall_latency",
    "wake",
    "sessions",
    "resident_memory",
    "gated_writes",
    "precision",
    "cache",
    "nvme_fsync",
];

/// Every provenance field the report must carry.
pub(crate) const PROVENANCE_FIELDS: [&str; 11] = [
    "git_sha",
    "target_triple",
    "cpu",
    "memory",
    "os",
    "filesystem",
    "plan_hash",
    "corpus_hash",
    "seed",
    "sample_counts",
    "evidence_kind",
];

/// Label pinned on every ratio: the denominator was measured wall-clock in
/// this same run. No other baseline kind is representable.
pub(crate) const MEASURED_WALL_CLOCK_BASELINE: &str = "measured_wall_clock";

/// How a run was produced. A smoke is ALWAYS non-publishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunMode {
    /// Full run: floors apply, the exact session curve applies, cache events
    /// must come from real traffic.
    Full,
    /// Synthetic smoke over the bundled fixtures. Never publishable.
    SyntheticSmoke,
}

impl RunMode {
    pub(crate) const fn is_full(self) -> bool {
        matches!(self, Self::Full)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::SyntheticSmoke => "synthetic_smoke",
        }
    }
}

/// What kind of evidence a cell or axis rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvidenceKind {
    /// Timed in this process against real engine calls.
    MeasuredWallClock,
    /// Timed in this process, but over deliberately under-floor synthetic
    /// fixtures. Never publishable as a performance claim.
    SyntheticSmoke,
    /// Read from bench-owned event rows produced by real traffic.
    IngestedRealTrafficEvents,
    /// Environment description, not an engine benchmark row.
    DescriptiveExternal,
}

/// A single reportable slot. There is no fourth state, and no state carries a
/// silent zero: an absent measurement is `not_ready`, an inapplicable one is
/// `not_applicable`, and both carry a reason string.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Cell<T> {
    Measured { value: T },
    NotApplicable { reason: String },
    NotReady { reason: String },
}

impl<T> Cell<T> {
    pub(crate) fn measured(value: T) -> Self {
        Self::Measured { value }
    }

    pub(crate) fn not_applicable(reason: impl Into<String>) -> Self {
        Self::NotApplicable {
            reason: reason.into(),
        }
    }

    pub(crate) fn not_ready(reason: impl Into<String>) -> Self {
        Self::NotReady {
            reason: reason.into(),
        }
    }

    /// `Some` becomes a measured cell; `None` becomes an explicit `not_ready`
    /// with the caller's reason. This is the ONLY conversion from an optional
    /// measurement, so a missing value can never fall through to `0`.
    pub(crate) fn from_option(value: Option<T>, reason: impl Into<String>) -> Self {
        match value {
            Some(value) => Self::measured(value),
            None => Self::not_ready(reason),
        }
    }

    pub(crate) fn value(&self) -> Option<&T> {
        match self {
            Self::Measured { value } => Some(value),
            Self::NotApplicable { .. } | Self::NotReady { .. } => None,
        }
    }

    pub(crate) fn is_measured(&self) -> bool {
        matches!(self, Self::Measured { .. })
    }
}

/// Nearest-rank percentile summary over one sample set. `p95` is carried
/// explicitly because the contract rows are p50/p95, not a mean.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Percentiles {
    pub(crate) count: usize,
    pub(crate) p50: f64,
    pub(crate) p95: f64,
    pub(crate) p99: f64,
    pub(crate) min: f64,
    pub(crate) max: f64,
    pub(crate) mean: f64,
}

impl Percentiles {
    /// `None` for an empty sample set — the caller turns that into an explicit
    /// `not_ready` cell rather than a zero row.
    pub(crate) fn from_samples(samples: &[f64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_by(f64::total_cmp);
        let sum: f64 = sorted.iter().sum();
        Some(Self {
            count: sorted.len(),
            p50: percentile(&sorted, 50.0),
            p95: percentile(&sorted, 95.0),
            p99: percentile(&sorted, 99.0),
            min: sorted[0],
            max: sorted[sorted.len() - 1],
            mean: sum / sorted.len() as f64,
        })
    }
}

/// Nearest-rank percentile over an ascending-sorted, non-empty slice.
fn percentile(sorted: &[f64], pct: f64) -> f64 {
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// A ratio between two values BOTH measured wall-clock in this run.
///
/// There is no constructor that accepts a simulated, injected or authored
/// denominator, and the only producer is [`measured_speedup`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Ratio {
    pub(crate) value: f64,
    pub(crate) numerator: String,
    pub(crate) numerator_ms: f64,
    pub(crate) denominator: String,
    pub(crate) denominator_ms: f64,
    pub(crate) baseline_kind: &'static str,
}

/// Builds a speedup ONLY from two measured wall-clock values. When the
/// baseline was not measured (or is degenerate) the result is `None` and the
/// caller's field is omitted from the JSON entirely.
pub(crate) fn measured_speedup(
    numerator: &str,
    numerator_ms: Option<f64>,
    denominator: &str,
    denominator_ms: Option<f64>,
) -> Option<Ratio> {
    let numerator_ms = numerator_ms?;
    let denominator_ms = denominator_ms?;
    if !numerator_ms.is_finite() || !denominator_ms.is_finite() || denominator_ms <= 0.0 {
        return None;
    }
    Some(Ratio {
        value: numerator_ms / denominator_ms,
        numerator: numerator.to_owned(),
        numerator_ms,
        denominator: denominator.to_owned(),
        denominator_ms,
        baseline_kind: MEASURED_WALL_CLOCK_BASELINE,
    })
}

/// One retrieval sample set. Warm and cold each get their OWN instance; the
/// type carries no field that could hold a merged population.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct SampleSet {
    pub(crate) label: &'static str,
    pub(crate) samples: usize,
    pub(crate) latency_ms: Cell<Percentiles>,
    pub(crate) recall_at_k: Cell<Percentiles>,
    pub(crate) telemetry_run_ids: usize,
    pub(crate) errors: usize,
}

impl SampleSet {
    pub(crate) fn new(
        label: &'static str,
        latency_samples: &[f64],
        recall_samples: &[f64],
        telemetry_run_ids: usize,
        errors: usize,
    ) -> Self {
        Self {
            label,
            samples: latency_samples.len(),
            latency_ms: Cell::from_option(
                Percentiles::from_samples(latency_samples),
                format!("no {label} latency samples were collected"),
            ),
            recall_at_k: Cell::from_option(
                Percentiles::from_samples(recall_samples),
                format!("no {label} recall samples were collected"),
            ),
            telemetry_run_ids,
            errors,
        }
    }

    pub(crate) fn p50_ms(&self) -> Option<f64> {
        self.latency_ms.value().map(|p| p.p50)
    }
}

/// Axis 1: warm and cold recall/latency, kept as two disjoint sample sets.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct RecallLatencyAxis {
    pub(crate) k: usize,
    pub(crate) indexed_docs: usize,
    pub(crate) queries: usize,
    pub(crate) meets_full_run_floor: bool,
    pub(crate) floor: &'static str,
    /// Cold first, warm second — and never merged. There is intentionally no
    /// `combined`, `overall`, `merged` or `all_samples` field on this type.
    pub(crate) cold: SampleSet,
    pub(crate) warm: SampleSet,
    pub(crate) cold_definition: &'static str,
    pub(crate) separation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cold_over_warm_speedup: Option<Ratio>,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) note: &'static str,
}

/// Cold-session definition pinned into every report: no pre-seed, no warm, no
/// replay before the measurement window opens.
pub(crate) const COLD_DEFINITION: &str = "fresh vault handle reopened from disk, measured on its \
     first pass with no pre-seeding, warming or replay before the window; the OS page cache is \
     NOT dropped and no such claim is made";
const SEPARATION_NOTE: &str = "warm and cold percentiles are computed over disjoint sample sets; \
     no combined or averaged population is emitted anywhere in this axis";
const RECALL_NOTE: &str = "recall here is harness-internal planted-ground-truth consistency for \
     regression detection; retrieval QUALITY and cost remain BEAM-owned and are not scored here";

impl RecallLatencyAxis {
    pub(crate) fn new(
        k: usize,
        indexed_docs: usize,
        queries: usize,
        cold: SampleSet,
        warm: SampleSet,
        evidence_kind: EvidenceKind,
    ) -> Self {
        let cold_over_warm_speedup = measured_speedup(
            "cold p50 latency",
            cold.p50_ms(),
            "warm p50 latency",
            warm.p50_ms(),
        );
        Self {
            k,
            indexed_docs,
            queries,
            meets_full_run_floor: indexed_docs >= FULL_RUN_MIN_INDEXED_DOCS
                && queries >= FULL_RUN_MIN_QUERIES,
            floor: "full-run latency/recall requires >=1000 indexed docs and >=100 queries",
            cold,
            warm,
            cold_definition: COLD_DEFINITION,
            separation: SEPARATION_NOTE,
            cold_over_warm_speedup,
            evidence_kind,
            note: RECALL_NOTE,
        }
    }

    /// Fail-closed rewrite for a run that claims full-run status while sitting
    /// below the floor: latency/recall cells and the ratio become explicitly
    /// not-applicable instead of numbers.
    pub(crate) fn enforce_full_run_floor(&mut self) {
        if self.meets_full_run_floor {
            return;
        }
        let reason = format!(
            "below the full-run floor ({} indexed docs, {} queries; requires \
             >={FULL_RUN_MIN_INDEXED_DOCS} indexed docs and >={FULL_RUN_MIN_QUERIES} queries)",
            self.indexed_docs, self.queries
        );
        for set in [&mut self.cold, &mut self.warm] {
            set.latency_ms = Cell::not_applicable(reason.clone());
            set.recall_at_k = Cell::not_applicable(reason.clone());
        }
        self.cold_over_warm_speedup = None;
    }
}

/// How readiness was decided. TCP accept is the only representable answer:
/// there is no log-text, stdout-scan or fixed-sleep variant of this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReadinessSignal {
    TcpAccept,
}

/// Axis 2: process spawn-to-ready wake latency.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct WakeAxis {
    pub(crate) readiness_signal: ReadinessSignal,
    pub(crate) readiness_rule: &'static str,
    pub(crate) accept_poll_interval_us: u64,
    pub(crate) samples: usize,
    pub(crate) spawn_to_ready_ms: Cell<Percentiles>,
    pub(crate) child: Cell<String>,
    pub(crate) errors: Vec<String>,
    pub(crate) evidence_kind: EvidenceKind,
}

/// Readiness rule pinned into every report.
pub(crate) const READINESS_RULE: &str = "ready == the parent's TCP accept for this child completed; child stdout/stderr is never read, \
     scanned or waited on, and no sleep stands in for readiness";

/// One point on the concurrent-session curve.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct SessionCurvePoint {
    pub(crate) sessions: usize,
    pub(crate) queries: usize,
    pub(crate) wall_clock_ms: f64,
    pub(crate) latency_ms: Cell<Percentiles>,
    pub(crate) throughput_qps: Cell<f64>,
    pub(crate) errors: usize,
}

/// Axis 3: concurrent sessions against ONE vault.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct SessionsAxis {
    pub(crate) vaults: usize,
    pub(crate) required_full_curve: [usize; 4],
    pub(crate) requested_curve: Vec<usize>,
    pub(crate) exact_full_curve: bool,
    pub(crate) curve: Vec<SessionCurvePoint>,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) note: &'static str,
}

/// Axis 4: resident memory for exactly ten ready children / active vaults.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ResidentMemoryAxis {
    pub(crate) required_ready_children: usize,
    pub(crate) ready_children_observed: usize,
    pub(crate) child_holds_open_vault: bool,
    pub(crate) per_child_rss_bytes: Cell<Vec<u64>>,
    pub(crate) total_child_rss_bytes: Cell<u64>,
    pub(crate) mean_child_rss_bytes: Cell<u64>,
    pub(crate) parent_rss_bytes: Cell<u64>,
    /// Comparison slot only. The MEASUREMENT is the ten children above.
    pub(crate) arch_0023b_per_vault_budget_mb: u64,
    pub(crate) budget_comparison: Cell<String>,
    pub(crate) errors: Vec<String>,
    pub(crate) evidence_kind: EvidenceKind,
}

/// Axis 5: gated-write throughput through the public claim door.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct GatedWriteAxis {
    pub(crate) write_path: &'static str,
    pub(crate) warmup_commits: usize,
    pub(crate) measured_commits: usize,
    pub(crate) commits_ok: usize,
    pub(crate) commit_errors: usize,
    pub(crate) error_kinds: BTreeMap<String, usize>,
    pub(crate) wall_clock_ms: f64,
    pub(crate) commits_per_second: Cell<f64>,
    pub(crate) commit_latency_ms: Cell<Percentiles>,
    pub(crate) gate_decisions_recorded: usize,
    pub(crate) one_decision_per_commit: bool,
    pub(crate) gate_outcomes: BTreeMap<String, usize>,
    pub(crate) meets_full_run_floor: bool,
    pub(crate) floor: &'static str,
    pub(crate) evidence_kind: EvidenceKind,
}

/// The write path pinned into every report: public seams only, no raw LMDB.
pub(crate) const GATED_WRITE_PATH: &str = "ClaimCandidate::new + WriteEnvelope::new -> BatchBuilder::claim_candidate -> commit; one \
     candidate per commit, no raw LMDB writes and no engine-internal door";

/// The whole report. Deliberately has NO composite/overall score field.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct PerfReport {
    pub(crate) schema: &'static str,
    pub(crate) mode: RunMode,
    pub(crate) publishable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) non_publishable_reason: Option<String>,
    pub(crate) scoring_policy: &'static str,
    pub(crate) beam_relationship: &'static str,
    pub(crate) plan_label: String,
    pub(crate) provenance: super::external::Provenance,
    pub(crate) recall_latency: RecallLatencyAxis,
    pub(crate) wake: WakeAxis,
    pub(crate) sessions: SessionsAxis,
    pub(crate) resident_memory: ResidentMemoryAxis,
    pub(crate) gated_writes: GatedWriteAxis,
    pub(crate) precision: super::precision::PrecisionAxis,
    pub(crate) cache: super::workloads::CacheAxis,
    pub(crate) nvme_fsync: super::external::NvmeFsyncAxis,
}

/// Scoring policy pinned into every report.
pub(crate) const SCORING_POLICY: &str = "axes are reported side by side and never collapsed into one score; accuracy and cost stay \
     BEAM-owned (ONEIRON-ARCH-0042) and are not restated, re-weighted or summarized here";
/// Relationship to BEAM pinned into every report.
pub(crate) const BEAM_RELATIONSHIP: &str = "sibling harness: BEAM answers 'is the answer good and what did it cost', this answers 'does \
     the engine hold up'; results live beside BEAM, never inside its score";

/// Axis keys that are present and non-null in `value`, reported as the ones
/// that are MISSING. Used by the smoke path itself before it emits, so a
/// dropped axis fails the command instead of shipping a partial report.
pub(crate) fn missing_axes(value: &serde_json::Value) -> Vec<&'static str> {
    AXES.into_iter()
        .filter(|axis| !is_present(value, axis))
        .collect()
}

/// Provenance keys that are missing or null under `value.provenance`.
pub(crate) fn missing_provenance_fields(value: &serde_json::Value) -> Vec<&'static str> {
    let Some(provenance) = value.get("provenance") else {
        return PROVENANCE_FIELDS.to_vec();
    };
    PROVENANCE_FIELDS
        .into_iter()
        .filter(|field| !is_present(provenance, field))
        .collect()
}

fn is_present(value: &serde_json::Value, key: &str) -> bool {
    value.get(key).is_some_and(|found| !found.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(label: &'static str, latency: &[f64]) -> SampleSet {
        let recall: Vec<f64> = latency.iter().map(|_| 1.0).collect();
        SampleSet::new(label, latency, &recall, latency.len(), 0)
    }

    /// The contract is that warm and cold are two POPULATIONS, never one
    /// average. This pins three things at once: the two sample sets keep
    /// independent percentiles, the merged population that a collapsing
    /// implementation would report appears nowhere, and the axis exposes no
    /// key that could hold a combined view.
    #[test]
    fn cold_and_warm_samples_stay_separate() {
        let cold_samples = [40.0, 50.0, 60.0, 70.0];
        let warm_samples = [1.0, 2.0, 3.0, 4.0];
        let axis = RecallLatencyAxis::new(
            10,
            FULL_RUN_MIN_INDEXED_DOCS,
            FULL_RUN_MIN_QUERIES,
            set("cold", &cold_samples),
            set("warm", &warm_samples),
            EvidenceKind::MeasuredWallClock,
        );

        let cold = axis.cold.latency_ms.value().expect("cold measured");
        let warm = axis.warm.latency_ms.value().expect("warm measured");
        assert_eq!(cold.count, 4, "cold keeps its own sample count");
        assert_eq!(warm.count, 4, "warm keeps its own sample count");
        assert!(
            (cold.p50 - 50.0).abs() < f64::EPSILON,
            "cold p50 is drawn only from cold samples, got {}",
            cold.p50
        );
        assert!(
            (warm.p50 - 2.0).abs() < f64::EPSILON,
            "warm p50 is drawn only from warm samples, got {}",
            warm.p50
        );
        assert!(
            (cold.p95 - 70.0).abs() < f64::EPSILON,
            "cold p95 is drawn only from cold samples"
        );
        assert!(
            (warm.p95 - 4.0).abs() < f64::EPSILON,
            "warm p95 is drawn only from warm samples"
        );

        // What a collapsing implementation would have produced. It must equal
        // NEITHER reported value, and must appear nowhere in the JSON.
        let mut merged: Vec<f64> = cold_samples.to_vec();
        merged.extend_from_slice(&warm_samples);
        let merged = Percentiles::from_samples(&merged).expect("merged percentiles");
        assert!((merged.p50 - 4.0).abs() < f64::EPSILON);
        assert!(
            (merged.p50 - cold.p50).abs() > f64::EPSILON,
            "the merged p50 must not be what cold reports"
        );

        let json = serde_json::to_value(&axis).expect("axis serializes");
        let object = json.as_object().expect("axis is a json object");
        for forbidden in [
            "combined",
            "overall",
            "merged",
            "average",
            "all_samples",
            "samples",
            "latency_ms",
            "recall_at_k",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "the axis must not expose `{forbidden}` at the top level; samples live only \
                 inside the separate `cold` and `warm` objects"
            );
        }
        assert!(object.contains_key("cold") && object.contains_key("warm"));
        let rendered = serde_json::to_string(&axis).expect("axis renders");
        assert!(
            !rendered.contains(&format!("{:?}", merged.mean)),
            "the merged mean must not leak into the rendered report"
        );
    }

    #[test]
    fn a_cell_without_a_measurement_is_never_zero() {
        let cell: Cell<f64> = Cell::from_option(None, "probe unavailable");
        assert!(!cell.is_measured());
        assert!(cell.value().is_none());
        let rendered = serde_json::to_string(&cell).expect("cell renders");
        assert!(rendered.contains("not_ready"), "{rendered}");
        assert!(!rendered.contains(": 0"), "{rendered}");
    }

    #[test]
    fn a_speedup_without_a_measured_baseline_is_omitted() {
        assert!(measured_speedup("candidate", Some(4.0), "baseline", None).is_none());
        assert!(measured_speedup("candidate", None, "baseline", Some(4.0)).is_none());
        assert!(measured_speedup("candidate", Some(4.0), "baseline", Some(0.0)).is_none());
        let ratio = measured_speedup("candidate", Some(4.0), "baseline", Some(2.0))
            .expect("both sides measured");
        assert!((ratio.value - 2.0).abs() < f64::EPSILON);
        assert_eq!(ratio.baseline_kind, MEASURED_WALL_CLOCK_BASELINE);
    }

    #[test]
    fn an_under_floor_full_run_reports_not_applicable_instead_of_numbers() {
        let mut axis = RecallLatencyAxis::new(
            10,
            10,
            2,
            set("cold", &[9.0, 9.0]),
            set("warm", &[1.0, 1.0]),
            EvidenceKind::MeasuredWallClock,
        );
        assert!(!axis.meets_full_run_floor);
        axis.enforce_full_run_floor();
        assert!(matches!(axis.cold.latency_ms, Cell::NotApplicable { .. }));
        assert!(matches!(axis.warm.recall_at_k, Cell::NotApplicable { .. }));
        assert!(axis.cold_over_warm_speedup.is_none());
    }
}
