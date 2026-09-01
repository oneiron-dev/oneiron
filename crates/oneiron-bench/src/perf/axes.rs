//! ONE-1579 axis shapes and the floors they are held to.
//!
//! Each axis is its own object with its own evidence kind and its own sample
//! counts. Nothing here fuses two axes, and nothing here carries a composite
//! score — the report envelope in `report.rs` has no such field either.
//!
//! Two floors are enforced on this side rather than merely documented:
//!
//! * the PLAN floor (>=1000 indexed docs, >=100 queries) that admission
//!   already checks, and
//! * the COMPLETED-SAMPLE floor, which counts only retrieval calls that
//!   actually returned. Failed calls are omitted from [`SampleSet`], so a plan
//!   with 100 queries whose calls mostly errored can no longer present
//!   publishable percentiles drawn from a handful of survivors.

use std::collections::BTreeMap;

use serde::Serialize;

use super::cells::{Cell, EvidenceKind, Percentiles, Ratio, measured_speedup};

/// ARCH-0042-sibling contract: the exact concurrent-session curve a full run
/// must walk against ONE vault. Omitting or reordering it invalidates the plan.
pub(crate) const REQUIRED_FULL_SESSION_CURVE: [usize; 4] = [1, 10, 100, 300];
/// RAM/RSS axis is defined at exactly ten ready child processes / active vaults.
pub(crate) const REQUIRED_READY_CHILDREN: usize = 10;
/// Full-run latency/recall floor: indexed documents.
pub(crate) const FULL_RUN_MIN_INDEXED_DOCS: usize = 1_000;
/// Full-run latency/recall floor: distinct queries.
pub(crate) const FULL_RUN_MIN_QUERIES: usize = 100;
/// Full-run latency/recall floor: COMPLETED retrieval calls per sample set.
/// A call that errored is not a sample and cannot help satisfy this.
pub(crate) const FULL_RUN_MIN_COMPLETED_SAMPLES: usize = FULL_RUN_MIN_QUERIES;
/// Full-run gated-write floor: unmeasured warmup commits.
pub(crate) const FULL_RUN_MIN_GATED_WRITE_WARMUP: usize = 1_000;
/// Full-run gated-write floor: measured commits.
pub(crate) const FULL_RUN_MIN_GATED_WRITE_MEASURED: usize = 10_000;
/// ARCH-0023b per-vault RAM budget, carried as a COMPARISON SLOT only. The
/// measurement itself is the ten ready children below it, never this number.
pub(crate) const ARCH_0023B_PER_VAULT_BUDGET_MB: u64 = 50;

/// One retrieval sample set. Warm and cold each get their OWN instance; the
/// type carries no field that could hold a merged population.
///
/// `samples` counts COMPLETED calls only: a call that returned an error is
/// counted in `errors` and contributes to neither percentile nor the floor.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct SampleSet {
    pub(crate) label: &'static str,
    pub(crate) samples: usize,
    pub(crate) latency_ms: Cell<Percentiles>,
    pub(crate) recall_at_k: Cell<Percentiles>,
    pub(crate) telemetry_run_ids: usize,
    pub(crate) errors: usize,
    pub(crate) completed_sample_floor: usize,
    pub(crate) meets_completed_sample_floor: bool,
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
            completed_sample_floor: FULL_RUN_MIN_COMPLETED_SAMPLES,
            meets_completed_sample_floor: latency_samples.len()
                >= FULL_RUN_MIN_COMPLETED_SAMPLES
                && recall_samples.len() >= FULL_RUN_MIN_COMPLETED_SAMPLES,
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
    /// The plan asked for enough docs and queries.
    pub(crate) meets_plan_floor: bool,
    /// Enough calls actually COMPLETED in both sample sets.
    pub(crate) meets_completed_sample_floor: bool,
    /// Both of the above. Only this one may gate publication.
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
const FLOOR_RULE: &str = "a full run requires >=1000 indexed docs and >=100 planned queries AND \
     >=100 COMPLETED calls in each of the warm and cold sets; retrieval calls that errored are \
     counted as errors and can never help satisfy the floor";

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
        let meets_plan_floor =
            indexed_docs >= FULL_RUN_MIN_INDEXED_DOCS && queries >= FULL_RUN_MIN_QUERIES;
        let meets_completed_sample_floor =
            cold.meets_completed_sample_floor && warm.meets_completed_sample_floor;
        Self {
            k,
            indexed_docs,
            queries,
            meets_plan_floor,
            meets_completed_sample_floor,
            meets_full_run_floor: meets_plan_floor && meets_completed_sample_floor,
            floor: FLOOR_RULE,
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
    /// below either floor: latency/recall cells and the ratio become
    /// explicitly not-applicable instead of numbers.
    pub(crate) fn enforce_full_run_floor(&mut self) {
        if self.meets_full_run_floor {
            return;
        }
        let reason = format!(
            "below the full-run floor (plan: {} indexed docs, {} queries, requires \
             >={FULL_RUN_MIN_INDEXED_DOCS}/{FULL_RUN_MIN_QUERIES}; completed calls: {} cold and \
             {} warm, requires >={FULL_RUN_MIN_COMPLETED_SAMPLES} each)",
            self.indexed_docs, self.queries, self.cold.samples, self.warm.samples
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

/// Readiness rule pinned into every report.
pub(crate) const READINESS_RULE: &str = "ready == the parent's TCP accept for this child completed; child stdout/stderr is never read, \
     scanned or waited on, and no sleep stands in for readiness";
/// Shutdown rule pinned into every report carrying a child probe.
pub(crate) const CHILD_SHUTDOWN_RULE: &str = "after readiness the PARENT owns the child's lifetime: it closes the accepted stream and then \
     waits a bounded budget, terminating and reaping any child that does not exit on its own; no \
     wait on a caller-supplied child is unbounded";

/// Axis 2: process spawn-to-ready wake latency.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct WakeAxis {
    pub(crate) readiness_signal: ReadinessSignal,
    pub(crate) readiness_rule: &'static str,
    pub(crate) shutdown_rule: &'static str,
    pub(crate) accept_poll_interval_us: u64,
    pub(crate) samples: usize,
    pub(crate) spawn_to_ready_ms: Cell<Percentiles>,
    pub(crate) child: Cell<String>,
    /// How each probed child left: `exited` on its own, or
    /// `terminated_after_budget` because it outlived the bounded wait.
    pub(crate) shutdown_outcomes: BTreeMap<String, usize>,
    pub(crate) errors: Vec<String>,
    pub(crate) evidence_kind: EvidenceKind,
}

/// One point on the concurrent-session curve.
///
/// `wall_clock_ms` opens only AFTER every worker has arrived at the release
/// gate, so it measures overlapping query work and never the serial cost of
/// creating the threads. `spawn_ms` carries that excluded creation cost.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct SessionCurvePoint {
    pub(crate) sessions: usize,
    pub(crate) workers_released: usize,
    pub(crate) synchronized: bool,
    pub(crate) queries: usize,
    pub(crate) spawn_ms: f64,
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
    pub(crate) synchronization: &'static str,
    pub(crate) note: &'static str,
}

/// Synchronization rule pinned into every sessions axis.
pub(crate) const SESSION_SYNCHRONIZATION_RULE: &str = "every session worker is created first and then held at a release gate; the measurement window \
     opens only once all of them have arrived, so a curve point measures concurrent work rather \
     than staggered thread creation";

/// Axis 4: resident memory for exactly ten ready children / active vaults.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ResidentMemoryAxis {
    pub(crate) required_ready_children: usize,
    pub(crate) ready_children_observed: usize,
    pub(crate) child_holds_open_vault: bool,
    /// Every RSS sample was taken while all `required` children were still
    /// connected and alive. False turns the measurement into `not_ready`.
    pub(crate) sampled_while_all_children_ready: bool,
    pub(crate) child_hold_ms: u64,
    pub(crate) minimum_child_hold_ms: u64,
    pub(crate) per_child_rss_bytes: Cell<Vec<u64>>,
    pub(crate) total_child_rss_bytes: Cell<u64>,
    pub(crate) mean_child_rss_bytes: Cell<u64>,
    pub(crate) parent_rss_bytes: Cell<u64>,
    /// Comparison slot only. The MEASUREMENT is the ten children above.
    pub(crate) arch_0023b_per_vault_budget_mb: u64,
    pub(crate) budget_comparison: Cell<String>,
    pub(crate) shutdown_rule: &'static str,
    pub(crate) shutdown_outcomes: BTreeMap<String, usize>,
    pub(crate) errors: Vec<String>,
    pub(crate) evidence_kind: EvidenceKind,
}

/// Axis 5: gated-write throughput through the public claim door.
///
/// `commits_per_second` is derived from `commits_ok` — SUCCESSFUL commits —
/// and is `not_ready` when none succeeded. The attempt rate is reported
/// beside it under its own name so neither number can be read as the other.
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
    pub(crate) commits_per_second_numerator: &'static str,
    pub(crate) attempted_commits_per_second: Cell<f64>,
    pub(crate) commit_latency_ms: Cell<Percentiles>,
    pub(crate) failed_attempt_latency_ms: Cell<Percentiles>,
    pub(crate) gate_decisions_recorded: usize,
    pub(crate) one_decision_per_commit: bool,
    /// Zero failed commits AND exactly one ledger decision per measured
    /// commit. Publication is refused unless this holds.
    pub(crate) gate_enforcement_valid: bool,
    pub(crate) gate_outcomes: BTreeMap<String, usize>,
    pub(crate) meets_full_run_floor: bool,
    pub(crate) floor: &'static str,
    pub(crate) evidence_kind: EvidenceKind,
}

/// The write path pinned into every report: public seams only, no raw LMDB.
pub(crate) const GATED_WRITE_PATH: &str = "ClaimCandidate::new + WriteEnvelope::new -> BatchBuilder::claim_candidate -> commit; one \
     candidate per commit, no raw LMDB writes and no engine-internal door";
/// What the successful-commit throughput numerator is, pinned into the row.
pub(crate) const COMMITS_PER_SECOND_NUMERATOR: &str = "commits_ok (successful commits only); the attempt rate is reported separately as \
     attempted_commits_per_second and the two are never interchanged";
/// The gated-write floor rule pinned into the row.
pub(crate) const GATED_WRITE_FLOOR_RULE: &str = "full-run gated writes require >=1000 warmup and >=10000 measured commits";

#[cfg(test)]
mod tests {
    use super::*;

    fn set(label: &'static str, latency: &[f64]) -> SampleSet {
        let recall: Vec<f64> = latency.iter().map(|_| 1.0).collect();
        SampleSet::new(label, latency, &recall, latency.len(), 0)
    }

    fn full_set(label: &'static str, value: f64) -> SampleSet {
        let latency = vec![value; FULL_RUN_MIN_COMPLETED_SAMPLES];
        set(label, &latency)
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
    fn an_under_floor_full_run_reports_not_applicable_instead_of_numbers() {
        let mut axis = RecallLatencyAxis::new(
            10,
            10,
            2,
            set("cold", &[9.0, 9.0]),
            set("warm", &[1.0, 1.0]),
            EvidenceKind::MeasuredWallClock,
        );
        assert!(!axis.meets_plan_floor);
        assert!(!axis.meets_full_run_floor);
        axis.enforce_full_run_floor();
        assert!(matches!(axis.cold.latency_ms, Cell::NotApplicable { .. }));
        assert!(matches!(axis.warm.recall_at_k, Cell::NotApplicable { .. }));
        assert!(axis.cold_over_warm_speedup.is_none());
    }

    /// A plan that ASKED for the full query count but whose retrieval calls
    /// mostly failed must not present publishable percentiles: the floor is
    /// counted on completed calls, and the survivors are rewritten to
    /// not-applicable exactly as an under-planned run is.
    #[test]
    fn a_plan_sized_run_whose_calls_failed_does_not_satisfy_the_floor() {
        let survivors = [3.0, 4.0, 5.0];
        let recall = [1.0, 1.0, 1.0];
        let cold = SampleSet::new(
            "cold",
            &survivors,
            &recall,
            survivors.len(),
            FULL_RUN_MIN_QUERIES - survivors.len(),
        );
        let mut axis = RecallLatencyAxis::new(
            10,
            FULL_RUN_MIN_INDEXED_DOCS,
            FULL_RUN_MIN_QUERIES,
            cold,
            full_set("warm", 1.0),
            EvidenceKind::MeasuredWallClock,
        );

        assert!(
            axis.meets_plan_floor,
            "the PLAN did ask for the full query count"
        );
        assert!(
            !axis.cold.meets_completed_sample_floor,
            "three completed calls cannot satisfy a hundred-sample floor"
        );
        assert!(
            axis.warm.meets_completed_sample_floor,
            "the warm set did complete its calls"
        );
        assert!(
            !axis.meets_completed_sample_floor && !axis.meets_full_run_floor,
            "one starved set is enough to fail the axis floor"
        );
        assert_eq!(axis.cold.errors, FULL_RUN_MIN_QUERIES - survivors.len());

        axis.enforce_full_run_floor();
        assert!(
            matches!(axis.cold.latency_ms, Cell::NotApplicable { .. }),
            "percentiles over three survivors must not be published"
        );
        assert!(matches!(axis.warm.latency_ms, Cell::NotApplicable { .. }));
        assert!(axis.cold_over_warm_speedup.is_none());
    }

    /// The happy path still passes: a fully completed, plan-sized run keeps
    /// its numbers.
    #[test]
    fn a_fully_completed_plan_sized_run_keeps_its_numbers() {
        let mut axis = RecallLatencyAxis::new(
            10,
            FULL_RUN_MIN_INDEXED_DOCS,
            FULL_RUN_MIN_QUERIES,
            full_set("cold", 9.0),
            full_set("warm", 1.0),
            EvidenceKind::MeasuredWallClock,
        );
        assert!(axis.meets_plan_floor && axis.meets_completed_sample_floor);
        assert!(axis.meets_full_run_floor);
        axis.enforce_full_run_floor();
        assert!(axis.cold.latency_ms.is_measured());
        assert!(axis.warm.latency_ms.is_measured());
        assert!(axis.cold_over_warm_speedup.is_some());
    }
}
