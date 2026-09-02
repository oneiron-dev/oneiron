//! ONE-1579 acceptance evidence: structured support for the five ONE-1578
//! lifecycle knobs, and the exact relationship to ONE-1537's narrower
//! single-query embedding-latency gate.
//!
//! ONE-1578 proposes idle TTL, hot-vault extension, reap lookahead, spawn cap
//! and SIGKILL grace. This bench does not run the supervisor, so it never says
//! that those knob values were directly exercised. Instead every knob row
//! carries its traceable proposal, the report cells this run actually measured
//! that inform the decision, and an explicit statement of the evidence still
//! outside this harness. A setting is never copied into a measurement slot.
//!
//! ONE-1537 requires a separate Oneironer single-query embed p95 measurement
//! against its <50 ms budget. This harness runs a TEXT-ONLY vault and issues no
//! embedding call. It therefore carries the canonical ticket link, metric and
//! budget, accepts an external p95 only through a declared evidence input, and
//! reports the in-harness warm retrieval p95 beside it as a separate serial
//! component. It never adds percentiles or invents an embedding number.

use serde::Serialize;

use super::axes::{
    REQUIRED_FULL_SESSION_CURVE, RecallLatencyAxis, ResidentMemoryAxis, SessionCurvePoint,
    SessionsAxis, WakeAxis,
};
use super::cells::{Cell, EvidenceKind};

/// The ticket whose five supervisor lifecycle knobs need measurement support.
pub(crate) const KNOB_TICKET: &str = "ONE-1578";
pub(crate) const KNOB_TICKET_URL: &str = "https://linear.app/oneiron/issue/ONE-1578/infra-6-node-supervisor-vault-process-lifecycle-wake-reap-wake-ledger";
/// The ticket that owns the narrower Oneironer embed-latency acceptance gate.
pub(crate) const EMBED_LATENCY_GATE_TICKET: &str = "ONE-1537";
pub(crate) const EMBED_LATENCY_GATE_URL: &str = "https://linear.app/oneiron/issue/ONE-1537/infra-5-oneironer-serving-bench-gate-int8-cpu-measure-vs-d10-budgets";
/// ONE-1537's stated budget. This is the ticket's acceptance threshold, not a
/// benchmark result invented by ONE-1579.
pub(crate) const EMBED_LATENCY_BUDGET_MS: f64 = 50.0;
/// Environment variable declaring a traceable external ONE-1537 single-query
/// embedding p95 measurement for the same target node.
pub(crate) const EMBED_LATENCY_MEASUREMENT_ENV: &str = "ONEIRON_BENCH_ONE_1537_EMBED_P95_MS";
/// Evidence reference paired with the declared external measurement (artifact
/// URI, run id, or immutable result path). A number without this reference is
/// not promoted into the report as traceable evidence.
pub(crate) const EMBED_LATENCY_REFERENCE_ENV: &str = "ONEIRON_BENCH_ONE_1537_REF";

const EMBED_RELATIONSHIP: &str = "ONE-1537 owns a separate Oneironer single-query embedding p95 measurement against its <50 ms budget; this text-only harness issues no embedding call, so warm retrieval p95 is a separate downstream serial component, not a substitute for embed p95, and the two percentiles are never added into a fabricated end-to-end percentile";
const KNOB_RULE: &str = "ONE-1578's five v1 proposals are named and linked exactly; each row distinguishes the proposed setting, direct supervisor evidence (not measured here), and supporting cells actually measured by this report, so no proposal is restated as a benchmark result";
const DIRECT_KNOB_MEASUREMENT_MISSING: &str = "this bench does not run the node supervisor or a lifecycle policy sweep, so the knob value was not directly exercised; use the linked supporting measurements and the traceable ONE-1578 proposal without treating either as a direct knob result";

/// One cell from this report that informs (but does not directly exercise) a
/// ONE-1578 lifecycle knob.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct SupportingMeasurement {
    pub(crate) metric: &'static str,
    pub(crate) report_cell: &'static str,
    pub(crate) measured_value: Cell<f64>,
    pub(crate) unit: &'static str,
}

/// One of ONE-1578's five v1 lifecycle knob proposals and the exact evidence
/// ONE-1579 can provide for it without running the supervisor.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct KnobMeasurement {
    pub(crate) knob: &'static str,
    pub(crate) ticket: &'static str,
    pub(crate) ticket_url: &'static str,
    pub(crate) proposed_setting: u64,
    pub(crate) proposed_setting_unit: &'static str,
    pub(crate) directly_exercised_by_this_harness: bool,
    pub(crate) direct_measurement: Cell<f64>,
    pub(crate) supporting_measurements: Vec<SupportingMeasurement>,
    pub(crate) relationship: &'static str,
}

/// How this report relates to the ONE-1537 embed-latency acceptance gate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct EmbedLatencyRelationship {
    pub(crate) gate_ticket: &'static str,
    pub(crate) gate_ticket_url: &'static str,
    pub(crate) required_metric: &'static str,
    pub(crate) acceptance_operator: &'static str,
    pub(crate) budget_ms: f64,
    /// Always false: no embedding call is made anywhere in this harness.
    pub(crate) measured_by_this_harness: bool,
    pub(crate) relationship: &'static str,
    pub(crate) external_measurement_source: &'static str,
    pub(crate) external_evidence_reference_source: &'static str,
    pub(crate) external_evidence_reference: Cell<String>,
    pub(crate) external_embed_p95_ms: Cell<f64>,
    pub(crate) external_gate_headroom_ms: Cell<f64>,
    pub(crate) external_measurement_within_gate: Cell<bool>,
    pub(crate) in_harness_metric: &'static str,
    pub(crate) in_harness_report_cell: &'static str,
    pub(crate) warm_retrieval_p95_ms: Cell<f64>,
}

/// The structured acceptance envelope carried by every report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct AcceptanceEvidence {
    pub(crate) knob_ticket: &'static str,
    pub(crate) knob_ticket_url: &'static str,
    pub(crate) knob_rule: &'static str,
    pub(crate) knobs: Vec<KnobMeasurement>,
    /// Exact, auditable QPS support for lifecycle sizing. It is explicitly not
    /// promoted into ONE-1537's different embed-latency acceptance gate.
    pub(crate) measured_qps: MeasuredQpsEvidence,
    pub(crate) embed_latency_gate: EmbedLatencyRelationship,
    pub(crate) beam_boundary: &'static str,
}

/// Trace from one synchronized, error-free session point to the PEAK measured
/// QPS copied into acceptance. The numerator and denominator are carried beside
/// the value so a consumer can reproduce it; an invalid/synthetic point becomes
/// `not_ready`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct MeasuredQpsEvidence {
    pub(crate) lifecycle_ticket: &'static str,
    pub(crate) lifecycle_ticket_url: &'static str,
    pub(crate) related_embed_gate_ticket: &'static str,
    pub(crate) related_embed_gate_url: &'static str,
    pub(crate) source_report_cell: String,
    /// Concurrency of the point the peak was actually measured at.
    pub(crate) sessions: usize,
    pub(crate) completed_queries_numerator: Cell<usize>,
    pub(crate) wall_clock_ms_denominator: Cell<f64>,
    pub(crate) measured_qps: Cell<f64>,
    pub(crate) evidence_kind: EvidenceKind,
    /// How many curve points were admissible evidence at all.
    pub(crate) traceable_points: usize,
    /// The largest concurrency a full curve must walk, carried so a reader can
    /// see whether the peak came from it or from an earlier point.
    pub(crate) largest_required_sessions: usize,
    /// Whether that largest point was itself traceable. It is reported rather
    /// than used as a gate here: losing it does not erase a peak the earlier
    /// points really measured. The separate `session_curve_complete`
    /// publication check is what refuses an incomplete curve.
    pub(crate) largest_required_point_traceable: bool,
    pub(crate) peak_selection_rule: &'static str,
    pub(crate) valid_for_lifecycle_support: bool,
    pub(crate) valid_for_one_1537_embed_gate: bool,
    pub(crate) derivation: &'static str,
    pub(crate) relationship: &'static str,
}

const PEAK_QPS_RULE: &str = "peak throughput is the HIGHEST measured throughput_qps among this \
     run's traceable session points, compared by measured QPS rather than taken from whichever \
     point carried the largest concurrency: throughput commonly peaks before the largest point \
     once contention begins, and an untraceable largest point never erases the peak the earlier \
     points did measure; ties keep the lower concurrency, which reached that rate with fewer \
     sessions";

const BEAM_BOUNDARY: &str = "BEAM keeps accuracy and cost; nothing in this acceptance block restates, re-weights or \
     summarises a BEAM figure, and no knob row is an accuracy claim";

/// Everything the acceptance block reads. All of it is already-measured axis
/// state; this type never re-runs a workload.
pub(crate) struct AcceptanceInputs<'a> {
    pub(crate) recall_latency: &'a RecallLatencyAxis,
    pub(crate) wake: &'a WakeAxis,
    pub(crate) sessions: &'a SessionsAxis,
    pub(crate) resident_memory: &'a ResidentMemoryAxis,
}

impl AcceptanceEvidence {
    pub(crate) fn collect(inputs: &AcceptanceInputs<'_>) -> Self {
        let measured_qps = measured_qps_evidence(inputs.sessions);
        Self {
            knob_ticket: KNOB_TICKET,
            knob_ticket_url: KNOB_TICKET_URL,
            knob_rule: KNOB_RULE,
            knobs: knob_rows(inputs, &measured_qps),
            measured_qps,
            embed_latency_gate: embed_latency_relationship(inputs.recall_latency),
            beam_boundary: BEAM_BOUNDARY,
        }
    }
}

fn knob_rows(
    inputs: &AcceptanceInputs<'_>,
    measured_qps: &MeasuredQpsEvidence,
) -> Vec<KnobMeasurement> {
    vec![
        knob(
            "idle_ttl",
            15,
            "minutes",
            vec![wake_p95(inputs), resident_mean(inputs)],
            "the keep-alive cost is informed by proven per-vault RSS and the reap-then-wake cost by process wake p95; this run does not contain the idle-arrival distribution needed to select or validate a 15-minute TTL",
        ),
        knob(
            "hot_vault_extension",
            60,
            "minutes_maximum",
            vec![resident_mean(inputs), peak_throughput(measured_qps)],
            "active-vault RSS and the peak synchronized session point quantify costs while a vault is hot; this run does not apply a 60-minute extension or observe a hot-vault inter-arrival distribution",
        ),
        knob(
            "reap_lookahead",
            5,
            "minutes",
            vec![wake_p95(inputs)],
            "wake p95 quantifies one consequence of reaping before a due alarm, but this harness reads no wake ledger and therefore does not exercise or validate the five-minute lookahead",
        ),
        knob(
            "spawn_concurrency_cap",
            8,
            "child_processes",
            vec![ready_children(inputs), wake_p95(inputs)],
            "the report proves how many child processes were simultaneously ready and measures sequential spawn-to-ready samples; it does not run a supervisor with eight concurrent spawn slots, so the cap itself remains direct external lifecycle evidence",
        ),
        knob(
            "sigkill_grace",
            30,
            "seconds",
            vec![exited_children(inputs)],
            "the benchmark records whether released helper children exit inside its own bounded cleanup budget, but it does not send the supervisor's SIGTERM protocol or wait the proposed 30-second SIGKILL grace",
        ),
    ]
}

fn wake_p95(inputs: &AcceptanceInputs<'_>) -> SupportingMeasurement {
    support(
        "process_spawn_to_tcp_ready_p95",
        "wake.spawn_to_ready_ms.p95",
        inputs
            .wake
            .spawn_to_ready_ms
            .value()
            .map(|percentiles| percentiles.p95),
        "milliseconds",
        "the wake axis did not produce a complete TCP-ready latency distribution",
    )
}

fn resident_mean(inputs: &AcceptanceInputs<'_>) -> SupportingMeasurement {
    let measured = if inputs.resident_memory.child_holds_open_vault {
        inputs
            .resident_memory
            .mean_child_rss_bytes
            .value()
            .copied()
            .map(|bytes| bytes as f64)
    } else {
        None
    };
    support(
        "mean_rss_per_proven_active_vault",
        "resident_memory.mean_child_rss_bytes",
        measured,
        "bytes",
        "no complete harness-owned child cohort proved both RSS and open-vault residency",
    )
}

fn peak_throughput(evidence: &MeasuredQpsEvidence) -> SupportingMeasurement {
    support(
        "peak_measured_session_throughput",
        "acceptance.measured_qps.measured_qps",
        evidence.measured_qps.measured_f64(),
        "queries_per_second",
        "no session point produced traceable measured-wall-clock QPS to take a peak from",
    )
}

/// One curve point is admissible acceptance evidence only when its whole row is
/// internally consistent: every worker released together, no query error, and a
/// throughput that reproduces from its own numerator and denominator.
fn point_is_traceable(point: &SessionCurvePoint) -> bool {
    let reported = point.throughput_qps.measured_f64();
    let timed = point.wall_clock_ms.is_finite() && point.wall_clock_ms > 0.0;
    let derived =
        (timed && point.queries > 0).then(|| point.queries as f64 / (point.wall_clock_ms / 1e3));
    let rate_agrees = reported.zip(derived).is_some_and(|(reported, derived)| {
        reported.is_finite()
            && reported > 0.0
            && (reported - derived).abs() <= f64::EPSILON * reported.abs().max(derived.abs()) * 8.0
    });
    point.workers_released == point.sessions
        && point.synchronized
        && point.errors == 0
        && rate_agrees
}

/// The traceable point with the highest MEASURED throughput. Ties keep the
/// lower concurrency: reaching the same rate with fewer sessions is the honest
/// peak point, and the choice is deterministic rather than curve-order dependent.
fn peak_point<'a>(traceable: &[&'a SessionCurvePoint]) -> Option<&'a SessionCurvePoint> {
    traceable.iter().copied().reduce(|best, point| {
        let best_qps = best.throughput_qps.measured_f64().unwrap_or(f64::MIN);
        let point_qps = point.throughput_qps.measured_f64().unwrap_or(f64::MIN);
        if point_qps > best_qps || (point_qps == best_qps && point.sessions < best.sessions) {
            point
        } else {
            best
        }
    })
}

fn measured_qps_evidence(sessions: &SessionsAxis) -> MeasuredQpsEvidence {
    let largest = REQUIRED_FULL_SESSION_CURVE
        .last()
        .copied()
        .unwrap_or_default();
    let measured_kind = sessions.evidence_kind == EvidenceKind::MeasuredWallClock;
    let traceable: Vec<&SessionCurvePoint> = if measured_kind {
        sessions
            .curve
            .iter()
            .filter(|point| point_is_traceable(point))
            .collect()
    } else {
        Vec::new()
    };
    let peak = peak_point(&traceable);
    let valid = peak.is_some();
    let reason = if measured_kind {
        format!(
            "none of the {} emitted session point(s) released all of its workers together, \
             completed every query without error, and reproduced its throughput_qps from \
             completed_queries / wall_clock_seconds, so there is no measured peak to report",
            sessions.curve.len()
        )
    } else {
        "the session curve is synthetic smoke rather than publishable measured-wall-clock evidence"
            .to_owned()
    };
    MeasuredQpsEvidence {
        lifecycle_ticket: KNOB_TICKET,
        lifecycle_ticket_url: KNOB_TICKET_URL,
        related_embed_gate_ticket: EMBED_LATENCY_GATE_TICKET,
        related_embed_gate_url: EMBED_LATENCY_GATE_URL,
        source_report_cell: format!(
            "sessions.curve[sessions={}].throughput_qps",
            peak.map_or(largest, |point| point.sessions)
        ),
        sessions: peak.map_or(largest, |point| point.sessions),
        completed_queries_numerator: Cell::from_option(peak.map(|point| point.queries), &reason),
        wall_clock_ms_denominator: Cell::from_option(
            peak.map(|point| point.wall_clock_ms),
            &reason,
        ),
        measured_qps: Cell::from_option(
            peak.and_then(|point| point.throughput_qps.measured_f64()),
            &reason,
        ),
        evidence_kind: sessions.evidence_kind,
        traceable_points: traceable.len(),
        largest_required_sessions: largest,
        largest_required_point_traceable: traceable.iter().any(|p| p.sessions == largest),
        peak_selection_rule: PEAK_QPS_RULE,
        valid_for_lifecycle_support: valid,
        valid_for_one_1537_embed_gate: false,
        derivation: "the peak point's queries / (its wall_clock_ms / 1000), selected by comparing measured throughput_qps across every traceable point; each candidate must release all of its workers together, complete every query without error, and carry measured_wall_clock evidence",
        relationship: "this QPS is traceable support for ONE-1578 lifecycle sizing only; ONE-1537 owns a different Oneironer single-query embed-p95 gate, so the QPS is never substituted for or combined with that acceptance measurement",
    }
}

fn ready_children(inputs: &AcceptanceInputs<'_>) -> SupportingMeasurement {
    support(
        "simultaneously_ready_child_processes",
        "resident_memory.ready_children_observed",
        inputs
            .resident_memory
            .sampled_while_all_children_ready
            .then_some(inputs.resident_memory.ready_children_observed as f64),
        "child_processes",
        "no complete ready-child cohort was sampled",
    )
}

fn exited_children(inputs: &AcceptanceInputs<'_>) -> SupportingMeasurement {
    support(
        "children_exited_inside_benchmark_shutdown_budget",
        "resident_memory.shutdown_outcomes.exited",
        inputs
            .resident_memory
            .sampled_while_all_children_ready
            .then_some(
                inputs
                    .resident_memory
                    .shutdown_outcomes
                    .get("exited")
                    .copied()
                    .unwrap_or(0) as f64,
            ),
        "child_processes",
        "no complete ready-child cohort reached the bounded release phase",
    )
}

fn knob(
    knob: &'static str,
    proposed_setting: u64,
    proposed_setting_unit: &'static str,
    supporting_measurements: Vec<SupportingMeasurement>,
    relationship: &'static str,
) -> KnobMeasurement {
    KnobMeasurement {
        knob,
        ticket: KNOB_TICKET,
        ticket_url: KNOB_TICKET_URL,
        proposed_setting,
        proposed_setting_unit,
        directly_exercised_by_this_harness: false,
        direct_measurement: Cell::not_ready(format!("{knob}: {DIRECT_KNOB_MEASUREMENT_MISSING}")),
        supporting_measurements,
        relationship,
    }
}

fn support(
    metric: &'static str,
    report_cell: &'static str,
    measured: Option<f64>,
    unit: &'static str,
    missing: &'static str,
) -> SupportingMeasurement {
    SupportingMeasurement {
        metric,
        report_cell,
        measured_value: Cell::from_option(measured, missing),
        unit,
    }
}

fn embed_latency_relationship(recall_latency: &RecallLatencyAxis) -> EmbedLatencyRelationship {
    let declared_p95 = declared_embed_latency_p95_ms();
    let external_reference = declared_embed_latency_reference();
    let external_p95 = declared_p95
        .zip(external_reference.as_ref())
        .map(|(p95, _)| p95);
    let external_headroom = external_p95.map(|measured| EMBED_LATENCY_BUDGET_MS - measured);
    let warm_p95 = recall_latency
        .warm
        .latency_ms
        .value()
        .map(|percentiles| percentiles.p95);
    EmbedLatencyRelationship {
        gate_ticket: EMBED_LATENCY_GATE_TICKET,
        gate_ticket_url: EMBED_LATENCY_GATE_URL,
        required_metric: "oneironer_single_query_embed_p95_ms",
        acceptance_operator: "less_than",
        budget_ms: EMBED_LATENCY_BUDGET_MS,
        measured_by_this_harness: false,
        relationship: EMBED_RELATIONSHIP,
        external_measurement_source: EMBED_LATENCY_MEASUREMENT_ENV,
        external_evidence_reference_source: EMBED_LATENCY_REFERENCE_ENV,
        external_evidence_reference: Cell::from_option(
            external_reference,
            format!(
                "no traceable external {EMBED_LATENCY_GATE_TICKET} artifact reference was \
                 declared via {EMBED_LATENCY_REFERENCE_ENV}"
            ),
        ),
        external_embed_p95_ms: Cell::from_option(
            external_p95,
            format!(
                "a traceable external {EMBED_LATENCY_GATE_TICKET} single-query embed p95 needs \
                 BOTH a positive finite number in {EMBED_LATENCY_MEASUREMENT_ENV} and its run or \
                 artifact reference in {EMBED_LATENCY_REFERENCE_ENV}; this text-only harness \
                 makes no embedding call and will not invent either"
            ),
        ),
        external_gate_headroom_ms: Cell::from_option(
            external_headroom,
            format!(
                "headroom against the traceable {EMBED_LATENCY_BUDGET_MS} ms ticket budget needs \
                 an external {EMBED_LATENCY_GATE_TICKET} embed p95 measurement"
            ),
        ),
        external_measurement_within_gate: Cell::from_option(
            external_p95.map(|measured| measured < EMBED_LATENCY_BUDGET_MS),
            "no external embed p95 exists to compare with ONE-1537's strict <50 ms budget",
        ),
        in_harness_metric: "text_only_warm_retrieval_p95_ms",
        in_harness_report_cell: "recall_latency.warm.latency_ms.p95",
        warm_retrieval_p95_ms: Cell::from_option(
            warm_p95,
            "the separate in-harness warm retrieval p95 was not measured in this run",
        ),
    }
}

fn declared_embed_latency_p95_ms() -> Option<f64> {
    let raw = std::env::var(EMBED_LATENCY_MEASUREMENT_ENV).ok()?;
    let parsed: f64 = raw.trim().parse().ok()?;
    if parsed.is_finite() && parsed > 0.0 {
        return Some(parsed);
    }
    None
}

fn declared_embed_latency_reference() -> Option<String> {
    let raw = std::env::var(EMBED_LATENCY_REFERENCE_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_owned())
}

#[cfg(test)]
mod tests;
