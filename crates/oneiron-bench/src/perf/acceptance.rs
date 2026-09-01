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

use super::axes::{RecallLatencyAxis, ResidentMemoryAxis, SessionsAxis, WakeAxis};
use super::cells::Cell;

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
    pub(crate) embed_latency_gate: EmbedLatencyRelationship,
    pub(crate) beam_boundary: &'static str,
}

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
        Self {
            knob_ticket: KNOB_TICKET,
            knob_ticket_url: KNOB_TICKET_URL,
            knob_rule: KNOB_RULE,
            knobs: knob_rows(inputs),
            embed_latency_gate: embed_latency_relationship(inputs.recall_latency),
            beam_boundary: BEAM_BOUNDARY,
        }
    }
}

fn knob_rows(inputs: &AcceptanceInputs<'_>) -> Vec<KnobMeasurement> {
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
            vec![resident_mean(inputs), peak_throughput(inputs)],
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

fn peak_throughput(inputs: &AcceptanceInputs<'_>) -> SupportingMeasurement {
    let measured = inputs
        .sessions
        .curve
        .iter()
        .max_by_key(|point| point.sessions)
        .and_then(|point| point.throughput_qps.measured_f64());
    support(
        "peak_session_curve_throughput",
        "sessions.curve[peak].throughput_qps",
        measured,
        "queries_per_second",
        "no session-curve point produced measured throughput",
    )
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
mod tests {
    use std::collections::BTreeMap;

    use super::super::axes::{
        CHILD_SHUTDOWN_RULE, FULL_RUN_MIN_COMPLETED_SAMPLES, FULL_RUN_MIN_INDEXED_DOCS,
        FULL_RUN_MIN_QUERIES, READINESS_RULE, REQUIRED_FULL_SESSION_CURVE, REQUIRED_READY_CHILDREN,
        ReadinessSignal, SESSION_SYNCHRONIZATION_RULE, SampleSet, SessionCurvePoint,
    };
    use super::super::cells::{EvidenceKind, Percentiles};
    use super::*;

    fn recall_latency() -> RecallLatencyAxis {
        let latency = vec![2.0; FULL_RUN_MIN_COMPLETED_SAMPLES];
        let recall = vec![1.0; FULL_RUN_MIN_COMPLETED_SAMPLES];
        RecallLatencyAxis::new(
            10,
            FULL_RUN_MIN_INDEXED_DOCS,
            FULL_RUN_MIN_QUERIES,
            SampleSet::new("cold", &latency, &recall, latency.len(), 0),
            SampleSet::new("warm", &latency, &recall, latency.len(), 0),
            EvidenceKind::MeasuredWallClock,
        )
    }

    fn wake() -> WakeAxis {
        WakeAxis {
            readiness_signal: ReadinessSignal::TcpAccept,
            readiness_rule: READINESS_RULE,
            shutdown_rule: CHILD_SHUTDOWN_RULE,
            accept_poll_interval_us: 100,
            samples: 2,
            spawn_to_ready_ms: Cell::from_option(
                Percentiles::from_samples(&[3.0, 4.0]),
                "test wake samples",
            ),
            child: Cell::measured("oneiron-bench perf wake-child".to_owned()),
            shutdown_outcomes: BTreeMap::from([("exited".to_owned(), 2)]),
            errors: Vec::new(),
            evidence_kind: EvidenceKind::MeasuredWallClock,
        }
    }

    fn sessions() -> SessionsAxis {
        SessionsAxis {
            vaults: 1,
            required_full_curve: REQUIRED_FULL_SESSION_CURVE,
            requested_curve: vec![1, 10],
            exact_full_curve: false,
            curve: vec![SessionCurvePoint {
                sessions: 10,
                workers_released: 10,
                synchronized: true,
                queries: 40,
                spawn_ms: 1.0,
                wall_clock_ms: 20.0,
                latency_ms: Cell::from_option(Percentiles::from_samples(&[1.0]), "none"),
                throughput_qps: Cell::measured(2_000.0),
                errors: 0,
            }],
            evidence_kind: EvidenceKind::MeasuredWallClock,
            synchronization: SESSION_SYNCHRONIZATION_RULE,
            note: "test",
        }
    }

    fn resident_memory() -> ResidentMemoryAxis {
        ResidentMemoryAxis {
            required_ready_children: REQUIRED_READY_CHILDREN,
            ready_children_observed: REQUIRED_READY_CHILDREN,
            child_holds_open_vault: true,
            vault_residency_evidence: "harness-owned wake-child opened every vault",
            sampled_while_all_children_ready: true,
            child_hold_ms: 30_000,
            minimum_child_hold_ms: 25_000,
            per_child_rss_bytes: Cell::measured(vec![1_024; REQUIRED_READY_CHILDREN]),
            total_child_rss_bytes: Cell::measured(10_240),
            mean_child_rss_bytes: Cell::measured(1_024),
            parent_rss_bytes: Cell::measured(2_048),
            arch_0023b_per_vault_budget_mb: 50,
            budget_comparison: Cell::measured("test".to_owned()),
            shutdown_rule: CHILD_SHUTDOWN_RULE,
            shutdown_outcomes: BTreeMap::from([("exited".to_owned(), REQUIRED_READY_CHILDREN)]),
            errors: Vec::new(),
            evidence_kind: EvidenceKind::MeasuredWallClock,
        }
    }

    fn evidence<'a>(
        recall: &'a RecallLatencyAxis,
        wake: &'a WakeAxis,
        sessions: &'a SessionsAxis,
        memory: &'a ResidentMemoryAxis,
    ) -> AcceptanceEvidence {
        AcceptanceEvidence::collect(&AcceptanceInputs {
            recall_latency: recall,
            wake,
            sessions,
            resident_memory: memory,
        })
    }

    /// The acceptance section names ONE-1578's actual lifecycle knobs, not
    /// unrelated retrieval or precision parameters. Each proposal is linked,
    /// distinguished from direct evidence, and supported only by measured
    /// report cells that really exist in this run.
    #[test]
    fn acceptance_structures_the_five_one_1578_knob_relationships() {
        let recall = recall_latency();
        let wake = wake();
        let sessions = sessions();
        let memory = resident_memory();
        let evidence = evidence(&recall, &wake, &sessions, &memory);

        assert_eq!(evidence.knob_ticket, "ONE-1578");
        assert_eq!(evidence.knob_ticket_url, KNOB_TICKET_URL);
        let proposals: Vec<(&str, u64, &str)> = evidence
            .knobs
            .iter()
            .map(|knob| (knob.knob, knob.proposed_setting, knob.proposed_setting_unit))
            .collect();
        assert_eq!(
            proposals,
            vec![
                ("idle_ttl", 15, "minutes"),
                ("hot_vault_extension", 60, "minutes_maximum"),
                ("reap_lookahead", 5, "minutes"),
                ("spawn_concurrency_cap", 8, "child_processes"),
                ("sigkill_grace", 30, "seconds"),
            ]
        );
        for knob in &evidence.knobs {
            assert_eq!(knob.ticket, "ONE-1578");
            assert_eq!(knob.ticket_url, KNOB_TICKET_URL);
            assert!(!knob.directly_exercised_by_this_harness);
            assert!(
                !knob.direct_measurement.is_measured(),
                "{} must not turn its proposal into a measurement",
                knob.knob
            );
            assert!(!knob.supporting_measurements.is_empty(), "{}", knob.knob);
            assert!(
                knob.supporting_measurements
                    .iter()
                    .all(|measurement| !measurement.report_cell.is_empty()),
                "{} must point at traceable report cells",
                knob.knob
            );
            assert!(!knob.relationship.is_empty());
        }
        let idle = &evidence.knobs[0];
        assert!(
            idle.supporting_measurements
                .iter()
                .all(|measurement| measurement.measured_value.is_measured()),
            "the fixture measured wake p95 and proven per-vault RSS"
        );
    }

    /// ONE-1537 owns a strict single-query embed p95 gate. Warm retrieval p95
    /// is carried as a separate downstream component and never substituted for
    /// the missing external embedding measurement.
    #[test]
    fn one_1537_relationship_is_linked_and_never_invented() {
        let recall = recall_latency();
        let relationship = embed_latency_relationship(&recall);

        assert_eq!(relationship.gate_ticket, "ONE-1537");
        assert_eq!(relationship.gate_ticket_url, EMBED_LATENCY_GATE_URL);
        assert_eq!(
            relationship.required_metric,
            "oneironer_single_query_embed_p95_ms"
        );
        assert_eq!(relationship.acceptance_operator, "less_than");
        assert!((relationship.budget_ms - 50.0).abs() < f64::EPSILON);
        assert!(!relationship.measured_by_this_harness);
        assert_eq!(
            relationship.in_harness_report_cell,
            "recall_latency.warm.latency_ms.p95"
        );
        assert_eq!(relationship.warm_retrieval_p95_ms.measured_f64(), Some(2.0));
        assert!(relationship.relationship.contains("never added"));

        match (
            declared_embed_latency_p95_ms(),
            declared_embed_latency_reference(),
        ) {
            (Some(external), Some(reference)) => {
                assert_eq!(
                    relationship.external_embed_p95_ms.measured_f64(),
                    Some(external)
                );
                assert_eq!(
                    relationship.external_evidence_reference.value(),
                    Some(&reference)
                );
                assert_eq!(
                    relationship
                        .external_measurement_within_gate
                        .value()
                        .copied(),
                    Some(external < EMBED_LATENCY_BUDGET_MS)
                );
                assert_eq!(
                    relationship.external_gate_headroom_ms.measured_f64(),
                    Some(EMBED_LATENCY_BUDGET_MS - external)
                );
            }
            _ => {
                assert!(!relationship.external_embed_p95_ms.is_measured());
                assert!(!relationship.external_gate_headroom_ms.is_measured());
                assert!(!relationship.external_measurement_within_gate.is_measured());
                let rendered = serde_json::to_string(&relationship).expect("relationship renders");
                assert!(
                    rendered.contains(EMBED_LATENCY_MEASUREMENT_ENV),
                    "{rendered}"
                );
                assert!(rendered.contains(EMBED_LATENCY_REFERENCE_ENV), "{rendered}");
                assert!(rendered.contains(EMBED_LATENCY_GATE_URL), "{rendered}");
            }
        }
    }

    /// Even measured process RSS is not per-vault support when a custom child
    /// command has only proved TCP readiness.
    #[test]
    fn custom_child_rss_is_not_promoted_to_one_1578_vault_residency_evidence() {
        let recall = recall_latency();
        let wake = wake();
        let sessions = sessions();
        let mut memory = resident_memory();
        memory.child_holds_open_vault = false;
        memory.vault_residency_evidence = "custom child proved TCP readiness only";
        let evidence = evidence(&recall, &wake, &sessions, &memory);
        let idle_rss = &evidence.knobs[0].supporting_measurements[1];
        assert_eq!(idle_rss.metric, "mean_rss_per_proven_active_vault");
        assert!(
            !idle_rss.measured_value.is_measured(),
            "opaque custom-child RSS must not become per-vault evidence"
        );
    }
}
