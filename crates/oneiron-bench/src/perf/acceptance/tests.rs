//! Regressions for the ONE-1579 acceptance evidence.
//!
//! Split out of `acceptance.rs` so the evidence module itself stays well under
//! the repository's giant-file bar; nothing here is reachable outside
//! `cfg(test)`.

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

/// One arithmetically self-consistent curve point: the throughput cell is
/// derived from the very numerator and denominator the point carries, so the
/// fixture cannot accidentally test an untraceable row.
fn point(sessions: usize, queries: usize, wall_clock_ms: f64) -> SessionCurvePoint {
    SessionCurvePoint {
        sessions,
        workers_released: sessions,
        synchronized: true,
        queries,
        spawn_ms: 1.0,
        wall_clock_ms,
        latency_ms: Cell::from_option(Percentiles::from_samples(&[1.0]), "none"),
        throughput_qps: Cell::measured(queries as f64 / (wall_clock_ms / 1e3)),
        errors: 0,
    }
}

/// A full curve whose throughput PEAKS at 100 sessions and then falls back at
/// 300 under contention — the ordinary shape once a vault is saturated.
fn contended_curve() -> SessionsAxis {
    let mut axis = sessions();
    axis.requested_curve = REQUIRED_FULL_SESSION_CURVE.to_vec();
    axis.exact_full_curve = true;
    // 1,000 qps; 5,000 qps; 20,000 qps (the peak); 10,000 qps under contention.
    axis.curve = vec![
        point(1, 100, 100.0),
        point(10, 1_000, 200.0),
        point(100, 8_000, 400.0),
        point(300, 9_000, 900.0),
    ];
    axis
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

/// QPS copied into acceptance is backed by an exact report cell plus its
/// numerator and denominator. Synthetic, unsynchronized, erroneous, or
/// arithmetically inconsistent points remain not-ready, and QPS is never
/// promoted into ONE-1537's unrelated embed gate.
#[test]
fn measured_qps_acceptance_is_traceable_and_never_invented() {
    let mut axis = sessions();
    let point = axis.curve.first_mut().expect("fixture point");
    point.sessions = 300;
    point.workers_released = 300;
    point.synchronized = true;
    point.queries = 600;
    point.wall_clock_ms = 20.0;
    point.throughput_qps = Cell::measured(30_000.0);
    point.errors = 0;
    axis.evidence_kind = EvidenceKind::MeasuredWallClock;

    let evidence = measured_qps_evidence(&axis);
    assert!(evidence.valid_for_lifecycle_support);
    assert!(!evidence.valid_for_one_1537_embed_gate);
    assert_eq!(evidence.sessions, 300);
    assert_eq!(evidence.completed_queries_numerator.value(), Some(&600));
    assert_eq!(
        evidence.wall_clock_ms_denominator.measured_f64(),
        Some(20.0)
    );
    assert_eq!(evidence.measured_qps.measured_f64(), Some(30_000.0));
    assert_eq!(
        evidence.source_report_cell,
        "sessions.curve[sessions=300].throughput_qps"
    );
    assert!(evidence.relationship.contains("never substituted"));

    axis.curve[0].throughput_qps = Cell::measured(99_999.0);
    let invented = measured_qps_evidence(&axis);
    assert!(!invented.valid_for_lifecycle_support);
    assert!(!invented.measured_qps.is_measured());

    axis.curve[0].throughput_qps = Cell::measured(30_000.0);
    axis.curve[0].errors = 1;
    let partial = measured_qps_evidence(&axis);
    assert!(!partial.measured_qps.is_measured());

    axis.curve[0].errors = 0;
    axis.evidence_kind = EvidenceKind::SyntheticSmoke;
    let smoke = measured_qps_evidence(&axis);
    assert!(!smoke.measured_qps.is_measured());
}

/// Peak throughput is chosen by comparing MEASURED QPS, not by taking the
/// largest concurrency row. Throughput commonly peaks before the largest point
/// once contention begins, and an untraceable largest point must not erase the
/// peak the earlier points really measured.
#[test]
fn peak_throughput_is_selected_by_measured_qps_not_by_largest_concurrency() {
    let axis = contended_curve();
    let largest = axis.curve.last().expect("the 300-session point exists");
    assert_eq!(largest.sessions, 300);
    assert_eq!(largest.throughput_qps.measured_f64(), Some(10_000.0));

    let peak = measured_qps_evidence(&axis);
    assert!(peak.valid_for_lifecycle_support);
    assert_eq!(
        peak.sessions, 100,
        "the peak is the highest measured throughput, not the largest concurrency"
    );
    assert_eq!(peak.measured_qps.measured_f64(), Some(20_000.0));
    assert_eq!(peak.completed_queries_numerator.value(), Some(&8_000));
    assert_eq!(peak.wall_clock_ms_denominator.measured_f64(), Some(400.0));
    assert_eq!(
        peak.source_report_cell, "sessions.curve[sessions=100].throughput_qps",
        "the cell reference must point at the row the peak came from"
    );
    assert_eq!(peak.traceable_points, 4);
    assert_eq!(peak.largest_required_sessions, 300);
    assert!(peak.largest_required_point_traceable);

    // Losing ONLY the largest point must not blank the acceptance cell: the
    // earlier points still measured a real peak.
    let mut without_largest = contended_curve();
    without_largest.curve[3].errors = 1;
    let partial = measured_qps_evidence(&without_largest);
    assert!(
        partial.valid_for_lifecycle_support,
        "an untraceable 300-session point must not invalidate the measured peak"
    );
    assert_eq!(partial.measured_qps.measured_f64(), Some(20_000.0));
    assert_eq!(partial.sessions, 100);
    assert_eq!(partial.traceable_points, 3);
    assert!(
        !partial.largest_required_point_traceable,
        "the lost largest point stays visible in the evidence"
    );

    // Dropping it from the curve entirely behaves the same way.
    let mut absent = contended_curve();
    absent.curve.pop();
    let absent = measured_qps_evidence(&absent);
    assert_eq!(absent.measured_qps.measured_f64(), Some(20_000.0));
    assert!(!absent.largest_required_point_traceable);

    // Ties are deterministic and keep the lower concurrency: the same rate at
    // fewer sessions is the honest peak point.
    let mut tied = contended_curve();
    tied.curve[3] = point(300, 8_000, 400.0);
    let tied = measured_qps_evidence(&tied);
    assert_eq!(tied.measured_qps.measured_f64(), Some(20_000.0));
    assert_eq!(tied.sessions, 100, "a tie keeps the lower concurrency");

    // With no traceable point at all the cell is still fail-closed.
    let mut broken = contended_curve();
    for curve_point in &mut broken.curve {
        curve_point.synchronized = false;
    }
    let broken = measured_qps_evidence(&broken);
    assert!(!broken.valid_for_lifecycle_support);
    assert!(!broken.measured_qps.is_measured());
    assert_eq!(broken.traceable_points, 0);
    assert_eq!(
        broken.sessions, 300,
        "with no peak the cell still names the largest required point it looked for"
    );

    // The knob row that consumes the peak quotes exactly this cell.
    let recall = recall_latency();
    let wake = wake();
    let memory = resident_memory();
    let curve = contended_curve();
    let all = evidence(&recall, &wake, &curve, &memory);
    let hot_vault = &all.knobs[1];
    assert_eq!(hot_vault.knob, "hot_vault_extension");
    let throughput = &hot_vault.supporting_measurements[1];
    assert_eq!(throughput.metric, "peak_measured_session_throughput");
    assert_eq!(
        throughput.report_cell,
        "acceptance.measured_qps.measured_qps"
    );
    assert_eq!(throughput.measured_value.measured_f64(), Some(20_000.0));
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
