//! ONE-1579 acceptance evidence: the ONE-1578 knobs this harness turns, and
//! the relationship between what it measures and the ONE-1537 embed-latency
//! gate.
//!
//! This block exists so a consumer does not have to READ PROSE off a generic
//! axis to answer "which knob did you turn, and what did it cost". Every knob
//! row names the plan setting it was run at, the dotted path of the report
//! cell that answers for it, and that cell's measured value — pulled out of
//! the axes that were actually measured, never restated by hand.
//!
//! The ONE-1537 relationship is deliberately fail-closed. This harness runs a
//! TEXT-ONLY vault: it never issues an embedding call, so it does not and
//! cannot measure embed latency. Rather than invent a number, it says so, and
//! it compares its measured warm retrieval p50 against an embed-latency gate
//! only when an authoritative figure is DECLARED for the run. With no declared
//! gate the comparison is `not_ready`, exactly like any other unmeasured cell.

use serde::Serialize;

use super::axes::{GatedWriteAxis, RecallLatencyAxis, ResidentMemoryAxis, SessionsAxis};
use super::cells::Cell;
use super::precision::PrecisionAxis;

/// The ticket whose knob settings this harness sweeps.
pub(crate) const KNOB_TICKET: &str = "ONE-1578";
/// The ticket that owns the embed-latency acceptance gate.
pub(crate) const EMBED_LATENCY_GATE_TICKET: &str = "ONE-1537";
/// Environment variable declaring the authoritative ONE-1537 embed-latency
/// gate, in milliseconds, for the host this run happened on.
pub(crate) const EMBED_LATENCY_GATE_ENV: &str = "ONEIRON_BENCH_EMBED_LATENCY_GATE_MS";

const EMBED_RELATIONSHIP: &str = "this harness runs a TEXT-ONLY vault and issues no embedding call, so it does not measure the \
     ONE-1537 embed-latency gate and never restates it; the relationship is one of consumption — \
     retrieval latency measured here is paid AFTER whatever the embed gate admits, so a warm \
     retrieval p50 is only meaningful beside a separately owned embed-latency figure, which must \
     be declared for the run rather than derived from it";
const KNOB_RULE: &str = "each row names the plan setting the knob was run at and the dotted report path whose measured \
     cell answers for it; an unmeasured knob is not_ready and is never filled in from the setting";

/// One ONE-1578 knob, the setting it ran at, and the measured cell that
/// answers for it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct KnobMeasurement {
    pub(crate) knob: &'static str,
    pub(crate) ticket: &'static str,
    /// What the plan set this knob to for this run.
    pub(crate) setting: u64,
    /// Dotted path of the cell in THIS report that answers for the knob.
    pub(crate) measured_cell: &'static str,
    pub(crate) measured_value: Cell<f64>,
    pub(crate) unit: &'static str,
}

/// How this report relates to the ONE-1537 embed-latency acceptance gate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct EmbedLatencyRelationship {
    pub(crate) gate_ticket: &'static str,
    /// Always false: no embedding call is made anywhere in this harness.
    pub(crate) measured_by_this_harness: bool,
    pub(crate) relationship: &'static str,
    pub(crate) declared_gate_source: &'static str,
    pub(crate) declared_gate_ms: Cell<f64>,
    pub(crate) warm_retrieval_p50_ms: Cell<f64>,
    /// `declared_gate_ms - warm_retrieval_p50_ms`, present only when BOTH
    /// sides exist: one declared for the run and one measured in it.
    pub(crate) headroom_ms: Cell<f64>,
    pub(crate) warm_retrieval_within_declared_gate: Cell<bool>,
}

/// The structured acceptance envelope carried by every report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct AcceptanceEvidence {
    pub(crate) knob_ticket: &'static str,
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
    pub(crate) k: usize,
    pub(crate) warm_passes: usize,
    pub(crate) recall_latency: &'a RecallLatencyAxis,
    pub(crate) sessions: &'a SessionsAxis,
    pub(crate) resident_memory: &'a ResidentMemoryAxis,
    pub(crate) gated_writes: &'a GatedWriteAxis,
    pub(crate) precision: &'a PrecisionAxis,
}

impl AcceptanceEvidence {
    pub(crate) fn collect(inputs: &AcceptanceInputs<'_>) -> Self {
        Self {
            knob_ticket: KNOB_TICKET,
            knob_rule: KNOB_RULE,
            knobs: knob_rows(inputs),
            embed_latency_gate: embed_latency_relationship(inputs.recall_latency),
            beam_boundary: BEAM_BOUNDARY,
        }
    }
}

fn knob_rows(inputs: &AcceptanceInputs<'_>) -> Vec<KnobMeasurement> {
    let peak_sessions = inputs
        .sessions
        .curve
        .iter()
        .max_by_key(|point| point.sessions);
    vec![
        KnobMeasurement {
            knob: "retrieval_k",
            ticket: KNOB_TICKET,
            setting: inputs.k as u64,
            measured_cell: "recall_latency.cold.recall_at_k.p50",
            measured_value: Cell::from_option(
                inputs
                    .recall_latency
                    .cold
                    .recall_at_k
                    .value()
                    .map(|percentiles| percentiles.p50),
                "the cold recall distribution was not measured in this run",
            ),
            unit: "recall_fraction",
        },
        KnobMeasurement {
            knob: "warm_passes",
            ticket: KNOB_TICKET,
            setting: inputs.warm_passes as u64,
            measured_cell: "recall_latency.warm.latency_ms.p50",
            measured_value: Cell::from_option(
                inputs.recall_latency.warm.p50_ms(),
                "the warm latency distribution was not measured in this run",
            ),
            unit: "milliseconds",
        },
        KnobMeasurement {
            knob: "concurrent_sessions_peak",
            ticket: KNOB_TICKET,
            setting: peak_sessions.map_or(0, |point| point.sessions as u64),
            measured_cell: "sessions.curve[peak].throughput_qps",
            measured_value: Cell::from_option(
                peak_sessions.and_then(|point| point.throughput_qps.measured_f64()),
                "no session-curve point produced a measured throughput in this run",
            ),
            unit: "queries_per_second",
        },
        KnobMeasurement {
            knob: "binary_prefix_breadth",
            ticket: KNOB_TICKET,
            setting: inputs.precision.binary_prefix_breadth as u64,
            measured_cell: "precision.rows[binary_prefix_rescore].mean_recall_at_k",
            measured_value: Cell::from_option(
                inputs
                    .precision
                    .rows
                    .last()
                    .and_then(|row| row.mean_recall_at_k.measured_f64()),
                "the binary-prefix rescore row did not produce a measured recall in this run",
            ),
            unit: "recall_fraction",
        },
        KnobMeasurement {
            knob: "gated_write_measured_commits",
            ticket: KNOB_TICKET,
            setting: inputs.gated_writes.measured_commits as u64,
            measured_cell: "gated_writes.commits_per_second",
            measured_value: Cell::from_option(
                inputs.gated_writes.commits_per_second.measured_f64(),
                "no gated-write commit succeeded, so there is no successful-commit throughput",
            ),
            unit: "successful_commits_per_second",
        },
        KnobMeasurement {
            knob: "ready_children",
            ticket: KNOB_TICKET,
            setting: inputs.resident_memory.required_ready_children as u64,
            measured_cell: "resident_memory.total_child_rss_bytes",
            measured_value: Cell::from_option(
                inputs
                    .resident_memory
                    .total_child_rss_bytes
                    .value()
                    .map(|bytes| *bytes as f64),
                "the ten-ready-children resident memory was not measured in this run",
            ),
            unit: "bytes",
        },
    ]
}

fn embed_latency_relationship(recall_latency: &RecallLatencyAxis) -> EmbedLatencyRelationship {
    let declared = declared_embed_latency_gate_ms();
    let warm_p50 = recall_latency.warm.p50_ms();
    let headroom = declared.zip(warm_p50).map(|(gate, warm)| gate - warm);
    EmbedLatencyRelationship {
        gate_ticket: EMBED_LATENCY_GATE_TICKET,
        measured_by_this_harness: false,
        relationship: EMBED_RELATIONSHIP,
        declared_gate_source: EMBED_LATENCY_GATE_ENV,
        declared_gate_ms: Cell::from_option(
            declared,
            format!(
                "no authoritative {EMBED_LATENCY_GATE_TICKET} embed-latency gate was declared for \
                 this run via {EMBED_LATENCY_GATE_ENV}; this harness measures no embedding call \
                 and will not invent one"
            ),
        ),
        warm_retrieval_p50_ms: Cell::from_option(
            warm_p50,
            "the warm retrieval latency was not measured in this run",
        ),
        headroom_ms: Cell::from_option(
            headroom,
            format!(
                "headroom needs BOTH a declared {EMBED_LATENCY_GATE_TICKET} gate and a measured \
                 warm retrieval p50; at least one is missing"
            ),
        ),
        warm_retrieval_within_declared_gate: Cell::from_option(
            headroom.map(|headroom| headroom >= 0.0),
            "no declared gate to compare the measured warm retrieval p50 against",
        ),
    }
}

fn declared_embed_latency_gate_ms() -> Option<f64> {
    let raw = std::env::var(EMBED_LATENCY_GATE_ENV).ok()?;
    let parsed: f64 = raw.trim().parse().ok()?;
    if parsed.is_finite() && parsed > 0.0 {
        return Some(parsed);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::axes::{
        COMMITS_PER_SECOND_NUMERATOR, CHILD_SHUTDOWN_RULE, FULL_RUN_MIN_COMPLETED_SAMPLES,
        FULL_RUN_MIN_INDEXED_DOCS, FULL_RUN_MIN_QUERIES, GATED_WRITE_FLOOR_RULE, GATED_WRITE_PATH,
        REQUIRED_FULL_SESSION_CURVE, REQUIRED_READY_CHILDREN, SESSION_SYNCHRONIZATION_RULE,
        SampleSet, SessionCurvePoint,
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
            shutdown_outcomes: BTreeMap::new(),
            errors: Vec::new(),
            evidence_kind: EvidenceKind::MeasuredWallClock,
        }
    }

    fn gated_writes(commits_ok: usize) -> GatedWriteAxis {
        GatedWriteAxis {
            write_path: GATED_WRITE_PATH,
            warmup_commits: 2,
            measured_commits: 4,
            commits_ok,
            commit_errors: 4 - commits_ok,
            error_kinds: BTreeMap::new(),
            wall_clock_ms: 10.0,
            commits_per_second: if commits_ok == 0 {
                Cell::not_ready("no commit succeeded")
            } else {
                Cell::measured(commits_ok as f64 * 100.0)
            },
            commits_per_second_numerator: COMMITS_PER_SECOND_NUMERATOR,
            attempted_commits_per_second: Cell::measured(400.0),
            commit_latency_ms: Cell::not_ready("test"),
            failed_attempt_latency_ms: Cell::not_ready("test"),
            gate_decisions_recorded: 4,
            one_decision_per_commit: true,
            gate_enforcement_valid: commits_ok == 4,
            gate_outcomes: BTreeMap::new(),
            meets_full_run_floor: false,
            floor: GATED_WRITE_FLOOR_RULE,
            evidence_kind: EvidenceKind::MeasuredWallClock,
        }
    }

    fn precision() -> PrecisionAxis {
        super::super::precision::evaluate(
            &[vec![1.0, 0.0], vec![0.0, 1.0], vec![0.5, 0.5]],
            &[vec![1.0, 0.1]],
            2,
            2,
            EvidenceKind::MeasuredWallClock,
        )
    }

    /// A consumer must be able to read the ONE-1578 knob settings and their
    /// measured cells structurally, and must be told in the same envelope that
    /// the ONE-1537 embed-latency gate is not measured here.
    #[test]
    fn acceptance_names_the_knobs_and_the_embed_latency_relationship() {
        let recall = recall_latency();
        let sessions = sessions();
        let memory = resident_memory();
        let writes = gated_writes(4);
        let precision = precision();
        let evidence = AcceptanceEvidence::collect(&AcceptanceInputs {
            k: 10,
            warm_passes: 2,
            recall_latency: &recall,
            sessions: &sessions,
            resident_memory: &memory,
            gated_writes: &writes,
            precision: &precision,
        });

        assert_eq!(evidence.knob_ticket, "ONE-1578");
        let names: Vec<&str> = evidence.knobs.iter().map(|knob| knob.knob).collect();
        assert_eq!(
            names,
            vec![
                "retrieval_k",
                "warm_passes",
                "concurrent_sessions_peak",
                "binary_prefix_breadth",
                "gated_write_measured_commits",
                "ready_children",
            ],
            "every knob this harness turns must be named, not left to axis prose"
        );
        for knob in &evidence.knobs {
            assert_eq!(knob.ticket, "ONE-1578");
            assert!(
                !knob.measured_cell.is_empty(),
                "{} must point at the cell that answers for it",
                knob.knob
            );
            assert!(
                knob.measured_value.is_measured(),
                "{} was measured in this fixture and must carry its value",
                knob.knob
            );
        }
        let sessions_knob = &evidence.knobs[2];
        assert_eq!(sessions_knob.setting, 10);
        assert!(
            (sessions_knob.measured_value.measured_f64().unwrap_or(0.0) - 2_000.0).abs()
                < f64::EPSILON,
            "the knob row must carry the value the axis actually measured"
        );

        assert_eq!(evidence.embed_latency_gate.gate_ticket, "ONE-1537");
        assert!(
            !evidence.embed_latency_gate.measured_by_this_harness,
            "a text-only harness must not claim to measure embed latency"
        );
        assert!(
            evidence.embed_latency_gate.warm_retrieval_p50_ms.is_measured(),
            "the consumer side of the relationship IS measured here"
        );
    }

    /// With no declared gate the relationship stays fail-closed: no headroom,
    /// no verdict, and an explicit reason naming how to declare one.
    #[test]
    fn an_undeclared_embed_latency_gate_stays_not_ready() {
        // The bench process does not set this variable; if an operator has
        // exported one, the declared branch is the one under test instead.
        let recall = recall_latency();
        let relationship = embed_latency_relationship(&recall);
        match declared_embed_latency_gate_ms() {
            None => {
                assert!(!relationship.declared_gate_ms.is_measured());
                assert!(!relationship.headroom_ms.is_measured());
                assert!(!relationship.warm_retrieval_within_declared_gate.is_measured());
                let rendered =
                    serde_json::to_string(&relationship).expect("relationship renders");
                assert!(rendered.contains(EMBED_LATENCY_GATE_ENV), "{rendered}");
            }
            Some(gate) => {
                assert!(relationship.declared_gate_ms.is_measured());
                let headroom = relationship
                    .headroom_ms
                    .measured_f64()
                    .expect("headroom follows from both sides");
                let warm = relationship
                    .warm_retrieval_p50_ms
                    .measured_f64()
                    .expect("warm measured");
                assert!((headroom - (gate - warm)).abs() < 1e-9);
            }
        }
    }

    /// A knob whose axis produced no measurement is not_ready; the SETTING is
    /// never promoted into the measured slot.
    #[test]
    fn an_unmeasured_knob_is_not_ready_rather_than_its_setting() {
        let recall = recall_latency();
        let sessions = sessions();
        let memory = resident_memory();
        let writes = gated_writes(0);
        let precision = precision();
        let evidence = AcceptanceEvidence::collect(&AcceptanceInputs {
            k: 10,
            warm_passes: 2,
            recall_latency: &recall,
            sessions: &sessions,
            resident_memory: &memory,
            gated_writes: &writes,
            precision: &precision,
        });
        let commits = &evidence.knobs[4];
        assert_eq!(commits.knob, "gated_write_measured_commits");
        assert_eq!(commits.setting, 4, "the setting is still reported");
        assert!(
            !commits.measured_value.is_measured(),
            "no commit succeeded, so the knob has no measured answer"
        );
        let rendered = serde_json::to_string(&commits).expect("knob renders");
        assert!(rendered.contains("not_ready"), "{rendered}");
    }
}
