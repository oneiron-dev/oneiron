//! The run's report file: its header, the per-case table, the counts, and the
//! engine's route calibration report, as one JSON document.

use std::io::Write;
use std::path::Path;

use oneiron::EntityId;
use oneiron::llm::decision::questions::{CalibrationPair, DecisionRoute, RouteCalibrationReport};
use oneiron::llm::decision::{DecisionAnswer, DecisionDial, DecisionTime, HumanAskReason};
use serde::Serialize;

use super::cases::Case;
use super::house_read::ModelPins;
use crate::eval::EvalResult;

pub(super) const ROUTE_CALIBRATION_CONTRACT_VERSION: &str = "oneiron.eval_route_calibration.v1";

/// The whole report: what ran, what each case did, and the per-route report.
#[derive(Serialize)]
pub(super) struct RouteCalibrationRun {
    pub(super) header: RunHeader,
    pub(super) counts: CaseCounts,
    pub(super) cases: Vec<CaseRow>,
    /// `route_calibration_report` over the question's calibration pairs.
    pub(super) report: RouteCalibrationReport,
}

#[derive(Serialize)]
pub(super) struct RunHeader {
    pub(super) contract_version: &'static str,
    pub(super) run_id: String,
    /// Unix seconds.
    pub(super) started_at: u64,
    pub(super) finished_at: u64,
    /// The vault the run made; its pairs stay readable there.
    pub(super) vault: String,
    /// The embedded owner: the question's principal and every write's actor.
    pub(super) owner: String,
    pub(super) models: ModelPins,
    pub(super) question: QuestionPins,
    pub(super) cases: CasePins,
}

#[derive(Serialize)]
pub(super) struct QuestionPins {
    pub(super) id: String,
    pub(super) version: u32,
    pub(super) definition: String,
    /// BLAKE3 of the definition file's bytes, as read.
    pub(super) definition_blake3: String,
    pub(super) dial: DecisionDial,
    /// Each decision's clock: the definition's own, or the vault's question
    /// call budget.
    pub(super) deadline_ms: u64,
    pub(super) outcome_predicate: &'static str,
    pub(super) horizon_seconds: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct CasePins {
    pub(super) path: String,
    /// BLAKE3 of the cases file's bytes, as read.
    pub(super) blake3: String,
    pub(super) count: usize,
}

/// Where one case's walk ended. Every status is counted apart, and none is
/// filled with another's label or probability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CaseStatus {
    /// Answered, labelled, and its pair read back.
    Paired,
    /// Answered and labelled, but the pair reader returned no pair for it.
    PairMissing,
    /// The ladder abstained, so nothing was admitted or labelled.
    Abstained,
    /// The ladder call failed.
    LadderFailed,
    /// The standing preparation refused the unit.
    PrepareFailed,
    /// The admit door refused the decision.
    AdmitFailed,
    /// The answer landed, but its gold claim did not.
    GoldWriteFailed,
}

/// One case's row of the per-case table.
#[derive(Serialize)]
pub(super) struct CaseRow {
    pub(super) id: String,
    pub(super) source: String,
    pub(super) unit: String,
    pub(super) status: CaseStatus,
    pub(super) gold: bool,
    /// The admitted answer's claim.
    pub(super) answer: Option<String>,
    /// The gold claim that labels it.
    pub(super) fact: Option<String>,
    /// The approval the gate stored the gold claim at.
    pub(super) fact_approval: Option<String>,
    pub(super) prediction: Option<DecisionAnswer>,
    /// The admitted answer's raw P(yes), from the decision read.
    pub(super) probability: Option<f64>,
    /// The route the answer's calibration pair names; none without a pair.
    pub(super) route: Option<DecisionRoute>,
    /// The decision's clock, as its receipt keeps it.
    pub(super) clock: Option<DecisionTime>,
    pub(super) human_ask: Option<HumanAskReason>,
    pub(super) error: Option<String>,
}

impl CaseRow {
    /// A row for `case` on `unit`, at the first step's failure until a later
    /// step moves it.
    pub(super) fn new(case: &Case, unit: EntityId) -> Self {
        Self {
            id: case.id.clone(),
            source: case.source.clone(),
            unit: unit.to_hex(),
            status: CaseStatus::PrepareFailed,
            gold: case.gold,
            answer: None,
            fact: None,
            fact_approval: None,
            prediction: None,
            probability: None,
            route: None,
            clock: None,
            human_ask: None,
            error: None,
        }
    }
}

/// The run's counts: each case status, and what the question's readers hold.
#[derive(Default, Serialize)]
pub(super) struct CaseCounts {
    pub(super) cases: usize,
    pub(super) paired: usize,
    pub(super) pair_missing: usize,
    pub(super) abstained: usize,
    pub(super) ladder_failed: usize,
    pub(super) prepare_failed: usize,
    pub(super) admit_failed: usize,
    pub(super) gold_write_failed: usize,
    /// Every pair the question's pair reader returned.
    pub(super) pairs: usize,
    /// Every outcome label the question holds.
    pub(super) outcome_labels: usize,
    /// Labels the closing projection bound that arrival had not.
    pub(super) labels_projected_at_close: usize,
}

impl CaseCounts {
    pub(super) fn of(
        rows: &[CaseRow],
        pairs: usize,
        outcome_labels: usize,
        labels_projected_at_close: usize,
    ) -> Self {
        let mut counts = Self {
            cases: rows.len(),
            pairs,
            outcome_labels,
            labels_projected_at_close,
            ..Self::default()
        };
        for row in rows {
            let slot = match row.status {
                CaseStatus::Paired => &mut counts.paired,
                CaseStatus::PairMissing => &mut counts.pair_missing,
                CaseStatus::Abstained => &mut counts.abstained,
                CaseStatus::LadderFailed => &mut counts.ladder_failed,
                CaseStatus::PrepareFailed => &mut counts.prepare_failed,
                CaseStatus::AdmitFailed => &mut counts.admit_failed,
                CaseStatus::GoldWriteFailed => &mut counts.gold_write_failed,
            };
            *slot += 1;
        }
        counts
    }
}

/// Each labelled case's route, from the pair of its own answer and gold fact.
/// A case whose pair the reader did not return stays `PairMissing`.
pub(super) fn join_pairs(rows: &mut [CaseRow], pairs: &[CalibrationPair]) {
    for row in rows {
        if row.status != CaseStatus::PairMissing {
            continue;
        }
        let (Some(answer), Some(fact)) = (&row.answer, &row.fact) else {
            continue;
        };
        let pair = pairs.iter().find(|pair| {
            pair.outcome.answer.to_hex() == *answer && pair.outcome.fact.to_hex() == *fact
        });
        if let Some(pair) = pair {
            row.route = Some(pair.route);
            row.status = CaseStatus::Paired;
        }
    }
}

/// Writes `run` to `path`, a file this call creates; an existing file is
/// refused, never overwritten.
pub(super) fn write(path: &Path, run: &RouteCalibrationRun) -> EvalResult<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let mut writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, run)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}
