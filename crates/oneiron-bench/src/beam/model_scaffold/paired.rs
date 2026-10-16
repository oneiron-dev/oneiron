//! Paired no-memory rows (ARCH-0042 scour:G12, ZERO-RETRIEVAL = A). Every arm
//! of one reader is paired, question by question, with the same reader given
//! no optional memory, per task family and per comparison regime.
use super::{AnswererArm, Effort, ModelRow, model_params_hash};
use crate::beam::{BeamResult, model::ArmKind};
use oneiron::ModelId;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::beam) enum Regime {
    /// Every arm shares the reader's pinned output cap; spend may differ.
    FixedAnswerCap,
    /// A row whose query tokens pass the effort's allowance scores zero.
    FixedTotalTokens,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::beam) struct PairedRow {
    pub regime: Regime,
    pub answerer: ModelId,
    pub answerer_params_sha256: String,
    pub task_family: String,
    pub arm: ArmKind,
    pub effort: String,
    pub pairs: usize,
    pub score: f64,
    pub solo_score: f64,
    /// Mean over questions of this arm's score minus backbone-solo's.
    pub paired_difference: f64,
    pub mean_input_tokens: f64,
    pub mean_output_tokens: f64,
    pub context_truncation_rate: f64,
    pub output_truncation_rate: f64,
    pub over_allowance_rate: f64,
    pub query_cost_usd: f64,
}

/// The setting these rows pick for one reader and task family.
#[derive(Debug, Clone, Serialize)]
pub(in crate::beam) struct ReaderPick {
    pub regime: Regime,
    pub answerer: ModelId,
    pub answerer_params_sha256: String,
    pub task_family: String,
    /// `backbone_solo` unless another arm beat it on these pairs.
    pub arm: ArmKind,
    pub effort: Option<String>,
    /// `None` is no optional memory; only a recalling arm sets it.
    pub optional_memory_tokens: Option<usize>,
    /// The pack view an engine-pack arm served; `None` for every other arm.
    pub tier: Option<&'static str>,
    pub paired_difference: f64,
}

pub(super) fn paired_rows(
    rows: &[ModelRow],
    answerers: &[AnswererArm],
    efforts: &[Effort],
) -> BeamResult<Vec<PairedRow>> {
    let Some(solo) = answerers.iter().find(|a| a.arm == ArmKind::BackboneSolo) else {
        return Ok(Vec::new());
    };
    let reader = model_params_hash(&solo.model)?;
    let mut out = Vec::new();
    for regime in [Regime::FixedAnswerCap, Regime::FixedTotalTokens] {
        for effort in efforts {
            let solo_rows: BTreeMap<_, _> = rows
                .iter()
                .filter(|r| r.arm == ArmKind::BackboneSolo && r.effort == effort.name)
                .map(|r| (r.question_id.as_str(), r))
                .collect();
            for arm in answerers {
                // Chat is a cheaper reader, so it has no same-reader baseline here.
                if arm.arm == ArmKind::BackboneSolo || model_params_hash(&arm.model)? != reader {
                    continue;
                }
                let mut families: BTreeMap<&str, Vec<(&ModelRow, &ModelRow)>> = BTreeMap::new();
                for row in rows
                    .iter()
                    .filter(|r| r.arm == arm.arm && r.effort == effort.name)
                {
                    if let Some(solo_row) = solo_rows.get(row.question_id.as_str()) {
                        families
                            .entry(row.task_family.as_str())
                            .or_default()
                            .push((row, solo_row));
                    }
                }
                for (family, pairs) in families {
                    let n = pairs.len() as f64;
                    let mean = |f: &dyn Fn(&ModelRow, &ModelRow) -> f64| {
                        pairs.iter().map(|(row, solo)| f(row, solo)).sum::<f64>() / n
                    };
                    let rate =
                        |f: &dyn Fn(&ModelRow) -> bool| mean(&|row, _| f64::from(u8::from(f(row))));
                    let score = |row: &ModelRow| regime_score(regime, effort, row);
                    out.push(PairedRow {
                        regime,
                        answerer: arm.model.model_id.clone(),
                        answerer_params_sha256: reader.clone(),
                        task_family: family.to_owned(),
                        arm: arm.arm,
                        effort: effort.name.clone(),
                        pairs: pairs.len(),
                        score: mean(&|row, _| score(row)),
                        solo_score: mean(&|_, solo| score(solo)),
                        paired_difference: mean(&|row, solo| score(row) - score(solo)),
                        mean_input_tokens: mean(&|row, _| row.query_cost.input_tokens as f64),
                        mean_output_tokens: mean(&|row, _| row.query_cost.output_tokens as f64),
                        context_truncation_rate: rate(&|row| row.context_truncated),
                        output_truncation_rate: rate(&|row| row.output_truncated),
                        over_allowance_rate: rate(&|row| over_allowance(effort, row)),
                        query_cost_usd: pairs.iter().map(|(row, _)| row.query_cost.cost_usd).sum(),
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Zero optional memory stays the pick unless an arm beats it strictly.
/// On a tie, an arm without vault recall wins, then the smaller memory
/// budget, then the cheaper row.
pub(super) fn picks(paired: &[PairedRow], efforts: &[Effort]) -> Vec<ReaderPick> {
    let memory_tokens = |row: &PairedRow| {
        efforts
            .iter()
            .find(|effort| recalls(row.arm) && effort.name == row.effort)
            .map(|effort| effort.token_budget)
    };
    let mut groups: BTreeMap<_, Vec<&PairedRow>> = BTreeMap::new();
    for row in paired {
        groups
            .entry((
                row.regime,
                &row.answerer,
                row.answerer_params_sha256.as_str(),
                row.task_family.as_str(),
            ))
            .or_default()
            .push(row);
    }
    groups
        .into_values()
        .map(|rows| {
            let first = rows[0];
            let best = rows
                .iter()
                .copied()
                .filter(|row| row.paired_difference > 0.0)
                .max_by(|a, b| {
                    a.paired_difference
                        .total_cmp(&b.paired_difference)
                        .then(memory_tokens(b).cmp(&memory_tokens(a)))
                        .then(b.query_cost_usd.total_cmp(&a.query_cost_usd))
                });
            ReaderPick {
                regime: first.regime,
                answerer: first.answerer.clone(),
                answerer_params_sha256: first.answerer_params_sha256.clone(),
                task_family: first.task_family.clone(),
                arm: best.map_or(ArmKind::BackboneSolo, |row| row.arm),
                effort: best.map(|row| row.effort.clone()),
                optional_memory_tokens: best.and_then(memory_tokens),
                tier: best
                    .filter(|row| matches!(row.arm, ArmKind::Deterministic | ArmKind::Agentic))
                    .map(|_| crate::beam::arms::BEAM_PACK_VIEW.1),
                paired_difference: best.map_or(0.0, |row| row.paired_difference),
            }
        })
        .collect()
}

fn recalls(arm: ArmKind) -> bool {
    !matches!(arm, ArmKind::BackboneSolo | ArmKind::TrajectoryOnly)
}

fn over_allowance(effort: &Effort, row: &ModelRow) -> bool {
    row.query_cost.input_tokens + row.query_cost.output_tokens > effort.total_token_allowance
}

fn regime_score(regime: Regime, effort: &Effort, row: &ModelRow) -> f64 {
    if regime == Regime::FixedTotalTokens && over_allowance(effort, row) {
        return 0.0;
    }
    row.scoring
        .beam
        .as_ref()
        .expect("FixedBeamScorer produces BEAM columns")
        .aggregate
        .official_int_cast
}
