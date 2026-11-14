//! The deterministic scorer, the per-arm summary and the pairing by history.
//!
//! No model judges. The reader replies one JSON action, `{"action": <tool>,
//! "fields": {<field>: <option>}}`; values compare trimmed and case-folded.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::super::{BeamResult, model_usage::sum_costs, report_model::CostComponentReport};
use super::{
    ActionRow,
    arms::MemoryArm,
    extraction::Probe,
    tasks::{FollowUp, TaskKind},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct FollowUpScore {
    /// The tool the reply named, when the reply parsed and named a tool.
    action: Option<String>,
    /// The reply's fields as given.
    fields: BTreeMap<String, String>,
    /// The rubric's tool, and every expected field at its expected value.
    pub(super) action_correct: bool,
    /// Correction follow-ups only: no superseded value given.
    pub(super) correction_persisted: Option<bool>,
    /// A standing value changed, or a field or option the tool lacks given.
    pub(super) unsupported_change: bool,
    /// No JSON action, or one naming no tool of the follow-up.
    pub(super) invalid: bool,
    /// Follow-ups whose rubric names another world's values: a valid
    /// action gave one (cross-scope leakage).
    pub(super) leaked: Option<bool>,
    /// Follow-ups whose rubric names deleted values: a valid action gave
    /// one (reappearance after deletion).
    pub(super) reappeared: Option<bool>,
}

pub(super) fn score(follow_up: &FollowUp, reply: &str) -> FollowUpScore {
    let parsed = parse_action(reply);
    let tool = parsed
        .as_ref()
        .and_then(|(action, _)| follow_up.tool(action));
    let invalid = tool.is_none();
    let (action, fields) = parsed.map_or((None, BTreeMap::new()), |(action, fields)| {
        (Some(action), fields)
    });
    let rubric = &follow_up.rubric;
    let given = |field: &str| fields.get(field).map(String::as_str).map(fold);
    let action_correct = !invalid
        && action.as_deref() == Some(rubric.action.as_str())
        && rubric
            .expect
            .iter()
            .all(|(field, value)| given(field) == Some(fold(value)));
    let correction_persisted = (follow_up.kind == TaskKind::CorrectedSource).then(|| {
        !invalid
            && rubric.stale.iter().all(|(field, values)| {
                given(field).is_none_or(|given| values.iter().all(|value| fold(value) != given))
            })
    });
    let unsupported_change = tool.is_some_and(|tool| {
        let off_tool = fields.iter().any(|(field, value)| {
            tool.fields
                .get(field)
                .is_none_or(|options| options.iter().all(|option| fold(option) != fold(value)))
        });
        let changed = rubric
            .keep
            .iter()
            .any(|(field, value)| given(field).is_some_and(|given| given != fold(value)));
        off_tool || changed
    });
    let gives_one_of = |named: &BTreeMap<String, Vec<String>>| {
        (!named.is_empty()).then(|| {
            !invalid
                && named.iter().any(|(field, values)| {
                    given(field)
                        .is_some_and(|given| values.iter().any(|value| fold(value) == given))
                })
        })
    };
    let leaked = gives_one_of(&rubric.other_scope);
    let reappeared = gives_one_of(&rubric.deleted);
    FollowUpScore {
        action,
        fields,
        action_correct,
        correction_persisted,
        unsupported_change,
        invalid,
        leaked,
        reappeared,
    }
}

/// The reply's JSON action: the outermost `{...}` (a fenced or prefaced
/// reply still parses), with string `action` and string field values.
fn parse_action(reply: &str) -> Option<(String, BTreeMap<String, String>)> {
    let start = reply.find('{')?;
    let end = reply.rfind('}')?;
    let value: serde_json::Value = serde_json::from_str(reply.get(start..=end)?).ok()?;
    let action = value.get("action")?.as_str()?.trim().to_owned();
    let fields = value
        .get("fields")?
        .as_object()?
        .iter()
        .map(|(field, value)| Some((field.trim().to_owned(), value.as_str()?.to_owned())))
        .collect::<Option<BTreeMap<_, _>>>()?;
    Some((action, fields))
}

fn fold(value: &str) -> String {
    value.trim().to_lowercase()
}

/// The five scores, as numbers a mean can be taken of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Metric {
    ActionCorrect,
    CorrectionPersisted,
    UnsupportedChange,
    Leaked,
    Reappeared,
}

const METRICS: [Metric; 5] = [
    Metric::ActionCorrect,
    Metric::CorrectionPersisted,
    Metric::UnsupportedChange,
    Metric::Leaked,
    Metric::Reappeared,
];

impl Metric {
    fn of(self, score: &FollowUpScore) -> Option<f64> {
        let value = match self {
            Self::ActionCorrect => Some(score.action_correct),
            Self::CorrectionPersisted => score.correction_persisted,
            Self::UnsupportedChange => Some(score.unsupported_change),
            Self::Leaked => score.leaked,
            Self::Reappeared => score.reappeared,
        };
        value.map(|hit| if hit { 1.0 } else { 0.0 })
    }
}

/// The columns a run's rows fall in: each memory arm, and each extraction
/// arm at each probe, in the plan's arm order.
fn columns(arms: &[MemoryArm]) -> Vec<(MemoryArm, Option<Probe>)> {
    arms.iter()
        .flat_map(|&arm| {
            if arm.extracts() {
                vec![
                    (arm, Some(Probe::AfterCorrection)),
                    (arm, Some(Probe::AfterConsolidation)),
                ]
            } else {
                vec![(arm, None)]
            }
        })
        .collect()
}

/// One arm over every follow-up it read (an extraction arm at one probe):
/// its means and its stage costs.
#[derive(Debug, Serialize)]
pub(super) struct ArmSummary {
    arm: MemoryArm,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe: Option<Probe>,
    follow_ups: usize,
    action_correct: f64,
    /// Over correction follow-ups only; absent when there are none.
    correction_persisted: Option<f64>,
    unsupported_change: f64,
    /// Over follow-ups scored on leakage only; absent when there are none.
    leaked: Option<f64>,
    /// Over follow-ups scored on reappearance only; absent when there are none.
    reappeared: Option<f64>,
    invalid: usize,
    /// Stage: recall (zero for an arm that never reads the vault).
    recall_elapsed_us: u64,
    context_lines: usize,
    context_chars: usize,
    items_off_arm: usize,
    /// Stage: the reader, as the provider counted it.
    reader: CostComponentReport,
    /// Stage: the scorer.
    score_elapsed_us: u64,
}

pub(super) fn summarize(rows: &[ActionRow], arms: &[MemoryArm]) -> BeamResult<Vec<ArmSummary>> {
    columns(arms)
        .into_iter()
        .map(|(arm, probe)| {
            let mine: Vec<&ActionRow> = rows
                .iter()
                .filter(|row| row.arm == arm && row.probe == probe)
                .collect();
            let costs: Vec<CostComponentReport> =
                mine.iter().map(|row| row.reader.clone()).collect();
            Ok(ArmSummary {
                arm,
                probe,
                follow_ups: mine.len(),
                action_correct: mean(
                    mine.iter()
                        .filter_map(|row| Metric::ActionCorrect.of(&row.score)),
                )
                .unwrap_or(0.0),
                correction_persisted: mean(
                    mine.iter()
                        .filter_map(|row| Metric::CorrectionPersisted.of(&row.score)),
                ),
                unsupported_change: mean(
                    mine.iter()
                        .filter_map(|row| Metric::UnsupportedChange.of(&row.score)),
                )
                .unwrap_or(0.0),
                leaked: mean(mine.iter().filter_map(|row| Metric::Leaked.of(&row.score))),
                reappeared: mean(
                    mine.iter()
                        .filter_map(|row| Metric::Reappeared.of(&row.score)),
                ),
                invalid: mine.iter().filter(|row| row.score.invalid).count(),
                recall_elapsed_us: mine.iter().map(|row| row.recall_elapsed_us).sum(),
                context_lines: mine.iter().map(|row| row.context_lines).sum(),
                context_chars: mine.iter().map(|row| row.context.chars().count()).sum(),
                items_off_arm: mine.iter().map(|row| row.items_off_arm).sum(),
                reader: sum_costs(&costs)?,
                score_elapsed_us: mine.iter().map(|row| row.score_elapsed_us).sum(),
            })
        })
        .collect()
}

/// One arm (an extraction arm at one probe) against no memory on one
/// metric, paired by history: per history, the arm's mean minus the
/// no-memory mean over the same follow-ups; then the mean of those
/// differences, its standard error and the history count.
#[derive(Debug, Serialize)]
pub(super) struct PairedRow {
    arm: MemoryArm,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe: Option<Probe>,
    metric: Metric,
    histories: usize,
    paired_difference: f64,
    /// Sample standard deviation over histories, over the square root of
    /// their count; absent below two histories.
    standard_error: Option<f64>,
}

pub(super) fn paired_by_history(rows: &[ActionRow], arms: &[MemoryArm]) -> Vec<PairedRow> {
    let histories: BTreeSet<&str> = rows.iter().map(|row| row.history.as_str()).collect();
    let mut paired = Vec::new();
    for (arm, probe) in columns(arms)
        .into_iter()
        .filter(|&(arm, _)| arm != MemoryArm::None)
    {
        for metric in METRICS {
            let differences: Vec<f64> = histories
                .iter()
                .filter_map(|&history| history_difference(rows, history, (arm, probe), metric))
                .collect();
            let Some(paired_difference) = mean(differences.iter().copied()) else {
                continue;
            };
            paired.push(PairedRow {
                arm,
                probe,
                metric,
                histories: differences.len(),
                paired_difference,
                standard_error: standard_error(&differences, paired_difference),
            });
        }
    }
    paired
}

/// The arm's mean minus no memory's, over this history's follow-ups that
/// both arms scored on this metric.
fn history_difference(
    rows: &[ActionRow],
    history: &str,
    column: (MemoryArm, Option<Probe>),
    metric: Metric,
) -> Option<f64> {
    let none = scored(rows, history, (MemoryArm::None, None), metric);
    let pairs: Vec<(f64, f64)> = scored(rows, history, column, metric)
        .into_iter()
        .filter_map(|(follow_up, value)| Some((value, *none.get(follow_up)?)))
        .collect();
    let arm_mean = mean(pairs.iter().map(|&(value, _)| value))?;
    let none_mean = mean(pairs.iter().map(|&(_, value)| value))?;
    Some(arm_mean - none_mean)
}

/// One column's score on one metric per follow-up of one history.
fn scored<'a>(
    rows: &'a [ActionRow],
    history: &str,
    (arm, probe): (MemoryArm, Option<Probe>),
    metric: Metric,
) -> BTreeMap<&'a str, f64> {
    rows.iter()
        .filter(|row| row.history == history && row.arm == arm && row.probe == probe)
        .filter_map(|row| Some((row.follow_up.as_str(), metric.of(&row.score)?)))
        .collect()
}

fn mean(values: impl Iterator<Item = f64>) -> Option<f64> {
    let (sum, count) = values.fold((0.0, 0_u32), |(sum, count), value| (sum + value, count + 1));
    (count > 0).then(|| sum / f64::from(count))
}

fn standard_error(values: &[f64], mean: f64) -> Option<f64> {
    let count = u32::try_from(values.len())
        .ok()
        .filter(|&count| count >= 2)?;
    let squares: f64 = values.iter().map(|value| (value - mean).powi(2)).sum();
    let variance = squares / f64::from(count - 1);
    Some((variance / f64::from(count)).sqrt())
}
