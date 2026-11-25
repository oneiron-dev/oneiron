//! The forecast score view (design pass 32 r2, section 4.7): how well each
//! declared runner model's rung forecasts came true on one line.
//!
//! A forecast resolves when its rung's outcome is written: 1 for
//! `success = true`, 0 for `false`. A rung that is open, awaiting review or
//! held keeps it pending. A rung closed invalid, or a rung an arm left open
//! when it closed (a withdrawal), leaves it unresolved for good: it is
//! counted, never scored. Once the line's `forecast_score_after` forecasts
//! have resolved (pass 34: read from the line, default 20), the row carries
//! the Brier score and ten calibration bins; before that the score is
//! unknown, shown as "resolved of needed". Forecasts never move an allowance
//! or a refund.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::EntityId;

use super::{ExperimentArm, RungEnd, RungState};

/// The calibration bins: one per tenth of `pass_per_mille`.
pub const CALIBRATION_BINS: usize = 10;
/// The width of one calibration bin, in thousandths.
const BIN_PER_MILLE: u16 = 100;

/// One declared runner model's forecasts on one line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForecastScoreRow {
    /// The line: the lane project's id.
    pub line: EntityId,
    /// The runner's model as the arms declare it: a claim, never attested.
    pub model: String,
    /// Forecasts whose rung's outcome is written.
    pub resolved: u32,
    /// Forecasts whose rung has no outcome yet.
    pub pending: u32,
    /// Forecasts whose rung closed with no outcome: never scored.
    pub invalid: u32,
    /// The resolved forecasts the line wants before it scores
    /// (`forecast_score_after`).
    pub needed: u32,
    /// `None` while fewer than `needed` (or no) forecasts have resolved.
    pub score: Option<ForecastScore>,
}

/// The score of a set of resolved forecasts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForecastScore {
    /// The mean of `(p - outcome)^2` with `p = pass_per_mille / 1000`, in
    /// millionths, rounded down: 0 is perfect, 250,000 is a constant one
    /// half, 1,000,000 is always certain and always wrong.
    pub brier_per_million: u64,
    /// [`CALIBRATION_BINS`] bins in rising order of `pass_per_mille`.
    pub bins: Vec<CalibrationBin>,
}

/// The resolved forecasts whose `pass_per_mille` falls in one bin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalibrationBin {
    /// The bin holds `from_per_mille` up to 99 more; the last bin also
    /// holds 1000.
    pub from_per_mille: u16,
    pub forecasts: u32,
    /// How many of them passed.
    pub passed: u32,
}

/// What became of one forecast.
enum Resolution {
    Resolved { pass_per_mille: u16, passed: bool },
    Pending,
    Invalid,
}

#[derive(Default)]
struct Tally {
    pending: u32,
    invalid: u32,
    /// `(pass_per_mille, passed)` of each resolved forecast.
    resolved: Vec<(u16, bool)>,
}

/// The forecast score rows of the line `line` over `arms` (the arms of
/// other lines are skipped), one per declared runner model in model order,
/// scored once `score_after` forecasts have resolved.
#[must_use]
pub fn forecast_scores<'a>(
    line: EntityId,
    arms: impl IntoIterator<Item = &'a ExperimentArm>,
    score_after: u32,
) -> Vec<ForecastScoreRow> {
    let mut tallies: BTreeMap<&str, Tally> = BTreeMap::new();
    for arm in arms.into_iter().filter(|arm| arm.line == line) {
        for rung in &arm.rungs {
            let Some(forecast) = &rung.forecast else {
                continue;
            };
            let tally = tallies.entry(forecast.runner.model.as_str()).or_default();
            let resolution = match (&rung.outcome, &rung.state) {
                (Some(outcome), _) => Resolution::Resolved {
                    pass_per_mille: forecast.pass_per_mille,
                    passed: outcome.success,
                },
                (
                    None,
                    RungState::Closed {
                        end: RungEnd::Invalid { .. },
                    },
                ) => Resolution::Invalid,
                (None, _) if !arm.is_open() => Resolution::Invalid,
                (None, _) => Resolution::Pending,
            };
            match resolution {
                Resolution::Resolved {
                    pass_per_mille,
                    passed,
                } => tally.resolved.push((pass_per_mille, passed)),
                Resolution::Pending => tally.pending += 1,
                Resolution::Invalid => tally.invalid += 1,
            }
        }
    }
    tallies
        .into_iter()
        .map(|(model, tally)| {
            let resolved = count(tally.resolved.len());
            ForecastScoreRow {
                line,
                model: model.to_owned(),
                resolved,
                pending: tally.pending,
                invalid: tally.invalid,
                needed: score_after,
                score: (resolved > 0 && resolved >= score_after).then(|| score(&tally.resolved)),
            }
        })
        .collect()
}

/// The Brier score and calibration bins of `resolved`, which is not empty.
fn score(resolved: &[(u16, bool)]) -> ForecastScore {
    let mut bins: Vec<CalibrationBin> = (0..CALIBRATION_BINS)
        .map(|index| CalibrationBin {
            from_per_mille: u16::try_from(index).unwrap_or(u16::MAX) * BIN_PER_MILLE,
            forecasts: 0,
            passed: 0,
        })
        .collect();
    let mut squared_sum: u64 = 0;
    for &(pass_per_mille, passed) in resolved {
        let outcome: u64 = if passed { 1_000 } else { 0 };
        let error = u64::from(pass_per_mille).abs_diff(outcome);
        squared_sum += error * error;
        let index = usize::from(pass_per_mille / BIN_PER_MILLE).min(CALIBRATION_BINS - 1);
        if let Some(bin) = bins.get_mut(index) {
            bin.forecasts += 1;
            bin.passed += u32::from(passed);
        }
    }
    ForecastScore {
        brier_per_million: squared_sum / u64::try_from(resolved.len()).unwrap_or(u64::MAX),
        bins,
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}
