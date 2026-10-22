//! Finishing a measurement: the complete matched set, the estimator once,
//! and the card read from its numbers. A set with any case or leg missing
//! settles Partial with its reasons; its survivors are never estimated alone.

use std::collections::BTreeSet;

use super::doors::{measurement_in_txn, put_in_txn};
use super::statistics::{PairedScores, estimate};
use super::{EvalMeasurement, MeasurementState, MeasurementUnavailable, ScoreDirection};
use crate::Vault;
use crate::error::{Error, Result};
use crate::skill_optimize::eval_set::cohort::cohort_in_txn;
use crate::skill_optimize::eval_set::{SufficiencyInput, sufficiency_card};

/// The axis a blind judge score measures: how well one response carries out
/// its task by the judge's rubric and the case's labels (CALL).
pub const JUDGE_SCORE_AXIS: &str = "judge_response_score";
/// Its units: the judge's 0..1 score, higher is better (CALL).
pub const JUDGE_SCORE_UNITS: &str = "score_0_1";

/// Why the set is not a complete matched one: each missing case, and each
/// leg with no finite score, by the reason it gave.
fn gaps(row: &EvalMeasurement) -> Vec<MeasurementUnavailable> {
    let mut reasons = BTreeSet::new();
    if row.members.is_empty() {
        reasons.insert(MeasurementUnavailable::IncompleteCase);
    }
    for member in &row.members {
        let Some(case) = row
            .cases
            .iter()
            .find(|case| case.case == *member && case.recorded_at.is_some())
        else {
            reasons.insert(MeasurementUnavailable::IncompleteCase);
            continue;
        };
        for leg in case.legs() {
            if leg.score.is_none_or(|score| !score.is_finite()) {
                reasons.insert(
                    leg.unavailable
                        .unwrap_or(MeasurementUnavailable::IncompleteCase),
                );
            }
        }
    }
    reasons.into_iter().collect()
}

/// The matched cases as the estimator reads them, higher-is-better.
fn paired(row: &EvalMeasurement) -> Vec<PairedScores<'_>> {
    let sign = match row.request.axis.direction {
        ScoreDirection::HigherIsBetter => 1.0,
        ScoreDirection::LowerIsBetter => -1.0,
    };
    row.cases
        .iter()
        .filter(|case| row.members.contains(&case.case))
        .filter_map(|case| {
            Some(PairedScores {
                family: case.family,
                stratum: case.stratum.as_deref(),
                incumbent: sign * case.incumbent.score?,
                candidate: sign * case.candidate.score?,
                retest: sign * case.retest.score?,
            })
        })
        .collect()
}

impl Vault {
    /// Finish a claimed measurement once every member case is recorded with
    /// three scored legs: the family estimator runs over the whole matched
    /// set, and the sufficiency card is read once from its numbers and kept
    /// with the family summaries under the same digest. A set with any gap
    /// settles Partial with its reasons and no card. No canary is measured
    /// beside the axis, so the card reads unknown with `NoCanary`. A settled
    /// row is kept as it is.
    /// # Errors
    /// A missing measurement or cohort, or storage errors.
    pub fn finish_eval_measurement(&self, digest: &[u8; 32], now: u64) -> Result<EvalMeasurement> {
        self.with_write_txn_grouped(|txn| {
            let mut row = measurement_in_txn(self, &*txn, digest)?.ok_or(Error::EntityNotFound)?;
            if row.state != MeasurementState::Claimed {
                return Ok(row);
            }
            let reasons = gaps(&row);
            if !reasons.is_empty() {
                row.state = MeasurementState::Partial { reasons };
                row.settled_at = Some(now);
                put_in_txn(self, txn, digest, &row)?;
                return Ok(row);
            }
            let cohort = cohort_in_txn(self, &*txn, &row.request.cohort)?;
            let found = estimate(
                &paired(&row),
                &row.request.floor_slices.required,
                row.request.floor_slices.min_families,
                digest,
            );
            let input = SufficiencyInput {
                families: u32::try_from(found.families.len()).unwrap_or(u32::MAX),
                floor_slices: found.slice_families,
                min_families_per_slice: row.request.floor_slices.min_families_per_slice,
                retest_noise: found.retest_noise,
                owner_margin: None,
                paired_interval: found.interval,
                detectable_effect: found.detectable_effect,
                set_changed: cohort.retired_at.is_some()
                    || cohort.membership_digest != row.request.membership_digest,
                rubric_changed: cohort.rubric_revision != row.request.rubric_revision,
                canary_diverged: None,
            };
            row.card = Some(sufficiency_card(input)?);
            row.families = found.families;
            row.mean_delta = found.mean_delta;
            row.gap = found.gap;
            row.state = MeasurementState::Final;
            row.settled_at = Some(now);
            put_in_txn(self, txn, digest, &row)?;
            Ok(row)
        })
    }
}
