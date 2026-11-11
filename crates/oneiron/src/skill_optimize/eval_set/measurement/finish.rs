//! Finishing a measurement: the complete matched set, the estimator once,
//! and the card read from its numbers. A set with any case or leg missing
//! settles Partial with its reasons; its survivors are never estimated alone.

use std::collections::BTreeSet;

use super::doors::{canary_failure_divergence_tolerance, measurement_in_txn, put_in_txn};
use super::statistics::{PairedScores, estimate};
use super::{
    EvalLegRecord, EvalMeasurement, MeasurementState, MeasurementUnavailable, ScoreDirection,
};
use crate::EntityId;
use crate::Vault;
use crate::error::{Error, Result};
use crate::receipt::{CALL_RECEIPT_REF_PREFIX, CallOutcome, CallReceipt};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::eval_set::cohort::cohort_in_txn;
use crate::skill_optimize::eval_set::{SufficiencyInput, sufficiency_card};
use crate::store::Store;

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

/// The call receipt ledger, read in place.
const CALL_RECEIPTS: SideTable<EntityId, CallReceipt, Named> =
    SideTable::new(&side_table::CALL_RECEIPT);

/// The id a `call:<32hex>` leg receipt ref names; `None` for anything else.
fn call_receipt_id(receipt_ref: &str) -> Option<EntityId> {
    let hex = receipt_ref.strip_prefix(CALL_RECEIPT_REF_PREFIX)?;
    if hex.len() != 32 {
        return None;
    }
    EntityId::from_hex(hex).ok()
}

/// One arm's resolved calls and their failures. A leg with no number counts
/// as one failed call; a leg whose receipt ref resolves counts its receipt's
/// outcome. Legs with no ref, an unparsable ref or a missing receipt read
/// unknown and stay out of both counts (FIX 10437).
fn arm_calls(store: &Store, txn: &heed::RoTxn<'_>, legs: &[&EvalLegRecord]) -> Result<(u64, u64)> {
    let mut calls = 0;
    let mut failures = 0;
    for leg in legs {
        if leg.unavailable.is_some() {
            calls += 1;
            failures += 1;
            continue;
        }
        let Some(receipt_ref) = leg.receipt.as_deref() else {
            continue;
        };
        let Some(id) = call_receipt_id(receipt_ref) else {
            continue;
        };
        let Some(receipt) = CALL_RECEIPTS.get(store, txn, &id)? else {
            continue;
        };
        calls += 1;
        if matches!(receipt.outcome, CallOutcome::Refused { .. }) {
            failures += 1;
        }
    }
    Ok((calls, failures))
}

/// Whether the candidate arm's call failure rate sits above the incumbent
/// arm's past tolerance, from the legs' own receipts beside the axis. `None`
/// while either arm has no resolved call, so the card keeps honest `NoCanary`
/// (FIX 10437).
fn canary_diverged(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &EvalMeasurement,
) -> Result<Option<bool>> {
    let mut incumbent_legs = Vec::new();
    let mut candidate_legs = Vec::new();
    for case in &row.cases {
        incumbent_legs.push(&case.incumbent);
        incumbent_legs.push(&case.retest);
        candidate_legs.push(&case.candidate);
    }
    let (incumbent_calls, incumbent_failures) = arm_calls(store, txn, &incumbent_legs)?;
    let (candidate_calls, candidate_failures) = arm_calls(store, txn, &candidate_legs)?;
    if incumbent_calls == 0 || candidate_calls == 0 {
        return Ok(None);
    }
    let incumbent_rate = incumbent_failures as f64 / incumbent_calls as f64;
    let candidate_rate = candidate_failures as f64 / candidate_calls as f64;
    Ok(Some(
        candidate_rate - incumbent_rate > canary_failure_divergence_tolerance(),
    ))
}

impl Vault {
    /// Finish a claimed measurement once every member case is recorded with
    /// three scored legs: the family estimator runs over the whole matched
    /// set, and the sufficiency card is read once from its numbers and kept
    /// with the family summaries under the same digest. A set with any gap
    /// settles Partial with its reasons and no card. The generic call-failure
    /// canary is measured beside the axis from the legs' own receipts; arms
    /// with no resolved call keep honest `NoCanary` (FIX 10437). A settled
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
                canary_diverged: canary_diverged(&self.store, &*txn, &row)?,
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
