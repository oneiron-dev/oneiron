//! Current native inputs for a stock offer's measured comparison.

use super::doors::cohort_moved;
use super::{EvalCaseMeasurement, EvalMeasurement, MeasurementMethodPin, ScoreDirection};
use crate::skill_optimize::eval_set::{case_in_txn, cohort::cohorts_in_txn};
use crate::skill_optimize::{JUDGE_SCORE_AXIS, JUDGE_SCORE_UNITS, eval_seat_canary};
use crate::{Result, Vault};

impl Vault {
    pub(crate) fn offer_measurement_current_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        measured: &EvalMeasurement,
        scorer: &str,
    ) -> Result<bool> {
        let request = &measured.request;
        let Some(cohort) = cohorts_in_txn(self, txn, &request.seat)?
            .into_iter()
            .filter(|cohort| cohort.retired_at.is_none())
            .max_by_key(|cohort| (cohort.cut_at, cohort.id))
        else {
            return Ok(false);
        };
        if request.decision != "training_offer"
            || request.scorer != scorer
            || request.axis.axis != JUDGE_SCORE_AXIS
            || request.axis.units != JUDGE_SCORE_UNITS
            || request.axis.direction != ScoreDirection::HigherIsBetter
            || request.method != MeasurementMethodPin::current()
            || request.cohort != cohort.id
            || cohort_moved(&cohort, request)
            || request.canary.as_deref() != eval_seat_canary(&request.seat)
            || request.floor_slices != self.offer_floor_slices_in_txn(txn, &request.seat)?
            || measured.members != cohort.cases
            || measured.cases.len() != measured.members.len()
        {
            return Ok(false);
        }
        for member in &measured.members {
            let Some(recorded) = measured.cases.iter().find(|case| case.case == *member) else {
                return Ok(false);
            };
            let Some(live) = case_in_txn(self, txn, member)? else {
                return Ok(false);
            };
            if !live.labels.iter().any(|label| label.kind.anchors())
                || recorded.scoring_labels.as_deref()
                    != Some(EvalCaseMeasurement::scoring_labels_fingerprint(&live.labels)?.as_str())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
