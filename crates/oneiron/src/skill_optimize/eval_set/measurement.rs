//! Paired, family-grouped eval measurements (FIX 574, OF-578; ARCH-0053).
//!
//! A measurement is asked for one frozen request: a seat, the exact
//! incumbent and candidate pins, the cohort and its membership digest, the
//! rubric revision, the scorer, the axis and the method. The request's digest
//! keys one row, which moves Pending -> Claimed -> Final, or to Partial with
//! typed reasons. The trusted measuring host claims it, which counts three
//! Candidate exposures of the cohort (incumbent, candidate and the incumbent
//! retest), records each case's three legs, and finishes it: the family
//! estimator runs once over the complete matched set, and the sufficiency
//! card is read from its numbers. Nothing missing is filled with zero, and a
//! Partial row carries no card: "a set too small to judge shows as unknown".

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{EvalSeat, SufficiencyCard};
use crate::compaction::output::OutputRef;
use crate::entity_id::EntityId;

mod doors;
mod finish;
mod statistics;

pub use self::doors::eval_seat_canary;
pub(super) use self::doors::{
    measurement_in_txn, measurements_in_txn, put_in_txn as put_measurement_in_txn,
};
pub use self::finish::{JUDGE_SCORE_AXIS, JUDGE_SCORE_UNITS};
pub use self::statistics::{EstimateGap, EvalFamilySummary, MeasurementMethodPin};
pub(crate) use self::statistics::{PairedScores, estimate as estimate_paired};

#[doc(hidden)]
pub use oneiron_records::skill_optimize::eval_set::measurement::{
    EvalArmPin, EvalAxisPin, FloorSlicePolicy, MeasurementState, MeasurementUnavailable,
    ScoreDirection,
};

/// What a measurement is asked for. Every field is frozen into the digest
/// that keys its row: a changed pin, cohort, rubric, scorer or method is
/// another measurement, never this one's card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalMeasurementRequest {
    /// The decision that waits on it, such as `training_offer`.
    pub decision: String,
    pub seat: EvalSeat,
    pub incumbent: EvalArmPin,
    pub candidate: EvalArmPin,
    /// The constructed incumbent and candidate offers when this was asked.
    /// A changed route or rate gets a new request key. Actual serving evidence
    /// still comes only from each answered leg, never from this snapshot.
    pub requested_offers: Option<[EvalServingOffer; 2]>,
    pub cohort: EntityId,
    pub membership_digest: String,
    pub rubric_revision: String,
    /// The scorer's revision (the replay judge's algorithm and wording).
    pub scorer: String,
    pub axis: EvalAxisPin,
    pub floor_slices: FloorSlicePolicy,
    /// The seat's declared canary metric; `None` while none is declared.
    pub canary: Option<String>,
    pub method: MeasurementMethodPin,
    /// The re-request generation: 0 for the first ask, N+1 to retry after N's
    /// Partial with transient reasons (FIX 10442).
    pub retry: u32,
}

/// The exact host offer that answered a measured leg. The fingerprint is
/// the gate's full binding identity; credential names stay behind its hash.
/// Rates are the same binding's native prices, not catalog list prices.
/// This is historical evidence, never permission to send or switch a model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalServingOffer {
    pub fingerprint: String,
    pub rates: Vec<crate::llm::run_admission::UnitRate>,
}

impl EvalServingOffer {
    /// Captures the constructed offer held by the exact-model call's ladder.
    #[must_use]
    pub fn from_binding(binding: &crate::llm::run_admission::OfferBinding) -> Self {
        Self {
            fingerprint: binding.fingerprint(),
            rates: binding.rates.clone(),
        }
    }

    /// Whether a current constructed offer is the one that was measured.
    /// This does not attest model files, live policy or current sufficiency.
    #[must_use]
    pub fn matches(&self, binding: &crate::llm::run_admission::OfferBinding) -> bool {
        self.fingerprint == binding.fingerprint() && self.rates == binding.rates
    }
}

/// One leg of a case: one arm's answer and its blind score.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalLegRecord {
    /// The stored raw response.
    pub output: Option<OutputRef>,
    /// The leg's own receipt.
    pub receipt: Option<String>,
    /// The provider that answered, as the model ladder stamped it.
    pub served: Option<String>,
    /// The actual exact generative offer, or unknown for other execution paths.
    pub serving_offer: Option<EvalServingOffer>,
    /// The blind score on the measured axis, as the scorer answered it.
    pub score: Option<f64>,
    /// The scorer that answered, `model@version`.
    pub judge: Option<String>,
    pub unavailable: Option<MeasurementUnavailable>,
}

impl EvalLegRecord {
    /// A leg with no number, and why.
    #[must_use]
    pub fn unavailable(reason: MeasurementUnavailable) -> Self {
        Self {
            unavailable: Some(reason),
            ..Self::default()
        }
    }
}

/// One case's three legs on the same task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCaseMeasurement {
    pub case: EntityId,
    pub family: EntityId,
    pub stratum: Option<String>,
    /// BLAKE3 of the task every leg was given, as hex.
    pub task_hash: Option<String>,
    pub incumbent: EvalLegRecord,
    pub candidate: EvalLegRecord,
    /// The incumbent again, on the same task: the retest.
    pub retest: EvalLegRecord,
    pub started_at: u64,
    /// `None` while the legs are under way: a resumed measurement reads such
    /// a case as uncertain, never as unpaid.
    pub recorded_at: Option<u64>,
    /// The rows the case, its labels and the task were read from (FIX 5761);
    /// `None` when any is unknown.
    pub source_rows: Option<Vec<EntityId>>,
}

impl EvalCaseMeasurement {
    /// The legs in order: incumbent, candidate, retest.
    #[must_use]
    pub fn legs(&self) -> [&EvalLegRecord; 3] {
        [&self.incumbent, &self.candidate, &self.retest]
    }
}

/// One measurement's row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalMeasurement {
    /// The request digest, as hex.
    pub digest: String,
    pub request: EvalMeasurementRequest,
    pub state: MeasurementState,
    pub requested_at: u64,
    pub claimed_at: Option<u64>,
    pub settled_at: Option<u64>,
    /// The cohort's cases as the claim released them.
    pub members: Vec<EntityId>,
    /// The three Candidate exposures the claim counted: incumbent,
    /// candidate, retest.
    pub exposures: Vec<EntityId>,
    pub cases: Vec<EvalCaseMeasurement>,
    pub families: Vec<EvalFamilySummary>,
    /// The equal-weight mean of family deltas, candidate minus incumbent.
    pub mean_delta: Option<f64>,
    /// Why the estimator drew no interval, when it drew none.
    pub gap: Option<EstimateGap>,
    pub card: Option<SufficiencyCard>,
}

impl EvalMeasurement {
    /// Both offers only when every settled leg kept the same pair, including
    /// the incumbent retest. A model name or one surviving case is not a pair.
    #[must_use]
    pub fn serving_offers(&self) -> Option<(&EvalServingOffer, &EvalServingOffer)> {
        if self.state != MeasurementState::Final || self.cases.is_empty() {
            return None;
        }
        let first = self.cases.first()?;
        let incumbent = first.incumbent.serving_offer.as_ref()?;
        let candidate = first.candidate.serving_offer.as_ref()?;
        self.cases
            .iter()
            .all(|case| {
                case.recorded_at.is_some()
                    && case.legs().iter().all(|leg| leg.unavailable.is_none())
                    && case.incumbent.serving_offer.as_ref() == Some(incumbent)
                    && case.retest.serving_offer.as_ref() == Some(incumbent)
                    && case.candidate.serving_offer.as_ref() == Some(candidate)
            })
            .then_some((incumbent, candidate))
    }
}
