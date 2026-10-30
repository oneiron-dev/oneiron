//! A training offer's measured card: the paired measurement of exactly the
//! offer's incumbent and stock candidate, on the seat's live cohort, asked
//! for on each draft and attached once it is Final. Until then the offer's
//! evidence stays as it was grounded (a pilot's card, or none: unknown,
//! never not-worse). One pair's card is never lent to another option, and
//! nothing switches the seat.

use oneiron::skill_optimize::{
    EvalArmPin, EvalAxisPin, EvalMeasurementRequest, FloorSlicePolicy, HeldOutReplayNotes,
    JUDGE_SCORE_AXIS, JUDGE_SCORE_UNITS, MeasurementMethodPin, MeasurementState, OfferCandidate,
    OfferModelPin, ScoreDirection, TrainingOfferDraft, eval_seat_canary,
};
use oneiron::{Error, Vault};

/// The decision a training offer's measurement waits on.
const OFFER_DECISION: &str = "training_offer";

fn arm(pin: &OfferModelPin) -> EvalArmPin {
    EvalArmPin {
        model: pin.model.clone(),
        revision: pin.revision.clone(),
        skill_digest: None,
    }
}

/// Asks for the draft's pair's measurement and, when it is Final for that
/// exact request, puts its card, cohort, rubric revision and exposures
/// (first) on the draft. A trained candidate has no measurement here: its
/// weights have no loader yet.
/// # Errors
/// Storage errors.
pub(in crate::ai_host) fn attach_measured_card(
    vault: &Vault,
    draft: &mut TrainingOfferDraft,
    now: u64,
) -> oneiron::Result<()> {
    let OfferCandidate::Stock { model, .. } = &draft.candidate else {
        return Ok(());
    };
    let Some(judge) = crate::replay_judge::registered() else {
        return Ok(());
    };
    let Some(cohort) = vault
        .eval_cohorts(&draft.seat)?
        .into_iter()
        .rev()
        .find(|cohort| cohort.retired_at.is_none())
    else {
        return Ok(());
    };
    let request = EvalMeasurementRequest {
        decision: OFFER_DECISION.to_owned(),
        seat: draft.seat.clone(),
        incumbent: arm(&draft.incumbent),
        candidate: arm(model),
        cohort: cohort.id,
        membership_digest: cohort.membership_digest,
        rubric_revision: cohort.rubric_revision,
        scorer: judge.judge_revision().to_owned(),
        axis: EvalAxisPin {
            axis: JUDGE_SCORE_AXIS.to_owned(),
            direction: ScoreDirection::HigherIsBetter,
            units: JUDGE_SCORE_UNITS.to_owned(),
        },
        floor_slices: FloorSlicePolicy::default(),
        canary: eval_seat_canary(&draft.seat).map(str::to_owned),
        method: MeasurementMethodPin::current(),
        retry: 0,
    };
    let digest = match vault.request_eval_measurement(&request, now) {
        Ok(digest) => digest,
        // A pair the measurement door refuses is measured by nothing.
        Err(Error::InvalidConfig(reason)) => {
            tracing::debug!(%reason, "the offer's pair has no eval measurement");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let Some(measured) = vault.eval_measurement(&digest)? else {
        return Ok(());
    };
    if measured.state != MeasurementState::Final || measured.request != request {
        return Ok(());
    }
    let Some(card) = measured.card else {
        return Ok(());
    };
    let earlier = std::mem::take(&mut draft.evidence.exposures);
    let mut exposures = measured.exposures;
    for exposure in earlier {
        if !exposures.contains(&exposure) {
            exposures.push(exposure);
        }
    }
    draft.evidence.cohort = Some(request.cohort);
    draft.evidence.exposures = exposures;
    draft.evidence.rubric_revision = Some(request.rubric_revision);
    draft.evidence.card = Some(card);
    Ok(())
}
