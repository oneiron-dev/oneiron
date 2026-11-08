//! A training offer's measured card: the paired measurement of exactly the
//! offer's incumbent and exact stock or returned trained candidate, on the seat's live cohort, asked
//! for on each draft and attached once it is Final. Until then the offer's
//! evidence stays as it was grounded (a pilot's card, or none: unknown,
//! never not-worse). One pair's card is never lent to another option, and
//! nothing switches the seat.

use oneiron::skill_optimize::{
    EvalArmPin, EvalAxisPin, EvalMeasurementRequest, EvalServingOffer, HeldOutReplayNotes,
    JUDGE_SCORE_AXIS, JUDGE_SCORE_UNITS, MeasurementMethodPin, MeasurementState, OfferCandidate,
    OfferModelPin, ScoreDirection, TrainingOfferDraft, eval_seat_canary,
};
use oneiron::{Error, ModelId};

use crate::server::SyncServer;

/// The decision a training offer's measurement waits on.
const OFFER_DECISION: &str = "training_offer";

fn arm(pin: &OfferModelPin) -> EvalArmPin {
    EvalArmPin {
        model: pin.model.clone(),
        revision: pin.revision.clone(),
        skill_digest: None,
    }
}

/// A request-time snapshot of the actual two constructed offers, not a
/// claim about what a later measurement will serve or permission to switch.
fn requested_offers(
    server: &SyncServer,
    incumbent: &OfferModelPin,
    candidate: &OfferModelPin,
) -> Option<[EvalServingOffer; 2]> {
    let router = server.ai.model_runtime().router()?;
    let capture = |pin: &OfferModelPin| {
        let model = ModelId::new(pin.model.clone()).ok()?;
        let (_, ladder) = router.served(&model)?;
        ladder
            .exact_offer_binding()
            .map(EvalServingOffer::from_binding)
    };
    Some([capture(incumbent)?, capture(candidate)?])
}

/// Asks for the draft's pair's measurement and, when it is Final for that
/// exact request, puts its card, cohort, rubric revision and exposures
/// (first) on the draft. A trained embedder recipe measures its actual
/// returned checkpoint, not its base or a hypothetical later training run.
/// # Errors
/// Storage errors.
pub(in crate::ai_host) fn attach_measured_card(
    server: &SyncServer,
    draft: &mut TrainingOfferDraft,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let candidate = match &draft.candidate {
        OfferCandidate::Stock { model, .. } => arm(model),
        OfferCandidate::TrainRecipe {
            base, recipe_ref, ..
        } if draft.seat == oneiron::skill_optimize::EvalSeat::Embedder => {
            let Some(id) = recipe_ref
                .strip_prefix("training_run:")
                .and_then(|id| oneiron::EntityId::from_hex(id).ok())
            else {
                return Ok(());
            };
            let Some(run) = vault.training_run(&id)? else {
                return Ok(());
            };
            if run.plan.seat != draft.seat
                || oneiron::skill_optimize::offer_pilot::training_base_pin(&run).as_ref()
                    != Some(base)
            {
                return Ok(());
            }
            let Some(source) = vault.training_embedder_source(&id)? else {
                return Ok(());
            };
            EvalArmPin {
                model: source.checkpoint.model.as_str().to_owned(),
                revision: blake3::Hash::from(source.checkpoint.content_hash()?)
                    .to_hex()
                    .to_string(),
                skill_digest: None,
            }
        }
        _ => return Ok(()),
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
        candidate,
        // A trained recipe is measured only on the native embedder seat,
        // which has no constructed serving offer to snapshot.
        requested_offers: match &draft.candidate {
            OfferCandidate::Stock { model, .. } if !super::native_seat(&draft.seat) => {
                requested_offers(server, &draft.incumbent, model)
            }
            _ => None,
        },
        cohort: cohort.id,
        membership_digest: cohort.membership_digest,
        rubric_revision: cohort.rubric_revision,
        scorer: judge.judge_revision().to_owned(),
        axis: EvalAxisPin {
            axis: JUDGE_SCORE_AXIS.to_owned(),
            direction: ScoreDirection::HigherIsBetter,
            units: JUDGE_SCORE_UNITS.to_owned(),
        },
        floor_slices: vault.offer_floor_slices(&draft.seat)?,
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
    draft.evidence.paired_measurement = Some(digest);
    Ok(())
}
