//! Measured per-seat pilot evidence beside the production offer skill's brief.
use super::{Choice, EvalSeat, OfferModelPin, TrainingOfferDraft, Vault};
use oneiron::skill_optimize::offer_pilot::{candidate_rows, latest_pilot};

pub(super) fn brief(
    vault: &Vault,
    seat: &EvalSeat,
    incumbent: &OfferModelPin,
    choices: &mut [Choice],
) -> oneiron::Result<()> {
    for candidate in candidate_rows(vault, Some(seat))? {
        if candidate.setup.incumbent != *incumbent {
            continue;
        }
        let Some(choice) = choices.iter_mut().find(|choice| {
            choice.candidate == candidate.setup.candidate
                && choice.destination == candidate.setup.destination
        }) else {
            continue;
        };
        if let Some(pilot) = latest_pilot(vault, &candidate)? {
            choice.data["pilot"] = serde_json::json!({
                "pilot": pilot.id,
                "cohort": pilot.exposure.cohort,
                "rubric_revision": pilot.rubric_revision,
                "families": pilot.families,
                "sufficiency": pilot.card,
                "measurement": pilot.measurement,
            });
        }
    }
    Ok(())
}

pub(super) fn ground(vault: &Vault, draft: &mut TrainingOfferDraft) -> oneiron::Result<()> {
    for candidate in candidate_rows(vault, Some(&draft.seat))? {
        if candidate.setup.incumbent != draft.incumbent {
            continue;
        }
        let Some(pilot) = latest_pilot(vault, &candidate)? else {
            continue;
        };
        let Some(measurement) = &pilot.measurement else {
            continue;
        };
        // A USD list-price projection cannot absorb another currency's
        // one-off cost. It stays unknown rather than treating it as zero.
        let same_currency = measurement.currency == draft.cost.currency;
        if candidate.setup.candidate == draft.candidate
            && candidate.setup.destination == draft.destination
        {
            draft.evidence.cohort = Some(pilot.exposure.cohort);
            draft.evidence.exposures = vec![pilot.exposure.id];
            draft.evidence.rubric_revision = Some(pilot.rubric_revision);
            draft.evidence.card = pilot.card;
            draft.baseline.score = measurement.incumbent_score;
            draft.baseline.evidence_refs = vec![format!("offer_pilot:{}", pilot.id.to_hex())];
            draft.cost.one_off = same_currency.then_some(measurement.one_off_cost).flatten();
            draft.cost.payback_months = super::payback(
                draft.cost.monthly_before,
                draft.cost.monthly_after,
                draft.cost.one_off,
            );
        }
        for alternative in &mut draft.alternatives {
            let pin = match &candidate.setup.candidate {
                oneiron::skill_optimize::OfferCandidate::Stock { model, .. } => model,
                oneiron::skill_optimize::OfferCandidate::TrainRecipe { base, .. } => base,
            };
            if alternative.model == *pin {
                alternative.score = measurement.candidate_score;
                alternative.evidence_refs = vec![format!("offer_pilot:{}", pilot.id.to_hex())];
                alternative.cost.one_off =
                    same_currency.then_some(measurement.one_off_cost).flatten();
                alternative.cost.payback_months = super::payback(
                    alternative.cost.monthly_before,
                    alternative.cost.monthly_after,
                    alternative.cost.one_off,
                );
            }
        }
    }
    Ok(())
}
