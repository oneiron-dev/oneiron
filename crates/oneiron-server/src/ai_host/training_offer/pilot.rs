//! Measured per-seat pilot evidence beside the production offer skill's brief.
//! Each option gets the latest pilot of exactly it, by seat, incumbent, whole
//! candidate and destination, kept on its choice: the draft's options are
//! projected from those exact pilots (`draft.rs`, FIX 9469), never matched
//! again by model alone.
use super::{Choice, EvalSeat, OfferModelPin, Sources, Vault};
use oneiron::skill_optimize::offer_pilot::{candidate_rows, latest_pilot};

pub(super) fn brief(
    vault: &Vault,
    seat: &EvalSeat,
    incumbent: &OfferModelPin,
    choices: &mut [Choice],
    sources: &mut Sources,
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
            // The pilot's measurement, with its release, as it froze their
            // rows (FIX 5760).
            sources.set(pilot.measurement_source_rows.as_deref());
            choice.data["pilot"] = serde_json::json!({
                "pilot": pilot.id,
                "cohort": pilot.exposure.cohort,
                "rubric_revision": pilot.rubric_revision,
                "families": pilot.families,
                "sufficiency": pilot.card,
                "measurement": pilot.measurement,
            });
            choice.pilot = Some(pilot);
        }
    }
    Ok(())
}
