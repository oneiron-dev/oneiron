//! The offer the Coach's answer names, projected from the brief it read. The
//! chosen option and each alternative are grounded only on their own
//! option's pilot, matched exactly by seat, incumbent, whole candidate and
//! destination while the brief was gathered (`pilot.rs`, FIX 9469). A pilot
//! of another recipe or destination on the same base model grounds nothing
//! here: an option no measured pilot matched keeps its score, its one-off
//! cost and its measurement evidence unknown, and its own refs.
use oneiron::EntityId;
use oneiron::skill_optimize::offer_pilot::{OfferPilot, OfferPilotMeasurement};

use super::{
    AnswerWire, Brief, CATALOG_CURRENCY, CHECK_AFTER_SECS, ESTIMATE_NOTE, OfferCost, OfferOption,
    PRICING_NOTE, TrainingOfferDraft, payback,
};

/// An option's pilot, when it was measured, with its measurement.
fn measured(pilot: Option<&OfferPilot>) -> Option<(&OfferPilot, &OfferPilotMeasurement)> {
    pilot.and_then(|pilot| {
        pilot
            .measurement
            .as_ref()
            .map(|measurement| (pilot, measurement))
    })
}

/// A measured one-off cost an offer's options can carry: one in their
/// currency. A list-price projection cannot absorb another currency's
/// one-off cost, so it stays unknown rather than read as zero.
fn one_off(measurement: &OfferPilotMeasurement) -> Option<f64> {
    (measurement.currency == CATALOG_CURRENCY)
        .then_some(measurement.one_off_cost)
        .flatten()
}

/// A pilot as an option's evidence ref.
fn pilot_ref(pilot: &OfferPilot) -> String {
    format!("offer_pilot:{}", pilot.id.to_hex())
}

impl Brief {
    /// The offer the Coach's answer names, or `None` for no offer: it named
    /// none, named no option given, or repeats an offer without saying what
    /// changed.
    pub(super) fn draft(
        mut self,
        answer: AnswerWire,
        offer_skill: (EntityId, String),
        now: u64,
    ) -> Option<TrainingOfferDraft> {
        let chosen = answer.offer?;
        let index = self.choices.iter().position(|choice| choice.id == chosen)?;
        let what_changed = answer
            .what_changed
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned);
        if self.previous.is_some() && what_changed.is_none() {
            return None;
        }
        let choice = self.choices.remove(index);
        let note = if choice.estimate {
            ESTIMATE_NOTE
        } else {
            PRICING_NOTE
        };
        let cost = |monthly: Option<f64>, one_off: Option<f64>| OfferCost {
            currency: CATALOG_CURRENCY.to_owned(),
            monthly_before: self.baseline_monthly,
            monthly_after: monthly,
            one_off,
            payback_months: payback(self.baseline_monthly, monthly, one_off),
        };
        // The chosen option's own pilot measured the incumbent beside it.
        let chosen_pilot = measured(choice.pilot.as_ref());
        let baseline = OfferOption {
            label: format!("keep {}", self.incumbent.model),
            model: self.incumbent.clone(),
            // Keeping the seat costs nothing once.
            cost: cost(self.baseline_monthly, Some(0.0)),
            score: chosen_pilot.and_then(|(_, measurement)| measurement.incumbent_score),
            evidence_refs: chosen_pilot.map_or_else(Vec::new, |(pilot, _)| vec![pilot_ref(pilot)]),
        };
        let alternatives = self
            .choices
            .iter()
            .map(|other| {
                let pilot = measured(other.pilot.as_ref());
                OfferOption {
                    label: other.label.clone(),
                    model: other.pin.clone(),
                    cost: cost(
                        other.monthly,
                        pilot.and_then(|(_, measurement)| one_off(measurement)),
                    ),
                    score: pilot.and_then(|(_, measurement)| measurement.candidate_score),
                    evidence_refs: pilot.map_or_else(
                        || other.evidence_refs.clone(),
                        |(pilot, _)| vec![pilot_ref(pilot)],
                    ),
                }
            })
            .collect();
        // The risk line carries the price note after the Coach's words.
        let risk = answer
            .risk
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map_or_else(|| note.to_owned(), |risk| format!("{risk} {note}"));
        let mut evidence = self.evidence;
        if let Some((pilot, _)) = chosen_pilot {
            evidence.cohort = Some(pilot.exposure.cohort);
            evidence.exposures = vec![pilot.exposure.id];
            evidence.rubric_revision = Some(pilot.rubric_revision.clone());
            evidence.card = pilot.card.clone();
        }
        evidence.losses = answer
            .losses
            .iter()
            .map(|loss| loss.trim())
            .filter(|loss| !loss.is_empty())
            .map(str::to_owned)
            .collect();
        evidence.risk = Some(risk);
        // The offer skill whose body the Coach ran on this brief.
        let mut sources = self.sources;
        sources.row(offer_skill.0);
        Some(TrainingOfferDraft {
            seat: self.seat,
            offer_skill: Some(offer_skill),
            incumbent: self.incumbent,
            candidate: choice.candidate,
            baseline,
            alternatives,
            workload: self.workload,
            cost: cost(
                choice.monthly,
                chosen_pilot.and_then(|(_, measurement)| one_off(measurement)),
            ),
            evidence,
            destination: choice.destination,
            previous: self.previous,
            what_changed: self.previous.and(what_changed),
            check_at: now.saturating_add(CHECK_AFTER_SECS),
            source_rows: sources.rows(),
        })
    }
}
