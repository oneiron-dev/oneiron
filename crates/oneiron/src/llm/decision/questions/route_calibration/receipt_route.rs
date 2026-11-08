//! A calibration pair's route, routing policy revision and answering pins, read from the
//! answer's receipt alone.

use crate::EntityId;
use crate::llm::decision::questions::{
    AnswerRecord, CalibrationPair, DecisionRoute, OutcomeLabel, RoutingPolicy,
};
use crate::llm::decision::{DecisionReceipt, DecisionRung, ProviderPin, Reasoning};

/// The calibration pair of `answer`'s receipted prediction at `probability` against
/// `outcome`, derived from `derived_from`: its route, policy revision and answering pins
/// joined from the answer's own receipt.
pub(in crate::llm::decision::questions) fn answer_pair(
    answer: &AnswerRecord,
    probability: f64,
    outcome: OutcomeLabel,
    derived_from: Vec<EntityId>,
) -> CalibrationPair {
    let receipt = &answer.decision.receipt;
    let route = receipt_route(receipt);
    CalibrationPair {
        prediction: answer.decision.answer.clone(),
        probability,
        outcome,
        question_version: receipt.question_version,
        route,
        policy: Some(receipt_policy(receipt)),
        providers: answering_pins(receipt, route),
        derived_from,
    }
}

/// How `receipt`'s answer was returned. No clock is no route. On a clock, the rung whose
/// answer stands decides: the rule rung is [`DecisionRoute::Rule`], the person rung
/// [`DecisionRoute::Person`], a model rung reads its reasoning. With no rung standing, an
/// answered ask is the person's route; anything else names none.
fn receipt_route(receipt: &DecisionReceipt) -> DecisionRoute {
    let Some(time) = &receipt.time else {
        return DecisionRoute::Unrouted;
    };
    match time.answered {
        Some(DecisionRung::Rule) => DecisionRoute::Rule,
        Some(DecisionRung::Human) => DecisionRoute::Person,
        Some(rung) => match time.reasoning {
            Reasoning::NotNeeded => DecisionRoute::Direct { rung },
            Reasoning::Ran(_) => DecisionRoute::SteppedUp { rung },
            Reasoning::Skipped(_) | Reasoning::Cut(_) => DecisionRoute::StepUnfinished { rung },
        },
        None if receipt
            .asked
            .as_ref()
            .is_some_and(|ask| ask.answered.is_some()) =>
        {
            DecisionRoute::Person
        }
        None => DecisionRoute::Unrouted,
    }
}

/// The routing policy revision `receipt` pins.
fn receipt_policy(receipt: &DecisionReceipt) -> RoutingPolicy {
    RoutingPolicy {
        band_version: receipt.band_version,
        think_row: receipt.think_row,
        person_row: receipt.person_row,
        rule: receipt.rule,
    }
}

/// The pins whose measurement the answer's probability is, each once, in receipt order: its
/// pins at the rung `route` names, or every model pin it names when the route names none.
fn answering_pins(receipt: &DecisionReceipt, route: DecisionRoute) -> Vec<ProviderPin> {
    let rung = match route {
        DecisionRoute::Rule => Some(DecisionRung::Rule),
        DecisionRoute::Direct { rung }
        | DecisionRoute::SteppedUp { rung }
        | DecisionRoute::StepUnfinished { rung } => Some(rung),
        DecisionRoute::Person | DecisionRoute::Unrouted => None,
    };
    let mut pins: Vec<ProviderPin> = Vec::new();
    for pin in &receipt.providers {
        let measured = rung.map_or(pin.rung != DecisionRung::Human, |rung| pin.rung == rung);
        if measured && !pins.contains(pin) {
            pins.push(pin.clone());
        }
    }
    pins
}
