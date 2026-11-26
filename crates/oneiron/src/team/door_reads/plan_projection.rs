//! A spawn's selected plan as the owner's reads project it: what the plan
//! resolved, and beside it each knob as the spawn's own call asked for it.

use crate::agent_dispatch::SpawnPlanReceipt;
use crate::team::spawn_need::SpawnCallKnobs;
use crate::team::spawn_override::SpawnOverride;

use super::super::doors::{
    CoordinationPatternView, PlanObservation, ProviderPinView, SkillRevisionView, SpawnAskKnob,
    SpawnAskObservation, TypeStamp,
};

pub(in crate::team) fn plan_view(receipt: &SpawnPlanReceipt) -> PlanObservation {
    let plan = &receipt.plan;
    PlanObservation {
        type_ref: TypeStamp::from(&receipt.asked.type_ref),
        model: plan.model.as_str().to_owned(),
        width: plan.shape.width,
        pattern: plan.shape.pattern.into(),
        hard_cap_units: plan.envelope.hard_cap_units,
        expected_spend_units: plan.envelope.expected_spend_units,
        available_units: plan.envelope.available_units,
        over_budget: plan.over_budget,
        fitted_to_budget: plan.fitted_to_budget,
        why: receipt.why.clone(),
        team_shape: receipt.team_shape.as_ref().map(SkillRevisionView::from),
        pattern_skill: plan.pattern_skill.as_ref().map(SkillRevisionView::from),
        rung_skill: receipt.rung_skill.as_ref().map(SkillRevisionView::from),
        rung_providers: receipt
            .rung_providers
            .iter()
            .map(ProviderPinView::from)
            .collect(),
        asked: ask_view(&receipt.call_knobs),
        what_more_would_buy: plan.what_more_would_buy.clone(),
    }
}

/// The knobs the spawn's call set, as the receipt captured them before the
/// owner's choices filled or replaced any.
fn ask_view(asked: &SpawnCallKnobs) -> SpawnAskObservation {
    SpawnAskObservation {
        model: asked
            .model
            .as_ref()
            .map(|knob| knob_view(knob, |model| model.as_str().to_owned())),
        width: asked
            .width
            .as_ref()
            .map(|knob| knob_view(knob, |width| *width)),
        pattern: asked
            .pattern
            .as_ref()
            .map(|knob| knob_view(knob, |pattern| CoordinationPatternView::from(*pattern))),
        budget_cap_units: asked
            .budget_cap_units
            .as_ref()
            .map(|knob| knob_view(knob, |cap| *cap)),
    }
}

fn knob_view<T, U>(knob: &SpawnOverride<T>, view: impl FnOnce(&T) -> U) -> SpawnAskKnob<U> {
    match knob {
        SpawnOverride::Seed { value, weight_runs } => SpawnAskKnob::Seed {
            value: view(value),
            weight_runs: *weight_runs,
        },
        SpawnOverride::Pin { value } => SpawnAskKnob::Pin { value: view(value) },
    }
}
