//! The budget a plan is fitted to and launched under (FIX 9561). A pinned
//! budget is the cap exactly. A seeded budget is a prior worth its
//! `weight_runs`: before the plan is fitted it is weighed against the spend
//! the launch has learned for the shape, each side by its weight in runs, and
//! the plan launches under what it resolves to. Either is met with the
//! caller's and parent's caps, never widens them; with no learned spend the
//! seed stands as given.

use super::super::spend_calibration::{ExpectedSpend, SpendBasis};
use super::super::types::{SpawnNeed, SpawnOverride};
use super::{PlanBudget, TeamPlan};

/// The spawn's budget ask, resolved for a shape of `width` agents expected
/// to spend `per_agent` each: a pin's value; a seed weighed against the
/// shape's calibrated spend; `None` with no ask.
fn resolved_ask(
    asked: Option<&SpawnOverride<u64>>,
    width: u32,
    per_agent: ExpectedSpend,
) -> Option<u64> {
    let (seed, weight_runs) = match asked? {
        SpawnOverride::Pin { value } => return Some(*value),
        SpawnOverride::Seed { value, weight_runs } => (*value, *weight_runs),
    };
    let samples = match per_agent.basis {
        SpendBasis::Calibrated => per_agent.samples,
        _ => 0,
    };
    if samples == 0 {
        return Some(seed);
    }
    // The need door holds a seed weight to a positive, finite run count.
    let weight = weight_runs.max(0.0);
    let learned = per_agent.units.saturating_mul(u64::from(width)) as f64;
    let samples = samples as f64;
    let resolved = (weight * seed as f64 + samples * learned) / (weight + samples);
    Some(resolved.ceil() as u64)
}

/// The cap a planned launch's group runs under: a pinned ask's value, or the
/// hard cap a seeded ask resolved to when its plan was fitted (the seed
/// itself where that plan states none).
pub(in crate::agent_dispatch) fn launch_budget(asked: &SpawnNeed, plan: &TeamPlan) -> Option<u64> {
    match asked.budget_cap_units.as_ref()? {
        SpawnOverride::Pin { value } => Some(*value),
        SpawnOverride::Seed { value, .. } => plan.envelope.hard_cap_units.or(Some(*value)),
    }
}

impl PlanBudget {
    /// The budget a shape of `width` agents expected to spend `per_agent`
    /// each is fitted to: this one, its cap narrowed to the resolved ask.
    pub(super) fn resolved_for(
        self,
        need: &SpawnNeed,
        width: u32,
        per_agent: ExpectedSpend,
    ) -> Self {
        match resolved_ask(need.budget_cap_units.as_ref(), width, per_agent) {
            Some(asked) => Self {
                cap_units: Some(self.cap_units.map_or(asked, |cap| cap.min(asked))),
                available_units: self.available_units,
            },
            None => self,
        }
    }
}
