//! Which captured step a contribution check regenerates (FIX 2870, OF-542):
//! a loaded skill's check, the run's first step, the one input no answer of
//! the run has touched yet; an ancestor check on one used edge, the earliest
//! step that exposed the edge's source, where the run first read it. Each is
//! of the latest lease generation that captured it, whose answer the run
//! kept. The exposure is the typed slot the host tagged as it put the body in
//! the run's task ([`super::super::replay_capsule::ExposureSlot`]); nothing
//! is found by searching the request's text.

use std::cmp::Reverse;

use super::super::replay_capsule::{ExposureSlot, StepReplayCapsule};
use super::{ContributionReplayUnavailable, FIRST_STEP};
use crate::skill_attribution::ContributionTarget;

/// The step `target`'s check regenerates among `capsules`, one run's
/// captured steps; else why there is none.
pub(super) fn target_step(
    capsules: Vec<StepReplayCapsule>,
    target: ContributionTarget,
) -> std::result::Result<StepReplayCapsule, ContributionReplayUnavailable> {
    let none = match target {
        ContributionTarget::LoadedSkill(_) => ContributionReplayUnavailable::NoCapsule,
        ContributionTarget::UsedEdge { .. } if capsules.is_empty() => {
            ContributionReplayUnavailable::NoCapsule
        }
        ContributionTarget::UsedEdge { .. } => ContributionReplayUnavailable::NoExposure,
    };
    capsules
        .into_iter()
        .filter(|capsule| match target {
            ContributionTarget::LoadedSkill(_) => capsule.step == FIRST_STEP,
            ContributionTarget::UsedEdge { .. } => !target_slots(capsule, target).is_empty(),
        })
        .max_by_key(|capsule| (capsule.lease_generation, Reverse(capsule.step)))
        .ok_or(none)
}

/// Each exposure of the entity `target`'s check leaves out in `capsule`.
pub(super) fn target_slots(
    capsule: &StepReplayCapsule,
    target: ContributionTarget,
) -> Vec<&ExposureSlot> {
    let removed = target.removed();
    capsule
        .exposures
        .iter()
        .filter(|slot| slot.skill == removed)
        .collect()
}
