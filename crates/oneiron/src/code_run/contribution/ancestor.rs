//! Which captured step a contribution check regenerates (FIX 2870, OF-542):
//! a loaded skill's check, the run's first step, the one input no answer of
//! the run has touched yet; an ancestor check on one used edge, the earliest
//! step that exposed the edge's source, where the run first read it. Each is
//! of the latest lease generation that captured it, whose answer the run
//! kept. The exposure is the typed slot the host tagged as it put the body in
//! the run's task ([`super::super::replay_capsule::ExposureSlot`]); nothing
//! is found by searching the request's text.
//!
//! A loaded skill whose first step's task does not expose it, but whose load
//! a step's own program called as a callable, has its check regenerate the
//! step after that call's (FIX 3608, [`super::execution`]): the first call
//! its step's replay context froze, in the earliest such step of the latest
//! lease generation. The step-zero rule for a body in the task stays as it
//! is.

use std::cmp::Reverse;

use super::super::replay_capsule::{ExposureSlot, StepReplayCapsule};
use super::execution::{CallableTarget, callable_target_in_txn};
use super::{ContributionReplayUnavailable, FIRST_STEP};
use crate::skill_attribution::ContributionTarget;
use crate::{Result, Vault};

/// What a contribution check regenerates.
pub(super) enum TargetStep {
    /// The step whose task exposed the target, else why there is none.
    Knowledge(std::result::Result<StepReplayCapsule, ContributionReplayUnavailable>),
    /// The step after a call of the target's load (FIX 3608).
    Callable(Box<CallableTarget>),
}

impl TargetStep {
    /// The capsule its forks regenerate, when there is one.
    pub(super) fn regenerated(&self) -> Option<&StepReplayCapsule> {
        match self {
            Self::Knowledge(capsule) => capsule.as_ref().ok(),
            Self::Callable(callable) => callable.next.as_ref(),
        }
    }
}

/// What `target`'s check regenerates among `capsules`, one run's captured
/// steps, read in `txn`: the knowledge step [`target_step`] selects when its
/// task exposes the target, else the step after a call of the target's
/// load, when a step's replay context froze one, else the knowledge step's
/// reason.
///
/// # Errors
///
/// Storage errors.
pub(super) fn select_target(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    capsules: &[StepReplayCapsule],
    target: ContributionTarget,
) -> Result<TargetStep> {
    let knowledge = target_step(capsules, target);
    let exposed = knowledge
        .as_ref()
        .is_ok_and(|capsule| !target_slots(capsule, target).is_empty());
    if !exposed && let Some(callable) = callable_target_in_txn(vault, txn, capsules, target)? {
        return Ok(TargetStep::Callable(Box::new(callable)));
    }
    Ok(TargetStep::Knowledge(knowledge))
}

/// The step `target`'s check regenerates among `capsules`, one run's
/// captured steps; else why there is none.
pub(super) fn target_step(
    capsules: &[StepReplayCapsule],
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
        .iter()
        .filter(|capsule| match target {
            ContributionTarget::LoadedSkill(_) => capsule.step == FIRST_STEP,
            ContributionTarget::UsedEdge { .. } => !target_slots(capsule, target).is_empty(),
        })
        .max_by_key(|capsule| (capsule.lease_generation, Reverse(capsule.step)))
        .cloned()
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
