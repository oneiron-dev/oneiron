//! What a submitted pair's stored forks prove (FIX 3610, FIX 2870): the A
//! side records a contribution check as measured only when the fork
//! receipts this runner kept for the pair's canonical candidate are the ones
//! submitted, scored as submitted for the candidate's outcome, and
//! regenerated the capsule of the step the target's check regenerates as it
//! stands, read on the caller's snapshot. An engine step's forks also prove
//! their scores only by a kept execution (FIX 3607): each fork's own answer
//! run from that capsule's start under the one pin both forks' frozen
//! scoring identity names. A pair they do not prove is still recorded, as
//! unmatched; nothing here refuses it.

use serde::{Deserialize, Serialize};

use super::super::replay_capsule::{CapsuleHost, StepReplayCapsule};
use super::super::storage::{fork_rows_in_txn, step_replay_capsules_in_txn};
use super::ancestor::target_step;
use super::{
    ContributionForkReceipt, ForkEvidence, ForkScoring, ForkTreatment, anchor_hash, pair_digest,
    receipt_attempt,
};
use crate::skill_attribution::{ContributionCandidate, ContributionFork};
use crate::{Result, Vault};

/// Why a pair's stored forks do not prove it. None of these is a verdict on
/// the skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkMismatch {
    /// The runner recorded the pair unavailable.
    Unavailable,
    /// No fork receipt is kept for a side of the pair.
    MissingFork,
    /// A kept fork has another receipt than the one submitted for its side.
    OtherReceipt,
    /// A kept fork is not scored yet.
    Unscored,
    /// A kept fork was scored otherwise than submitted.
    OtherScore,
    /// The two forks were not scored against one anchor: their stored
    /// anchors differ, a stored anchor is not the candidate's anchor bound
    /// to its fork's frozen scoring identity, or a fork was scored on other
    /// evidence than its step's (an engine step's executed program under
    /// that identity's pin, a workflow step's answer text).
    AnchorDiverged,
    /// A fork did not regenerate the capsule of the step the target's check
    /// regenerates as it stands: another capsule, request, model, route
    /// prompt or seed, or the capsule's content is gone; or an engine step's
    /// fork's execution did not run its own answer from that capsule's start.
    OtherCapsule,
    /// A kept fork was scored for another outcome, goal revision or axis
    /// than the candidate's.
    OtherOutcome,
}

/// The facts a pair's kept forks prove: each side's score, as kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MatchedContributionFacts {
    pub(crate) with_skill_passed: bool,
    pub(crate) without_skill_passed: bool,
}

/// Whether the forks kept for `candidate`'s pair prove `with_skill` and
/// `without_skill`, on `txn`'s snapshot: the facts when they do, else every
/// reason they do not.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn matched_contribution_facts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidate: &ContributionCandidate,
    with_skill: &ContributionFork,
    without_skill: &ContributionFork,
) -> Result<std::result::Result<MatchedContributionFacts, Vec<ForkMismatch>>> {
    let rows = fork_rows_in_txn(vault, txn, &pair_digest(candidate))?;
    let mut reasons = Vec::new();
    if rows.unavailable.is_some() {
        reasons.push(ForkMismatch::Unavailable);
    }
    let (Some(with_fork), Some(without_fork)) = (rows.with_skill, rows.without_skill) else {
        reasons.push(ForkMismatch::MissingFork);
        return Ok(Err(reasons));
    };
    for (fork, submitted, treatment) in [
        (&with_fork, with_skill, ForkTreatment::WithSkill),
        (&without_fork, without_skill, ForkTreatment::WithoutSkill),
    ] {
        if fork.receipt != submitted.receipt || fork.treatment != treatment {
            reasons.push(ForkMismatch::OtherReceipt);
        }
        match fork.passed {
            None => reasons.push(ForkMismatch::Unscored),
            Some(passed) if passed != submitted.passed => reasons.push(ForkMismatch::OtherScore),
            Some(_) => {}
        }
    }
    if with_fork.anchor != without_fork.anchor {
        reasons.push(ForkMismatch::AnchorDiverged);
    }
    if anchor_hash(candidate, &with_fork.anchor_scoring)? != with_fork.anchor
        || anchor_hash(candidate, &without_fork.anchor_scoring)? != without_fork.anchor
    {
        reasons.push(ForkMismatch::AnchorDiverged);
    }
    let scoring = ForkScoring::of(candidate);
    if with_fork.scoring != scoring || without_fork.scoring != scoring {
        reasons.push(ForkMismatch::OtherOutcome);
    }
    match target_capsule(vault, txn, candidate)? {
        Some(capsule)
            if regenerates(&capsule, &with_fork) && regenerates(&capsule, &without_fork) =>
        {
            reasons.extend(evidence_mismatch(&capsule, &with_fork));
            reasons.extend(evidence_mismatch(&capsule, &without_fork));
        }
        _ => reasons.push(ForkMismatch::OtherCapsule),
    }
    reasons.sort_unstable();
    reasons.dedup();
    if !reasons.is_empty() {
        return Ok(Err(reasons));
    }
    match (with_fork.passed, without_fork.passed) {
        (Some(with_skill_passed), Some(without_skill_passed)) => Ok(Ok(MatchedContributionFacts {
            with_skill_passed,
            without_skill_passed,
        })),
        _ => Ok(Err(vec![ForkMismatch::Unscored])),
    }
}

/// The capsule of the step `candidate`'s target check regenerates
/// ([`super::ancestor`]), as it stands in `txn`.
fn target_capsule(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidate: &ContributionCandidate,
) -> Result<Option<StepReplayCapsule>> {
    let Some(attempt) = receipt_attempt(&candidate.attempt_receipt) else {
        return Ok(None);
    };
    let capsules = step_replay_capsules_in_txn(vault, txn, attempt)?;
    Ok(target_step(&capsules, candidate.target).ok())
}

/// Whether `fork` regenerated `capsule`: its request, model, route prompt
/// and seed, with its content still held.
fn regenerates(capsule: &StepReplayCapsule, fork: &ContributionForkReceipt) -> bool {
    let Some(binding) = &capsule.binding else {
        return false;
    };
    let route_prompt = binding
        .prompt
        .as_deref()
        .map(|prompt| *blake3::hash(prompt.as_bytes()).as_bytes());
    capsule.content.actor().is_some()
        && fork.attempt == capsule.attempt
        && fork.lease_generation == capsule.lease_generation
        && fork.step == capsule.step
        && fork.capsule_request == capsule.request_hash
        && fork.model == binding.model
        && fork.route_prompt == route_prompt
        && fork.seed == capsule.seed
        && fork.seed_unsupported == capsule.seed.is_none()
}

/// Why `fork`'s score is not proved on `capsule`'s evidence (FIX 3607), if
/// it is not: a workflow step's fork is scored on its answer's text alone;
/// an engine step's only on its kept execution (`Unscored` without one),
/// whose pin is the one its frozen scoring identity names, run on the fork's
/// own answer from the capsule's start.
fn evidence_mismatch(
    capsule: &StepReplayCapsule,
    fork: &ContributionForkReceipt,
) -> Option<ForkMismatch> {
    match (capsule.host, fork.anchor_scoring.evidence) {
        (CapsuleHost::WorkflowStep, ForkEvidence::AnswerText) => fork
            .execution
            .is_some()
            .then_some(ForkMismatch::AnchorDiverged),
        (CapsuleHost::EngineStep, ForkEvidence::ExecutedProgram { pin }) => {
            let Some(execution) = &fork.execution else {
                return Some(ForkMismatch::Unscored);
            };
            if execution.pin.digest() != pin {
                return Some(ForkMismatch::AnchorDiverged);
            }
            let from_start = capsule.start.as_ref().is_some_and(|start| {
                start.digest == execution.pin.start
                    && start.bridge_start == execution.pin.bridge_start
            });
            (!from_start || execution.response != fork.response)
                .then_some(ForkMismatch::OtherCapsule)
        }
        _ => Some(ForkMismatch::AnchorDiverged),
    }
}
