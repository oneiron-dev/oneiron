//! What a submitted pair's stored forks prove (FIX 3610, FIX 2870): the A
//! side records a contribution check as measured only when the fork
//! receipts this runner kept for the pair's canonical candidate are the ones
//! submitted, scored as submitted for the candidate's outcome, and
//! regenerated the capsule of the step the target's check regenerates as it
//! stands, read on the caller's snapshot. Both forks were also scored in
//! one evidence mode, the one their kept program runs settle (FIX 3607,
//! [`super::execution`]): `Text`, or `Executed` under the one pin both ran
//! their own answers under from that capsule's start. An owner verdict's
//! forks were both scored by the owner's one word that its pending pair
//! kept as judged, and every other anchor's by its scorer (FIX 3609,
//! [`super::owner`]). A pair they do not prove is still recorded, as
//! unmatched; nothing here refuses it.

use serde::{Deserialize, Serialize};

use super::super::replay_capsule::StepReplayCapsule;
use super::super::storage::{fork_rows_in_txn, step_replay_capsules_in_txn};
use super::ancestor::select_target;
use super::execution::pair_evidence_mode;
use super::owner::OwnerPair;
use super::{
    ContributionForkReceipt, ForkEvidenceMode, ForkExecutionOutcome, ForkJudge, ForkScoring,
    ForkTreatment, anchor_hash, pair_digest, receipt_attempt,
};
use crate::learning::Anchor;
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
    /// to its fork's frozen scoring identity, the forks were not scored
    /// in one evidence mode, the one their kept program runs settle, or not
    /// by the one judge the anchor takes (FIX 3609).
    AnchorDiverged,
    /// A fork did not regenerate the capsule of the step the target's check
    /// regenerates as it stands: another capsule, request, model, route
    /// prompt or seed, or the capsule's content is gone; or, in the
    /// `Executed` mode, a fork's execution did not run from that capsule's
    /// start.
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
        match fork.score {
            None => reasons.push(ForkMismatch::Unscored),
            Some(score) if score.passed != submitted.passed => {
                reasons.push(ForkMismatch::OtherScore);
            }
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
            reasons.extend(evidence_mismatch(&capsule, &with_fork, &without_fork));
        }
        _ => reasons.push(ForkMismatch::OtherCapsule),
    }
    let pending = rows.owner_pair.as_ref();
    reasons.extend(judge_mismatch(
        candidate,
        pending,
        &with_fork,
        &without_fork,
    ));
    reasons.sort_unstable();
    reasons.dedup();
    if !reasons.is_empty() {
        return Ok(Err(reasons));
    }
    match (with_fork.score, without_fork.score) {
        (Some(with_score), Some(without_score)) => Ok(Ok(MatchedContributionFacts {
            with_skill_passed: with_score.passed,
            without_skill_passed: without_score.passed,
        })),
        _ => Ok(Err(vec![ForkMismatch::Unscored])),
    }
}

/// The capsule of the step `candidate`'s target check regenerates
/// ([`super::ancestor`]), as it stands in `txn`: for a callable's load or a
/// delivered body (FIX 3608), the step after its call's.
fn target_capsule(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidate: &ContributionCandidate,
) -> Result<Option<StepReplayCapsule>> {
    let Some(attempt) = receipt_attempt(&candidate.attempt_receipt) else {
        return Ok(None);
    };
    let capsules = step_replay_capsules_in_txn(vault, txn, attempt)?;
    let target = select_target(vault, txn, &capsules, candidate.target)?;
    Ok(target.regenerated().cloned())
}

/// Whether `fork` regenerated `capsule`: its request, model, route prompt
/// (by the hash of its body as stored, FIX 6255) and seed, with its content
/// still held.
fn regenerates(capsule: &StepReplayCapsule, fork: &ContributionForkReceipt) -> bool {
    let Some(binding) = &capsule.binding else {
        return false;
    };
    let route_prompt = binding.stored_prompt_hash();
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

/// Why the pair's two scores are not proved in the evidence mode its kept
/// forks settle (FIX 3607), if they are not. Both forks are scored in one
/// mode, the one [`pair_evidence_mode`] reads from their kept program runs,
/// so a `Text` score and an `Executed` score never pair. In the `Executed`
/// mode each fork's execution ran from `capsule`'s start. A fork not scored
/// yet is reported as `Unscored` by the caller.
fn evidence_mismatch(
    capsule: &StepReplayCapsule,
    with_fork: &ContributionForkReceipt,
    without_fork: &ContributionForkReceipt,
) -> Option<ForkMismatch> {
    let (Some(with_score), Some(without_score)) = (with_fork.score, without_fork.score) else {
        return None;
    };
    let settled = pair_evidence_mode(capsule.host, with_fork, without_fork);
    if with_score.mode != without_score.mode || settled != Some(with_score.mode) {
        return Some(ForkMismatch::AnchorDiverged);
    }
    let from_start = |fork: &ContributionForkReceipt| {
        let execution = fork
            .execution
            .as_ref()
            .and_then(ForkExecutionOutcome::executed);
        execution.is_some_and(|execution| {
            capsule.start.as_ref().is_some_and(|start| {
                start.digest == execution.pin.start
                    && start.bridge_start == execution.pin.bridge_start
            })
        })
    };
    let executed = matches!(with_score.mode, ForkEvidenceMode::Executed { .. });
    (executed && !(from_start(with_fork) && from_start(without_fork)))
        .then_some(ForkMismatch::OtherCapsule)
}

/// Why the pair's two scores are not proved by the judge its anchor takes
/// (FIX 3609), if they are not. An owner verdict's forks are both scored by
/// one owner's word, the one its pending pair kept as judged, on the two
/// forks it showed. Every other anchor's forks are scored by its scorer. A
/// fork not scored yet is reported as `Unscored` by the caller.
fn judge_mismatch(
    candidate: &ContributionCandidate,
    pending: Option<&OwnerPair>,
    with_fork: &ContributionForkReceipt,
    without_fork: &ContributionForkReceipt,
) -> Option<ForkMismatch> {
    let (Some(with_score), Some(without_score)) = (with_fork.score, without_fork.score) else {
        return None;
    };
    let proved = match (candidate.anchor, with_score.judge) {
        (Anchor::OwnerVerdict, ForkJudge::Owner(judgment)) => {
            without_score.judge == with_score.judge
                && pending.is_some_and(|pair| pair.judged(judgment, with_fork, without_fork))
        }
        (Anchor::OwnerVerdict, ForkJudge::Scorer) => false,
        (_, judge) => judge == ForkJudge::Scorer && without_score.judge == ForkJudge::Scorer,
    };
    (!proved).then_some(ForkMismatch::AnchorDiverged)
}
