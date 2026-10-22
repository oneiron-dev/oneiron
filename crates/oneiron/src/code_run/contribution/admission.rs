//! What a submitted pair's stored forks prove (FIX 3610): the A side records
//! a contribution check as measured only when the fork receipts this runner
//! kept for the pair's canonical candidate are the ones submitted, scored
//! as submitted, and regenerated the run's first-step capsule as it stands,
//! read on the caller's snapshot. A pair they do not prove is still recorded,
//! as unmatched; nothing here refuses it.

use serde::{Deserialize, Serialize};

use super::super::storage::{fork_rows_in_txn, step_replay_capsules_in_txn};
use super::{ContributionForkReceipt, FIRST_STEP, ForkTreatment, pair_digest, receipt_attempt};
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
    /// The two forks were not scored against one anchor.
    AnchorDiverged,
    /// A fork did not regenerate the run's first-step capsule as it stands:
    /// another capsule, request, model, route prompt or seed, or the
    /// capsule's content is gone.
    OtherCapsule,
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
    if !regenerates_first_step(vault, txn, candidate, &with_fork)?
        || !regenerates_first_step(vault, txn, candidate, &without_fork)?
    {
        reasons.push(ForkMismatch::OtherCapsule);
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

/// Whether `fork` regenerated the first-step capsule of `candidate`'s run,
/// the one of its latest lease generation, as it stands in `txn`: its
/// request, model, route prompt and seed, with its content still held.
fn regenerates_first_step(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidate: &ContributionCandidate,
    fork: &ContributionForkReceipt,
) -> Result<bool> {
    let Some(attempt) = receipt_attempt(&candidate.attempt_receipt) else {
        return Ok(false);
    };
    let Some(capsule) = step_replay_capsules_in_txn(vault, txn, attempt)?
        .into_iter()
        .filter(|capsule| capsule.step == FIRST_STEP)
        .max_by_key(|capsule| capsule.lease_generation)
    else {
        return Ok(false);
    };
    let Some(binding) = &capsule.binding else {
        return Ok(false);
    };
    let route_prompt = binding
        .prompt
        .as_deref()
        .map(|prompt| *blake3::hash(prompt.as_bytes()).as_bytes());
    Ok(capsule.content.actor().is_some()
        && fork.attempt == capsule.attempt
        && fork.lease_generation == capsule.lease_generation
        && fork.step == capsule.step
        && fork.capsule_request == capsule.request_hash
        && fork.model == binding.model
        && fork.route_prompt == route_prompt
        && fork.seed == capsule.seed
        && fork.seed_unsupported == capsule.seed.is_none())
}
