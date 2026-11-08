//! Committing skill-edit decisions and answered-proposal closure.
//! Entry function: `decide_in_txn`.
//! The gate root owns the verdict and score vocabulary imported through `super`.

use super::*;

/// The decision itself, over the committing snapshot. `primary_unknown`: a
/// primary axis was measured inconclusive, so non-regression is unknown.
/// `give_up`: the measured give-up that fired, if any, closing the unknown
/// primary instead of deferring it again.
#[expect(
    clippy::too_many_arguments,
    reason = "the decision names every input it rests on, and hiding them in a struct would only move the list"
)]
pub(super) fn decide_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    proposal: &EntityId,
    staged: &SkillRecord,
    current: Option<&SkillRecord>,
    cycle: &SkillEditCycle,
    basis: &ScoredBasis,
    goal_axes: &BTreeMap<String, GoalAxisScore>,
    primary_unknown: bool,
    give_up: Option<live::InconclusiveTrigger>,
) -> Result<SkillEditDisposition> {
    require_open_optimizer_proposal(staged)?;
    // The predecessor was readable when the basis was taken; if it is not
    // readable now it was purged or overwritten mid-flight, which is the same
    // stale-target answer — carried, this time, with the real score pair.
    let Some(current) = current else {
        return Ok(SkillEditDisposition::RefusedStaleTarget);
    };
    if !target_is_current(staged, current) {
        return Ok(SkillEditDisposition::RefusedStaleTarget);
    }
    // The two bodies, as they stand in the snapshot this row commits into,
    // against the two that were scored. A version bump would already have been
    // caught, but a body can move in ways a version does not have to name, and
    // the question here is not "did the version change" — it is "is this the
    // record the judge was shown".
    //
    // The two sides are DIFFERENT answers, and collapsing them was the defect.
    // A moved PROPOSAL means the judge scored bytes this transaction can no
    // longer see: nothing was learned about the proposal that is here now, so
    // there is nothing to rule, and ruling anyway durably closed a freshly
    // edited candidate nobody had ever scored. That is the retryable abort the
    // moved-evidence arm below already takes — `Err` rolls the transaction
    // back, so no row, no closure and no cap spend commits and the proposal is
    // left open exactly as a call that never ran would have left it.
    if skill_body_binding_digest(staged)? != basis.proposal_digest {
        return Err(retry(
            "the staged proposal moved while the scorer was thinking",
        ));
    }
    // A moved TARGET is the durable answer it always was: the revision this
    // proposal was drafted against is not the one it would now supersede.
    if skill_body_binding_digest(current)? != basis.target_digest {
        return Ok(SkillEditDisposition::RefusedStaleTarget);
    }
    // The evidence, RECOMPUTED here rather than trusted from the read that fed
    // the scorer. An outcome attributed while the judge was thinking reserves
    // new held-out evidence, and accepting on a stale reserve would be exactly
    // the accept-time recomputation rule stated and then not kept.
    let committed = held_out_receipts_in_txn(vault, wtxn, &target_of(staged)?)?;
    let (count, digest) = evidence_identity(&committed);
    if count != basis.evidence_count || digest != basis.evidence_digest {
        // Not a ruling: the scores in hand are about a set this transaction can
        // no longer see, and nothing was learned about the proposal. Returning
        // `Err` from the closure ROLLS THE TRANSACTION BACK, so no row, no
        // closure and no cap spend commits, and the proposal is left exactly as
        // a call that never ran would have left it.
        return Err(retry(
            "the reserved evidence moved while the scorer was thinking",
        ));
    }
    let world_now = held_out_outcome_results_in_txn(vault, wtxn, &target_of(staged)?)?;
    if world_labels_digest(&world_now) != basis.world_digest {
        return Err(retry(
            "world outcome labels moved while the judge was measuring",
        ));
    }
    if goal_definition_in_txn(vault, wtxn, &target_of(staged)?)?.revision != basis.goal_revision
        || goal_definition_in_txn(vault, wtxn, &target_of(staged)?)?.goal_id != basis.goal_id
    {
        return Err(retry("goal definition moved while the scorer was thinking"));
    }
    // A floor regression never votes as a tradeoff, regardless of gains on
    // other axes. Pure ties and dominated vectors are final rejections.
    // Mixed non-floor gains and losses need a separate preference decision;
    // only strict vector dominance reaches automatic admission.
    if floor_regressed(goal_axes) {
        return Ok(SkillEditDisposition::Rejected);
    }
    // An unknown primary axis is carried as a tie, so a vector with no gain
    // on its known axes still rejects; one it would admit or escalate defers
    // below, after the tier checks (OF-495).
    if !dominates(goal_axes) && !is_tradeoff(goal_axes) {
        return Ok(SkillEditDisposition::Rejected);
    }
    // Accept-time recheck. ONE-1448 already excluded protected tiers at
    // SELECTION; this is the second door, and the one that binds a proposal
    // nobody's selector drafted.
    let target_tier = tier_verdict_in_txn(vault, wtxn, &target_of(staged)?, current)?.tier();
    match target_tier {
        Some(tier) if tier.is_protected() => {
            return Ok(SkillEditDisposition::RefusedProtectedTier);
        }
        // An ambiguous tier is not optimizable either: the fail-closed rule is
        // the same one the candidate list applies.
        None => return Ok(SkillEditDisposition::RefusedProtectedTier),
        Some(_) => {}
    }
    // And the PROPOSAL's own tier, resolved independently in this same
    // snapshot. The body digest normalizes the tier away by design (it is a
    // state axis), so without this arm an owner's `identity` mark on the
    // candidate itself changed nothing the gate could see: the proposal would
    // be accepted and then activated as a protected record the loop was never
    // allowed to author. Protected, ambiguous, or simply not the tier the basis
    // was taken over are all the same answer.
    let proposal_tier = tier_verdict_in_txn(vault, wtxn, proposal, staged)?.tier();
    let bound = proposal_tier.is_some_and(|tier| !tier.is_protected())
        && proposal_tier == basis.proposal_tier
        && proposal_tier == target_tier;
    if !bound {
        return Ok(SkillEditDisposition::RefusedProtectedTier);
    }
    // The judge's rubric revises at most once per campaign, and only on k
    // fresh anchored labels since its last revision (ARCH-0042 judge re-pin
    // cadence). A tradeoff on it is not put to anyone before then either.
    if current.skill_id == JUDGE_SKILL_ID
        && !judge_revision_due_in_txn(
            vault,
            wtxn,
            cycle,
            proposal,
            &target_of(staged)?,
            world_now.len(),
        )?
    {
        return Ok(SkillEditDisposition::DeferredJudgeCadence);
    }
    // The full vector's non-regression is not established while a primary
    // axis is unknown: no automatic admission and no ask on a partial vector.
    // The proposal stays open, and the next pass measures it again — unless
    // the measured give-up fired, closing it as Inconclusive (Engine 00:26).
    if primary_unknown {
        if let Some(trigger) = give_up {
            return Ok(trigger.disposition());
        }
        return Ok(SkillEditDisposition::DeferredInconclusive);
    }
    // A mixed vector may reach the preference ladder only after both tier
    // checks. Otherwise a protected candidate could remain open indefinitely.
    if is_tradeoff(goal_axes) {
        return Ok(SkillEditDisposition::NeedsTradeoffDecision);
    }
    let cap = cycle_cap_in_txn(vault, wtxn)?;
    if accepted_in_cycle_in_txn(vault, wtxn, cycle, proposal)? >= cap {
        return Ok(SkillEditDisposition::DeferredCycleCap);
    }
    Ok(SkillEditDisposition::Accepted)
}

/// Moves an ANSWERED proposal out of the open question set.
///
/// `approval: proposed → rejected`, and the lifecycle deliberately does not
/// move: ARCH-0053 §6 gives `Candidate` exactly one outgoing edge (to `Active`),
/// so the approval axis is the one that can carry "this was answered" without
/// inventing a transition. The record, its provenance and its text survive
/// intact — a closed proposal is readable history, not a deletion.
///
/// Why it must happen at all: `optimize_candidates` treats every
/// `candidate + proposed` revision as an unanswered question and skips the
/// skill. A rejection that left the record open would therefore stop the
/// optimizer from ever proposing for that skill again — one tie, and the skill
/// is frozen out of the loop forever.
///
/// Idempotent, and silent when the record has already moved: the caller is
/// inside a transaction that has just written the ruling, and racing to close a
/// record someone else closed is not a reason to roll that ruling back.
pub(in crate::skill_optimize::gate) fn close_answered_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
    at: u64,
) -> Result<()> {
    let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
    if staged.lifecycle_status != SkillLifecycle::Candidate
        || staged.approval_status != ClaimApprovalStatus::Proposed
    {
        return Ok(());
    }
    let mut closed = staged.clone();
    closed.approval_status = ClaimApprovalStatus::Rejected;
    validate_skill_update(&staged, &closed)?;
    let data = encode_skill_record(&closed)?;
    vault.apply_skill_record_body(
        wtxn,
        proposal,
        TimeRange { start: at, end: at },
        at,
        data,
        false,
    )
}
