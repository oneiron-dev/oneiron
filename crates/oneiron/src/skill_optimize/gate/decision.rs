//! The gate itself: the entry points, and the transaction that rules.

use super::*;
use crate::error::ArtifactError;
use crate::skill_optimize::labels::JUDGE_SKILL_ID;

mod commit;

use self::commit::decide_in_txn;

pub(super) use self::commit::close_answered_proposal_in_txn;

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Rules on one optimizer-born proposal. THE entry point.
///
/// Two arguments, because that is what a caller holding a drafted proposal
/// actually has. Everything else is resolved from the record and the vault: the
/// judge is the host's registered one ([`register_held_out_replay_scorer`]),
/// the cycle is the one the proposal was DRAFTED into
/// ([`SkillEditCycle::of_proposal`]), and the clock is the wall clock.
///
/// The two explicit variants exist for the two callers that genuinely know
/// better: [`score_gate_skill_edit_with_scorer`] injects a judge (tests, and a
/// host running more than one), and [`score_gate_skill_edit_in_cycle`] names
/// the wake by its ATTEMPT (a runner batching several proposals under one cap,
/// and any runner picking a cap-deferred proposal up in a later cycle).
///
/// # Errors
///
/// [`ArtifactError::InvalidSkillBody`](crate::error::ArtifactError::InvalidSkillBody) when no judge is registered or the proposal
/// names no drafting cycle; then everything
/// [`score_gate_skill_edit_in_cycle`] errors on.
pub fn score_gate_skill_edit(vault: &Vault, proposal: &EntityId) -> Result<HeldOutVerdict> {
    score_gate_skill_edit_with_scorer(vault, proposal, host_replay_scorer()?)
}

/// [`score_gate_skill_edit`] with the judge supplied by the caller.
///
/// The scorer is a required argument here, not a defaulted one: see
/// [`HeldOutReplayNotes`]. The cycle is still resolved by
/// [`SkillEditCycle::of_proposal`].
///
/// # Errors
///
/// Everything [`score_gate_skill_edit_in_cycle`] errors on, plus
/// [`ArtifactError::InvalidSkillBody`](crate::error::ArtifactError::InvalidSkillBody) when the proposal names no drafting cycle.
pub fn score_gate_skill_edit_with_scorer(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
) -> Result<HeldOutVerdict> {
    let cycle = SkillEditCycle::of_proposal(vault, proposal)?;
    rule_on_proposal(
        vault,
        proposal,
        scorer,
        &cycle,
        vault.store.clock.now_recorded_at(),
        None,
    )
}

/// [`score_gate_skill_edit`] under the cycle a Dreamer ATTEMPT proves.
///
/// The wake is named by its scheduler identity, not by a string: the label is
/// derived from `attempt`'s durable queue row through the one resolver the
/// drafting door also uses (`super::proven_cycle`). A caller that cannot show
/// a real attempt cannot name a cycle at all, which is what makes K a bound on
/// one REAL wake rather than on whoever spells a fresh label. Presenting an
/// attempt whose cycle differs from the proposal's birth stamp is the lawful
/// later-cycle pickup: the row records the cycle actually used, and the cap
/// counts it there.
///
/// # Errors
///
/// [`ArtifactError::InvalidSkillBody`](crate::error::ArtifactError::InvalidSkillBody) when `attempt` names no stored queue row; then
/// everything the gate itself errors on (see the entry point's list).
pub fn score_gate_skill_edit_in_cycle(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
    attempt: AttemptId,
    at: u64,
) -> Result<HeldOutVerdict> {
    let cycle = proven_cycle(vault, attempt)?;
    rule_on_proposal(vault, proposal, scorer, &cycle, at, None)
}

/// The same gate, with the caller's owner proof revalidated in every write.
/// No owner exception changes its evidence, tiers, cap or tradeoff ladder.
pub(crate) fn score_gate_skill_edit_as_owner(
    vault: &Vault,
    owner: &crate::consent::AuthenticatedOwner,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
) -> Result<HeldOutVerdict> {
    owner.revalidate(vault)?;
    let cycle = SkillEditCycle::of_proposal(vault, proposal)?;
    rule_on_proposal(
        vault,
        proposal,
        scorer,
        &cycle,
        vault.now_recorded_at(),
        Some(owner),
    )
}

/// The gate itself, over a cycle that is already proven.
///
/// The order of the steps IS the contract:
/// 1. read the proposal and the ACTIVE predecessor it names, lock-free, and
///    form the terminal reason (if any) that read implies;
/// 2. open ONE write transaction and re-read all of it there. A terminal reason
///    that still holds is written AS a verdict row and CLOSES the proposal in
///    that same transaction; a reason that no longer holds — or one that only
///    appeared at the write door — commits nothing and returns the retryable
///    outcome, because a refusal the world has already outrun is a false
///    terminal answer, and those must be unrepresentable;
/// 3. take the BASIS in that same snapshot (both body digests, the evidence
///    count and digest, and the PROPOSAL's resolved tier) and answer a repeat
///    delivery from the ledger: a standing ruling over exactly this basis — an
///    acceptance, or a cap deferral from this same cycle — is returned as it
///    stands, unscored and unrecounted, so a retried delivery pays no second
///    replay, spends no second slot and appends no duplicate row;
/// 4. score both instruction versions over that one set, outside any
///    transaction: the LLM tier never runs inside the storage write door;
/// 5. re-read everything inside the VERDICT transaction and decide there — the
///    held-out set is RECOMPUTED and compared with the scored basis, both tiers
///    are rechecked, the cap is counted and the row commits, all in one
///    snapshot. An owner's identity mark landing mid-flight cannot be missed,
///    an outcome arriving mid-flight cannot be scored around, and two
///    concurrent gates cannot both see the last accept slot free;
/// 6. a terminal answer CLOSES the proposal in that same transaction, so a
///    denial cannot wedge the skill it was denying.
///
/// Scoring deliberately precedes the tier refusal rather than short-circuiting
/// on it: "refused even though it improved" is the exact sentence a protected
/// tier's receipt has to be able to say, and it cannot say it without the pair.
/// The cost is one replay on a path ONE-1448 structurally never produces —
/// protected skills are absent from its candidate list, so only a hand-crafted
/// proposal arrives here.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the proposal is gone; whatever the scorer
/// returns; [`ArtifactError::InvalidSkillBody`](crate::error::ArtifactError::InvalidSkillBody) for a proposal that is not an open,
/// cycle-stamped optimizer-born candidate, an unusable score, and every refusal
/// arm of [`SkillEditDisposition`]; [`ArtifactError::SkillEditGateRetry`](crate::error::ArtifactError::SkillEditGateRetry) when the
/// snapshot moved under the call — the proposal body, the reserved evidence, or
/// a terminal reason — and when the skill reserves no evidence to score over at
/// all. Rejections and cap deferrals are `Ok`.
fn rule_on_proposal(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
    cycle: &SkillEditCycle,
    at: u64,
    owner: Option<&crate::consent::AuthenticatedOwner>,
) -> Result<HeldOutVerdict> {
    let judge_revision = scorer.judge_revision();
    validate_judge_revision(judge_revision)?;
    // The lock-free pre-read. Sequential, never nested: LMDB allows one read
    // transaction per thread, so a snapshot opened around a call that opens its
    // own is a `BadRslot`, not a consistency win. Nothing here decides
    // anything — every conclusion is re-taken at the write door below.
    let proposal_record = vault
        .get_skill_record(proposal)?
        .ok_or(Error::EntityNotFound)?;
    require_open_optimizer_proposal(&proposal_record)?;
    let target = target_of(&proposal_record)?;
    let target_record = readable_target(vault.get_skill_record(&target))?;
    let presented = terminal_reason(&proposal_record, target_record.as_ref());
    race_hook();

    let prepared = vault.with_write_txn_grouped(|wtxn| {
        if let Some(owner) = owner {
            owner.revalidate_in_txn(vault, wtxn)?;
        }
        ensure_current_judge_in_txn(vault, &*wtxn, judge_revision)?;
        let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
        require_open_optimizer_proposal(&staged)?;
        let target = target_of(&staged)?;
        let current = readable_target(vault.read_skill_record_in_txn(&*wtxn, &target).map(Some))?;
        // The reason is re-verified in the transaction that would WRITE it.
        // Ruling only when both reads agree is what makes a false terminal
        // refusal — one the world had already outrun — impossible to commit.
        match (presented, terminal_reason(&staged, current.as_ref())) {
            (Some(presented), Some(committed)) if presented == committed => {
                let verdict = refusal(vault.store.clock.entity_id()?, proposal, &target, cycle, committed, at);
                record_verdict_in_txn(vault, wtxn, &verdict)?;
                if committed.closes_proposal() {
                    close_answered_proposal_in_txn(vault, wtxn, proposal, at)?;
                }
                Ok(Prepared::Ruled(Box::new(verdict)))
            }
            (None, None) => {
                let current = current.ok_or(Error::InvariantViolation(
                    "a non-terminal pre-score snapshot has a readable target",
                ))?;
                let held_out = held_out_receipts_in_txn(vault, &*wtxn, &target)?;
                // An empty reserve is not an answer ABOUT the proposal, so it
                // does not close one. The gate scores against reserved
                // evidence; a skill whose split has reserved none yet cannot be
                // scored at all, and the drafting door already refuses to spend
                // an author on one ([`super::super::optimize_candidates`]).
                // What is left here is the race and the direct call, and for
                // both the honest outcome is the retryable abort: nothing is
                // scored, nothing is written, and the question stays open for
                // the wake that finds a reserve.
                if held_out.is_empty() {
                    return Err(retry(
                        "no evidence is reserved for this skill, so there is nothing to score",
                    ));
                }
                let outcomes = held_out_outcome_results_in_txn(vault, &*wtxn, &target)?;
                let basis = ScoredBasis::of(
                    &staged,
                    &current,
                    &held_out,
                    &outcomes,
                    tier_verdict_in_txn(vault, &*wtxn, proposal, &staged)?.tier(),
                    goal_definition_in_txn(vault, wtxn, &target)?.revision,
                    goal_definition_in_txn(vault, wtxn, &target)?.goal_id,
                )?;
                // Idempotence, before the LLM tier rather than after it. A gate
                // call is a DELIVERY, and deliveries are retried; asking the
                // judge the same question twice would not only pay twice, it
                // would answer differently, because the first ruling has by
                // then moved the cap the second call is measured against.
                let standing =
                    standing_ruling_in_txn(vault, &*wtxn, proposal, &basis, cycle, judge_revision)?;
                if let Some(standing) = standing {
                    return Ok(Prepared::Ruled(Box::new(standing)));
                }
                Ok(Prepared::Score(Box::new(ScoreInputs {
                    judge_rubric_digest: judge_rubric_digest_in_txn(vault, &*wtxn)?,
                    outcomes,
                    proposal_instructions: super::rule_policy::gate_instructions_in_txn(
                        vault, &*wtxn, proposal, &staged,
                    ),
                    target_instructions: super::rule_policy::gate_instructions_in_txn(
                        vault, &*wtxn, &target, &current,
                    ),
                    proposal: staged,
                    target,
                    target_record: current,
                    held_out,
                    basis,
                    goal_definition: goal_definition_in_txn(vault, wtxn, &target)?,
                })))
            }
            _ => Err(retry(
                "the reason the gate was about to rule on no longer holds in the committing snapshot",
            )),
        }
    })?;
    let inputs = match prepared {
        Prepared::Ruled(verdict) => return answer(*verdict),
        Prepared::Score(inputs) => *inputs,
    };

    let current_case = HeldOutReplayCase {
        skill: inputs.target,
        skill_id: &inputs.target_record.skill_id,
        version: &inputs.target_record.version,
        instructions: &inputs.target_instructions,
        held_out_receipts: &inputs.held_out,
    };
    let proposed_case = HeldOutReplayCase {
        skill: inputs.target,
        skill_id: &inputs.target_record.skill_id,
        version: &inputs.proposal.version,
        instructions: &inputs.proposal_instructions,
        held_out_receipts: &inputs.held_out,
    };
    // A project goal's measured axes come from its bound live report, read
    // before any judgment so a missing one retries without spending them.
    let reported = live::live_axes(
        vault,
        proposal,
        &inputs.basis,
        &inputs.goal_definition,
        judge_revision,
    )?;
    let primary_unknown = !reported.inconclusive.is_empty();
    // The human picks in the skill's anchor, scored against the judge that
    // answers now, read before any judgment like the outcomes they sit beside.
    let incumbent = crate::skill_optimize::judge_incumbent(vault)?;
    let anchor = anchor_score(
        &crate::skill_optimize::labels::skill_label_anchor(vault, inputs.target)?,
        incumbent.as_ref().map(|incumbent| incumbent.judge.as_str()),
        judge_revision,
    );
    // Pair responses by their common-rubric scores and freeze the preference
    // before either version's instructions or a label is read; both share it.
    let blind = scorer.blind_preference(current_case.skill_id, &inputs.held_out)?;
    let measurements = measure(
        scorer,
        &current_case,
        &proposed_case,
        &inputs.outcomes,
        &blind,
        anchor,
        inputs.judge_rubric_digest.clone(),
    )?;
    let goal_axes = score_goal_axes(
        scorer,
        &current_case,
        &proposed_case,
        &inputs.goal_definition,
        reported.measured,
    )?;
    if scorer.judge_revision() != judge_revision {
        return Err(retry("candidate judge revision moved during scoring"));
    }
    let headline = goal_axes
        .values()
        .find(|axis| axis.kind == GoalAxisKind::Primary)
        .expect("validated primary axis");
    let before = headline.before;
    let after = headline.after;
    // A pending tradeoff climbs the preference ladder here, outside any write
    // transaction, because its judgment rung is a model call. A vector with an
    // unknown primary axis puts nothing to the ladder: the gate defers it.
    let ladder = if primary_unknown {
        tradeoff::TradeoffPlan::None
    } else {
        tradeoff::plan(
            vault,
            proposal,
            &inputs.basis,
            &inputs.goal_definition,
            &goal_axes,
            scorer,
        )?
    };

    // The scored set has done its work; what the row keeps of it is the bounded
    // display list, and the basis keeps the rest.
    let truncated = inputs.held_out.len() > SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE;
    let display = bounded_receipts(inputs.held_out);
    let basis = inputs.basis;
    let target = inputs.target;

    let verdict = vault.with_write_txn_grouped(|wtxn| {
        if let Some(owner) = owner {
            owner.revalidate_in_txn(vault, wtxn)?;
        }
        // Re-read at the write door, exactly as ONE-1448's draft path does: the
        // scorer ran outside this transaction, so the target may have been
        // superseded and either tier may have been re-marked while it thought.
        ensure_current_judge_in_txn(vault, &*wtxn, judge_revision)?;
        let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
        let current = readable_target(vault.read_skill_record_in_txn(&*wtxn, &target).map(Some))?;
        // A changed goal cannot return an old standing acceptance even if the
        // bodies and evidence stayed fixed while the judge was thinking.
        if goal_definition_in_txn(vault, wtxn, &target)?.revision != basis.goal_revision
            || goal_definition_in_txn(vault, wtxn, &target)?.goal_id != basis.goal_id
        {
            return Err(retry("goal definition moved while the scorer was thinking"));
        }
        // The rubric pin the measurements record is the one every judgment read.
        if judge_rubric_digest_in_txn(vault, &*wtxn)? != measurements.judge_rubric_digest {
            return Err(retry("the judge rubric moved while the scorer was thinking"));
        }
        // The concurrent duplicate: two deliveries that both got past the read
        // above serialize HERE, and the second one finds the first's row.
        if let Some(standing) =
            standing_ruling_in_txn(vault, &*wtxn, proposal, &basis, cycle, judge_revision)?
        {
            return Ok(standing);
        }
        let mut verdict = HeldOutVerdict {
            before,
            after,
            goal_axes: goal_axes.clone(),
            goal_revision: basis.goal_revision.clone(),
            goal_id: Some(basis.goal_id),
            tradeoff_resolution: None,
            tradeoff_jev: None,
            measurements: Some(measurements),
            accepted: false,
            judge_revision: Some(judge_revision.to_owned()),
            displaced_by_revision: None,
            id: vault.store.clock.entity_id()?,
            proposal: *proposal,
            skill: target,
            disposition: SkillEditDisposition::Rejected,
            cycle: cycle.as_str().to_owned(),
            held_out_receipts: display,
            held_out_count: basis.evidence_count,
            held_out_digest: basis.evidence_digest.clone(),
            held_out_truncated: truncated,
            proposal_digest: basis.proposal_digest.clone(),
            target_digest: basis.target_digest.clone(),
            proposal_tier: basis.proposal_tier,
            accepted_verdict: None,
            missing_sources: Vec::new(),
            at,
        };
        verdict.disposition = decide_in_txn(
            vault,
            wtxn,
            proposal,
            &staged,
            current.as_ref(),
            cycle,
            &basis,
            &goal_axes,
            primary_unknown,
        )?;
        let settled = tradeoff::apply_in_txn(vault, wtxn, cycle, &mut verdict, &ladder)?;
        verdict.accepted = verdict.disposition.admits();
        record_verdict_in_txn(vault, wtxn, &verdict)?;
        if verdict.disposition.closes_proposal() {
            close_answered_proposal_in_txn(vault, wtxn, proposal, at)?;
        }
        // A rule or confident Jev answered the pending row just written: the
        // decision door records the transition out of it.
        if let Some((choice, resolution)) = settled {
            return record_tradeoff_resolution_in_txn(
                vault, wtxn, verdict, resolution, choice, cycle, at,
            );
        }
        Ok(verdict)
    })?;
    answer(verdict)
}

/// What the pre-score transaction settled: a ruling already written (or already
/// standing), or the snapshot the scorer is about to be shown.
enum Prepared {
    Ruled(Box<HeldOutVerdict>),
    Score(Box<ScoreInputs>),
}

/// The snapshot a verdict is scored over, taken inside the pre-score
/// transaction and carried unchanged to the committing one.
struct ScoreInputs {
    proposal: SkillRecord,
    /// Each arm's instructions as the judge compares them (FIX 10878).
    proposal_instructions: String,
    target_instructions: String,
    target: EntityId,
    target_record: SkillRecord,
    held_out: Vec<String>,
    outcomes: Vec<(String, bool)>,
    basis: ScoredBasis,
    goal_definition: GoalDefinition,
    /// The judge rubric's pin in force when scoring began (FIX 3585).
    judge_rubric_digest: Option<String>,
}

/// The one place a durable ruling becomes the caller's answer.
///
/// A refusal is reported by `Err` as well as by the ledger; everything else is
/// an ordinary answer a loop keeps running after.
fn answer(verdict: HeldOutVerdict) -> Result<HeldOutVerdict> {
    if verdict.disposition.is_refusal() {
        return Err(verdict.disposition.refusal_error());
    }
    Ok(verdict)
}

/// The terminal pre-score rule, in ONE spelling.
///
/// Both the lock-free pre-read and the transaction that would write the row
/// call this with values they gathered their own way, so "is this terminal"
/// cannot be answered two different ways by two different snapshots.
///
/// `target` is `None` for every unreadable predecessor — missing, purged, an
/// entity of another kind, an undecodable shell. All of them are the SAME fact
/// about the proposal: the revision it was drafted against is not there to be
/// superseded.
///
/// The EMPTY RESERVE is deliberately not on this list. It is a fact about the
/// skill's evidence split rather than about the proposal, and answering it
/// terminally closed a perfectly good question the next wake could have ruled
/// on — see the retryable arm in [`rule_on_proposal`].
fn terminal_reason(
    proposal: &SkillRecord,
    target: Option<&SkillRecord>,
) -> Option<SkillEditDisposition> {
    let Some(target) = target else {
        return Some(SkillEditDisposition::RefusedStaleTarget);
    };
    if !target_is_current(proposal, target) {
        return Some(SkillEditDisposition::RefusedStaleTarget);
    }
    None
}

/// A target read, classified: absent-or-unreadable is a FACT about the target,
/// and a storage fault is not.
///
/// `EntityNotFound` and `InvalidSkillBody` (a non-SKILL row at that id, an
/// undecodable body) both mean "there is no predecessor here to score against",
/// which is a verdict the gate can write. Everything else — storage errors,
/// index corruption — propagates untouched: those are not answers about a
/// proposal.
pub(super) fn readable_target(read: Result<Option<SkillRecord>>) -> Result<Option<SkillRecord>> {
    match read {
        Ok(record) => Ok(record),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::EntityNotFound | ErrorKind::InvalidSkillBody
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// The typed, retryable "nothing was learned, and nothing was written".
const fn retry(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::SkillEditGateRetry(reason))
}

/// Test-only rendezvous between the lock-free pre-read and the transaction that
/// re-verifies it.
///
/// The window it opens is REAL — the pre-read holds no lock, so an outcome can
/// land in it — but a test cannot stand in a window it has no hook into, and a
/// sleeping thread is not a regression. Thread-local, so one test's hook cannot
/// reach another's vault, and compiled out entirely otherwise.
#[cfg(test)]
type PreScoreRaceHook = std::cell::RefCell<Option<Box<dyn Fn()>>>;

#[cfg(test)]
thread_local! {
    static PRE_SCORE_RACE_HOOK: PreScoreRaceHook = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(in crate::skill_optimize) fn set_pre_score_race_hook(hook: Box<dyn Fn()>) {
    PRE_SCORE_RACE_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(test)]
pub(in crate::skill_optimize) fn clear_pre_score_race_hook() {
    PRE_SCORE_RACE_HOOK.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn race_hook() {
    let hook = PRE_SCORE_RACE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
const fn race_hook() {}

/// Accept slots already spent by `cycle`, DERIVED from the verdict ledger.
///
/// Not a stored counter (doc-13 r1, the posture this module's open-question
/// rule already takes): a counter is a third thing to keep true, and one that
/// disagrees with the receipts would make the cap unauditable.
///
/// The unit is a PROPOSAL, not a row. The cap bounds how many edits one wake
/// may admit, and one edit ruled on twice is still one edit — counting rows
/// would let a retried delivery eat the budget of the next real proposal.
/// `spending` is excluded for the same reason from the other side: a proposal
/// re-ruled over moved evidence must not be deferred by its own earlier
/// acceptance.
pub(super) fn accepted_in_cycle_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    cycle: &SkillEditCycle,
    spending: &EntityId,
) -> Result<u32> {
    let mut accepted: BTreeSet<EntityId> = BTreeSet::new();
    for verdict in verdict_rows_in_txn(vault, rtxn)? {
        if verdict.disposition.admits()
            && verdict.cycle == cycle.as_str()
            && verdict.proposal != *spending
            && verdict.displaced_by_revision.is_none()
        {
            accepted.insert(verdict.proposal);
        }
    }
    Ok(u32::try_from(accepted.len()).unwrap_or(u32::MAX))
}

/// k: the fresh anchored labels a judge rubric revision needs since the last
/// one (ARCH-0042 "Each rubric revision needs k fresh labels since the last
/// revision"). Canon names no number; five is N, the evidence any skill needs
/// before the loop may edit it at all.
const JUDGE_REVISION_FRESH_LABELS: u64 = 5;

/// Whether the judge's rubric, `target`, may revise in `cycle`, the campaign.
///
/// No other edit of this judge may stand accepted in the same cycle, and its
/// anchor must hold k labels fresher than its last revision: the human picks
/// made after the ruling that admitted `target`, and the settled world
/// outcomes on `target`'s held-out receipts, every one of which landed after
/// it began judging. Derived from the verdict ledger like the cycle cap.
fn judge_revision_due_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    cycle: &SkillEditCycle,
    spending: &EntityId,
    target: &EntityId,
    world_outcomes: usize,
) -> Result<bool> {
    let mut since = 0_u64;
    for verdict in verdict_rows_in_txn(vault, rtxn)? {
        if !verdict.disposition.admits()
            || verdict.displaced_by_revision.is_some()
            || verdict.proposal == *spending
        {
            continue;
        }
        // The ruling that made `target` the judge, or another edit of it.
        if verdict.proposal == *target || verdict.skill == *target {
            if verdict.cycle == cycle.as_str() {
                return Ok(false);
            }
            if verdict.proposal == *target {
                since = since.max(verdict.at);
            }
        }
    }
    let picks = crate::skill_optimize::labels::anchor_labels_since_in_txn(vault, rtxn, since)?;
    let outcomes = u64::try_from(world_outcomes).unwrap_or(u64::MAX);
    Ok(picks.saturating_add(outcomes) >= JUDGE_REVISION_FRESH_LABELS)
}

/// Whether an approval of an edit to `target` may admit in `cycle`: always,
/// unless `target` is the judge's rubric and [`judge_revision_due_in_txn`]
/// holds it. An unreadable target is the stale-target answer's, not this one.
pub(super) fn judge_cadence_allows_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    cycle: &SkillEditCycle,
    spending: &EntityId,
    target: &EntityId,
) -> Result<bool> {
    let record = readable_target(vault.read_skill_record_in_txn(rtxn, target).map(Some))?;
    if record.is_none_or(|record| record.skill_id != JUDGE_SKILL_ID) {
        return Ok(true);
    }
    let outcomes = held_out_outcome_results_in_txn(vault, rtxn, target)?.len();
    judge_revision_due_in_txn(vault, rtxn, cycle, spending, target, outcomes)
}

/// Why an approved tradeoff cannot admit in `cycle` yet, if it cannot: the
/// cycle already spent its accepts, or the judge's cadence holds its rubric.
pub(super) fn approval_deferral_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    cycle: &SkillEditCycle,
    spending: &EntityId,
    target: &EntityId,
) -> Result<Option<SkillEditDisposition>> {
    if accepted_in_cycle_in_txn(vault, rtxn, cycle, spending)? >= cycle_cap_in_txn(vault, rtxn)? {
        return Ok(Some(SkillEditDisposition::DeferredCycleCap));
    }
    if !judge_cadence_allows_in_txn(vault, rtxn, cycle, spending, target)? {
        return Ok(Some(SkillEditDisposition::DeferredJudgeCadence));
    }
    Ok(None)
}

/// The standing ruling this delivery would only be repeating, if there is one.
///
/// "Standing" is the LATEST ruling, not any ruling: a proposal accepted and
/// then refused at the admission door has been answered, and the superseded
/// acceptance is history rather than a live permission.
///
/// Three rulings qualify, and each is a result a REDELIVERY must return
/// rather than re-earn:
///
/// - a standing ACCEPTANCE over exactly this basis, whatever cycle it was ruled
///   in — an acceptance keeps the cycle it was ruled in, and a duplicate
///   arriving under another label must not revoke it;
/// - a tradeoff needing a decision, on the same basis in any cycle, while it
///   still waits on its own terms ([`tradeoff::pending_waits_in_txn`]): asking
///   the judge again cannot replace the pending preference with another score;
/// - a standing DEFERRAL (cap, judge cadence or an inconclusive primary) over
///   exactly this basis AND this same cycle. The cycle equality is
///   load-bearing in the other direction: a deferral from wake X says nothing
///   about wake Y, so a genuine later-cycle pickup still re-scores and is
///   counted against the cycle that picked it up.
///
/// Returning the standing row is what makes delivery idempotent on all arms:
/// no second replay is paid, no second row is appended, and the cap is neither
/// re-spent nor re-measured.
fn standing_ruling_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    proposal: &EntityId,
    basis: &ScoredBasis,
    cycle: &SkillEditCycle,
    judge_revision: &str,
) -> Result<Option<HeldOutVerdict>> {
    let standing = standing_verdict_in_txn(vault, rtxn, proposal)?.filter(|verdict| {
        basis.matches(verdict)
            && verdict.displaced_by_revision.is_none()
            && verdict.judge_revision.as_deref() == Some(judge_revision)
            && (verdict.disposition.admits()
                || verdict.disposition == SkillEditDisposition::NeedsTradeoffDecision
                || (matches!(
                    verdict.disposition,
                    SkillEditDisposition::DeferredCycleCap
                        | SkillEditDisposition::DeferredJudgeCadence
                        | SkillEditDisposition::DeferredInconclusive
                ) && verdict.cycle == cycle.as_str()))
    });
    match standing {
        Some(pending)
            if pending.disposition == SkillEditDisposition::NeedsTradeoffDecision
                && !tradeoff::pending_waits_in_txn(vault, rtxn, &pending)? =>
        {
            Ok(None)
        }
        standing => Ok(standing),
    }
}

/// The most recent ruling on one proposal, whatever it said.
pub(super) fn standing_verdict_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    proposal: &EntityId,
) -> Result<Option<HeldOutVerdict>> {
    Ok(verdict_rows_in_txn(vault, rtxn)?
        .into_iter()
        .rfind(|verdict| verdict.proposal == *proposal))
}

/// A refusal ruled BEFORE any score exists.
///
/// The zero pair is honest here and only here: nothing was replayed, so there
/// is no pair to report, no basis, and therefore no bound tier. A refusal
/// reached after an acceptance carries that acceptance's real numbers instead
/// ([`HeldOutVerdict::refused_at_admission`]).
///
/// The row is always written by the transaction that RE-VERIFIED the reason,
/// together with the closure it implies — never by a transaction of its own,
/// which is how a reason that stopped holding used to become a durable answer.
fn refusal(
    id: EntityId,
    proposal: &EntityId,
    skill: &EntityId,
    cycle: &SkillEditCycle,
    disposition: SkillEditDisposition,
    at: u64,
) -> HeldOutVerdict {
    let (held_out_count, held_out_digest) = evidence_identity(&[]);
    HeldOutVerdict {
        before: 0.0,
        after: 0.0,
        goal_axes: BTreeMap::new(),
        goal_revision: String::new(),
        goal_id: None,
        tradeoff_resolution: None,
        tradeoff_jev: None,
        measurements: None,
        accepted: false,
        judge_revision: None,
        displaced_by_revision: None,
        id,
        proposal: *proposal,
        skill: *skill,
        disposition,
        cycle: cycle.as_str().to_owned(),
        held_out_receipts: Vec::new(),
        held_out_count,
        held_out_digest,
        held_out_truncated: false,
        proposal_digest: String::new(),
        target_digest: String::new(),
        proposal_tier: None,
        accepted_verdict: None,
        missing_sources: Vec::new(),
        at,
    }
}
