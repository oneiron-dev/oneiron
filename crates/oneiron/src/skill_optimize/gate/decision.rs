//! The gate itself: the entry points, and the transaction that rules.

use super::*;

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
/// [`Error::InvalidSkillBody`] when no judge is registered or the proposal
/// names no drafting cycle; then everything
/// [`score_gate_skill_edit_in_cycle`] errors on.
pub fn score_gate_skill_edit(vault: &Vault, proposal: &EntityId) -> Result<HeldOutVerdict> {
    score_gate_skill_edit_with_scorer(vault, proposal, host_replay_scorer()?)
}

/// [`score_gate_skill_edit`] with the judge supplied by the caller.
///
/// The scorer is a required argument here, not a defaulted one: see
/// [`HeldOutReplayScorer`]. The cycle is still resolved by
/// [`SkillEditCycle::of_proposal`].
///
/// # Errors
///
/// Everything [`score_gate_skill_edit_in_cycle`] errors on, plus
/// [`Error::InvalidSkillBody`] when the proposal names no drafting cycle.
pub fn score_gate_skill_edit_with_scorer(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayScorer,
) -> Result<HeldOutVerdict> {
    let cycle = SkillEditCycle::of_proposal(vault, proposal)?;
    rule_on_proposal(vault, proposal, scorer, &cycle, crate::unix_seconds_now())
}

/// [`score_gate_skill_edit`] under the cycle a Dreamer ATTEMPT proves.
///
/// The wake is named by its scheduler identity, not by a string: the label is
/// derived from `attempt`'s durable queue row through the one resolver the
/// drafting door also uses ([`super::proven_cycle`]). A caller that cannot show
/// a real attempt cannot name a cycle at all, which is what makes K a bound on
/// one REAL wake rather than on whoever spells a fresh label. Presenting an
/// attempt whose cycle differs from the proposal's birth stamp is the lawful
/// later-cycle pickup: the row records the cycle actually used, and the cap
/// counts it there.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] when `attempt` names no stored queue row; then
/// everything the gate itself errors on (see the entry point's list).
pub fn score_gate_skill_edit_in_cycle(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayScorer,
    attempt: AttemptId,
    at: u64,
) -> Result<HeldOutVerdict> {
    let cycle = proven_cycle(vault, attempt)?;
    rule_on_proposal(vault, proposal, scorer, &cycle, at)
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
/// returns; [`Error::InvalidSkillBody`] for a proposal that is not an open,
/// cycle-stamped optimizer-born candidate, an unusable score, and every refusal
/// arm of [`SkillEditDisposition`]; [`Error::SkillEditGateRetry`] when the
/// snapshot moved under the call. Rejections and cap deferrals are `Ok`.
fn rule_on_proposal(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayScorer,
    cycle: &SkillEditCycle,
    at: u64,
) -> Result<HeldOutVerdict> {
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
    let held_out = match target_record {
        Some(_) => held_out_receipts(vault, &target)?,
        None => Vec::new(),
    };
    let presented = terminal_reason(&proposal_record, target_record.as_ref(), &held_out);
    race_hook();

    let prepared = vault.with_write_txn(|wtxn| {
        let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
        require_open_optimizer_proposal(&staged)?;
        let target = target_of(&staged)?;
        let current = readable_target(vault.read_skill_record_in_txn(&*wtxn, &target).map(Some))?;
        let held_out = match current {
            Some(_) => held_out_receipts_in_txn(vault, &*wtxn, &target)?,
            None => Vec::new(),
        };
        // The reason is re-verified in the transaction that would WRITE it.
        // Ruling only when both reads agree is what makes a false terminal
        // refusal — one the world had already outrun — impossible to commit.
        match (presented, terminal_reason(&staged, current.as_ref(), &held_out)) {
            (Some(presented), Some(committed)) if presented == committed => {
                let verdict = refusal(proposal, &target, cycle, committed, at);
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
                let basis = ScoredBasis::of(
                    &staged,
                    &current,
                    &held_out,
                    tier_verdict_in_txn(vault, &*wtxn, proposal, &staged)?.tier(),
                )?;
                // Idempotence, before the LLM tier rather than after it. A gate
                // call is a DELIVERY, and deliveries are retried; asking the
                // judge the same question twice would not only pay twice, it
                // would answer differently, because the first ruling has by
                // then moved the cap the second call is measured against.
                let standing =
                    standing_ruling_in_txn(vault, &*wtxn, proposal, &basis, cycle)?;
                if let Some(standing) = standing {
                    return Ok(Prepared::Ruled(Box::new(standing)));
                }
                Ok(Prepared::Score(Box::new(ScoreInputs {
                    proposal: staged,
                    target,
                    target_record: current,
                    held_out,
                    basis,
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

    let before = validate_score(scorer.score(&HeldOutReplayCase {
        skill: inputs.target,
        skill_id: &inputs.target_record.skill_id,
        version: &inputs.target_record.version,
        instructions: &inputs.target_record.desc,
        held_out_receipts: &inputs.held_out,
    })?)?;
    let after = validate_score(scorer.score(&HeldOutReplayCase {
        skill: inputs.target,
        skill_id: &inputs.target_record.skill_id,
        version: &inputs.proposal.version,
        instructions: &inputs.proposal.desc,
        held_out_receipts: &inputs.held_out,
    })?)?;

    // The scored set has done its work; what the row keeps of it is the bounded
    // display list, and the basis keeps the rest.
    let truncated = inputs.held_out.len() > SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE;
    let display = bounded_receipts(inputs.held_out);
    let basis = inputs.basis;
    let target = inputs.target;

    let verdict = vault.with_write_txn(|wtxn| {
        // Re-read at the write door, exactly as ONE-1448's draft path does: the
        // scorer ran outside this transaction, so the target may have been
        // superseded and either tier may have been re-marked while it thought.
        let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
        let current = readable_target(vault.read_skill_record_in_txn(&*wtxn, &target).map(Some))?;
        // The concurrent duplicate: two deliveries that both got past the read
        // above serialize HERE, and the second one finds the first's row.
        if let Some(standing) = standing_ruling_in_txn(vault, &*wtxn, proposal, &basis, cycle)? {
            return Ok(standing);
        }
        let mut verdict = HeldOutVerdict {
            before,
            after,
            accepted: false,
            id: EntityId::now(),
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
            before,
            after,
        )?;
        verdict.accepted = verdict.disposition.admits();
        record_verdict_in_txn(vault, wtxn, &verdict)?;
        if verdict.disposition.closes_proposal() {
            close_answered_proposal_in_txn(vault, wtxn, proposal, at)?;
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
    target: EntityId,
    target_record: SkillRecord,
    held_out: Vec<String>,
    basis: ScoredBasis,
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
fn terminal_reason(
    proposal: &SkillRecord,
    target: Option<&SkillRecord>,
    held_out: &[String],
) -> Option<SkillEditDisposition> {
    let Some(target) = target else {
        return Some(SkillEditDisposition::RefusedStaleTarget);
    };
    if !target_is_current(proposal, target) {
        return Some(SkillEditDisposition::RefusedStaleTarget);
    }
    if held_out.is_empty() {
        return Some(SkillEditDisposition::RefusedNoHeldOutEvidence);
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
    Error::SkillEditGateRetry(reason)
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

/// The decision itself, over the committing snapshot.
#[expect(
    clippy::too_many_arguments,
    reason = "the decision names every input it rests on, and hiding them in a struct would only move the list"
)]
fn decide_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    proposal: &EntityId,
    staged: &SkillRecord,
    current: Option<&SkillRecord>,
    cycle: &SkillEditCycle,
    basis: &ScoredBasis,
    before: f32,
    after: f32,
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
    if skill_body_binding_digest(staged)? != basis.proposal_digest
        || skill_body_binding_digest(current)? != basis.target_digest
    {
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
    // Strict improvement, and evaluated BEFORE the tier and cap arms so a
    // regression is reported as the regression it is rather than as whatever
    // else was also wrong. No epsilon (blueprint note: the anti-Goodhart
    // floor), and a TIE lives on this branch. Written as `<=` rather than a
    // negated `>` because both scalars are already validated finite, so the
    // two are equivalent and this one reads as the rule it is.
    if after <= before {
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
    let cap = cycle_cap_in_txn(vault, wtxn)?;
    if accepted_in_cycle_in_txn(vault, wtxn, cycle, proposal)? >= cap {
        return Ok(SkillEditDisposition::DeferredCycleCap);
    }
    Ok(SkillEditDisposition::Accepted)
}

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
fn accepted_in_cycle_in_txn(
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
        {
            accepted.insert(verdict.proposal);
        }
    }
    Ok(u32::try_from(accepted.len()).unwrap_or(u32::MAX))
}

/// The standing ruling this delivery would only be repeating, if there is one.
///
/// "Standing" is the LATEST ruling, not any ruling: a proposal accepted and
/// then refused at the admission door has been answered, and the superseded
/// acceptance is history rather than a live permission.
///
/// Two rulings qualify, and both are answers a REDELIVERY must return rather
/// than re-earn:
///
/// - a standing ACCEPTANCE over exactly this basis, whatever cycle it was ruled
///   in — an acceptance keeps the cycle it was ruled in, and a duplicate
///   arriving under another label must not revoke it;
/// - a standing CAP DEFERRAL over exactly this basis AND this same cycle. The
///   cycle equality is load-bearing in the other direction: a deferral from
///   wake X says nothing about wake Y, so a genuine later-cycle pickup still
///   re-scores and is counted against the cycle that picked it up.
///
/// Returning the standing row is what makes delivery idempotent on BOTH arms:
/// no second replay is paid, no second row is appended, and the cap is neither
/// re-spent nor re-measured.
fn standing_ruling_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    proposal: &EntityId,
    basis: &ScoredBasis,
    cycle: &SkillEditCycle,
) -> Result<Option<HeldOutVerdict>> {
    Ok(
        standing_verdict_in_txn(vault, rtxn, proposal)?.filter(|verdict| {
            basis.matches(verdict)
                && (verdict.disposition.admits()
                    || (verdict.disposition == SkillEditDisposition::DeferredCycleCap
                        && verdict.cycle == cycle.as_str()))
        }),
    )
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
        accepted: false,
        id: EntityId::now(),
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
pub(super) fn close_answered_proposal_in_txn(
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
