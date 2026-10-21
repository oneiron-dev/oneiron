//! An approved tradeoff that cannot admit yet (FIX 8848). When the cycle has
//! spent its accepts, or the judge's cadence holds its rubric, a person's
//! approval is kept on a deferred row instead of refused, at the owner door as
//! at an A/B pick. A later cycle that scores the same question admits through
//! the kept approval rather than asking again, and defers it again while the
//! cycle or the cadence still holds.
use super::*;

/// Keep `resolution`, an approval of `pending`, on a new row deferred as
/// `disposition` and charged to `cycle`. The proposal stays open, and any
/// A/B ask about it is answered by this row.
/// # Errors
/// An unreadable goal, an invalid row, or storage errors.
pub(super) fn record_deferred_approval_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pending: HeldOutVerdict,
    resolution: TradeoffResolution,
    disposition: SkillEditDisposition,
    cycle: &SkillEditCycle,
    at: u64,
) -> Result<HeldOutVerdict> {
    let deferred = HeldOutVerdict {
        id: vault.store.clock.entity_id()?,
        disposition,
        accepted: false,
        tradeoff_resolution: Some(resolution),
        goal_revision: goal_definition_in_txn(vault, txn, &pending.skill)?.revision,
        cycle: cycle.as_str().to_owned(),
        at,
        ..pending
    };
    record_verdict_in_txn(vault, txn, &deferred)?;
    tradeoff::clear_ask_in_txn(vault, txn, &deferred.proposal)?;
    Ok(deferred)
}

/// The person's approval kept on `proposal`'s standing deferred row, when that
/// row was scored on this same basis into the same tradeoff, the same axes
/// gained and lost: the same question, so the approval still answers it. A
/// rule's or a judgment's approval is not carried; the ladder rules again.
/// # Errors
/// An unreadable verdict row, or storage errors.
pub(super) fn deferred_approval_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: &EntityId,
    basis: &ScoredBasis,
    axes: &BTreeMap<String, GoalAxisScore>,
) -> Result<Option<TradeoffResolution>> {
    let Some(standing) = standing_verdict_in_txn(vault, txn, proposal)? else {
        return Ok(None);
    };
    let same_question = matches!(
        standing.disposition,
        SkillEditDisposition::DeferredCycleCap | SkillEditDisposition::DeferredJudgeCadence
    ) && standing.displaced_by_revision.is_none()
        && basis.matches(&standing)
        && signature(&standing.goal_axes) == signature(axes);
    Ok(standing.tradeoff_resolution.filter(|resolution| {
        same_question && matches!(resolution.rung, TradeoffRung::Person | TradeoffRung::Role)
    }))
}

/// The axes a vector gains and loses on. A re-scored judge answer may move a
/// score without moving the question it puts.
fn signature(axes: &BTreeMap<String, GoalAxisScore>) -> (BTreeSet<&str>, BTreeSet<&str>) {
    let moved = |keep: fn(&GoalAxisScore) -> bool| {
        axes.iter()
            .filter(|(_, axis)| keep(axis))
            .map(|(name, _)| name.as_str())
            .collect::<BTreeSet<_>>()
    };
    (
        moved(|axis| axis.after > axis.before),
        moved(|axis| axis.after < axis.before),
    )
}
