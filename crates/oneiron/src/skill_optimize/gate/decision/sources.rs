//! Native verdict and anchor inputs behind the gate's cap and judge cadence.

use super::*;

pub(super) fn observe_sources<T, S: IntoIterator<Item = EntityId>>(
    sources: &mut Option<Vec<EntityId>>,
    (value, rows): (T, Option<S>),
) -> T {
    *sources = crate::attempt_queue::source_rows::union_source_rows([
        sources.take(),
        rows.map(|rows| rows.into_iter().collect()),
    ]);
    value
}

/// The same count beside every native verdict body consulted, including
/// nonmatching and displaced rulings. Sources never alter the cap comparison.
pub(super) fn accepted_in_cycle_sourced_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    cycle: &SkillEditCycle,
    spending: &EntityId,
) -> Result<(u32, Option<Vec<EntityId>>)> {
    let mut accepted: BTreeSet<EntityId> = BTreeSet::new();
    let (verdicts, source_rows) = super::super::ledger::verdict_rows_sourced_in_txn(vault, rtxn)?;
    for verdict in verdicts {
        if verdict.disposition.admits()
            && verdict.cycle == cycle.as_str()
            && verdict.proposal != *spending
            && verdict.displaced_by_revision.is_none()
        {
            accepted.insert(verdict.proposal);
        }
    }
    Ok((
        u32::try_from(accepted.len()).unwrap_or(u32::MAX),
        source_rows,
    ))
}

/// The cadence's original verdict walk and label count, with their native
/// body identities from those same reads, not just the matching rulings.
pub(super) fn judge_revision_due_sourced_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    cycle: &SkillEditCycle,
    spending: &EntityId,
    target: &EntityId,
    world_outcomes: usize,
) -> Result<(bool, Option<Vec<EntityId>>)> {
    let mut since = 0_u64;
    let (verdicts, verdict_rows) = super::super::ledger::verdict_rows_sourced_in_txn(vault, rtxn)?;
    for verdict in verdicts {
        if !verdict.disposition.admits()
            || verdict.displaced_by_revision.is_some()
            || verdict.proposal == *spending
        {
            continue;
        }
        // The ruling that made `target` the judge, or another edit of it.
        if verdict.proposal == *target || verdict.skill == *target {
            if verdict.cycle == cycle.as_str() {
                return Ok((false, verdict_rows));
            }
            if verdict.proposal == *target {
                since = since.max(verdict.at);
            }
        }
    }
    let (picks, label_rows) =
        crate::skill_optimize::labels::anchor_labels_since_sourced_in_txn(vault, rtxn, since)?;
    let source_rows =
        crate::attempt_queue::source_rows::union_source_rows([verdict_rows, Some(label_rows)]);
    let outcomes = u64::try_from(world_outcomes).unwrap_or(u64::MAX);
    Ok((
        picks.saturating_add(outcomes) >= JUDGE_REVISION_FRESH_LABELS,
        source_rows,
    ))
}

/// The original standing-ruling read, including the native rows filtered out.
pub(super) fn standing_ruling_sourced_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    proposal: &EntityId,
    basis: &ScoredBasis,
    cycle: &SkillEditCycle,
    judge_revision: &str,
) -> Result<(Option<HeldOutVerdict>, Option<Vec<EntityId>>)> {
    let (standing, mut sources) =
        super::super::ledger::skill_edit_verdict_sourced_in_txn(vault, rtxn, proposal)?;
    let standing = standing.filter(|verdict| {
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
    if let Some(pending) = &standing
        && pending.disposition == SkillEditDisposition::NeedsTradeoffDecision
    {
        let (waits, ask_sources) =
            super::super::tradeoff::pending_waits_sourced_in_txn(vault, rtxn, pending)?;
        sources = crate::attempt_queue::source_rows::union_source_rows([sources, ask_sources]);
        if !waits {
            return Ok((None, sources));
        }
    }
    Ok((standing, sources))
}
