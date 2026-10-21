//! Who carries a spent span (FIX 7498): the nightly child whose branch holds
//! the span's TURN, never the nightly parent, and, once a child's preparation
//! splits that TURN's part off, the sibling that now owes it. A receipt keeps
//! its key layout and every field; only the attempt that carries it moves.

use std::collections::{BTreeMap, BTreeSet};

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::ConsolidationBranchPlan;
use crate::dreamer_runner::EnqueueDreamerAttemptOutcome;
use crate::{EntityId, Error, Result};

use super::CONSUMED;

/// Each planned TURN's carrying child: the attempt its branch enqueued as,
/// or the one standing under the same key, for every TURN of every part.
/// `plans` and `outcomes` pair one to one, in order, as the enqueue returns
/// them; counts that differ are a fault, never a shorter pairing. A TURN two
/// branches hold keeps the first's.
pub(crate) fn consumed_carriers(
    plans: &[ConsolidationBranchPlan],
    outcomes: &[EnqueueDreamerAttemptOutcome],
) -> Result<BTreeMap<EntityId, AttemptId>> {
    if plans.len() != outcomes.len() {
        return Err(Error::InvariantViolation(
            "nightly children and their enqueue outcomes differ in count",
        ));
    }
    let mut carriers = BTreeMap::new();
    for (plan, outcome) in plans.iter().zip(outcomes) {
        let carrier = match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        };
        for turn in plan.turn_ids() {
            carriers.entry(turn).or_insert(carrier);
        }
    }
    Ok(carriers)
}

/// Moves the receipts `from` carries for `turns` to `to`, in the caller's
/// commit: the sibling a preparation split those TURNs off into now carries
/// their spans. Each moved receipt keeps its span, TURN, source, range,
/// kind, score and `at`; its key and `attempt` name `to`, and nothing is
/// spent again. A receipt `from` does not carry stays where it is, so one
/// already moved to another sibling is never taken. Returns how many moved.
pub(crate) fn retarget_consumed_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    from: AttemptId,
    to: AttemptId,
    turns: &[EntityId],
) -> Result<usize> {
    if from == to || turns.is_empty() {
        return Ok(0);
    }
    let turns: BTreeSet<EntityId> = turns.iter().copied().collect();
    let rows = CONSUMED.scan_from(store, txn, from.as_bytes())?;
    let mut moved = 0_usize;
    for ((carrier, span), mut receipt) in rows {
        if carrier != from || !turns.contains(&receipt.turn) {
            continue;
        }
        CONSUMED.delete(store, txn, &(carrier, span))?;
        receipt.attempt = to;
        CONSUMED.put(store, txn, &(to, span), &receipt)?;
        moved += 1;
    }
    Ok(moved)
}
