//! Fenced rounds: the in-transaction watermark advance and the snapshot fence
//! that guards a planned round's dirty-turn IDs.

use super::*;

/// An advance's settlement round, enumerated in a read snapshot.
pub(crate) struct WatermarkAdvance {
    current: ConsolidationWatermark,
    upper_learned_at: u64,
    round: Vec<AdmissibleTurnRow>,
}

/// The read half of [`advance_watermark_in_txn`]: the current watermark and
/// the SAME capped prefix it settles, enumerated in the caller's snapshot.
/// `None` when `stop` stopped the enumeration; nothing is settled then.
pub(crate) fn read_watermark_advance_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
    upper_learned_at: u64,
    stop: WakeStop<'_>,
) -> Result<Option<WatermarkAdvance>> {
    let current = read_watermark_in_txn(vault, txn, scope)?;
    let Some(round) = enumerate_admissible_turns(
        vault,
        txn,
        scope,
        &current,
        Some(upper_learned_at),
        effective_dirty_turn_limit_in_txn(vault, txn, scope, usize::MAX)?,
        stop,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(WatermarkAdvance {
        current,
        upper_learned_at,
        round,
    }))
}

/// The write half of [`advance_watermark_in_txn`]: settles the enumerated
/// round on its final `(learned_at, id)` through [`settle_round_in_txn`].
/// An empty round is the empty matched round: nothing was planned through
/// `upper_learned_at`, so the cursor takes that complete-second position.
/// Fail-closed on a backwards complete-second advance: rewinding the cursor
/// over consumed work would re-plan it. A round of pending carriers alone
/// may sit behind the cursor's second; it moves no cursor.
pub(crate) fn apply_watermark_advance_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    advance: &WatermarkAdvance,
) -> Result<()> {
    if advance.round.iter().any(|row| !row.deferred) {
        return settle_round_in_txn(vault, wtxn, scope, &advance.round);
    }
    if advance.upper_learned_at < advance.current.last_learned_at {
        return Err(invalid_consolidation(
            "dreamer watermark cannot settle behind its own position",
        ));
    }
    park_deferred_in_txn(vault, wtxn, &advance.round)?;
    write_watermark_position_in_txn(vault, wtxn, scope, advance.upper_learned_at, None)
}

/// Settles a fenced round inside a caller-owned write transaction: its read
/// half, then its apply half.
pub(crate) fn advance_watermark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    upper_learned_at: u64,
) -> Result<()> {
    // NEVER never stops, so the read phase always yields its advance.
    let Some(advance) =
        read_watermark_advance_in_txn(vault, wtxn, scope, upper_learned_at, WakeStop::NEVER)?
    else {
        return Ok(());
    };
    apply_watermark_advance_in_txn(vault, wtxn, scope, &advance)
}

/// Collects the admissible dirty-turn IDs a planned round covers, through a
/// caller-owned write transaction, for snapshot fencing. It shares
/// [`enumerate_admissible_turns`] with [`scan_dirty_turns`] — same order, same
/// admissibility, same scope-keyed round cap — and drops only the conversation
/// pass, which is irrelevant to fencing.
///
/// The lower bound is the LIVE watermark read inside this transaction, not
/// `lower_exclusive` alone: enumeration starts strictly after the current
/// compound position and runs through `upper_inclusive`, so a planner that
/// advanced WITHIN the caller's second yields a different prefix here and the
/// caller's identity comparison defers the round. `lower_exclusive` is the
/// caller's claim about that position's second; when it no longer matches, the
/// round is stale and the answer is an empty set, never an error.
pub(crate) fn collect_dirty_turn_ids_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
    lower_exclusive: u64,
    upper_inclusive: u64,
) -> Result<Vec<EntityId>> {
    // NEVER never stops, so the collection always yields its ids.
    Ok(collect_dirty_turn_ids_until(
        vault,
        txn,
        scope,
        lower_exclusive,
        upper_inclusive,
        WakeStop::NEVER,
    )?
    .unwrap_or_default())
}

/// [`collect_dirty_turn_ids_in_txn`] with a stop: `None` when `stop`
/// stopped the enumeration; nothing is fenced then.
pub(crate) fn collect_dirty_turn_ids_until(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
    lower_exclusive: u64,
    upper_inclusive: u64,
    stop: WakeStop<'_>,
) -> Result<Option<Vec<EntityId>>> {
    // `upper_inclusive` may sit behind `lower_exclusive`: a round of pending
    // re-dirty carriers alone, which the cursor does not cut.
    let current = read_watermark_in_txn(vault, txn, scope)?;
    if current.last_learned_at != lower_exclusive {
        return Ok(Some(Vec::new()));
    }
    let Some(admissible) = enumerate_admissible_turns(
        vault,
        txn,
        scope,
        &current,
        Some(upper_inclusive),
        effective_dirty_turn_limit_in_txn(vault, txn, scope, usize::MAX)?,
        stop,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(
        admissible
            .into_iter()
            .filter(|row| !row.deferred)
            .map(|row| row.turn_id)
            .collect(),
    ))
}
