//! Advisory own-rate counters and erasure in a caller-owned transaction.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::store::own_rate_record::{OwnRate, OwnRateCheck, OwnRateKind};
use crate::{EntityId, Result, Vault};

/// Counted acts per (actor, kind) in the current window.
const WINDOWS: SideTable<(EntityId, String), OwnRateWindow, Named> =
    SideTable::new(&side_table::OWN_RATE_WINDOW);
/// The latest crossing per (actor, kind).
pub(crate) const CHECKS: SideTable<(EntityId, String), OwnRateCheck, Named> =
    SideTable::new(&side_table::OWN_RATE_CHECK);
/// Every crossing in the order it was kept: the recorded clock read in the
/// keeping transaction and a store-local id minted there. Both lead fields
/// only rise and writes commit one at a time, so key order is keeping order,
/// and the host's health check reads past one cursor (ARCH-0044 C5).
const CHECK_ORDER: SideTable<(u64, EntityId), OwnRateCheck, Named> =
    SideTable::new(&side_table::OWN_RATE_CHECK_ORDER);

/// How long a kept crossing stays in [`CHECK_ORDER`] for the health check to
/// read; a host that has not read it by then has been down for a month.
const ORDER_KEPT_SECS: u64 = 30 * 86_400;
/// Most expired rows one keeping write removes from [`CHECK_ORDER`].
const ORDER_PRUNE_PER_WRITE: usize = 16;

#[derive(Serialize, Deserialize)]
struct OwnRateWindow {
    window: u64,
    count: u64,
}

/// Counts one act in the actor's current window, inside the act's own
/// transaction, and returns the window's count. A rolled-back act leaves no
/// count and no check.
pub(crate) fn count_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    kind: OwnRateKind,
    actor: EntityId,
    now: u64,
    rate: OwnRate,
) -> Result<u64> {
    let window = now / rate.window_seconds.max(1);
    let key = (actor, kind.token().to_owned());
    let count = match WINDOWS.get(store, txn, &key)? {
        Some(row) if row.window == window => row.count,
        _ => 0,
    }
    .saturating_add(1);
    WINDOWS.put(store, txn, &key, &OwnRateWindow { window, count })?;
    observe_in_txn(store, txn, kind, actor, window, count, rate)?;
    Ok(count)
}

/// Writes the typed check for the first act past the threshold in force in
/// `window`. A caller that keeps its own window counter calls this directly.
///
/// "First" is judged against the check already written, not by `count`
/// landing exactly on `threshold + 1`: a threshold narrowed below an actor's
/// running count would otherwise never meet that equality, and the act that
/// first runs past the narrowed one still owes its check.
pub(crate) fn observe_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    kind: OwnRateKind,
    actor: EntityId,
    window: u64,
    count: u64,
    rate: OwnRate,
) -> Result<()> {
    if count <= rate.threshold {
        return Ok(());
    }
    let key = (actor, kind.token().to_owned());
    let window_started_at = window.saturating_mul(rate.window_seconds);
    if let Some(check) = CHECKS.get(store, txn, &key)?
        && check.window_started_at == window_started_at
        && check.window_seconds == rate.window_seconds
        && check.threshold == rate.threshold
    {
        return Ok(());
    }
    let check = OwnRateCheck {
        kind,
        actor: actor.to_hex(),
        window_started_at,
        window_seconds: rate.window_seconds,
        count,
        threshold: rate.threshold,
    };
    CHECKS.put(store, txn, &key, &check)?;
    keep_in_order(store, txn, &check)
}

/// Keeps `check` in [`CHECK_ORDER`] in the crossing's own transaction, and
/// removes a few rows kept longer than [`ORDER_KEPT_SECS`] ago.
fn keep_in_order(store: &Store, txn: &mut heed::RwTxn<'_>, check: &OwnRateCheck) -> Result<()> {
    let kept_at = store.clock.now_recorded_at();
    let mut expired = Vec::new();
    for row in CHECK_ORDER
        .iter_from(store, txn, &[])?
        .take(ORDER_PRUNE_PER_WRITE)
    {
        let (key, _) = row?;
        if key.0.saturating_add(ORDER_KEPT_SECS) >= kept_at {
            break;
        }
        expired.push(key);
    }
    for key in &expired {
        CHECK_ORDER.delete(store, txn, key)?;
    }
    CHECK_ORDER.put(store, txn, &(kept_at, store.clock.entity_id()?), check)
}

/// The kept crossings after `after`, in keeping order, at most `limit`.
pub(crate) fn checks_in_order_after(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    after: Option<(u64, EntityId)>,
    limit: usize,
) -> Result<Vec<((u64, EntityId), OwnRateCheck)>> {
    let start = after.map_or(Bound::Unbounded, Bound::Excluded);
    CHECK_ORDER
        .iter_range(store, txn, start.as_ref(), Bound::Unbounded)?
        .take(limit)
        .collect()
}

/// Erasing `actor` (FIX 3520): its windows go, every kind, in the erase's own
/// transaction. A window counts one actor's acts and keys on that actor.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_window_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    WINDOWS.delete_from(&vault.store, wtxn, actor.as_bytes())?;
    Ok(())
}

/// Erasing `actor` (FIX 3520): its checks go, every kind, in the erase's own
/// transaction. A check asks about one actor's rate and keys on that actor.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_check_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    CHECKS.delete_from(&vault.store, wtxn, actor.as_bytes())?;
    Ok(())
}

/// Erasing `actor` (FIX 3520): its kept crossings leave the keeping order too,
/// in the erase's own transaction. The order keys on time, so the scrub reads
/// the table, which holds at most a month of first crossings.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_check_order_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let actor = actor.to_hex();
    let keys: Vec<(u64, EntityId)> = CHECK_ORDER
        .iter_from(&vault.store, wtxn, &[])?
        .filter_map(|row| match row {
            Ok((key, check)) => (check.actor == actor).then_some(Ok(key)),
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<_>>()?;
    for key in &keys {
        CHECK_ORDER.delete(&vault.store, wtxn, key)?;
    }
    Ok(())
}
