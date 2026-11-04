//! Advisory own-rate counters and erasure in a caller-owned transaction.

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
    CHECKS.put(
        store,
        txn,
        &key,
        &OwnRateCheck {
            kind,
            actor: actor.to_hex(),
            window_started_at,
            window_seconds: rate.window_seconds,
            count,
            threshold: rate.threshold,
        },
    )
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

