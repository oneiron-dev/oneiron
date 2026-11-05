//! Core half of `store::housekeeping_wake`: its store-layer items live in `oneiron_store::housekeeping_wake` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::housekeeping_wake::*;

use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::housekeeping_schedule::HousekeepingSweep;
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};

const WAKE: SideTable<WakeKey, (), Raw> = SideTable::new(&side_table::HOUSEKEEPING_WAKE);

/// Notes that `sweep` has work due at `at`, in the caller's transaction, so
/// the note commits with the deadline it records. A sweep without notes
/// notes nothing.
pub(crate) fn note_wake_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    sweep: HousekeepingSweep,
    at: u64,
) -> Result<()> {
    match tag(sweep) {
        Some(tag) => WAKE.put(store, txn, &(tag, at, store.clock.entity_id()?), &()),
        None => Ok(()),
    }
}

/// The earliest deadline noted for `sweep`.
pub(crate) fn earliest_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    sweep: HousekeepingSweep,
) -> Result<Option<u64>> {
    let Some(tag) = tag(sweep) else {
        return Ok(None);
    };
    let mut rows = WAKE.iter_from(store, txn, &tag)?;
    Ok(rows.next().transpose()?.map(|((_, at, _), ())| at))
}

/// The rows of `sweep` due by `now`, as they stand before a run starting now.
pub(crate) fn due_by(vault: &Vault, sweep: HousekeepingSweep, now: u64) -> Result<Vec<WakeKey>> {
    let Some(tag) = tag(sweep) else {
        return Ok(Vec::new());
    };
    let txn = vault.store.env.read_txn()?;
    let mut due = Vec::new();
    for row in WAKE.iter_from(&vault.store, &txn, &tag)? {
        let (key, ()) = row?;
        if key.1 > now || due.len() == CLEAR_LIMIT {
            break;
        }
        due.push(key);
    }
    Ok(due)
}

/// Removes the rows a covering run read before it started.
pub(crate) fn clear(vault: &Vault, covered: &[WakeKey]) -> Result<()> {
    if covered.is_empty() {
        return Ok(());
    }
    let mut txn = vault.store.env.write_txn()?;
    for key in covered {
        WAKE.delete(&vault.store, &mut txn, key)?;
    }
    txn.commit()?;
    Ok(())
}
