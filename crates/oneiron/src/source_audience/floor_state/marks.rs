//! A floor's wait marks (READ-LINEAGE L1): what each waiting row waits on,
//! kept by the awaited id (so the write that lands it raises the row again)
//! and by the row (so a raise takes every mark the row no longer waits on,
//! #10108 review P1).

use std::collections::BTreeSet;

use heed::RwTxn;

use crate::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// What each row whose floor waits waits on: the awaited id, then the row.
pub(super) const AWAITED: SideTable<(EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_AWAITED);
/// The marks of [`AWAITED`] by row: the waiting row, then the awaited id.
pub(super) const WAITS: SideTable<(EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_WAITS);

/// Marks `row` as waiting on `awaited`.
pub(super) fn mark_wait_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    awaited: &EntityId,
    row: &EntityId,
) -> Result<()> {
    AWAITED.put(store, txn, &(*awaited, *row), &())?;
    WAITS.put(store, txn, &(*row, *awaited), &())
}

/// Takes the mark that `row` waits on `awaited`.
pub(super) fn take_mark_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    awaited: &EntityId,
    row: &EntityId,
) -> Result<()> {
    AWAITED.delete(store, txn, &(*awaited, *row))?;
    WAITS.delete(store, txn, &(*row, *awaited)).map(drop)
}

/// Takes each mark of what `row` waits on that names no id in `keep`.
pub(super) fn take_marks_of_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    keep: &BTreeSet<EntityId>,
) -> Result<()> {
    for (_, awaited) in WAITS.scan_keys(store, txn, row.as_bytes())? {
        if !keep.contains(&awaited) {
            take_mark_in_txn(store, txn, &awaited, row)?;
        }
    }
    Ok(())
}
