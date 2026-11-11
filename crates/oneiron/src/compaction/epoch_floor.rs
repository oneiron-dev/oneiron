//! Where a removed epoch summary leaves the count (OF-013).
//!
//! A soft erase keeps an epoch's keyframe in its row. A hard purge and a
//! local demotion remove the row, so before either does, the epoch's lineage
//! keeps the place that row held: its epoch and the turn it ended at,
//! nothing it said. [`super::epoch::prior_epoch_in_txn`] reads the floor
//! beside the rows that remain, so numbering never goes back under a removed
//! epoch. Each lineage keeps its own floor (FIX 5029): a SESSION's own log,
//! and each conversation's turns within it.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::epoch::EpochScope;
use super::withdrawn::stored_keyframe;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// The highest removed epoch of one lineage and the turn it ended at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct EpochFloor {
    epoch: u64,
    turn_end: u64,
}

impl EpochFloor {
    const fn position(self) -> (u64, u64) {
        (self.epoch, self.turn_end)
    }
}

/// Key: id16(session), then id16(conversation) for a conversation's lineage.
const FLOORS: SideTable<EpochScope, EpochFloor, Named> =
    SideTable::new(&side_table::COMPACTION_EPOCH_FLOOR);

/// Raises the floor of the lineage that stored row `envelope` (its header,
/// then its body) counts in, inside the transaction about to remove it. Any
/// other row, and a summary whose keyframe keys do not decode, writes
/// nothing. The floor only rises: by epoch, then by the turn it ended at.
pub(crate) fn raise_epoch_floor_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    envelope: &[u8],
) -> Result<()> {
    let Some(keyframe) = stored_keyframe(envelope) else {
        return Ok(());
    };
    raise_epoch_scope_floor_in_txn(
        store,
        txn,
        &keyframe.scope(),
        keyframe.epoch,
        keyframe.turn_end,
    )
}

/// The floor removed epochs left `scope`'s lineage, as `(epoch, turn_end)`.
pub(super) fn epoch_floor_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    scope: &EpochScope,
) -> Result<Option<(u64, u64)>> {
    Ok(FLOORS.get(store, txn, scope)?.map(EpochFloor::position))
}

/// Every lineage's floor, as `(scope, epoch, turn_end)` in key order: the
/// rows a whole-vault archive and a window's cutoff map carry.
pub(crate) fn epoch_floors_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<Vec<(EpochScope, u64, u64)>> {
    Ok(FLOORS
        .scan(store, txn)?
        .into_iter()
        .map(|(scope, floor)| (scope, floor.epoch, floor.turn_end))
        .collect())
}

/// Raises `scope`'s floor to `(epoch, turn_end)`, as a removal, a
/// whole-vault import and a carried floor raise it. The floor only rises, so
/// a held floor at or above this one stays.
pub(crate) fn raise_epoch_scope_floor_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    scope: &EpochScope,
    epoch: u64,
    turn_end: u64,
) -> Result<()> {
    let floor = EpochFloor { epoch, turn_end };
    let held = FLOORS.get(store, txn, scope)?;
    if held.is_some_and(|held| held.position() >= floor.position()) {
        return Ok(());
    }
    FLOORS.put(store, txn, scope, &floor)
}
