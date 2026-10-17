//! Where a removed epoch summary leaves the count (OF-013).
//!
//! A soft erase keeps an epoch's keyframe in its row. A hard purge and a
//! local demotion remove the row, so before either does, the session keeps
//! the place that row held: its epoch and the turn it ended at, nothing it
//! said. [`super::epoch::prior_epoch_in_txn`] reads the floor beside the rows
//! that remain, so numbering never goes back under a removed epoch.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::withdrawn::stored_keyframe;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// The highest removed epoch of one session and the turn it ended at.
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

const FLOORS: SideTable<EntityId, EpochFloor, Named> =
    SideTable::new(&side_table::COMPACTION_EPOCH_FLOOR);

/// Raises the floor of the session that stored row `envelope` (its header,
/// then its body) summarises, inside the transaction about to remove it. Any
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
    let floor = EpochFloor {
        epoch: keyframe.epoch,
        turn_end: keyframe.turn_end,
    };
    let held = FLOORS.get(store, txn, &keyframe.session)?;
    if held.is_some_and(|held| held.position() >= floor.position()) {
        return Ok(());
    }
    FLOORS.put(store, txn, &keyframe.session, &floor)
}

/// The floor removed epochs left `session`, as `(epoch, turn_end)`.
pub(super) fn epoch_floor_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    session: &EntityId,
) -> Result<Option<(u64, u64)>> {
    Ok(FLOORS.get(store, txn, session)?.map(EpochFloor::position))
}

/// Every session's floor, as `(session, epoch, turn_end)` in key order: the
/// rows a whole-vault archive carries.
pub(crate) fn epoch_floors_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<Vec<(EntityId, u64, u64)>> {
    Ok(FLOORS
        .scan(store, txn)?
        .into_iter()
        .map(|(session, floor)| (session, floor.epoch, floor.turn_end))
        .collect())
}

/// Raises `session`'s floor to `(epoch, turn_end)`, as a whole-vault import
/// restores it. The rule is [`raise_epoch_floor_in_txn`]'s: the floor only
/// rises, so a held floor at or above this one stays.
pub(crate) fn raise_session_epoch_floor_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    session: &EntityId,
    epoch: u64,
    turn_end: u64,
) -> Result<()> {
    let floor = EpochFloor { epoch, turn_end };
    let held = FLOORS.get(store, txn, session)?;
    if held.is_some_and(|held| held.position() >= floor.position()) {
        return Ok(());
    }
    FLOORS.put(store, txn, session, &floor)
}
