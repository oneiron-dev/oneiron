//! A room write's birth (FIX 4281; Engine 10-22): the `made_by` envelope a
//! NOTE or claim staged in an off-record room carries, stamped beside its row
//! in the room's overlay, in the segment that stages the row, and dropped
//! with the room at close. It is bookkeeping: it spends none of the room's
//! byte budget (`session_overlay::keyspace::unbudgeted_row`).
//!
//! A room keeps today's acceptance: an evidence ref the room does not read as
//! a TURN, and a concluded write with no evidence at all, still stage. The
//! birth keeps every supplied ref as supplied ([`RoomEvidence`]); only the
//! refs the caller read as a TURN are its inputs, hashed as read. Nothing
//! here is a base stamp: a base stamper treats the room's evidence as absent.

use heed::RwTxn;

use super::{ROW_BIRTH, RowBirth};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::live_entity_row_in_txn;

pub(crate) use crate::store::row_birth::SuppliedEvidence;

/// Stamps `birth`, a room's ([`RowBirth::in_room`]), for `row` in `view`'s
/// room, on the segment's transaction `txn` that staged the row. A birth is
/// immutable: a row the room already stamped keeps its first birth, and a
/// write staged again over it changes nothing here. The room never refuses
/// a write for its birth (Engine 10-22): a row the room does not hold as
/// live gets none.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for an engine-built birth that is not a room's
/// or is malformed (never a caller's input); storage errors as they occur.
pub(crate) fn stamp_room_birth_in_txn(
    view: &crate::store::SessionStoreView<'_>,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    if birth.room_evidence.is_none() || !birth.withheld.is_empty() {
        return Err(Error::InvalidConfig(
            "a room birth carries its room evidence and withholds no ref".into(),
        ));
    }
    birth.check_shape()?;
    if !live_entity_row_in_txn(view, txn, row)?.is_live() || ROW_BIRTH.contains(view, txn, row)? {
        return Ok(());
    }
    ROW_BIRTH.put(view, txn, row, birth)
}
