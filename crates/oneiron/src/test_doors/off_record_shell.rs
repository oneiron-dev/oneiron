//! Door for `tests/off_record_continuation_shell.rs` (FIX 22388): the BASE
//! conversation shell an off-record session's on-record stretch writes its
//! turns under.

use crate::EntityId;
use crate::error::Result;
use crate::off_record::OffRecordSession;
use crate::store::row_birth::RowBirth;

/// The on-record continuation shell of `session`, allocated on its first
/// read in an on-record stretch.
///
/// # Errors
///
/// The session is closing, or it is not on record.
pub fn on_record_continuation_shell(session: &OffRecordSession<'_>) -> Result<EntityId> {
    session.on_record_continuation_shell()
}

/// The room birth staged for `row` in `session`'s room, if any (L2 sweep
/// handle-build Red 1: the room NOTE birth's `made_by` class).
///
/// # Errors
///
/// Storage errors, or a closed session.
pub fn room_row_birth(session: &OffRecordSession<'_>, row: &EntityId) -> Result<Option<RowBirth>> {
    session.read_composed(|view, txn| crate::store::birth_record::ROW_BIRTH.get(view, txn, row))
}
