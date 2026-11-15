//! Door for `tests/off_record_continuation_shell.rs` (FIX 22388): the BASE
//! conversation shell an off-record session's on-record stretch writes its
//! turns under.

use crate::EntityId;
use crate::error::Result;
use crate::off_record::OffRecordSession;

/// The on-record continuation shell of `session`, allocated on its first
/// read in an on-record stretch.
///
/// # Errors
///
/// The session is closing, or it is not on record.
pub fn on_record_continuation_shell(session: &OffRecordSession<'_>) -> Result<EntityId> {
    session.on_record_continuation_shell()
}
