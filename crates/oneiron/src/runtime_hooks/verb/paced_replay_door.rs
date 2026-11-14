//! Door for `tests/check_in_share_create_effects.rs` (ROLES-CHECKIN P2.5
//! 2k8g review): what the retry of a paced call reads when the call's turn
//! ended refused. The error goes through the turn end's save, the paced call
//! table's row codec and the retry's read (`super::paced`). Compiled only
//! under `--cfg oneiron_test_support`; never API.

use super::ask::SavedOutcome;
use super::paced::{ended_error, ended_error_outcome};
use crate::memory::MemoryError;
use crate::side_table::{Named, SideCodec};
use crate::{Error, Result};

/// The error the retry of a paced call answers when the call's turn ended
/// refused with `error`.
///
/// # Errors
///
/// The paced call table's codec refused the saved outcome.
pub fn replayed_ended_error(error: MemoryError) -> Result<MemoryError> {
    let saved = ended_error_outcome(error, None);
    let row = <Named as SideCodec<SavedOutcome>>::encode(&saved)
        .map_err(|_| Error::InvariantViolation("paced verb call outcome encode"))?;
    let read = <Named as SideCodec<SavedOutcome>>::decode(&row)
        .map_err(|_| Error::CorruptedIndex("paced verb call outcome"))?;
    Ok(ended_error(read))
}
