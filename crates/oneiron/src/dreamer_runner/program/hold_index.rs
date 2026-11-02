//! The program runtime's holds by kind (FIX 6062): a commit that stores an
//! authority row, and a host that binds its program runtime, read the holds
//! whose cause it may return by key, never every parked try. Each index row
//! is written and deleted in the writer that parks or clears the try it
//! names, beside the parked row, so the index holds exactly the program
//! holds the parked table holds.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{DreamerParkCause, DreamerParkedAttemptRecord};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::PROGRAM_PARK_OWNER;
use super::resume::ProgramHold;

/// Each try the program runtime holds, keyed by its hold's kind (the
/// [`ProgramHold`] discriminant), then the try.
const PROGRAM_HOLD: SideTable<([u8; 1], AttemptId), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_HOLD);

/// The program hold `park` is, when it is the program runtime's own park
/// under one hold's exact reason.
fn hold_of(park: &DreamerParkedAttemptRecord) -> Option<ProgramHold> {
    if park.park_owner != PROGRAM_PARK_OWNER || park.cause != DreamerParkCause::Other {
        return None;
    }
    ProgramHold::of_reason(&park.reason)
}

/// Indexes `park` when it is a program hold, in the writer that parks it.
pub(crate) fn index_program_hold_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    park: &DreamerParkedAttemptRecord,
) -> Result<()> {
    let Some(hold) = hold_of(park) else {
        return Ok(());
    };
    PROGRAM_HOLD.put(vault, wtxn, &([hold as u8], park.attempt_id), &())
}

/// Drops `park`'s index row when it is a program hold, in the writer that
/// clears or replaces it.
pub(crate) fn unindex_program_hold_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    park: &DreamerParkedAttemptRecord,
) -> Result<()> {
    let Some(hold) = hold_of(park) else {
        return Ok(());
    };
    PROGRAM_HOLD
        .delete(vault, wtxn, &([hold as u8], park.attempt_id))
        .map(drop)
}

/// The tries held for `hold`, in attempt order.
pub(super) fn held_for_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hold: ProgramHold,
) -> Result<Vec<AttemptId>> {
    Ok(PROGRAM_HOLD
        .scan_keys(vault, txn, &[hold as u8])?
        .into_iter()
        .map(|(_, attempt)| attempt)
        .collect())
}
