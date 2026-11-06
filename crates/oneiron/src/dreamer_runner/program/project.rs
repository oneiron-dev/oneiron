//! The project a turn program's code run sends in (FIX 11906): the project
//! whose home room the turn that woke it landed in.

use super::ADMISSION;
use super::run::RUN;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The project the code run `code_run` of a turn program sends in: the
/// project of the room its waking turn landed in, that turn's thread's room
/// where the turn is in a thread. `None` for a code run of no program, an
/// admission that no longer reads, or a turn in any room no project homes.
///
/// # Errors
/// Storage errors, or a room row that does not decode.
pub(crate) fn program_run_project_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    code_run: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(run) = RUN.get_lenient(vault, txn, code_run)? else {
        return Ok(None);
    };
    let Some(admission) = ADMISSION.get_lenient(vault, txn, &run.admission)? else {
        return Ok(None);
    };
    let landed = admission.wake.turn;
    let room = match live_entity_row_in_txn(&vault.store, txn, &landed.turn)? {
        LiveEntityRow::Live { body, .. } => crate::workspace_roster::thread_binding(&body)?
            .map_or(landed.conversation, |binding| binding.room),
        _ => landed.conversation,
    };
    match crate::workspace_roster::room_project_in(vault, txn, room) {
        // A room gone since the turn landed homes no project now.
        Err(Error::EntityNotFound) => Ok(None),
        found => found,
    }
}
