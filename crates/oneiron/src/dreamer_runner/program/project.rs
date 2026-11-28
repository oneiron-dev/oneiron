//! The project a turn program's code run sends in (FIX 11906): the project
//! whose home room the turn that woke it landed in, or, for a program armed
//! as one run of a project ([RSI-PROJECT-WORKFLOW]), that project.

use super::ADMISSION;
use super::run::RUN;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The project the code run `code_run` of a turn program sends in: the
/// project of the room its waking turn landed in, that turn's thread's room
/// where the turn is in a thread; for a program a timer, idle stretch or
/// feed woke, the project its pin was armed for while the read fold serves
/// it. `None` for a code run of no program, an admission that no longer
/// reads, an occurrence of a program armed for no project (never a wider
/// read), or a turn in any room no project homes.
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
    // An occurrence (untangle slice 6.8c) landed in no room: its run sends
    // in the project its pin names, and none when it names none.
    if admission.wake.occurrence.is_some() {
        let Some(project) = admission
            .definition
            .as_ref()
            .and_then(|definition| definition.project)
        else {
            return Ok(None);
        };
        return Ok(vault
            .effective_project_in_txn(txn, project)?
            .map(|_| project));
    }
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
