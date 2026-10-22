//! The legal holds a sweep compaction meets (OF-470): a held entity
//! document keeps its bytes and its history, erased or not (FIX 10160), and
//! a hold met in the compaction's own writer defers it as the read before
//! did, never as a failure.

use super::run::{HardEraseSweepRun, WindowSweepState};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Whether a standing legal hold names entity document `id`, which the sweep
/// compacts or erases: read before any work, a hint and not the fence, since
/// the document's writer checks again. An unerased NOTE is the NOTE purge
/// door's, compacted nowhere here, so it reads unheld.
pub(super) fn document_held(vault: &Vault, id: EntityId, erase: bool) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    if !erase
        && vault.get_entity_type_in_txn(&rtxn, &id)? == Some(crate::registry::ENTITY_TYPE_NOTE)
    {
        return Ok(false);
    }
    crate::store::legal_hold::held_in_txn(&vault.store, &rtxn, id.as_bytes())
}

/// Whether `error`, from a compaction's writer, is a legal hold's refusal: a
/// hold placed after the read defers as the read does. Any other error
/// stays a failure.
pub(super) fn refused_by_hold(error: &Error) -> bool {
    crate::store::legal_hold::is_hold_refusal(error)
}

/// Counts one held deferral: the obligation stays and no retry is spent.
pub(super) fn defer_held(run: &mut HardEraseSweepRun, state: &mut WindowSweepState) {
    run.windows_deferred_held += 1;
    if matches!(state, WindowSweepState::AllCompacted) {
        *state = WindowSweepState::Deferred;
    }
}
