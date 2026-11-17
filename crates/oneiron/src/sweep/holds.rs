//! The cooperative restrictions a sweep compaction meets: a held entity
//! document keeps its bytes and its history, erased or not (FIX 10160).

use super::run::{HardEraseSweepRun, WindowSweepState};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Whether a cooperative restriction keeps entity document `id`, which the
/// sweep compacts or erases: read before any work, a hint and not the fence,
/// since the document's writer checks again. An unerased NOTE is the NOTE
/// purge door's, compacted nowhere here, so it reads unheld.
pub(super) fn document_held(vault: &Vault, id: EntityId, erase: bool) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    if !erase
        && vault.get_entity_type_in_txn(&rtxn, &id)? == Some(crate::registry::ENTITY_TYPE_NOTE)
    {
        return Ok(false);
    }
    crate::store::legal_hold::held_in_txn(&vault.store, &rtxn, id.as_bytes())
}

/// Counts one held deferral: the obligation stays and no retry is spent.
pub(super) fn defer_held(run: &mut HardEraseSweepRun, state: &mut WindowSweepState) {
    run.windows_deferred_held += 1;
    if matches!(state, WindowSweepState::AllCompacted) {
        *state = WindowSweepState::Deferred;
    }
}
