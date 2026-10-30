//! A deferred selection (FIX 3863). A Dreamer try that met a wait (a window
//! away from this replica, a continuation not yet due) goes back to the
//! queue as the same row, the deferral kept in its history, so a wait that
//! lasts months keeps one row. Its next run is still the selection retry the
//! fresh retry row a deferral once minted was: a consolidation branch widens
//! over its conversations' TURNs as a retry's does.

use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::error::Result;

use super::DreamerRunnerStore;

/// The reason a deferral leaves on its row's history.
pub(crate) const SELECTION_DEFERRED_REASON: &str = "consolidation selection deferred";

/// Whether `record` runs again after a deferred selection.
pub(crate) fn selection_deferred(record: &AttemptRecord) -> bool {
    record
        .history
        .iter()
        .any(|failure| failure.reason == SELECTION_DEFERRED_REASON)
}

/// The steps of `step_hashes` the try `attempt` has not yet pinned as paid,
/// once each, in `txn`: the same try runs again after each deferral, and a
/// step an earlier deferral of it pinned keeps its receipt (FIX 8728).
pub(super) fn unpinned_step_hashes_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    step_hashes: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>> {
    let mut unpinned = Vec::with_capacity(step_hashes.len());
    for hash in step_hashes {
        if !unpinned.contains(hash) && !store.step_charge_marked_in_txn(txn, attempt, hash)? {
            unpinned.push(*hash);
        }
    }
    Ok(unpinned)
}
