//! A deferred selection (FIX 3863). A Dreamer try that met a wait (a window
//! away from this replica, a continuation not yet due) goes back to the
//! queue as the same row, the deferral kept in its history, so a wait that
//! lasts months keeps one row. Its next run is still the selection retry the
//! fresh retry row a deferral once minted was: a consolidation branch widens
//! over its conversations' TURNs as a retry's does.

use crate::attempt_queue::AttemptRecord;
use crate::error::Result;
use crate::model_step_context::StepEffectBinding;

use super::DreamerRunnerStore;

/// The reason a deferral leaves on its row's history.
pub(crate) const SELECTION_DEFERRED_REASON: &str = "consolidation selection deferred";

/// The reason a backlog wait leaves on its row's history: the pass's frozen
/// preparation did not hold the try (it was queued after the capture, or
/// past the head), so it ran nothing and its next run is still its first.
pub(crate) const BACKLOG_DEFERRED_REASON: &str = "consolidation backlog deferred";

/// Whether `record` runs again after a deferred selection.
pub(crate) fn selection_deferred(record: &AttemptRecord) -> bool {
    record
        .history
        .iter()
        .any(|failure| failure.reason == SELECTION_DEFERRED_REASON)
}

/// The original step bindings not yet pinned as paid, once each, in `txn`.
/// A step an earlier deferral pinned keeps its receipt (FIX 8728).
pub(super) fn unpinned_step_bindings_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &heed::RoTxn<'_>,
    step_bindings: &[StepEffectBinding],
) -> Result<Vec<StepEffectBinding>> {
    let mut unpinned = Vec::with_capacity(step_bindings.len());
    for binding in step_bindings {
        if !unpinned.contains(binding)
            && !store.step_charge_marked_in_txn(txn, binding.attempt_id, &binding.step_hash)?
        {
            unpinned.push(*binding);
        }
    }
    Ok(unpinned)
}
