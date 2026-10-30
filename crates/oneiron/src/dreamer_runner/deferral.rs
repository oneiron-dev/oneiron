//! A deferred selection (FIX 3863). A Dreamer try that met a wait (a window
//! away from this replica, a continuation not yet due) goes back to the
//! queue as the same row, the deferral kept in its history, so a wait that
//! lasts months keeps one row. Its next run is still the selection retry the
//! fresh retry row a deferral once minted was: a consolidation branch widens
//! over its conversations' TURNs as a retry's does.

use crate::attempt_queue::AttemptRecord;

/// The reason a deferral leaves on its row's history.
pub(crate) const SELECTION_DEFERRED_REASON: &str = "consolidation selection deferred";

/// Whether `record` runs again after a deferred selection.
pub(crate) fn selection_deferred(record: &AttemptRecord) -> bool {
    record
        .history
        .iter()
        .any(|failure| failure.reason == SELECTION_DEFERRED_REASON)
}
