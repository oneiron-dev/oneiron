//! Windows a sweep holds closed while it rewrites their persisted state.
//!
//! A window being compacted must not be opened from the state the sweep is
//! replacing, or the open registers the history the sweep drops and keeps it
//! servable. The mark is per window: an open of a marked window waits for the
//! sweep and then reads what it wrote, and opens of every other window go
//! through.

use std::collections::HashSet;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use super::types::WindowKey;

#[derive(Default)]
pub(super) struct SweepFence {
    closed: Mutex<HashSet<WindowKey>>,
    reopened: Condvar,
}

impl SweepFence {
    /// The set is changed in single steps, so a holder that panicked left it
    /// whole.
    fn closed(&self) -> MutexGuard<'_, HashSet<WindowKey>> {
        self.closed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a sweep holds `key` closed.
    pub(super) fn holds(&self, key: &WindowKey) -> bool {
        self.closed().contains(key)
    }

    /// The windows held closed now.
    pub(super) fn keys(&self) -> Vec<WindowKey> {
        self.closed().iter().cloned().collect()
    }

    /// Waits until no sweep holds `key` closed.
    pub(super) fn wait_until_open(&self, key: &WindowKey) {
        let closed = self.closed();
        drop(
            self.reopened
                .wait_while(closed, |closed| closed.contains(key))
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Holds `key` closed until the returned mark drops, by return or by
    /// unwinding; `None` when another sweep holds it closed already.
    pub(super) fn close<'a>(&'a self, key: &'a WindowKey) -> Option<Closed<'a>> {
        // Lazily: a mark made and dropped would release the holder's.
        let inserted = self.closed().insert(key.clone());
        inserted.then(|| Closed { fence: self, key })
    }
}

/// A window a sweep holds closed.
pub(super) struct Closed<'a> {
    fence: &'a SweepFence,
    key: &'a WindowKey,
}

impl Drop for Closed<'_> {
    fn drop(&mut self) {
        self.fence.closed().remove(self.key);
        self.fence.reopened.notify_all();
    }
}
