//! Windows held closed while their persisted state is rewritten: by a sweep
//! that compacts them, or by a publication to a window no one has open.
//!
//! A window being rewritten must not be opened or replaced from the state the
//! rewrite is replacing, or the open registers the history a sweep drops and
//! keeps it servable, and a replacement installs over a publication's write
//! the state from before it. The mark is per window: an open or a replacement
//! of a marked window waits until every holder has released it and then reads
//! what they wrote, and opens of every other window go through.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use super::types::WindowKey;

#[derive(Default)]
pub(super) struct SweepFence {
    /// Each window held closed, with how many holders hold it.
    closed: Mutex<HashMap<WindowKey, usize>>,
    reopened: Condvar,
}

impl SweepFence {
    /// The map is changed in single steps, so a holder that panicked left it
    /// whole.
    fn closed(&self) -> MutexGuard<'_, HashMap<WindowKey, usize>> {
        self.closed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether any holder holds `key` closed.
    pub(super) fn holds(&self, key: &WindowKey) -> bool {
        self.closed().contains_key(key)
    }

    /// The windows held closed now.
    pub(super) fn keys(&self) -> Vec<WindowKey> {
        self.closed().keys().cloned().collect()
    }

    /// Waits until no holder holds `key` closed.
    pub(super) fn wait_until_open(&self, key: &WindowKey) {
        let closed = self.closed();
        drop(
            self.reopened
                .wait_while(closed, |closed| closed.contains_key(key))
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Holds `key` closed until the returned mark drops, by return or by
    /// unwinding; `None` when another holder holds it closed already.
    pub(super) fn close<'a>(&'a self, key: &'a WindowKey) -> Option<Closed<'a>> {
        let mut closed = self.closed();
        // Lazily: a mark made and dropped would release the holder's.
        if closed.contains_key(key) {
            return None;
        }
        closed.insert(key.clone(), 1);
        Some(Closed { fence: self, key })
    }

    /// Holds `key` closed alongside any holder that holds it already, until
    /// the matching [`Self::release`]. It never waits, so a holder that
    /// rewrites a window inside another holder's rewrite of it joins it.
    pub(super) fn hold(&self, key: &WindowKey) {
        *self.closed().entry(key.clone()).or_default() += 1;
    }

    /// Releases one hold on `key`. The window opens once its last holder
    /// releases it.
    pub(super) fn release(&self, key: &WindowKey) {
        let mut closed = self.closed();
        if let Some(holders) = closed.get_mut(key) {
            *holders = holders.saturating_sub(1);
            if *holders == 0 {
                closed.remove(key);
            }
        }
        drop(closed);
        self.reopened.notify_all();
    }
}

/// A window a sweep holds closed.
pub(super) struct Closed<'a> {
    fence: &'a SweepFence,
    key: &'a WindowKey,
}

impl Drop for Closed<'_> {
    fn drop(&mut self) {
        self.fence.release(self.key);
    }
}
