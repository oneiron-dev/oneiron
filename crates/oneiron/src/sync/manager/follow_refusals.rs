//! The followed windows the home refused on the manager-owned connection
//! lane (FOLLOWED-TOMBSTONE-HELD-WINDOW-REFUSED-LIVE). The live client notes
//! each `FOLLOW_REFUSED` here and forgets them as a new connection begins;
//! the residence upkeep, which runs on the manager and a client config alone,
//! asks the home again for each one's tombstone id set, held here or not.

use std::sync::PoisonError;

use super::WindowManager;
use crate::sync::WindowKey;

impl WindowManager {
    /// Notes that the home refused followed window `key` on the live socket.
    pub(in crate::sync) fn note_follow_refused(&self, key: &WindowKey) {
        self.follows_refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone());
    }

    /// Forgets every refusal: a new connection asks each follow again.
    pub(in crate::sync) fn clear_follows_refused(&self) {
        self.follows_refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Whether the home refused followed window `key` on the live socket.
    pub(in crate::sync) fn follow_refused(&self, key: &WindowKey) -> bool {
        self.follows_refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(key)
    }
}
