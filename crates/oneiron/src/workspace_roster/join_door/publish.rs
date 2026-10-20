//! A join's receipt reaching the live windows of its room or thread once
//! the write that filed or answered it commits (FIX 1794, 3458).

use super::JoinOutcome;
use crate::Vault;

impl JoinOutcome {
    /// Pushes this join's receipt, Ready, held or refused, to the live
    /// windows of its room or thread once the write that filed or answered
    /// it has committed: each join door's own step after its commit, and the
    /// one a raw-transaction owner of [`super::rooms_join_in_txn`] or
    /// [`super::rooms_consent_in_txn`] takes after its own (FIX 3458), whose
    /// write has no postcommit scope to queue the join in. Never before the
    /// commit: a join that rolls back reaches no window. Without sync there
    /// is no live window, and it does nothing.
    pub fn publish_after_commit(&self, vault: &Vault) {
        #[cfg(feature = "sync")]
        vault.refresh_room_rows_in_live_windows(&[self.join_ref.as_str()], &[]);
        #[cfg(not(feature = "sync"))]
        let _ = vault;
    }
}
