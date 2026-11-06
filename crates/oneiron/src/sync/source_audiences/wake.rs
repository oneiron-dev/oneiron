//! The live mirror's drain of policy wakes (fix list row 17203;
//! [`crate::source_audience`] keeps the wakes and the windows each policy
//! rides).
//!
//! Each pass takes a few pending wakes and a few of each one's windows. A
//! window this vault stores is opened as a flush opens one, and persisted
//! again: the persist refreshes its map to this vault's current word
//! ([`super::refresh_and_scrub`]), and the change commits as a bridge write
//! that Observer A persists and routes to the window's peers, cold window
//! or loaded. A window opened for the wake unloads again after. A window
//! this vault no longer stores, or whose map no longer carries the policy,
//! leaves the policy's list. The wake goes on from the last window taken,
//! and is retired once its last window took it; a window that fails keeps
//! the wake where it was, for the next pass. A newer change of the policy
//! starts its wake over, and an older drain leaves it standing.

use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::source_audience::{
    PolicyWake, advance_policy_wake, forget_policy_window, policy_wakes, policy_windows_after,
};
use crate::sync::WindowManager;
use crate::sync::types::WindowKey;

/// The most policy wakes one pass takes.
const POLICY_WAKES_PER_PASS: usize = 16;
/// The most windows one pass persists again for them, all wakes together.
const POLICY_WINDOWS_PER_PASS: usize = 8;

/// What one window's wake found.
enum Woken {
    /// The window took the policy's current word.
    Took,
    /// The window no longer carries the policy, or is not stored here.
    Gone,
}

impl WindowManager {
    /// One pass of the policy wakes: up to [`POLICY_WINDOWS_PER_PASS`]
    /// windows persisted again, across up to [`POLICY_WAKES_PER_PASS`]
    /// wakes. Best effort: a wake that does not finish stays for the next
    /// pass.
    pub(crate) fn drive_policy_wakes(self: &Arc<Self>) {
        let wakes = match policy_wakes(self.vault(), POLICY_WAKES_PER_PASS) {
            Ok(wakes) => wakes,
            Err(error) => {
                tracing::warn!(%error, "source audience policy wakes not read");
                return;
            }
        };
        let mut budget = POLICY_WINDOWS_PER_PASS;
        for (policy, wake) in wakes {
            if budget == 0 {
                return;
            }
            if let Err(error) = self.drive_policy_wake(&policy, &wake, &mut budget) {
                tracing::warn!(%error, "a source audience policy wake did not advance");
            }
        }
    }

    /// Takes up to `budget` more windows of `policy`'s `wake`, and records
    /// how far it went.
    fn drive_policy_wake(
        self: &Arc<Self>,
        policy: &EntityId,
        wake: &PolicyWake,
        budget: &mut usize,
    ) -> Result<()> {
        let windows = policy_windows_after(self.vault(), policy, wake, *budget)?;
        let complete = windows.len() < *budget;
        let mut last = None;
        for (hash, label) in windows {
            *budget -= 1;
            let woken = match WindowKey::try_new(label) {
                Some(key) => match self.wake_window(&key, policy) {
                    Ok(woken) => woken,
                    Err(error) => {
                        tracing::warn!(window = %key, %error, "a window did not take its policy wake");
                        if let Some(last) = last {
                            advance_policy_wake(self.vault(), policy, wake, Some(last))?;
                        }
                        return Ok(());
                    }
                },
                None => Woken::Gone,
            };
            if matches!(woken, Woken::Gone) {
                forget_policy_window(self.vault(), policy, hash)?;
            }
            last = Some(hash);
        }
        if complete {
            advance_policy_wake(self.vault(), policy, wake, None)
        } else {
            match last {
                Some(last) => advance_policy_wake(self.vault(), policy, wake, Some(last)),
                None => Ok(()),
            }
        }
    }

    /// Persists the window `key` again, loaded or cold, so its map takes
    /// this vault's current word of `policy` and routes it.
    fn wake_window(self: &Arc<Self>, key: &WindowKey, policy: &EntityId) -> Result<Woken> {
        if !self.loaded_keys().contains(key) {
            let txn = self.vault().store.env.read_txn()?;
            let stored = self
                .vault()
                .store
                .port_window_doc_with_raw(&txn, WindowAddress::new(key.as_str()), |_| Ok(()))?
                .is_some();
            if !stored {
                return Ok(Woken::Gone);
            }
        }
        let (window, opened) = self.open_window_for_room_fact_flush(key)?;
        let persisted = window.persist_state(self.vault());
        let carries = super::carries_policy(&window.doc, policy);
        drop(window);
        if opened && let Err(error) = self.unload_window(key) {
            tracing::debug!(window = %key, %error, "a window opened for a policy wake stays loaded");
        }
        persisted?;
        Ok(if carries { Woken::Took } else { Woken::Gone })
    }
}
