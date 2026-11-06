//! The live mirror's drain of policy wakes (fix list row 17203;
//! [`crate::source_audience`] keeps the wakes and the windows each policy
//! rides).
//!
//! Each pass takes the pending wakes from the one after the last policy it
//! took, and a few windows of each, eight in all. A loaded window that took
//! the policy live since its last export is filed first. Each window this
//! vault stores (a snapshot, or pending updates) is opened as a flush opens
//! one and persisted again: the persist refreshes its map to this vault's
//! current word ([`super::refresh_and_scrub`]), and the change commits as a
//! bridge write that Observer A persists and routes to the window's peers. A
//! window opened for the wake unloads again after. A window this vault no
//! longer stores, or whose map no longer carries the policy, leaves the
//! policy's list. The wake goes on from the last window taken and is retired
//! once its last window took it; a window that fails keeps the wake where it
//! was, for the next pass. A newer change of the policy starts its wake
//! over, and an older drain leaves it standing.

use std::cell::Cell;
use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::source_audience::{
    PolicyWake, advance_policy_wake, forget_policy_window, note_policy_windows, policy_wakes,
    policy_windows_after,
};
use crate::sync::WindowManager;
use crate::sync::types::WindowKey;

/// The most pending policy wakes one pass reads; it takes them from the one
/// after the last policy the pass before took, so a wake whose windows keep
/// failing never holds the others back.
const POLICY_WAKES_READ: usize = 256;
/// The most windows one pass persists again for them, all wakes together.
const POLICY_WINDOWS_PER_PASS: usize = 8;

thread_local! {
    /// The last policy the drain on this thread (one manager's mirror
    /// thread) took.
    static LAST_POLICY: Cell<Option<EntityId>> = const { Cell::new(None) };
}

/// What one window's wake found.
enum Woken {
    /// The window took the policy's current word.
    Took,
    /// The window no longer carries the policy, or is not stored here.
    Gone,
}

impl WindowManager {
    /// One pass of the policy wakes: up to [`POLICY_WINDOWS_PER_PASS`]
    /// windows persisted again, across the pending wakes, from the one after
    /// the last policy taken. Best effort: a wake that does not finish stays
    /// for the next pass.
    pub(crate) fn drive_policy_wakes(self: &Arc<Self>) {
        let mut wakes = match policy_wakes(self.vault(), POLICY_WAKES_READ) {
            Ok(wakes) => wakes,
            Err(error) => {
                tracing::warn!(%error, "source audience policy wakes not read");
                return;
            }
        };
        if wakes.is_empty() {
            return;
        }
        // From the one after the last policy taken, round to the start.
        let last = LAST_POLICY.with(Cell::get);
        let start = last.map_or(0, |last| {
            wakes.partition_point(|(policy, _)| *policy <= last)
        });
        let shift = start.min(wakes.len());
        wakes.rotate_left(shift);
        let mut budget = POLICY_WINDOWS_PER_PASS;
        for (policy, wake) in wakes {
            if budget == 0 {
                return;
            }
            LAST_POLICY.with(|cell| cell.set(Some(policy)));
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
        // A loaded window that took the policy live, since its last export
        // or persist, is filed first, as an export files it: one filed with
        // an older revision than this vault's starts the wake over, so a
        // cursor past it never retires the wake without it.
        for key in self.loaded_keys() {
            let carried = self
                .window(&key)
                .and_then(|window| super::carried_revision(&window.doc, policy));
            if let Some(revision) = carried {
                let mut filed = std::collections::BTreeMap::new();
                filed.insert(*policy, revision);
                note_policy_windows(self.vault(), key.as_str(), &filed)?;
            }
        }
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
            // Stored: a snapshot, or pending updates a cold open recovers.
            let txn = self.vault().store.env.read_txn()?;
            let store = &self.vault().store;
            let address = WindowAddress::new(key.as_str());
            let stored = store
                .port_window_doc_with_raw(&txn, address, |_| Ok(()))?
                .is_some()
                || store
                    .port_window_updates(&txn, address, |_, _| ())?
                    .next()
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
