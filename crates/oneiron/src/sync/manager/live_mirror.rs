//! The live mirror: rows a local commit writes reach the window docs this
//! manager has loaded. A cold open mirrors LMDB into a doc once (reverse
//! rematerialization); a write committed after its window loaded has no other
//! road into it, so it would ride no live update until the window next opened.
//! Each commit hands the rows it wrote here, and one thread per manager
//! mirrors them into the loaded windows that hold them. The thread keeps the
//! work off the writer and outside any Loro event: a sync import commits
//! through the same door from inside Observer B. Observer A then ships what
//! changed, live or through the queue.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::time::Duration;

use super::WindowManager;
use crate::Vault;
use crate::entity_id::EntityId;

/// How long the mirror thread waits for rows before it checks that its
/// manager still lives.
const LIVENESS_POLL: Duration = Duration::from_secs(1);

/// Rows committed here and not yet mirrored, and the thread that mirrors them.
#[derive(Default)]
pub(super) struct LiveMirror {
    rows: Mutex<BTreeSet<EntityId>>,
    wake: Condvar,
    started: AtomicBool,
}

impl WindowManager {
    /// Queues `rows`, just committed here, for the loaded windows that hold
    /// them, and starts the mirror thread on first use.
    pub(crate) fn note_committed_rows(self: &Arc<Self>, rows: BTreeSet<EntityId>) {
        if rows.is_empty() {
            return;
        }
        self.live_mirror
            .rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(rows);
        self.live_mirror.wake.notify_one();
        if !self.live_mirror.started.swap(true, Ordering::AcqRel) {
            let mirror = Arc::clone(&self.live_mirror);
            let manager = Arc::downgrade(self);
            if let Err(error) = std::thread::Builder::new()
                .name("oneiron-live-mirror".into())
                .spawn(move || mirror_loop(&mirror, &manager))
            {
                self.live_mirror.started.store(false, Ordering::Release);
                tracing::warn!(%error, "live mirror thread did not start");
            }
        }
    }

    /// Mirrors `rows` into every loaded window that holds them. Best effort:
    /// the rows are durable, and a window that misses them gets them at its
    /// next cold open.
    fn mirror_committed_rows(&self, rows: &BTreeSet<EntityId>) {
        for key in self.loaded_keys() {
            let Some(window) = self.window(&key) else {
                continue;
            };
            match super::super::window::reverse_rematerialize_rows(
                &self.vault,
                &window.doc,
                &key,
                rows,
            ) {
                Ok(0) => {}
                Ok(mirrored) => {
                    tracing::debug!(window = %key, mirrored, "committed rows mirrored into the live window");
                }
                Err(error) => {
                    tracing::warn!(window = %key, %error, "committed rows not mirrored into the live window");
                }
            }
        }
    }
}

/// The mirror thread: takes every row queued so far and mirrors it, holding
/// its manager only while it mirrors; ends once the manager is gone.
fn mirror_loop(mirror: &LiveMirror, manager: &Weak<WindowManager>) {
    loop {
        let rows = {
            let guard = mirror.rows.lock().unwrap_or_else(PoisonError::into_inner);
            let (mut guard, _) = mirror
                .wake
                .wait_timeout_while(guard, LIVENESS_POLL, |rows| rows.is_empty())
                .unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        let Some(manager) = manager.upgrade() else {
            return;
        };
        if !rows.is_empty() {
            manager.mirror_committed_rows(&rows);
        }
    }
}

impl Vault {
    /// Hands `rows`, just committed, to the attached window manager's live
    /// mirror. With no attached manager there is no live window to reach.
    pub(crate) fn note_committed_rows(&self, rows: BTreeSet<EntityId>) {
        if rows.is_empty() {
            return;
        }
        let manager = self
            .live_window_manager
            .lock()
            .ok()
            .and_then(|manager| manager.upgrade());
        if let Some(manager) = manager {
            manager.note_committed_rows(rows);
        }
    }
}
