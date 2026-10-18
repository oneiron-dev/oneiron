//! The live mirror: rows a local commit writes reach the window docs this
//! manager has loaded. A cold open mirrors LMDB into a doc once (reverse
//! rematerialization); a write committed after its window loaded has no other
//! road into it, so it would ride no live update until the window next opened.
//! Each commit hands the rows it wrote here, and one thread per manager
//! mirrors them into the loaded windows that hold them. The thread keeps the
//! work off the writer and outside any Loro event: a sync import commits
//! through the same door from inside Observer B. Observer A then ships what
//! changed, live or through the queue.
//!
//! A row a local write changed replaces the carrier the doc holds, so an
//! edit reaches peers as well as a new row. A row a sync import wrote
//! (Observer B, forward rematerialization: [`import_scope`]) is mirrored only
//! where the doc lacks it: the doc already holds what the import brought.
//!
//! The same thread retries the setup window's waiting rows once a local
//! embedding space move ends (OF-370): a received binding or retirement that
//! waited on that move lands then, through the window's remat-marker drain.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::time::Duration;

use super::WindowManager;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::sync::types::WindowKey;

/// How long the mirror thread waits for rows before it checks that its
/// manager still lives.
const LIVENESS_POLL: Duration = Duration::from_secs(1);

thread_local! {
    /// Set while this thread writes the rows a sync import brought.
    static IMPORTING: Cell<bool> = const { Cell::new(false) };
}

/// While it lives, the rows this thread commits are a sync import's: the
/// live mirror inserts them where a doc lacks them and never rewrites a
/// carrier with them.
pub(crate) struct ImportScope {
    was: bool,
}

/// Opens an [`ImportScope`] on this thread.
pub(crate) fn import_scope() -> ImportScope {
    ImportScope {
        was: IMPORTING.with(|importing| importing.replace(true)),
    }
}

impl Drop for ImportScope {
    fn drop(&mut self) {
        IMPORTING.with(|importing| importing.set(self.was));
    }
}

/// Rows committed and not yet mirrored: every one, and those a local write
/// changed. `setup_retry` asks for the setup window's waiting rows again.
#[derive(Default)]
struct Pending {
    rows: BTreeSet<EntityId>,
    edited: BTreeSet<EntityId>,
    setup_retry: bool,
}

/// Rows committed here and not yet mirrored, and the thread that mirrors them.
#[derive(Default)]
pub(super) struct LiveMirror {
    pending: Mutex<Pending>,
    wake: Condvar,
    started: AtomicBool,
}

impl WindowManager {
    /// Queues `rows`, just committed here, for the loaded windows that hold
    /// them, and starts the mirror thread on first use. When `edited`, a
    /// local write made them, and their bytes replace the carrier a doc holds.
    pub(crate) fn note_committed_rows(self: &Arc<Self>, rows: BTreeSet<EntityId>, edited: bool) {
        if rows.is_empty() {
            return;
        }
        {
            let mut pending = self
                .live_mirror
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if edited {
                pending.edited.extend(rows.iter().copied());
            }
            pending.rows.extend(rows);
        }
        self.wake_live_mirror();
    }

    /// Asks the mirror thread to retry the EMBEDDING_SETUP rows the setup
    /// window holds back here: a local move ended, so the slot or space they
    /// wait on may be free.
    pub(crate) fn note_setup_retry(self: &Arc<Self>) {
        self.live_mirror
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .setup_retry = true;
        self.wake_live_mirror();
    }

    /// Wakes the mirror thread, and starts it on first use.
    fn wake_live_mirror(self: &Arc<Self>) {
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

    /// Mirrors `rows` into every loaded window that holds them, `edited`
    /// ones over the carrier a doc holds. Best effort: the rows are durable,
    /// and a window that misses them gets them at its next cold open.
    ///
    /// Each window's read of LMDB and write of its doc run under the
    /// materializer lock (taken after the registry lock is released), so no
    /// remote import of the same row lands in LMDB between the two. An import
    /// that reached the doc first, and waits on the lock, finds the mirror's
    /// carrier there and leaves LMDB alone (`carrier_superseded`).
    fn mirror_committed_rows(&self, rows: &BTreeSet<EntityId>, edited: &BTreeSet<EntityId>) {
        // FIX 1794: a committed room turn's door wrote side rows that ride
        // its room's, parent's and thread root's windows as well as its own.
        let carriers = crate::sync::room_facts::committed_carriers(&self.vault, rows);
        for key in self.loaded_keys() {
            let Some(window) = self.window(&key) else {
                continue;
            };
            let _guard = self.materializer.lock();
            match super::super::window::reverse_rematerialize_rows(
                &self.vault,
                &window.doc,
                &key,
                rows,
                edited,
            ) {
                Ok(0) => {}
                Ok(mirrored) => {
                    tracing::debug!(window = %key, mirrored, "committed rows mirrored into the live window");
                }
                Err(error) => {
                    tracing::warn!(window = %key, %error, "committed rows not mirrored into the live window");
                }
            }
            // FIX 853: a MESSAGE row that lands after its document's head
            // finds the head here.
            crate::sync::message_docs::merge_committed_message_docs(
                &self.vault,
                &window.doc,
                &key,
                rows,
            );
            if !carriers.is_empty()
                && key.world().is_none()
                && let Err(error) = crate::sync::room_facts::mirror_carriers(
                    &self.vault,
                    &window.doc,
                    &carriers,
                    &[],
                )
            {
                tracing::warn!(window = %key, %error, "room side rows not mirrored into the live window");
            }
        }
    }

    /// Drains the setup window's remat markers: each waiting row lands now,
    /// or keeps its marker and waits on.
    fn retry_setup_rows(&self) {
        let window = WindowKey::from_timestamp(crate::embed::EMBEDDING_SETUP_LEARNED_AT);
        if let Err(error) = super::super::quarantine::drain_remat_markers_of(
            &self.vault,
            &self.user_id,
            &self.materializer,
            &window,
        ) {
            tracing::warn!(window = %window, %error, "setup rows not retried after a move ended");
        }
    }
}

/// The mirror thread: takes every row queued so far and mirrors it, holding
/// its manager only while it mirrors; ends once the manager is gone.
fn mirror_loop(mirror: &LiveMirror, manager: &Weak<WindowManager>) {
    loop {
        let pending = {
            let guard = mirror
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let (mut guard, _) = mirror
                .wake
                .wait_timeout_while(guard, LIVENESS_POLL, |pending| {
                    pending.rows.is_empty() && !pending.setup_retry
                })
                .unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        let Some(manager) = manager.upgrade() else {
            return;
        };
        if !pending.rows.is_empty() {
            manager.mirror_committed_rows(&pending.rows, &pending.edited);
        }
        if pending.setup_retry {
            manager.retry_setup_rows();
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
            let edited = !IMPORTING.with(Cell::get);
            manager.note_committed_rows(rows, edited);
        }
    }

    /// Hands a setup retry to the attached window manager's mirror thread
    /// ([`WindowManager::note_setup_retry`]). With no attached manager no
    /// window holds a waiting row live.
    pub(crate) fn retry_embedding_setup_rows(&self) {
        let manager = self
            .live_window_manager
            .lock()
            .ok()
            .and_then(|manager| manager.upgrade());
        if let Some(manager) = manager {
            manager.note_setup_retry();
        }
    }
}
