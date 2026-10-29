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
//!
//! It also flushes a room's side rows marked while no loaded window carried
//! them (FIX 3095): the room or thread root is queued by its own id, or by a
//! TURN whose facts it carries (FIX 3786), and its window alone is opened for
//! them. So is a cold MESSAGE's window, for the quote pins a local write gave
//! it (FIX 3462).

use std::cell::Cell;
use std::collections::{BTreeSet, VecDeque};
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

/// Whether a room or thread root queued by its own id, whose marked side
/// rows no loaded window takes, has its window opened for them (FIX 3095; a
/// call, canon is silent). Only the window of that carrier's learned month
/// opens, never a scan of every month, and the default window count stays.
/// `false` leaves the marks for that window's next open.
const ROOM_FACT_COLD_FLUSH: bool = true;

/// The windows a room fact or quote pin flush opened stay loaded, the most
/// recently used this many of them; the least recently used beyond it
/// unloads, unless another holder still has it. `0` unloads each one right
/// after its flush, as before (FIX 3095, FIX 11601; a call, canon is silent).
const ROOM_FACT_FLUSH_WINDOWS_KEPT: usize = 4;

/// Whether a MESSAGE a local write queued, holding quote pins, has its window
/// opened for them where no loaded window carries it (FIX 3462; a call, canon
/// is silent). Only the window of the message's learned month opens, and it
/// stays loaded as a room fact flush's does
/// ([`ROOM_FACT_FLUSH_WINDOWS_KEPT`]). `false` leaves the pins for that
/// window's next open.
const MESSAGE_PIN_COLD_FLUSH: bool = true;

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
    /// The windows flushes opened and keep loaded, least recently used first.
    flush_kept: Mutex<VecDeque<WindowKey>>,
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
    fn mirror_committed_rows(
        self: &Arc<Self>,
        rows: &BTreeSet<EntityId>,
        edited: &BTreeSet<EntityId>,
    ) {
        // FIX 1794: a committed room turn's door wrote side rows that ride
        // its room's, parent's and thread root's windows as well as its own.
        let carriers = crate::sync::room_facts::committed_carriers(&self.vault, rows);
        self.flush_cold_windows(rows, edited, &carriers);
        for key in self.mirror_keys() {
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
                    self.touch_flush_window(&key);
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
                    &key,
                    &carriers,
                    &[],
                )
            {
                tracing::warn!(window = %key, %error, "room side rows not mirrored into the live window");
            }
        }
    }

    /// The keys of every loaded window and of every window in transition. The
    /// mirror's [`Self::window`] lookup waits for a cold open to register its
    /// window, so a row committed during that open still reaches the doc, and
    /// finds a window an unload removed gone.
    fn mirror_keys(&self) -> Vec<WindowKey> {
        let mut keys = self.loaded_keys();
        for key in self.transition.keys() {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        keys
    }

    /// Opens each window no loaded one is that holds side rows `rows`, just
    /// committed, left out of every loaded window: the window of each of
    /// `carriers` with marked side rows (FIX 3095), each carrier of a TURN
    /// among `edited` marked first (FIX 3786), and the window of each MESSAGE
    /// among `edited` with quote pins (FIX 3462). The open mirrors them and
    /// routes the repair ([`Self::open_window_for_room_fact_flush`]); a window
    /// it opened stays loaded, among [`ROOM_FACT_FLUSH_WINDOWS_KEPT`] most
    /// recently used ([`Self::keep_flush_window`]).
    fn flush_cold_windows(
        self: &Arc<Self>,
        rows: &BTreeSet<EntityId>,
        edited: &BTreeSet<EntityId>,
        carriers: &[(EntityId, u8)],
    ) {
        let loaded = self.loaded_keys();
        let mut keys = Vec::new();
        if ROOM_FACT_COLD_FLUSH {
            crate::sync::room_facts::mark_cold_turn_carriers(&self.vault, edited, &loaded);
            keys =
                crate::sync::room_facts::cold_flush_windows(&self.vault, rows, carriers, &loaded);
        }
        if MESSAGE_PIN_COLD_FLUSH {
            for key in crate::sync::document_pins::cold_pin_windows(&self.vault, edited, &loaded) {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        for key in keys {
            let opened = match self.open_window_for_room_fact_flush(&key) {
                Ok((window, opened)) => {
                    crate::sync::room_facts::clear_turn_marks(&self.vault, &window.doc);
                    opened
                }
                Err(error) => {
                    tracing::warn!(window = %key, %error, "side rows not flushed into their window");
                    continue;
                }
            };
            if opened {
                self.keep_flush_window(&key);
            }
        }
    }

    /// Keeps `key`, just opened for a flush, loaded: most recently used
    /// among [`ROOM_FACT_FLUSH_WINDOWS_KEPT`]; unloads the least recently
    /// used beyond it.
    fn keep_flush_window(&self, key: &WindowKey) {
        let evicted = {
            let mut kept = self
                .live_mirror
                .flush_kept
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(pos) = kept.iter().position(|kept| kept == key) {
                kept.remove(pos);
            }
            kept.push_back(key.clone());
            let over = kept.len().saturating_sub(ROOM_FACT_FLUSH_WINDOWS_KEPT);
            kept.drain(..over).collect::<Vec<_>>()
        };
        for key in evicted {
            if let Err(error) = self.unload_window(&key) {
                tracing::debug!(window = %key, %error, "window opened for a flush stays loaded");
            }
        }
    }

    /// Marks `key` most recently used among the flush-kept windows, if kept.
    fn touch_flush_window(&self, key: &WindowKey) {
        let mut kept = self
            .live_mirror
            .flush_kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(pos) = kept.iter().position(|kept| kept == key) {
            kept.remove(pos);
            kept.push_back(key.clone());
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

    /// Drains `window`'s remat markers once: each row it holds back on a
    /// dependency that may have landed since is tried again (FIX 3820).
    pub(in crate::sync) fn retry_held_rows(&self, window: &WindowKey) -> crate::Result<()> {
        super::super::quarantine::drain_remat_markers_of(
            &self.vault,
            &self.user_id,
            &self.materializer,
            window,
        )?;
        Ok(())
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
