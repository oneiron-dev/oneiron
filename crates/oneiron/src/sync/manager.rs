//! Production window manager: ARCH-0023b startup orchestration + registry.
//!
//! This is the production entry point for opening window Docs. It enforces
//! the pinned startup ordering invariant (ARCH-0023b, "The ordering
//! invariant on startup"):
//!
//! 1. (per window) load `d:w:{key}` → apply pending `u:w:{key}:*`
//! 2. replay `pt:*` pending-tombstone markers (sync-off / crashed deletes)
//! 3. replay `pm:*` markers (LMDB-ahead torn writes → CRDT)
//! 4. reverse re-materialization (LMDB → CRDT, missing only)
//! 5. forward re-materialization (CRDT → LMDB, byte-compare)
//! 6. register Observer A + B — observers attach LAST
//!
//! Steps pt-replay → pm-replay → reverse remat → forward remat MUST run in
//! this order on the bare doc, BEFORE observers attach. Reversing the order
//! causes data loss: forward remat run first overwrites LMDB-ahead bytes
//! with the stale CRDT copy, and the later pm replay then byte-compares
//! equal and clears the marker without ever mirroring the lost write. The
//! pt replay runs FIRST so a recovered tombstone gates every later step —
//! a pm replay run before it would mirror the deleted body's bytes into
//! the doc's op history before the tombstone exists to suppress it.
//!
//! # Registry — exactly one live doc per window key per process
//!
//! The registry maps [`WindowKey`] → [`Arc<LoadedWindow>`]. `open_window`
//! returns clones of the registry-owned `Arc`, so every holder shares the
//! SAME `LoroDoc`; there is no code path that constructs a second live doc
//! for a registered key. This registry is the seam delete routing (M4-10)
//! uses to commit tombstones through the live doc instead of loading a
//! parallel snapshot copy.
//!
//! # Lock semantics
//!
//! - The registry mutex is held across the ENTIRE open (recovery included).
//!   Concurrent opens of the same key serialize; the loser observes the
//!   winner's instance. Opens are rare (startup + on-demand month faults),
//!   so the coarse critical section is deliberate.
//! - Lock order: **registry lock → materializer lock** (open holds the
//!   registry lock while step-5 forward remat takes the materializer lock).
//!   Observer callbacks take ONLY the materializer lock and never the
//!   registry lock, so observer traffic cannot deadlock against
//!   open/unload. Code built on the manager must never acquire the registry
//!   lock while holding the materializer lock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use super::bridge::{Materializer, OutboundSink};
use super::schema::create_window_doc;
use super::types::{SyncConfig, WindowKey};
use super::window::{
    LoadedWindow, apply_pending_window_updates, forward_rematerialize, load_window_from_state,
    replay_pending_mirrors, replay_pending_tombstones, reverse_rematerialize,
};
use crate::Vault;
use crate::error::{Error, Result};

/// Production registry + recovery orchestrator for window Docs.
///
/// See the module docs for the pinned startup order and lock semantics.
pub struct WindowManager {
    vault: Arc<Vault>,
    materializer: Arc<Materializer>,
    user_id: String,
    config: SyncConfig,
    /// Live windows, keyed by `WindowKey`. Guarded by a poison-recovering
    /// mutex; entries are inserted only after a fully successful open, so a
    /// panicked holder cannot leave a half-recovered window registered.
    windows: Mutex<HashMap<WindowKey, Arc<LoadedWindow>>>,
    /// Weak handles for every window doc issued by this manager. Unlike the
    /// live registry, this survives `discard_window` deregistration so the
    /// sweep can still observe an orphaned external `Arc<LoadedWindow>` that
    /// could persist a full-history snapshot later.
    issued_handles: Mutex<HashMap<WindowKey, Vec<Weak<LoadedWindow>>>>,
    /// Shared Observer A outbound sink: every window this manager opens
    /// routes its persisted local updates here (connection channel when
    /// attached, durable `SyncQueue` otherwise).
    outbound: Arc<OutboundSink>,
}

impl WindowManager {
    /// Creates a manager with the default [`SyncConfig`] (2 default loaded
    /// windows: current + previous month).
    pub fn new(
        vault: Arc<Vault>,
        materializer: Arc<Materializer>,
        user_id: impl Into<String>,
    ) -> Self {
        Self::with_config(vault, materializer, user_id, SyncConfig::default())
    }

    /// Creates a manager with an explicit [`SyncConfig`].
    pub fn with_config(
        vault: Arc<Vault>,
        materializer: Arc<Materializer>,
        user_id: impl Into<String>,
        config: SyncConfig,
    ) -> Self {
        Self {
            vault,
            materializer,
            user_id: user_id.into(),
            config,
            windows: Mutex::new(HashMap::new()),
            issued_handles: Mutex::new(HashMap::new()),
            outbound: Arc::new(OutboundSink::new()),
        }
    }

    /// The materializer shared by every window this manager opens.
    pub fn materializer(&self) -> &Arc<Materializer> {
        &self.materializer
    }

    /// The vault every window this manager opens shares.
    pub fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    /// The Observer A outbound sink shared by every window this manager
    /// opens. The sync connection attaches its local-update channel here;
    /// detached, updates fall back to the durable `SyncQueue`.
    pub fn outbound(&self) -> &Arc<OutboundSink> {
        &self.outbound
    }

    /// Registers this manager as the vault's live-window delete router
    /// (M4-10 / ONE-1135): `Vault::delete_entity*` then commits CRDT
    /// tombstones through the registry-owned live doc for OPEN windows —
    /// Observer A persists the `u:` row and the commit reaches every
    /// registry holder — instead of writing a parallel transient snapshot
    /// the live doc never sees (the `d:w:` clobber vector).
    ///
    /// The vault side holds a `Weak`, so a dropped manager degrades cleanly
    /// to the transient (import-merge) delete path.
    ///
    /// [`open_window`](Self::open_window) calls this itself, so ANY
    /// composition that opens a window through the manager activates the
    /// delete router — the wiring cannot be forgotten (ONE-1135 review
    /// blocker). Calling it explicitly before the first open remains valid
    /// (and is required only if deletes can race the first open). The
    /// attach is idempotent: re-attaching the same manager just overwrites
    /// the vault's `Weak` with an equivalent one. A process composing TWO
    /// managers over one vault is unsupported — the last attach wins.
    pub fn attach_to_vault(self: &Arc<Self>) {
        self.vault.attach_live_window_manager(Arc::downgrade(self));
    }

    /// Opens (or returns the already-live) window for `key`.
    ///
    /// First self-attaches as the vault's live-window delete router
    /// ([`attach_to_vault`](Self::attach_to_vault), idempotent) — the
    /// production composition activates ONE-1135 delete routing simply by
    /// opening windows; no separate wiring call exists to forget.
    ///
    /// If the window is registered, returns the existing instance — exactly
    /// one live doc per window key per process. Otherwise runs the pinned
    /// ARCH-0023b startup sequence on a bare doc:
    ///
    /// 1. Load the persisted doc (`d:w:{key}` + pending `u:w:{key}:*`) via
    ///    [`load_window_from_state`], or create a fresh doc when no
    ///    persisted state exists.
    /// 2. Step 2 — [`replay_pending_tombstones`] (`pt:*` markers: deletes
    ///    from sync-off builds or a crash between the purge txn and the
    ///    CRDT commit; OWNER-DECISION 4 cfg-off durability). Runs BEFORE
    ///    the pm replay so a recovered tombstone suppresses any pending
    ///    mirror of the same entity — the reverse order would mirror the
    ///    deleted body into the doc's op history first.
    /// 3. Step 3 — [`replay_pending_mirrors`] (`pm:*` crash markers).
    /// 4. Step 4 — [`reverse_rematerialize`] (LMDB → CRDT, missing only).
    /// 5. Step 5 — [`forward_rematerialize`] (CRDT → LMDB).
    /// 6. Step 6 — construct [`LoadedWindow`], attaching Observer A + B
    ///    LAST, and register it.
    ///
    /// The `rm:w:{key}` needs-rematerialization flag (set on Observer B
    /// failure; producer lands in M4-04) is consumed defensively: forward
    /// remat runs unconditionally in this sequence — which subsumes the
    /// forced re-materialization the flag requests — and the marker is
    /// cleared only after it succeeds. Any recovery error aborts the open
    /// with nothing registered and the marker still set (fail-closed).
    pub fn open_window(self: &Arc<Self>, key: &WindowKey) -> Result<Arc<LoadedWindow>> {
        // ONE-1135 production wiring: every open (re-)attaches this manager
        // as the vault's delete router. Idempotent; takes only the vault's
        // attach mutex, never the registry lock.
        self.attach_to_vault();
        let mut registry = self.lock_registry();
        if let Some(existing) = registry.get(key) {
            let existing = Arc::clone(existing);
            #[cfg(test)]
            test_hooks::maybe_pause_handle_issue();
            self.track_issued_handle(key, &existing);
            drop(registry);
            return Ok(existing);
        }

        // Startup steps 1-2 (per-window slice): persisted snapshot + pending
        // updates, or a fresh bare doc. A fresh doc still goes through full
        // recovery below — LMDB may be ahead of a window that never persisted
        // (first open, or sync_state lost), and reverse remat heals that.
        let doc = match load_window_from_state(&self.vault, &self.user_id, key) {
            Ok(doc) => doc,
            Err(Error::WindowNotFound { .. }) => {
                // No d:w: snapshot — but pending u:w: rows can still exist
                // (remote updates persisted before this window was ever
                // unloaded). They MUST replay onto the fresh doc or accepted
                // sync data is lost on restart: tombstones especially, whose
                // LMDB purge already ran and which reverse remat can never
                // reconstruct (ONE-1126).
                let doc = create_window_doc(&self.user_id, key);
                apply_pending_window_updates(&self.vault, &doc, key)?;
                doc
            }
            Err(err) => return Err(err),
        };

        let rm_key = format!("rm:w:{key}");
        let rm_flagged = self.sync_state_marker_present(&rm_key)?;
        if rm_flagged {
            tracing::info!(
                window = %key,
                "window-manager: rm: flag set — forward re-materialization forced for this window"
            );
        }

        // Steps 2 → 3 → 4 → 5 — pinned order, on the bare doc (no observers
        // yet). pt: replay runs FIRST so its tombstones gate the pm replay,
        // reverse remat, and forward remat of the same entities; it also
        // queues the recovered delete as a delete-bearing `q:` row, closing
        // the "delete while sync off → enable sync → tombstone never
        // published" hole (ONE-1135 review blocker, OWNER-DECISION 4).
        let pending_tombstones = replay_pending_tombstones(&self.vault, &doc, key)?;
        let replayed = replay_pending_mirrors(&self.vault, &doc, key)?;
        let mirrored = reverse_rematerialize(&self.vault, &doc, key)?;
        let materialized = forward_rematerialize(&self.vault, &doc, &self.materializer, key)?;
        tracing::debug!(
            window = %key,
            pending_tombstones,
            replayed,
            mirrored,
            materialized,
            "window-manager: recovery complete (pt replay → pm replay → reverse remat → forward remat)"
        );

        // Step 5 succeeded — consume the rm: flag. Cleared only here so a
        // failed open leaves it set for the next attempt (fail-closed).
        if rm_flagged {
            self.clear_sync_state_marker(&rm_key)?;
        }

        // Step 6 — observers attach LAST, on the recovered doc.
        let window = Arc::new(LoadedWindow::from_doc_with_outbound(
            doc,
            key.clone(),
            &self.vault,
            &self.materializer,
            Some(Arc::clone(&self.outbound)),
        ));
        registry.insert(key.clone(), Arc::clone(&window));
        #[cfg(test)]
        test_hooks::maybe_pause_handle_issue();
        self.track_issued_handle(key, &window);
        drop(registry);
        Ok(window)
    }

    /// Opens the default loaded-window set for `now_secs` per the
    /// ARCH-0023b window policy: 2 default windows (current + previous
    /// month); older windows stay ON-DISK in `sync_state` until opened on
    /// demand. Walks back `default_window_count` months, stopping at the
    /// epoch boundary.
    pub fn open_default_windows(self: &Arc<Self>, now_secs: u64) -> Result<Vec<Arc<LoadedWindow>>> {
        let mut opened = Vec::new();
        let mut next = Some(WindowKey::from_timestamp(now_secs));
        for _ in 0..self.config.default_window_count {
            let Some(key) = next else { break };
            opened.push(self.open_window(&key)?);
            next = key.previous_month();
        }
        Ok(opened)
    }

    /// Returns the live window for `key` if loaded — registry lookup only,
    /// never opens. This is the lookup seam M4-10 delete routing uses to
    /// commit tombstones through the live doc when the window is loaded.
    pub fn window(&self, key: &WindowKey) -> Option<Arc<LoadedWindow>> {
        let registry = self.lock_registry();
        let window = registry.get(key).map(Arc::clone)?;
        #[cfg(test)]
        test_hooks::maybe_pause_handle_issue();
        self.track_issued_handle(key, &window);
        drop(registry);
        Some(window)
    }

    /// Sweep live-window probe (ONE-1162): fail closed if this manager cannot
    /// prove `key` has no registered doc and no orphaned external handle.
    ///
    /// `discard_window` can remove the registry entry while caller-held
    /// `Arc<LoadedWindow>` clones keep the doc and observers alive. Those
    /// retained handles can still call `persist_state`, so the sweep must
    /// treat them exactly like a registered live window and defer compaction.
    pub(crate) fn window_live_for_sweep(&self, key: &WindowKey) -> bool {
        let registry = match self.windows.lock() {
            Ok(registry) => registry,
            Err(_) => return true,
        };
        if registry.contains_key(key) {
            return true;
        }
        drop(registry);

        let mut issued = match self.issued_handles.lock() {
            Ok(issued) => issued,
            Err(_) => return true,
        };
        Self::prune_issued_handles_locked(&mut issued, key)
    }

    /// Returns the keys of all currently loaded windows.
    pub fn loaded_keys(&self) -> Vec<WindowKey> {
        self.lock_registry().keys().cloned().collect()
    }

    /// Unloads the window for `key`: persists its Doc state to `sync_state`
    /// ([`LoadedWindow::persist_state`]), then deregisters it so the
    /// observer `Subscription` handles drop with the `LoadedWindow`.
    ///
    /// Returns `Ok(false)` if the window is not loaded. If the persist
    /// fails, the window STAYS registered and observed (fail-closed,
    /// retryable) and the error is returned.
    ///
    /// # Refusal with outstanding handles (ONE-1150)
    ///
    /// If a caller still holds an `Arc<LoadedWindow>` clone, the unload is
    /// REFUSED with [`Error::WindowBusy`] and has no effect: nothing is
    /// persisted, the window stays registered and discoverable via
    /// [`window`](Self::window), and its observers stay attached. The
    /// alternative — deregister-while-held, the pre-ONE-1150 behavior —
    /// is the second-live-doc trap: the next `open_window` would build a
    /// NEW doc for the key while the outstanding handle keeps writing to
    /// the orphaned one, whose commits bypass the manager's delete routing
    /// (the `window()` lookup no longer finds it), so deletes take the
    /// transient path while the orphaned doc still carries the deleted
    /// body. The refusal is graceful: the caller retries after the last
    /// external handle drops. Contrast `discard_window`,
    /// the FORCED eviction that deregisters even
    /// with outstanding holders because its doc state is known-stale.
    ///
    /// The check runs under the registry lock and counts only EXTERNAL
    /// holders (the registry's own `Arc` is excluded). When it passes, no
    /// external handle exists and none can appear before deregistration:
    /// minting a new handle requires `open_window`/`window`, which both
    /// need the registry lock this method holds.
    pub fn unload_window(&self, key: &WindowKey) -> Result<bool> {
        let mut registry = self.lock_registry();
        let Some(window) = registry.get(key) else {
            return Ok(false);
        };
        // ONE-1150 fail-closed guard: refuse BEFORE any side effect (no
        // persist, no deregister) so a refused unload is a pure no-op the
        // caller can poll. strong_count includes the registry's own Arc.
        let outstanding_handles = Arc::strong_count(window) - 1;
        if outstanding_handles > 0 {
            return Err(Error::WindowBusy {
                window_key: key.to_string(),
                outstanding_handles,
            });
        }
        // Persist BEFORE deregistering, while observers still cover the doc.
        window.persist_state(&self.vault)?;
        let window = registry
            .remove(key)
            .expect("window present under registry lock");
        drop(window);
        drop(registry);
        self.prune_issued_handles_for_key(key);
        Ok(true)
    }

    /// Discards the live window for `key` WITHOUT persisting its doc state
    /// — the fail-closed eviction for import-before-persist recovery
    /// (client analog of the server's evict-on-persist-failure, ONE-1129):
    /// when a remote import was applied to the live doc but its `u:w:` row
    /// could not be persisted, the doc's RAM state is AHEAD of durable
    /// state, and persisting it (as [`unload_window`](Self::unload_window)
    /// would) would durably commit the unconfirmed import. Dropping the
    /// registry entry instead lets the next open reload from durable state
    /// (`d:w:` + persisted `u:w:` rows); the failed update is absent from
    /// that doc's version vector, so the server re-sends it on the next VV
    /// exchange.
    ///
    /// Returns `false` if the window is not loaded.
    ///
    /// # Forced eviction vs graceful unload (ONE-1150)
    ///
    /// Unlike [`unload_window`](Self::unload_window) — which REFUSES with
    /// [`Error::WindowBusy`] while external `Arc` holders exist — discard
    /// deregisters UNCONDITIONALLY, outstanding holders or not, and that is
    /// deliberate: this path runs precisely when the doc's RAM state is
    /// WRONG (ahead of durable state), so keeping the stale doc registered
    /// until holders drop would keep serving it through `window()` —
    /// including to delete routing. Outstanding holders keep the stale doc
    /// (and its observer subscriptions) alive until they drop; this is
    /// logged because their writes are orphaned by design.
    pub fn discard_window(&self, key: &WindowKey) -> bool {
        let mut registry = self.lock_registry();
        let Some(window) = registry.remove(key) else {
            return false;
        };
        if Arc::strong_count(&window) > 1 {
            tracing::warn!(
                window = %key,
                "window-manager: discard with outstanding handles — the stale doc stays live until the last handle drops"
            );
        }
        drop(window);
        drop(registry);
        self.prune_issued_handles_for_key(key);
        true
    }

    /// Acquires the registry lock, recovering from poisoning (mirrors
    /// [`Materializer::lock`]): registry entries are only mutated after a
    /// fully successful open/unload, so a panicked holder cannot leave a
    /// half-registered window behind.
    fn lock_registry(&self) -> MutexGuard<'_, HashMap<WindowKey, Arc<LoadedWindow>>> {
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn track_issued_handle(&self, key: &WindowKey, window: &Arc<LoadedWindow>) {
        let weak = Arc::downgrade(window);
        let mut issued = self
            .issued_handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let handles = issued.entry(key.clone()).or_default();
        handles.retain(|handle| handle.strong_count() > 0);
        if !handles.iter().any(|handle| handle.ptr_eq(&weak)) {
            handles.push(weak);
        }
    }

    fn prune_issued_handles_for_key(&self, key: &WindowKey) -> bool {
        let mut issued = self
            .issued_handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::prune_issued_handles_locked(&mut issued, key)
    }

    fn prune_issued_handles_locked(
        issued: &mut HashMap<WindowKey, Vec<Weak<LoadedWindow>>>,
        key: &WindowKey,
    ) -> bool {
        let Some(handles) = issued.get_mut(key) else {
            return false;
        };
        handles.retain(|handle| handle.strong_count() > 0);
        let retained = !handles.is_empty();
        if !retained {
            issued.remove(key);
        }
        retained
    }

    /// Returns whether a 1-byte marker key is present in `sync_state`.
    fn sync_state_marker_present(&self, key: &str) -> Result<bool> {
        let rtxn = self.vault.store.env.read_txn()?;
        Ok(self.vault.store.sync_state.get(&rtxn, key)?.is_some())
    }

    /// Deletes a marker key from `sync_state`.
    fn clear_sync_state_marker(&self, key: &str) -> Result<()> {
        self.vault.with_write_txn(|wtxn| {
            self.vault.store.sync_state.delete(wtxn, key)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod test_hooks {
    use std::sync::{Arc, Condvar, Mutex};

    static HANDLE_ISSUE_PAUSE: Mutex<Option<Arc<HandleIssuePause>>> = Mutex::new(None);

    pub(super) struct HandleIssuePause {
        state: Mutex<PauseState>,
        cv: Condvar,
    }

    struct PauseState {
        reached: bool,
        release: bool,
    }

    impl HandleIssuePause {
        pub(super) fn new() -> Self {
            Self {
                state: Mutex::new(PauseState {
                    reached: false,
                    release: false,
                }),
                cv: Condvar::new(),
            }
        }

        pub(super) fn wait_until_reached(&self) {
            let mut state = self.state.lock().unwrap();
            while !state.reached {
                state = self.cv.wait(state).unwrap();
            }
        }

        pub(super) fn release(&self) {
            let mut state = self.state.lock().unwrap();
            state.release = true;
            self.cv.notify_all();
        }

        fn pause(&self) {
            let mut state = self.state.lock().unwrap();
            state.reached = true;
            self.cv.notify_all();
            while !state.release {
                state = self.cv.wait(state).unwrap();
            }
        }
    }

    pub(super) fn arm_handle_issue_pause(pause: Arc<HandleIssuePause>) {
        *HANDLE_ISSUE_PAUSE.lock().unwrap() = Some(pause);
    }

    pub(super) fn maybe_pause_handle_issue() {
        let pause = HANDLE_ISSUE_PAUSE.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.pause();
        }
    }
}

#[cfg(test)]
mod tests;
