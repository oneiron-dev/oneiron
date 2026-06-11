//! Production window manager: ARCH-0023b startup orchestration + registry.
//!
//! This is the production entry point for opening window Docs. It enforces
//! the pinned startup ordering invariant (ARCH-0023b, "The ordering
//! invariant on startup"):
//!
//! 1. (per window) load `d:w:{key}` → apply pending `u:w:{key}:*`
//! 2. replay `pm:*` markers (LMDB-ahead torn writes → CRDT)
//! 3. reverse re-materialization (LMDB → CRDT, missing only)
//! 4. forward re-materialization (CRDT → LMDB, byte-compare)
//! 5. register Observer A + B — observers attach LAST
//!
//! Steps pm-replay → reverse remat → forward remat MUST run in this order
//! on the bare doc, BEFORE observers attach. Reversing the order causes
//! data loss: forward remat run first overwrites LMDB-ahead bytes with the
//! stale CRDT copy, and the later pm replay then byte-compares equal and
//! clears the marker without ever mirroring the lost write.
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
use std::sync::{Arc, Mutex, MutexGuard};

use super::bridge::Materializer;
use super::schema::create_window_doc;
use super::types::{SyncConfig, WindowKey};
use super::window::{
    LoadedWindow, forward_rematerialize, load_window_from_state, replay_pending_mirrors,
    reverse_rematerialize,
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
        }
    }

    /// The materializer shared by every window this manager opens.
    pub fn materializer(&self) -> &Arc<Materializer> {
        &self.materializer
    }

    /// Opens (or returns the already-live) window for `key`.
    ///
    /// If the window is registered, returns the existing instance — exactly
    /// one live doc per window key per process. Otherwise runs the pinned
    /// ARCH-0023b startup sequence on a bare doc:
    ///
    /// 1. Load the persisted doc (`d:w:{key}` + pending `u:w:{key}:*`) via
    ///    [`load_window_from_state`], or create a fresh doc when no
    ///    persisted state exists.
    /// 2. Step 3 — [`replay_pending_mirrors`] (`pm:*` crash markers).
    /// 3. Step 4 — [`reverse_rematerialize`] (LMDB → CRDT, missing only).
    /// 4. Step 5 — [`forward_rematerialize`] (CRDT → LMDB).
    /// 5. Step 6 — construct [`LoadedWindow`], attaching Observer A + B
    ///    LAST, and register it.
    ///
    /// The `rm:w:{key}` needs-rematerialization flag (set on Observer B
    /// failure; producer lands in M4-04) is consumed defensively: forward
    /// remat runs unconditionally in this sequence — which subsumes the
    /// forced re-materialization the flag requests — and the marker is
    /// cleared only after it succeeds. Any recovery error aborts the open
    /// with nothing registered and the marker still set (fail-closed).
    pub fn open_window(&self, key: &WindowKey) -> Result<Arc<LoadedWindow>> {
        let mut registry = self.lock_registry();
        if let Some(existing) = registry.get(key) {
            return Ok(Arc::clone(existing));
        }

        // Startup steps 1-2 (per-window slice): persisted snapshot + pending
        // updates, or a fresh bare doc. A fresh doc still goes through full
        // recovery below — LMDB may be ahead of a window that never persisted
        // (first open, or sync_state lost), and reverse remat heals that.
        let doc = match load_window_from_state(&self.vault, &self.user_id, key) {
            Ok(doc) => doc,
            Err(Error::WindowNotFound { .. }) => create_window_doc(&self.user_id, key),
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

        // Steps 3 → 4 → 5 — pinned order, on the bare doc (no observers yet).
        let replayed = replay_pending_mirrors(&self.vault, &doc, key)?;
        let mirrored = reverse_rematerialize(&self.vault, &doc, key)?;
        let materialized = forward_rematerialize(&self.vault, &doc, &self.materializer)?;
        tracing::debug!(
            window = %key,
            replayed,
            mirrored,
            materialized,
            "window-manager: recovery complete (pm replay → reverse remat → forward remat)"
        );

        // Step 5 succeeded — consume the rm: flag. Cleared only here so a
        // failed open leaves it set for the next attempt (fail-closed).
        if rm_flagged {
            self.clear_sync_state_marker(&rm_key)?;
        }

        // Step 6 — observers attach LAST, on the recovered doc.
        let window = Arc::new(LoadedWindow::from_doc(
            doc,
            key.clone(),
            &self.vault,
            &self.materializer,
        ));
        registry.insert(key.clone(), Arc::clone(&window));
        Ok(window)
    }

    /// Opens the default loaded-window set for `now_secs` per the
    /// ARCH-0023b window policy: 2 default windows (current + previous
    /// month); older windows stay ON-DISK in `sync_state` until opened on
    /// demand. Walks back `default_window_count` months, stopping at the
    /// epoch boundary.
    pub fn open_default_windows(&self, now_secs: u64) -> Result<Vec<Arc<LoadedWindow>>> {
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
        self.lock_registry().get(key).map(Arc::clone)
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
    /// retryable) and the error is returned. If a caller still holds an
    /// `Arc` clone, the subscriptions stay live until the last handle
    /// drops; this is logged as a warning because the memory-budget intent
    /// of unloading is defeated until then.
    pub fn unload_window(&self, key: &WindowKey) -> Result<bool> {
        let mut registry = self.lock_registry();
        let Some(window) = registry.get(key) else {
            return Ok(false);
        };
        // Persist BEFORE deregistering, while observers still cover the doc.
        window.persist_state(&self.vault)?;
        let window = registry
            .remove(key)
            .expect("window present under registry lock");
        if Arc::strong_count(&window) > 1 {
            tracing::warn!(
                window = %key,
                "window-manager: unload with outstanding handles — observer subscriptions stay live until the last handle drops"
            );
        }
        drop(window);
        Ok(true)
    }

    /// Acquires the registry lock, recovering from poisoning (mirrors
    /// [`Materializer::lock`]): registry entries are only mutated after a
    /// fully successful open/unload, so a panicked holder cannot leave a
    /// half-registered window behind.
    fn lock_registry(&self) -> MutexGuard<'_, HashMap<WindowKey, Arc<LoadedWindow>>> {
        self.windows.lock().unwrap_or_else(|e| e.into_inner())
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
