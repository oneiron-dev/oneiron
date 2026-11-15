//! A window that sync traffic holds a frame at a time is still compacted by
//! the erasure sweep (census L9-41; ARCH-0038 #housekeeping-sla-open).
//!
//! The sweep may compact a window's history only while no live doc of it
//! exists, since a live doc's next persist would write the history back. A
//! host keeps every window it served registered, and each sync frame takes a
//! handle to it, so the probe found the window registered at every pass and
//! deferred it past the 30-day erasure deadline. The sweep now takes a
//! registered window from its holders first: no new handle is issued, the
//! issued ones have until the drain bound to drop, and the window is then
//! persisted, deregistered and kept closed through its compaction. A window
//! still held at the bound is deferred, as before, and stays its holder's.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! held_window_erasure_drain`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, mpsc};
use std::time::Duration;

use loro::LoroDoc;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::LoadedWindow;
use oneiron::temporal::TimeRange;
use oneiron::{DeleteReason, EntityId, HnswConfig, Vault, VaultConfig};

/// 2026-02-14 00:00 UTC, in [`WINDOW`].
const LEARNED: u64 = 1_771_027_200;
/// The window the erased row lands in.
const WINDOW: &str = "2026-02";

fn config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

/// A vault as a host opens it: an install keystore, so a delete signs its
/// receipt, and no bootstrap-month work in the way of the window.
fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), config()).unwrap();
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().unwrap();
    for key in vault.sync_state_keys_with_prefix("lm:w:1970-01:").unwrap() {
        vault.sync_state_delete(&key).unwrap();
    }
    (dir, Arc::new(vault))
}

/// A registered window over one row with persisted history, and the erasure
/// obligation that row's GDPR delete queued. Returns the manager, the
/// window's handle and the obligation's queue key.
fn window_with_obligation(vault: &Arc<Vault>) -> (Arc<WindowManager>, Arc<LoadedWindow>, Vec<u8>) {
    let erased = EntityId::now();
    vault
        .batch()
        .put(
            &erased,
            1,
            TimeRange {
                start: LEARNED,
                end: LEARNED,
            },
            LEARNED,
            b"erased-row-body",
        )
        .commit()
        .unwrap();
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "held-window-erasure",
    ));
    let window = manager.open_window(&WindowKey::new(WINDOW)).unwrap();
    window.persist_state(vault).unwrap();
    let before = persisted_snapshot(vault);
    assert!(
        !before.is_shallow(),
        "fixture: the window's persisted state carries its history"
    );
    let outcome = vault
        .delete_entity_with_reason(&erased, DeleteReason::GdprDelete)
        .unwrap();
    let sweep_key = outcome
        .sweep_key
        .expect("the delete queues an erasure obligation");
    (manager, window, sweep_key)
}

fn persisted_snapshot(vault: &Vault) -> LoroDoc {
    let snapshot = vault
        .sync_state_get(&format!("d:w:{WINDOW}"))
        .unwrap()
        .expect("the window's persisted snapshot");
    LoroDoc::from_snapshot(&snapshot).unwrap()
}

fn obligation_queued(vault: &Vault, sweep_key: &[u8]) -> bool {
    vault
        .sync_queue_rows_with_prefix(b"h:")
        .unwrap()
        .iter()
        .any(|(key, _)| key.as_slice() == sweep_key)
}

/// One sync frame holds the window as the erasure pass begins and lets it go
/// 300 ms in. The pass waits for it, compacts the window and discharges the
/// obligation; on main the registered window was deferred as live.
#[test]
fn a_window_a_frame_holds_is_compacted_once_the_frame_ends() {
    let (_dir, vault) = open_vault();
    let (manager, window, sweep_key) = window_with_obligation(&vault);
    let key = WindowKey::new(WINDOW);

    let (started_tx, started_rx) = mpsc::channel();
    let frame = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(window);
    });
    started_rx.recv().unwrap();
    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    frame.join().unwrap();

    assert_eq!(
        report.sweep_windows_deferred_live, 0,
        "the window the frame held was deferred as live: {report:?}"
    );
    assert!(report.sweep_windows_compacted >= 1, "{report:?}");
    assert_eq!(report.sweep_jobs_processed, 1, "{report:?}");
    assert!(
        !obligation_queued(&vault, &sweep_key),
        "the erasure obligation is discharged"
    );
    assert!(
        !manager.loaded_keys().contains(&key),
        "the pass unloaded the window before it compacted it"
    );
    assert!(
        persisted_snapshot(&vault).is_shallow(),
        "the window's persisted state is the compacted one"
    );
    // The next caller opens the window again over the compacted state.
    let reopened = manager.open_window(&key).unwrap();
    assert!(manager.loaded_keys().contains(&key));
    drop(reopened);
}

/// A handle held through the whole pass keeps its window: the pass defers
/// it once the drain bound passes, the manager hands the holder's window out
/// again at once, and the holder's later persist lands. Once the holder lets
/// go, the next pass discharges the obligation. The same on main.
#[test]
fn a_window_held_through_the_pass_is_deferred_and_stays_with_its_holder() {
    let (_dir, vault) = open_vault();
    let (manager, window, sweep_key) = window_with_obligation(&vault);
    let key = WindowKey::new(WINDOW);

    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert!(report.sweep_windows_deferred_live >= 1, "{report:?}");
    assert_eq!(report.sweep_jobs_processed, 0, "{report:?}");
    assert!(
        obligation_queued(&vault, &sweep_key),
        "the obligation stays while the window is held"
    );

    // The pass left no mark on the window: a lookup returns the same doc.
    let (lookup_tx, lookup_rx) = mpsc::channel();
    let lookup_manager = Arc::clone(&manager);
    let lookup_key = key.clone();
    std::thread::spawn(move || {
        lookup_tx.send(lookup_manager.window(&lookup_key)).unwrap();
    });
    let again = lookup_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("a lookup of the held window returns after the pass")
        .expect("the held window stays registered");
    assert!(Arc::ptr_eq(&again, &window));
    window.persist_state(&vault).unwrap();
    drop(again);
    drop(window);

    assert!(manager.unload_window(&key).unwrap());
    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(report.sweep_jobs_processed, 1, "{report:?}");
    assert!(!obligation_queued(&vault, &sweep_key));
}
