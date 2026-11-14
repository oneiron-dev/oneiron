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
//! persisted, deregistered and kept closed through its compaction.
//!
//! A window still held at the bound is compacted while its holder keeps it
//! (census L6-05): the pass pins it history-free, so the holder's next
//! persist stores a history-free snapshot rather than the history its doc
//! still holds, and then cuts its persisted rows. A refused late re-put of an
//! erased row owes its window a compaction, which the next pass runs.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! held_window_erasure_drain`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, mpsc};
use std::time::Duration;

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::deletion::LegalHoldTarget;
use oneiron::store::GateDecisionId;
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
    prepare_host_vault(dir, vault)
}

/// [`open_vault`] for an owned vault, whose owner can place a legal hold.
fn open_owned_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_owned(dir.path(), config()).unwrap();
    prepare_host_vault(dir, vault)
}

fn prepare_host_vault(dir: tempfile::TempDir, vault: Vault) -> (tempfile::TempDir, Arc<Vault>) {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().unwrap();
    for key in vault.sync_state_keys_with_prefix("lm:w:1970-01:").unwrap() {
        vault.sync_state_delete(&key).unwrap();
    }
    (dir, Arc::new(vault))
}

/// A registered window over one row with persisted history, and the erasure
/// obligation that row's GDPR delete queued.
struct HeldWindow {
    manager: Arc<WindowManager>,
    window: Arc<LoadedWindow>,
    /// The obligation's queue key.
    sweep_key: Vec<u8>,
    erased: EntityId,
    /// The erased row's bytes as the window carried them.
    erased_blob: Vec<u8>,
}

fn window_with_obligation(vault: &Arc<Vault>) -> HeldWindow {
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
    let erased_blob = match window.doc.get_map("entities").get(&erased.to_hex()) {
        Some(ValueOrContainer::Value(LoroValue::Binary(blob))) => blob.to_vec(),
        _ => panic!("fixture: the window carries the row's bytes"),
    };
    let outcome = vault
        .delete_entity_with_reason(&erased, DeleteReason::GdprDelete)
        .unwrap();
    let sweep_key = outcome
        .sweep_key
        .expect("the delete queues an erasure obligation");
    assert!(
        carries_erased_row(vault, &erased),
        "fixture: the window's stored history still carries the erased row"
    );
    HeldWindow {
        manager,
        window,
        sweep_key,
        erased,
        erased_blob,
    }
}

fn persisted_snapshot(vault: &Vault) -> LoroDoc {
    let snapshot = vault
        .sync_state_get(&format!("d:w:{WINDOW}"))
        .unwrap()
        .expect("the window's persisted snapshot");
    LoroDoc::from_snapshot(&snapshot).unwrap()
}

/// Whether the window's persisted snapshot carries `erased`: live in its
/// entities map, or put there by an operation it keeps.
fn carries_erased_row(vault: &Vault, erased: &EntityId) -> bool {
    let doc = persisted_snapshot(vault);
    let hex = erased.to_hex();
    if doc.get_map("entities").get(&hex).is_some() {
        return true;
    }
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    doc.export_json_updates(&doc.shallow_since_vv().to_vv(), &doc.oplog_vv())
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .any(|op| {
            op.container == entities
                && matches!(
                    &op.content,
                    JsonOpContent::Map(MapOp::Insert { key, .. }) if key.as_str() == hex
                )
        })
}

fn owed_compaction_queued(vault: &Vault) -> bool {
    vault
        .sync_queue_rows_with_prefix(format!("hc:{WINDOW}").as_bytes())
        .unwrap()
        .iter()
        .any(|(key, _)| key.as_slice() == format!("hc:{WINDOW}").as_bytes())
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
    let HeldWindow {
        manager,
        window,
        sweep_key,
        ..
    } = window_with_obligation(&vault);
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

/// A handle held through the whole pass keeps its window, and the pass still
/// compacts it: once the drain bound passes, the window is pinned
/// history-free and its persisted rows are cut while the holder keeps it.
/// The obligation is discharged, the stored window no longer carries the
/// erased row, and the manager hands the holder's window out again at once.
/// On main the pass deferred the held window as live and kept the
/// obligation.
#[test]
fn a_window_held_through_the_pass_is_compacted_and_stays_with_its_holder() {
    let (_dir, vault) = open_vault();
    let HeldWindow {
        manager,
        window,
        sweep_key,
        erased,
        ..
    } = window_with_obligation(&vault);
    let key = WindowKey::new(WINDOW);

    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(
        report.sweep_windows_deferred_live, 0,
        "the held window was deferred as live: {report:?}"
    );
    assert!(report.sweep_windows_compacted >= 1, "{report:?}");
    assert_eq!(report.sweep_jobs_processed, 1, "{report:?}");
    assert!(
        !obligation_queued(&vault, &sweep_key),
        "the erasure obligation is discharged"
    );
    assert!(
        !carries_erased_row(&vault, &erased),
        "the stored window still carries the erased row"
    );

    // The pass left the window with its holder: a lookup returns the same doc.
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
}

/// The holder's doc still holds the erased row's history in memory after
/// the pass. Its next persist stores a history-free snapshot under the pin,
/// so the cut stays a cut. On main the window was neither compacted nor
/// pinned, and the persist stored the whole history.
#[test]
fn a_held_windows_later_persist_brings_no_erased_history_back() {
    let (_dir, vault) = open_vault();
    let HeldWindow { window, erased, .. } = window_with_obligation(&vault);

    vault.maintain().run_hard_erase_sweep().run().unwrap();
    window.persist_state(&vault).unwrap();

    assert!(
        persisted_snapshot(&vault).is_shallow(),
        "the holder's persist stored its full history"
    );
    assert!(
        !carries_erased_row(&vault, &erased),
        "the holder's persist brought the erased row back"
    );
}

/// A re-put of the erased row reaches the window after the pass compacted
/// it, from a peer that never saw the delete. Ingest refuses it, but its
/// insert is now in the window's history: the window owes the sweep a
/// compaction, and the next pass runs it. On main the refusal raised no
/// owed compaction, and the re-put's insert stayed in the window's history.
#[test]
fn a_late_reput_of_an_erased_row_owes_its_window_a_compaction() {
    let (_dir, vault) = open_vault();
    let HeldWindow {
        manager,
        window,
        sweep_key,
        erased,
        erased_blob,
    } = window_with_obligation(&vault);
    let key = WindowKey::new(WINDOW);
    drop(window);
    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(report.sweep_jobs_processed, 1, "{report:?}");
    assert!(!obligation_queued(&vault, &sweep_key));
    assert!(!owed_compaction_queued(&vault), "fixture: nothing owed yet");

    let window = manager.open_window(&key).unwrap();
    let peer = window.doc.fork();
    peer.get_map("entities")
        .insert(&erased.to_hex(), erased_blob)
        .unwrap();
    peer.commit();
    let reput = peer
        .export(ExportMode::updates(&window.doc.oplog_vv()))
        .unwrap();
    window.doc.import(&reput).unwrap();
    window.persist_state(&vault).unwrap();
    assert!(
        owed_compaction_queued(&vault),
        "the refused re-put owes its window no compaction"
    );

    drop(window);
    assert!(manager.unload_window(&key).unwrap());
    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert!(report.sweep_windows_compacted >= 1, "{report:?}");
    assert!(
        !owed_compaction_queued(&vault),
        "the owed compaction is settled"
    );
    assert!(
        !carries_erased_row(&vault, &erased),
        "the stored window still carries the re-put"
    );
}

/// A legal hold on a row the held window carries keeps the window as it is
/// (OF-470): the pass neither pins nor cuts it, so the holder's next persist
/// stores the window's history whole, and the erasure obligation waits for
/// the hold. At cdf9cc5b4fe2 the pass pinned the window before the cut's own
/// hold check refused, and that persist stored a history-free snapshot, which
/// dropped the held row's history as a cut would.
#[test]
fn a_held_window_a_legal_hold_keeps_is_neither_pinned_nor_cut() {
    let (_dir, vault) = open_owned_vault();
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let held = EntityId::now();
    vault
        .batch()
        .put(
            &held,
            1,
            TimeRange {
                start: LEARNED,
                end: LEARNED,
            },
            LEARNED,
            b"held-row-body",
        )
        .commit()
        .unwrap();
    vault
        .place_legal_hold(&owner, vec![LegalHoldTarget::Record(held)], None)
        .unwrap();
    let HeldWindow {
        window, sweep_key, ..
    } = window_with_obligation(&vault);
    assert!(
        window.doc.get_map("entities").get(&held.to_hex()).is_some(),
        "fixture: the window carries the held row"
    );

    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    window.persist_state(&vault).unwrap();

    assert!(
        !persisted_snapshot(&vault).is_shallow(),
        "the held window was pinned or cut: {report:?}"
    );
    assert!(
        obligation_queued(&vault, &sweep_key),
        "the erasure obligation waits for the hold"
    );
}
