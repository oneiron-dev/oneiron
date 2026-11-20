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
//! A legal hold keeps a pinned window's history (OF-470): a persist or a
//! tombstone publish that would store a cut stores the window whole while a
//! hold keeps a row its history carries, read in the storing transaction, and
//! owes the sweep a compaction. A re-put that inserts the erased row and
//! deletes it again in one update owes its window a compaction in the
//! transaction that makes it durable (census L6-05 round 1).
//!
//! A replacement installs a peer's history-free snapshot as a new lineage
//! and drops the old window's stored snapshot and updates. While a legal hold
//! keeps a row those carriers hold, it is refused and the old window stays as
//! it was (OF-470, FIX L6-05-REPLACEMENT-OLD-LINEAGE-HOLD).
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! held_window_erasure_drain`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::deletion::{LEGAL_HOLD_REFUSAL, LegalHoldTarget};
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
    owed_compaction_raise(vault).is_some()
}

/// The value of the window's owed-compaction row: each raise writes a fresh
/// id first, so two reads that differ prove a raise between them.
fn owed_compaction_raise(vault: &Vault) -> Option<Vec<u8>> {
    let key = format!("hc:{WINDOW}");
    vault
        .sync_queue_rows_with_prefix(key.as_bytes())
        .unwrap()
        .into_iter()
        .find(|(row, _)| row.as_slice() == key.as_bytes())
        .map(|(_, value)| value)
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
/// The test reads the owe right after the import, before any persist: a
/// window's persist can owe a compaction of its own, so only a fresh raise
/// by the import proves that the refusal owed one.
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
    let raise_before_import = owed_compaction_raise(&vault);
    let peer = window.doc.fork();
    peer.get_map("entities")
        .insert(&erased.to_hex(), erased_blob)
        .unwrap();
    peer.commit();
    let reput = peer
        .export(ExportMode::updates(&window.doc.oplog_vv()))
        .unwrap();
    window.doc.import(&reput).unwrap();
    let raise = owed_compaction_raise(&vault);
    assert!(
        raise.is_some() && raise != raise_before_import,
        "the refused re-put owes its window no compaction"
    );
    window.persist_state(&vault).unwrap();

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

/// The owner of an owned vault, authenticated to place a legal hold.
fn owner_of(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .unwrap()
}

/// Puts `body` as row `id` in [`WINDOW`]; a second put revises it.
fn put_row(vault: &Vault, id: &EntityId, body: &[u8]) {
    vault
        .batch()
        .put(
            id,
            1,
            TimeRange {
                start: LEARNED,
                end: LEARNED,
            },
            LEARNED,
            body,
        )
        .commit()
        .unwrap();
}

/// Every body an operation `doc` keeps put as row `id`.
fn inserted_bodies(doc: &LoroDoc, id: &EntityId) -> Vec<Vec<u8>> {
    let hex = id.to_hex();
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    doc.export_json_updates(&doc.shallow_since_vv().to_vv(), &doc.oplog_vv())
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .filter(|op| op.container == entities)
        .filter_map(|op| match &op.content {
            JsonOpContent::Map(MapOp::Insert {
                key,
                value: LoroValue::Binary(blob),
            }) if key.as_str() == hex => Some(blob.to_vec()),
            _ => None,
        })
        .collect()
}

/// The body row `id` held before its live one, as `doc`'s history keeps it.
fn older_revision(doc: &LoroDoc, id: &EntityId) -> Vec<u8> {
    let live = match doc.get_map("entities").get(&id.to_hex()) {
        Some(ValueOrContainer::Value(LoroValue::Binary(blob))) => blob.to_vec(),
        _ => panic!("fixture: the window carries the row live"),
    };
    inserted_bodies(doc, id)
        .into_iter()
        .find(|body| *body != live)
        .expect("fixture: the window's history keeps the row's older revision")
}

/// A legal hold placed on a row after the pass pinned and cut its window
/// keeps that row's history (OF-470, census L6-05 round 1): the holder's doc
/// still holds the row's older revision, and its next persist stores the
/// window whole, owing the sweep a compaction, rather than the cut the pin
/// asks for. At 9a3a2919e8ea that persist stored the cut, which dropped the
/// held row's older revision.
#[test]
fn a_hold_placed_after_the_pin_keeps_the_held_rows_history_through_its_holders_persist() {
    let (_dir, vault) = open_owned_vault();
    let owner = owner_of(&vault);
    let held = EntityId::now();
    put_row(&vault, &held, b"held-row-first-body");
    put_row(&vault, &held, b"held-row-second-body");
    let HeldWindow { window, .. } = window_with_obligation(&vault);
    let first = older_revision(&window.doc, &held);

    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert!(report.sweep_windows_compacted >= 1, "{report:?}");
    vault
        .place_legal_hold(&owner, vec![LegalHoldTarget::Record(held)], None)
        .unwrap();
    let raise_before_persist = owed_compaction_raise(&vault);
    window.persist_state(&vault).unwrap();

    assert!(
        inserted_bodies(&persisted_snapshot(&vault), &held).contains(&first),
        "the holder's persist dropped the held row's older revision"
    );
    let raise = owed_compaction_raise(&vault);
    assert!(
        raise.is_some() && raise != raise_before_persist,
        "the window stored whole owes the sweep no compaction"
    );
}

/// A hard delete published into a pinned window keeps the window whole while
/// a legal hold keeps a row its history carries (OF-470, census L6-05 round
/// 1), and owes the sweep a compaction. At 9a3a2919e8ea the publish stored
/// the cut at the window's tip, which dropped the held row's older revision.
#[test]
fn a_hard_delete_published_into_a_pinned_window_keeps_a_held_rows_history() {
    let (_dir, vault) = open_owned_vault();
    let owner = owner_of(&vault);
    let held = EntityId::now();
    put_row(&vault, &held, b"held-row-first-body");
    put_row(&vault, &held, b"held-row-second-body");
    let deleted = EntityId::now();
    put_row(&vault, &deleted, b"deleted-row-body");
    let HeldWindow { window, .. } = window_with_obligation(&vault);
    let first = older_revision(&window.doc, &held);
    vault
        .place_legal_hold(&owner, vec![LegalHoldTarget::Record(held)], None)
        .unwrap();
    oneiron::sync::window::require_history_free_window(&vault, &WindowKey::new(WINDOW)).unwrap();

    vault
        .delete_entity_with_reason(&deleted, DeleteReason::GdprDelete)
        .unwrap();

    let stored = persisted_snapshot(&vault);
    assert!(
        stored
            .get_map("tombstones")
            .get(&deleted.to_hex())
            .is_some(),
        "fixture: the delete published into the stored window"
    );
    assert!(
        inserted_bodies(&stored, &held).contains(&first),
        "the publish dropped the held row's older revision"
    );
    assert!(
        owed_compaction_queued(&vault),
        "the window stored whole owes the sweep no compaction"
    );
    drop(window);
}

/// A late re-put that inserts the erased row's body and deletes it again in
/// one update leaves no live value for ingest to refuse, yet the update holds
/// the erased body (census L6-05 round 1). The transaction that makes it
/// durable owes its window a compaction, read before the window imports or
/// persists anything, and the next pass drops the body. At 9a3a2919e8ea the
/// update owed nothing, and its insert stayed in the window's stored history.
#[test]
fn a_history_only_late_reput_owes_its_window_a_compaction_where_it_persists() {
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
    let entities = peer.get_map("entities");
    entities.insert(&erased.to_hex(), erased_blob).unwrap();
    peer.commit();
    entities.delete(&erased.to_hex()).unwrap();
    peer.commit();
    assert!(
        entities.get(&erased.to_hex()).is_none(),
        "fixture: the update leaves the erased row out of the final map"
    );
    let reput = peer
        .export(ExportMode::updates(&window.doc.oplog_vv()))
        .unwrap();
    let inserts = oneiron::sync::window::admit_window_update_residence_with_vault(
        &vault,
        &window.doc,
        &reput,
        &key,
    )
    .unwrap();
    oneiron::sync::server_state::persist_imported_window_update(&vault, &key, &reput, &inserts)
        .unwrap();
    assert!(
        owed_compaction_queued(&vault),
        "the durable re-put owes its window no compaction"
    );

    window.doc.import(&reput).unwrap();
    window.persist_state(&vault).unwrap();
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

/// A window whose stored snapshot keeps row `held`'s older revision in its
/// history, and the history-free snapshot a peer's export door would send
/// for it: the window's state at its newest operation, with no history.
struct ReplacedWindow {
    manager: Arc<WindowManager>,
    key: WindowKey,
    held: EntityId,
    /// `held`'s older revision, which only the stored history keeps.
    first: Vec<u8>,
    snapshot: Vec<u8>,
}

fn window_with_history_free_peer_snapshot(vault: &Arc<Vault>) -> ReplacedWindow {
    let held = EntityId::now();
    put_row(vault, &held, b"held-row-first-body");
    put_row(vault, &held, b"held-row-second-body");
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "replacement-old-lineage-hold",
    ));
    let key = WindowKey::new(WINDOW);
    let window = manager.open_window(&key).unwrap();
    window.persist_state(vault).unwrap();
    let first = older_revision(&persisted_snapshot(vault), &held);
    let snapshot =
        oneiron::sync::window::export_window_replacement(vault, &key, &window.doc.fork(), None)
            .unwrap()
            .expect("fixture: the window ships a replacement");
    assert!(
        !inserted_bodies(&LoroDoc::from_snapshot(&snapshot).unwrap(), &held).contains(&first),
        "fixture: the peer's snapshot carries no history of the held row"
    );
    drop(window);
    ReplacedWindow {
        manager,
        key,
        held,
        first,
        snapshot,
    }
}

/// Every pending update row the window stores, by key.
fn stored_update_keys(vault: &Vault) -> Vec<String> {
    vault
        .sync_state_keys_with_prefix(&format!("u:w:{WINDOW}:"))
        .unwrap()
}

/// A replacement while a legal hold keeps a row the old window's stored
/// history carries is refused, and the window's stored snapshot and updates
/// stay as they were (OF-470, FIX L6-05-REPLACEMENT-OLD-LINEAGE-HOLD): the
/// install would drop every byte of them, the held row's older revision
/// among them, which no row of the peer's lineage keeps. At ae9e64de43c the
/// install stored the peer's history-free snapshot over them.
#[test]
fn a_replacement_is_refused_while_a_hold_keeps_a_row_of_the_old_windows_history() {
    let (_dir, vault) = open_owned_vault();
    let owner = owner_of(&vault);
    let ReplacedWindow {
        manager,
        key,
        held,
        first,
        snapshot,
    } = window_with_history_free_peer_snapshot(&vault);
    vault
        .place_legal_hold(&owner, vec![LegalHoldTarget::Record(held)], None)
        .unwrap();
    let stored = vault
        .sync_state_get(&format!("d:w:{WINDOW}"))
        .unwrap()
        .expect("fixture: the window's stored snapshot");
    let updates = stored_update_keys(&vault);

    let replaced = manager
        .replace_window(&key, &snapshot, &HashMap::new())
        .map(drop);

    assert!(
        inserted_bodies(&persisted_snapshot(&vault), &held).contains(&first),
        "the replacement dropped the held row's older revision: {replaced:?}"
    );
    let refused = replaced.expect_err("the replacement installed under the hold");
    assert!(
        format!("{refused:?}").contains(LEGAL_HOLD_REFUSAL),
        "not the hold's refusal: {refused:?}"
    );
    assert_eq!(
        vault.sync_state_get(&format!("d:w:{WINDOW}")).unwrap(),
        Some(stored),
        "the refused replacement rewrote the stored snapshot"
    );
    assert_eq!(
        stored_update_keys(&vault),
        updates,
        "the refused replacement retired stored updates"
    );
}

/// With no hold, the same replacement installs the peer's history-free
/// lineage: the refusal above is the hold's, not the snapshot's.
#[test]
fn a_replacement_with_no_hold_installs_the_peers_history_free_lineage() {
    let (_dir, vault) = open_owned_vault();
    let ReplacedWindow {
        manager,
        key,
        held,
        first,
        snapshot,
    } = window_with_history_free_peer_snapshot(&vault);

    manager
        .replace_window(&key, &snapshot, &HashMap::new())
        .unwrap();

    assert!(
        !inserted_bodies(&persisted_snapshot(&vault), &held).contains(&first),
        "the installed window still stores the old lineage's history"
    );
}
