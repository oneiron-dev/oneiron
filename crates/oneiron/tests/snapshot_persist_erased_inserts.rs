//! A window snapshot that stores a history-only re-put of a row erased here
//! owes the erasure sweep a compaction of the window
//! (L6-05-SNAPSHOT-PERSIST-ERASED-INSERTS; ARCH-0038
//! `#housekeeping-sla-open`).
//!
//! A peer's update that inserts an erased row's body and deletes it again
//! leaves no live value for ingest to refuse, yet its history holds the body,
//! which only a compaction drops. An update made durable by an append owes
//! that compaction (census L6-05 round 1). One that a client's bulk import or
//! a residence landing imports into the window's doc becomes durable in the
//! next snapshot persist instead, with no append. At f75de13fe4c neither
//! snapshot writer (`LoadedWindow::persist_state`,
//! `server_state::persist_window_snapshot`) read the history it stored, so
//! the body stayed in the window's stored history after the next sweep pass.
//! Each now reads the inserts of the history it stores past the window's
//! last stored snapshot and owes the compaction in the storing transaction.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! snapshot_persist_erased_inserts`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
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

/// A window whose one row the owner erased, the erasure pass already run:
/// the window is compacted and nothing is owed.
struct ErasedWindow {
    manager: Arc<WindowManager>,
    erased: EntityId,
    /// The erased row's bytes as the window carried them.
    erased_blob: Vec<u8>,
}

/// The window persists with the row's insert in its stored history before
/// the erase. The sweep's own persist of the registered window stores that
/// history again past nothing new, so the scan, which reads only the history
/// past the last stored snapshot, owes nothing there: the pass leaves no
/// owed compaction behind.
fn window_after_erasure(vault: &Arc<Vault>) -> ErasedWindow {
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
        "snapshot-persist-erased-inserts",
    ));
    let window = manager.open_window(&WindowKey::new(WINDOW)).unwrap();
    window.persist_state(vault).unwrap();
    let erased_blob = match window.doc.get_map("entities").get(&erased.to_hex()) {
        Some(ValueOrContainer::Value(LoroValue::Binary(blob))) => blob.to_vec(),
        _ => panic!("fixture: the window carries the row's bytes"),
    };
    let sweep_key = vault
        .delete_entity_with_reason(&erased, DeleteReason::GdprDelete)
        .unwrap()
        .sweep_key
        .expect("the delete queues an erasure obligation");
    drop(window);
    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(report.sweep_jobs_processed, 1, "{report:?}");
    assert!(
        !obligation_queued(vault, &sweep_key),
        "fixture: the erasure is discharged"
    );
    assert!(
        !owed_compaction_queued(vault),
        "fixture: nothing owed after the pass"
    );
    assert!(
        !carries_erased_row(vault, &erased),
        "fixture: the pass dropped the erased row's history"
    );
    ErasedWindow {
        manager,
        erased,
        erased_blob,
    }
}

/// A peer's update over `doc` that inserts `blob` under `id` and deletes it
/// again: history only, no live value.
fn history_only_reput(doc: &LoroDoc, id: &EntityId, blob: &[u8]) -> Vec<u8> {
    let peer = doc.fork();
    let entities = peer.get_map("entities");
    entities.insert(&id.to_hex(), blob.to_vec()).unwrap();
    peer.commit();
    entities.delete(&id.to_hex()).unwrap();
    peer.commit();
    assert!(
        entities.get(&id.to_hex()).is_none(),
        "fixture: the update leaves the row out of the final map"
    );
    peer.export(ExportMode::updates(&doc.oplog_vv())).unwrap()
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
    let key = format!("hc:{WINDOW}");
    vault
        .sync_queue_rows_with_prefix(key.as_bytes())
        .unwrap()
        .iter()
        .any(|(row, _)| row.as_slice() == key.as_bytes())
}

fn obligation_queued(vault: &Vault, sweep_key: &[u8]) -> bool {
    vault
        .sync_queue_rows_with_prefix(b"h:")
        .unwrap()
        .iter()
        .any(|(key, _)| key.as_slice() == sweep_key)
}

/// Runs a pass over the closed window and checks it dropped the re-put.
fn sweep_drops_the_reput(vault: &Vault, erased: &EntityId) {
    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert!(report.sweep_windows_compacted >= 1, "{report:?}");
    assert!(
        !owed_compaction_queued(vault),
        "the owed compaction is settled"
    );
    assert!(
        !carries_erased_row(vault, erased),
        "the stored window still carries the re-put"
    );
}

/// A bulk import lands a peer's history-only re-put of the erased row in the
/// live window, which persists whole. The persist owes the window a
/// compaction and the next pass drops the body. At f75de13fe4c the persist
/// owed nothing.
#[test]
fn a_history_only_reput_a_window_persist_stores_owes_its_window_a_compaction() {
    let (_dir, vault) = open_vault();
    let ErasedWindow {
        manager,
        erased,
        erased_blob,
    } = window_after_erasure(&vault);
    let key = WindowKey::new(WINDOW);

    let window = manager.open_window(&key).unwrap();
    let reput = history_only_reput(&window.doc, &erased, &erased_blob);
    window.doc.import(&reput).unwrap();
    assert!(
        !owed_compaction_queued(&vault),
        "fixture: ingest sees no live value and owes nothing"
    );
    window.persist_state(&vault).unwrap();
    assert!(
        carries_erased_row(&vault, &erased),
        "fixture: the stored snapshot's history holds the re-put"
    );
    assert!(
        owed_compaction_queued(&vault),
        "the window persist that stores the re-put owes its window no compaction"
    );

    drop(window);
    assert!(manager.unload_window(&key).unwrap());
    sweep_drops_the_reput(&vault, &erased);
}

/// The same re-put stored by the snapshot writer of a doc no window holds.
/// At f75de13fe4c it owed nothing.
#[test]
fn a_history_only_reput_a_stored_snapshot_holds_owes_its_window_a_compaction() {
    let (_dir, vault) = open_vault();
    let ErasedWindow {
        erased,
        erased_blob,
        ..
    } = window_after_erasure(&vault);
    let key = WindowKey::new(WINDOW);

    let doc = oneiron::sync::window::load_window_from_state(&vault, "peer", &key).unwrap();
    let reput = history_only_reput(&doc, &erased, &erased_blob);
    doc.import(&reput).unwrap();
    oneiron::sync::server_state::persist_window_snapshot(&vault, &key, &doc).unwrap();
    assert!(
        carries_erased_row(&vault, &erased),
        "fixture: the stored snapshot's history holds the re-put"
    );
    assert!(
        owed_compaction_queued(&vault),
        "the stored snapshot holding the re-put owes its window no compaction"
    );

    sweep_drops_the_reput(&vault, &erased);
}

/// Control: a history-only update of a row never erased here owes nothing,
/// in either writer, and a persist with no new history owes nothing either.
#[test]
fn a_snapshot_whose_history_inserts_no_erased_row_owes_nothing() {
    let (_dir, vault) = open_vault();
    let ErasedWindow { manager, .. } = window_after_erasure(&vault);
    let key = WindowKey::new(WINDOW);
    let kept = EntityId::now();

    let window = manager.open_window(&key).unwrap();
    window.persist_state(&vault).unwrap();
    assert!(
        !owed_compaction_queued(&vault),
        "a persist with no new history owes a compaction"
    );
    let reput = history_only_reput(&window.doc, &kept, b"kept-row-body");
    window.doc.import(&reput).unwrap();
    window.persist_state(&vault).unwrap();
    assert!(
        !owed_compaction_queued(&vault),
        "a window persist owes a compaction for a row never erased"
    );
    drop(window);
    assert!(manager.unload_window(&key).unwrap());

    let doc = oneiron::sync::window::load_window_from_state(&vault, "peer", &key).unwrap();
    let reput = history_only_reput(&doc, &kept, b"kept-row-body-again");
    doc.import(&reput).unwrap();
    oneiron::sync::server_state::persist_window_snapshot(&vault, &key, &doc).unwrap();
    assert!(
        !owed_compaction_queued(&vault),
        "a stored snapshot owes a compaction for a row never erased"
    );
}
