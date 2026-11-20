//! An entity document a live editor holds is compacted by the erasure sweep,
//! and an edge re-put naming an erased row owes its window a compaction
//! (HELD-ENTITY-DOCUMENT-DEFERRED; ARCH-0038 #housekeeping-sla-open).
//!
//! The sweep compacts every persisted document slot on each erasure pass. A
//! slot whose document was resident was skipped as live, and one such skip
//! left the whole pass deferred, so one open editor anywhere in the vault held
//! back every erasure obligation until it closed. A resident document holds no
//! Loro copy, and each of its writers reads the durable text in its own
//! transaction, so the pass now compacts it under its writer lock; its editor
//! reads the same text at the same version afterwards.
//!
//! The sweep drops an edge with an erased end as residue, but only an insert
//! into the entities map owed the compaction that takes a late re-put out of a
//! window's history (census L6-05): an edge re-put naming an erased row, live
//! or history-only, stayed in the stored window until some other erasure
//! compacted it. Both ends of an edge insert now count as rows it inserts.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! held_entity_document_erasure`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::LoadedWindow;
use oneiron::temporal::TimeRange;
use oneiron::{
    DeleteReason, EdgeActorClass, EdgeKind, EntityId, HnswConfig, Vault, VaultConfig, WriteActor,
};

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

fn put_turn(vault: &Vault, id: &EntityId, body: &[u8]) {
    vault
        .put_entity(
            id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: LEARNED,
                end: LEARNED,
            },
            LEARNED,
            body,
        )
        .unwrap();
}

/// A window over a kept row and a row the owner erased, the erasure pass
/// already run: the erased row's obligation is discharged and nothing is owed.
struct ErasedWindow {
    manager: Arc<WindowManager>,
    kept: EntityId,
    erased: EntityId,
}

fn window_after_erasure(vault: &Arc<Vault>) -> ErasedWindow {
    let kept = EntityId::now();
    let erased = EntityId::now();
    put_turn(vault, &kept, b"kept-row-body");
    put_turn(vault, &erased, b"erased-row-body");
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "held-entity-document-erasure",
    ));
    let window = manager.open_window(&WindowKey::new(WINDOW)).unwrap();
    window.persist_state(vault).unwrap();
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
        owed_compaction_raise(vault).is_none(),
        "fixture: nothing owed yet"
    );
    ErasedWindow {
        manager,
        kept,
        erased,
    }
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

/// A peer's update over `window` that puts an edge from `kept` to `erased`,
/// and with `then_removed` takes it out again, so only its history holds it.
fn edge_reput(
    window: &LoadedWindow,
    kept: &EntityId,
    erased: &EntityId,
    then_removed: bool,
) -> Vec<u8> {
    let peer: LoroDoc = window.doc.fork();
    let edges = peer.get_map("edges");
    let key = format_edge_key(kept, EdgeKind::Mentions, erased);
    let value = encode_edge_value_for_crdt(EdgeKind::Mentions, 1.0, LEARNED, None, None).unwrap();
    edges.insert(&key, value).unwrap();
    peer.commit();
    if then_removed {
        edges.delete(&key).unwrap();
        peer.commit();
        assert!(
            edges.get(&key).is_none(),
            "fixture: the update leaves the edge out of the final map"
        );
    }
    peer.export(ExportMode::updates(&window.doc.oplog_vv()))
        .unwrap()
}

/// An owner keeps a turn's text open in an editor while erasing another row.
/// The pass compacts the open document under its writer lock, defers nothing,
/// and discharges the erasure; the editor reads the same text at the same
/// version. On main the open document was skipped as live and the pass was
/// left deferred, so the erasure obligation stayed queued.
#[test]
fn an_open_editor_holds_back_no_erasure_and_its_document_is_compacted() {
    let (_dir, vault) = open_vault();
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "held-entity-document-erasure",
    ));
    let open = EntityId::now();
    put_turn(&vault, &open, b"ledger pointer");
    let author = EntityId::now();
    put_turn(&vault, &author, b"author");
    let document = manager.documents().open(open).unwrap();
    document
        .edit_text(
            WriteActor::new(author, EdgeActorClass::Human),
            LEARNED,
            0,
            0,
            "kept text",
        )
        .unwrap();
    let version = document.version_vector().unwrap();

    let erased = EntityId::now();
    put_turn(&vault, &erased, b"erased-row-body");
    let window = manager.open_window(&WindowKey::new(WINDOW)).unwrap();
    window.persist_state(&vault).unwrap();
    let sweep_key = vault
        .delete_entity_with_reason(&erased, DeleteReason::GdprDelete)
        .unwrap()
        .sweep_key
        .expect("the delete queues an erasure obligation");
    drop(window);

    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(
        report.sweep_windows_deferred_live, 0,
        "the open document was deferred as live: {report:?}"
    );
    assert_eq!(report.sweep_jobs_processed, 1, "{report:?}");
    assert!(
        !obligation_queued(&vault, &sweep_key),
        "the open editor held the erasure back"
    );
    assert_eq!(document.text().unwrap(), "kept text");
    assert_eq!(
        document.version_vector().unwrap(),
        version,
        "the compaction changed what the editor's peers resync from"
    );
}

/// A peer re-puts an edge from a kept row to the erased one into the live
/// window. The re-put owes the window a compaction, which the next pass runs;
/// on main only a re-put of the erased row itself owed one.
#[test]
fn an_edge_reput_naming_an_erased_row_owes_its_window_a_compaction() {
    let (_dir, vault) = open_vault();
    let ErasedWindow {
        manager,
        kept,
        erased,
    } = window_after_erasure(&vault);
    let key = WindowKey::new(WINDOW);

    let window = manager.open_window(&key).unwrap();
    let raise_before_import = owed_compaction_raise(&vault);
    let reput = edge_reput(&window, &kept, &erased, false);
    window.doc.import(&reput).unwrap();
    let raise = owed_compaction_raise(&vault);
    assert!(
        raise.is_some() && raise != raise_before_import,
        "the edge re-put owes its window no compaction"
    );
    window.persist_state(&vault).unwrap();
    drop(window);
    assert!(manager.unload_window(&key).unwrap());

    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert!(report.sweep_windows_compacted >= 1, "{report:?}");
    assert!(
        owed_compaction_raise(&vault).is_none(),
        "the owed compaction is settled"
    );
}

/// A peer's update puts the edge and takes it out again, so no live value is
/// left for ingest to see; the writer that makes the admitted update durable
/// owes the window a compaction for the edge its history holds. On main the
/// admitted inserts named entities-map rows only.
#[test]
fn a_history_only_edge_reput_owes_its_window_a_compaction_where_it_persists() {
    let (_dir, vault) = open_vault();
    let ErasedWindow {
        manager,
        kept,
        erased,
    } = window_after_erasure(&vault);
    let key = WindowKey::new(WINDOW);

    let window = manager.open_window(&key).unwrap();
    let reput = edge_reput(&window, &kept, &erased, true);
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
        owed_compaction_raise(&vault).is_some(),
        "the durable edge re-put owes its window no compaction"
    );
}
