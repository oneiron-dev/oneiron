use super::*;
use crate::sync::transport::decode_document;
use crate::{TimeRange, VaultConfig};

fn seed(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            b"ledger pointer",
        )
        .unwrap();
}

#[test]
fn document_crash_child() {
    let Some(path) = std::env::var_os("ONEIRON_DOCUMENT_CRASH_PATH") else {
        return;
    };
    let vault = Arc::new(Vault::open(path, VaultConfig::device()).unwrap());
    let id = EntityId::from_bytes([3; 16]).unwrap();
    seed(&vault, id);
    let registry = DocumentRegistry::new(vault);
    let doc = registry.open(id).unwrap();
    doc.edit_text(0, 0, "snapshot").unwrap();
    drop(doc);
    // Reopening checkpoints the snapshot, then one more durable update remains.
    let doc = registry.open(id).unwrap();
    doc.edit_text(8, 0, "+update").unwrap();
    std::process::abort();
}

#[test]
fn recovery_replays_snapshot_then_updates_after_kill_and_evicts_idle_docs() {
    let dir = tempfile::tempdir().unwrap();
    let exit = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sync::documents::tests::document_crash_child",
            "--nocapture",
        ])
        .env("ONEIRON_DOCUMENT_CRASH_PATH", dir.path())
        .status()
        .unwrap();
    assert!(!exit.success());
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let registry = DocumentRegistry::new(vault.clone());
    assert_eq!(registry.resident_count(), 0);
    let id = EntityId::from_bytes([3; 16]).unwrap();
    let doc = registry.open(id).unwrap();
    assert_eq!(doc.text().unwrap(), "snapshot+update");
    let same = registry.open(id).unwrap();
    same.edit_text(15, 0, "!").unwrap();
    assert_eq!(doc.text().unwrap(), "snapshot+update!");
    assert_eq!(registry.resident_count(), 1);
    drop(same);
    drop(doc);
    assert_eq!(registry.resident_count(), 0);
    assert_eq!(
        registry.open(id).unwrap().text().unwrap(),
        "snapshot+update!"
    );
    assert_eq!(vault.get(&id).unwrap().unwrap(), b"ledger pointer");
}

#[test]
fn admission_and_behind_shallow_peer_get_state_never_delta_and_future_edits_converge() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    seed(&vault, id);
    let registry = DocumentRegistry::new(vault.clone());
    let doc = registry.open(id).unwrap();
    doc.edit_text(0, 0, "secret past").unwrap();
    doc.edit_text(0, 11, "visible").unwrap();
    let admission = doc
        .export(b"selector-a", &VersionVector::default().encode())
        .unwrap();
    let frame = decode_document(&admission[1..]).unwrap();
    assert_eq!(frame.kind, document_sub_tags::STATE);
    let peer = LoroDoc::new();
    storage::import_complete(&peer, frame.payload).unwrap();
    assert_eq!(peer.get_text("body").to_string(), "visible");
    let behind = peer.oplog_vv().encode();
    doc.edit_text(7, 0, " after purge").unwrap();
    drop(doc);
    compact(&vault, id, false).unwrap();
    let doc = registry.open(id).unwrap();
    doc.edit_text(19, 0, "!").unwrap();
    // Pin the Loro 1.13.9 trap: an unchecked stale delta returns Ok with pending ops.
    let raw = doc
        .lock()
        .unwrap()
        .export(ExportMode::updates(&storage::decode_vv(&behind).unwrap()))
        .unwrap();
    let status = peer.import(&raw).unwrap();
    assert!(status.pending.is_some());
    assert_ne!(peer.get_text("body").to_string(), doc.text().unwrap());
    let response = doc.export(b"selector-a", &behind).unwrap();
    let frame = decode_document(&response[1..]).unwrap();
    assert_eq!(frame.kind, document_sub_tags::STATE);
    let peer = LoroDoc::new();
    storage::import_complete(&peer, frame.payload).unwrap();
    assert_eq!(peer.get_text("body").to_string(), doc.text().unwrap());
    let vv = peer.oplog_vv().encode();
    doc.edit_text(20, 0, " next").unwrap();
    let delta = doc.export(b"selector-a", &vv).unwrap();
    let frame = decode_document(&delta[1..]).unwrap();
    assert_eq!(frame.kind, document_sub_tags::UPDATE);
    storage::import_complete(&peer, frame.payload).unwrap();
    assert_eq!(peer.get_text("body").to_string(), doc.text().unwrap());
}

#[test]
fn offline_document_journal_survives_eviction_and_clears_only_on_covering_ack() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    seed(&vault, id);
    let registry = DocumentRegistry::new(vault);
    let doc = registry.open(id).unwrap();
    doc.edit_text(0, 0, "offline").unwrap();
    drop(doc);
    let doc = registry.open(id).unwrap();
    assert_eq!(doc.pending_frames().unwrap().len(), 1);
    doc.acknowledge(&VersionVector::default().encode()).unwrap();
    assert_eq!(doc.pending_frames().unwrap().len(), 1);
    let peer = LoroDoc::new();
    for frame in doc.pending_frames().unwrap() {
        storage::import_complete(&peer, decode_document(&frame[1..]).unwrap().payload).unwrap();
    }
    doc.acknowledge(&peer.oplog_vv().encode()).unwrap();
    assert!(doc.pending_frames().unwrap().is_empty());
    assert_eq!(peer.get_text("body").to_string(), "offline");
}

#[test]
fn document_sweep_defers_live_editor_then_erases_snapshot_updates_and_journal() {
    use crate::sync::{WindowManager, bridge::Materializer};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    seed(&vault, id);
    let manager = Arc::new(WindowManager::new(
        vault.clone(),
        Arc::new(Materializer::new()),
        "sweep",
    ));
    let doc = manager.documents().open(id).unwrap();
    doc.edit_text(0, 0, "erase-this").unwrap();
    assert!(!vault.compact_document_for_sweep(id, true).unwrap());
    drop(doc);
    assert!(vault.compact_document_for_sweep(id, true).unwrap());
    let doc = manager.documents().open(id).unwrap();
    assert_eq!(doc.text().unwrap(), "");
    assert!(doc.pending_frames().unwrap().is_empty());
}
