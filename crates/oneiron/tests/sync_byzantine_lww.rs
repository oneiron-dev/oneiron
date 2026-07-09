//! ONE-1156 — Byzantine LWW misbehaving-peer family (WAVE-C design).
//!
//! Pinned OWNER-DECISIONS under test:
//! - **OD-12** — the bulk-transfer ON-DISK arm routes through the standard
//!   gated machinery (`ensure_window` pinned open → OBSERVED import → inline
//!   `ra:` drain → `persist_state` → unload). The pre-fix arm wrote raw
//!   `d:w:`/`sv:w:`/`svf:w:` rows after a structure-only parse — remote
//!   bytes becoming doc state with NO Observer B door ever running.
//! - **OD-11** — doc-side tombstone re-assertion marker family:
//!   `ra:w:{window}:{entity_hex}` → the EXACT 25 B tombstone value
//!   `[reason:1][deleted_at:8 LE][request_id:16]`, byte-identical to the
//!   `dt:` local hard-delete row (HARD-only; soft-removal residue stays
//!   quarantine-only — pinned residual R4). Producers run inside Observer B
//!   callbacks (LMDB-only writes, the §8c.1 re-entrancy bar holds); the
//!   drain re-asserts at a safe commit point and queues the delta
//!   delete-bearing (`q:` + `d:{seq:8BE}` sidecar).
//!
//! Lives in its own integration binary (fresh process) like
//! `sync_quarantine.rs`: the lib test binary sits near a per-process LMDB
//! env-open budget on macOS.

#![cfg(feature = "sync")]

use core::assert_matches;
use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use oneiron::affect::Vad;
use oneiron::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::client::{SyncClient, SyncClientConfig, SyncEvent};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::quarantine::{QuarantineContainer, quarantined_records};
use oneiron::sync::{WindowKey, drain_reassert_markers, pending_reassert_windows, transport};
use oneiron::types::{EdgeKind, TimeRange};
use oneiron::{
    DeleteReason, EntityId, HnswConfig, TOMBSTONE_VALUE_V2_LEN, Vault, VaultConfig,
    decode_tombstone_value,
};
use tokio::sync::mpsc::UnboundedReceiver;
use xxhash_rust::xxh3::xxh3_64;

/// 2026-02-15 ≈ unix 1_771_027_200 ⇒ window "2026-02".
const LEARNED_AT: u64 = 1_771_027_200;
const WINDOW: &str = "2026-02";

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

fn test_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    (temp, vault)
}

fn make_manager(vault: &Arc<Vault>) -> Arc<WindowManager> {
    Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "test-user",
    ))
}

fn make_client(manager: &Arc<WindowManager>) -> (SyncClient, UnboundedReceiver<SyncEvent>) {
    SyncClient::new(Arc::clone(manager), SyncClientConfig::default()).unwrap()
}

/// Pinned 25-byte entity envelope: type u8 + occurred_start/end u64 BE +
/// learned_at u64 BE + body.
fn make_entity_blob(entity_type: u8, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

fn put_task(vault: &Vault, id: &EntityId, data: &[u8]) {
    vault
        .put_entity(
            id,
            1,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            data,
        )
        .unwrap();
}

/// Soft (`user_delete`) v2 tombstone wire value — the only soft reason.
fn soft_value(stamp: u8) -> Vec<u8> {
    let mut v = vec![1_u8];
    v.extend_from_slice(&1_771_200_000_u64.to_le_bytes());
    v.extend_from_slice(&[stamp; 16]);
    v
}

fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

fn dt_key(id: &EntityId) -> String {
    format!("dt:{}", id.to_hex())
}

fn ra_key(id: &EntityId) -> String {
    format!("ra:w:{WINDOW}:{}", id.to_hex())
}

/// Seeds an entity in LMDB, hard-deletes it (origin path → permanent `dt:`
/// marker + hard tombstone in the persisted/live window doc), and returns
/// the `dt:` row's exact 25 B value.
fn hard_delete_seeded(vault: &Arc<Vault>, id: &EntityId, reason: DeleteReason) -> Vec<u8> {
    put_task(vault, id, b"erase-me");
    vault.delete_entity_with_reason(id, reason).unwrap();
    let dt = vault
        .sync_state_get(&dt_key(id))
        .unwrap()
        .expect("hard delete must write the permanent dt: marker");
    assert_eq!(
        dt.len(),
        TOMBSTONE_VALUE_V2_LEN,
        "dt: value = 25 B [reason:1][deleted_at:8 LE][request_id:16]"
    );
    dt
}

// ─── (a) Bulk ON-DISK gate (OD-12) ───────────────────────────────────────────

/// ONE-1156(a) † delete-safety — a hostile bulk snapshot carrying a SOFT
/// tombstone over a locally hard-deleted id (the §8c.1 hard→soft downgrade,
/// crafted causally-after so it WINS the Loro map merge) must not weaken the
/// delete anywhere: LMDB stays purged, the `dt:` row stays byte-identical,
/// and the PERSISTED `d:w:` snapshot decodes HARD again — the OD-12 inline
/// `ra:` drain re-asserted the dt:-backed value BEFORE the persist. Pre-fix,
/// the ON-DISK arm wrote the hostile snapshot bytes raw into `d:w:` with no
/// door ever running.
#[test]
fn bulk_hostile_snapshot_soft_over_effective_hard_is_blocked() {
    let (_temp, vault) = test_vault();

    // Local truth first (no manager attached → transient write path
    // persists d:w: + sets the permanent dt: marker).
    let id = EntityId::now();
    let dt_before = hard_delete_seeded(&vault, &id, DeleteReason::UserHardDelete);

    // Hostile peer: synced (imports the local snapshot), then DOWNGRADES
    // the tombstone to soft — causally after ⇒ wins the map merge.
    let local_state = vault
        .sync_state_get(&format!("d:w:{WINDOW}"))
        .unwrap()
        .expect("local window snapshot");
    let hostile = LoroDoc::new();
    hostile.import(&local_state).unwrap();
    hostile
        .get_map("tombstones")
        .insert(&id.to_hex(), soft_value(0xAA).as_slice())
        .unwrap();
    hostile.commit();
    let snapshot = hostile.export(ExportMode::Snapshot).unwrap();

    let manager = make_manager(&vault);
    let (mut client, _rx) = make_client(&manager);
    client
        .handle_server_message(&transport::encode_bulk_transfer_done(WINDOW, &snapshot))
        .unwrap();

    // LMDB: the entity stays purged; dt: is never modified by replay/drain.
    assert!(
        vault.get_raw(&id).unwrap().is_none(),
        "hard-purged entity must stay purged through a hostile bulk import"
    );
    assert_eq!(
        vault.sync_state_get(&dt_key(&id)).unwrap().as_deref(),
        Some(dt_before.as_slice()),
        "dt: row must stay byte-identical"
    );

    // The persisted d:w: snapshot re-imports to a HARD tombstone whose
    // bytes are the dt: row's exact 25 B (OD-11 re-assert value).
    let persisted = vault
        .sync_state_get(&format!("d:w:{WINDOW}"))
        .unwrap()
        .expect("persisted bulk snapshot");
    let reimported = LoroDoc::new();
    reimported.import(&persisted).unwrap();
    let value = map_get_bytes(&reimported.get_map("tombstones"), &id.to_hex())
        .expect("tombstone present in persisted snapshot");
    assert!(
        decode_tombstone_value(&value).is_hard(),
        "post-drain doc tombstone must decode HARD (never-downgrade)"
    );
    assert_eq!(
        value.as_slice(),
        dt_before.as_slice(),
        "re-asserted value = the dt: row's exact 25 B, verbatim"
    );

    // The ra: marker was consumed in the drain's success txn.
    assert!(vault.sync_state_get(&ra_key(&id)).unwrap().is_none());
    assert!(pending_reassert_windows(&vault).unwrap().is_empty());
}

/// ONE-1156(a) † delete-safety — a hostile bulk snapshot that REMOVES the
/// tombstone and re-puts a live body for a dt:-marked id must not
/// materialize: the entity door's `dt:` gate SKIP-refuses (warn-level
/// `return Ok(())`, bridge.rs — deliberately NOT a quarantine), so no x: row
/// names the refused body; the tombstone REMOVAL itself and a
/// structurally-junk sibling blob DO quarantine. The removal also enqueues
/// the `ra:` re-assertion, so the persisted snapshot carries the hard
/// tombstone again with the zombie entities-map body swept.
#[test]
fn bulk_hostile_snapshot_live_body_over_hard_deleted_id_not_materialized() {
    let (_temp, vault) = test_vault();

    let id = EntityId::now();
    let dt_before = hard_delete_seeded(&vault, &id, DeleteReason::UserHardDelete);

    let local_state = vault
        .sync_state_get(&format!("d:w:{WINDOW}"))
        .unwrap()
        .expect("local window snapshot");
    let hostile = LoroDoc::new();
    hostile.import(&local_state).unwrap();
    // Byzantine resurrection: remove the tombstone, re-put a full body
    // under the canonical id — plus a structurally-junk sibling blob (key
    // is not 32-char hex) as the positive quarantine control.
    hostile.get_map("tombstones").delete(&id.to_hex()).unwrap();
    hostile
        .get_map("entities")
        .insert(
            &id.to_hex(),
            make_entity_blob(1, LEARNED_AT, b"zombie-body").as_slice(),
        )
        .unwrap();
    hostile
        .get_map("entities")
        .insert("not-a-hex-key", b"junk".as_slice())
        .unwrap();
    hostile.commit();
    let snapshot = hostile.export(ExportMode::Snapshot).unwrap();

    let manager = make_manager(&vault);
    let (mut client, _rx) = make_client(&manager);
    client
        .handle_server_message(&transport::encode_bulk_transfer_done(WINDOW, &snapshot))
        .unwrap();

    // No materialization: the dt: gate refused the body before any byte
    // was staged.
    assert!(
        vault.get_raw(&id).unwrap().is_none(),
        "dt:-marked id must never re-materialize from a bulk snapshot"
    );
    assert!(vault.get(&id).unwrap().is_none());
    assert_eq!(
        vault.sync_state_get(&dt_key(&id)).unwrap().as_deref(),
        Some(dt_before.as_slice()),
        "dt: row must stay byte-identical"
    );

    // Quarantine table: the removal (typed reason literal) and the junk
    // sibling — and NO x: row for the dt:-refused body (skip-refuse).
    let records = quarantined_records(&vault).unwrap();
    assert!(
        records
            .iter()
            .any(|(_, r)| r.container == QuarantineContainer::Tombstones
                && r.reason_code == "SyncProtocolError"
                && r.crdt_key_hash == xxh3_64(id.to_hex().as_bytes())),
        "tombstone removal must quarantine as a protocol violation"
    );
    assert!(
        records
            .iter()
            .any(|(_, r)| r.container == QuarantineContainer::Entities
                && r.reason_code == "CorruptedIndex"
                && r.crdt_key_hash == xxh3_64(b"not-a-hex-key")),
        "structurally-junk sibling blob must quarantine (header pre-validation literal)"
    );
    assert!(
        !records
            .iter()
            .any(|(_, r)| r.container == QuarantineContainer::Entities
                && r.crdt_key_hash == xxh3_64(id.to_hex().as_bytes())),
        "the dt:-refused body SKIP-refuses — no x: row (bridge.rs warn-level return)"
    );

    // The removal's ra: marker was enqueued AND drained inline (OD-12 step
    // 3): the persisted snapshot re-imports with the HARD tombstone back
    // and the zombie entities-map body removed in the re-assert commit.
    let persisted = vault
        .sync_state_get(&format!("d:w:{WINDOW}"))
        .unwrap()
        .expect("persisted bulk snapshot");
    let reimported = LoroDoc::new();
    reimported.import(&persisted).unwrap();
    let value = map_get_bytes(&reimported.get_map("tombstones"), &id.to_hex())
        .expect("tombstone re-asserted in persisted snapshot");
    assert!(decode_tombstone_value(&value).is_hard());
    assert_eq!(value.as_slice(), dt_before.as_slice());
    assert!(
        map_get_bytes(&reimported.get_map("entities"), &id.to_hex()).is_none(),
        "the re-assert commit removes the re-put entities-map body (active carrier)"
    );
    assert!(vault.sync_state_get(&ra_key(&id)).unwrap().is_none());
}

/// ONE-1156(a) positive control — a benign bulk snapshot still works
/// end-to-end through the gated arm: the entity materializes via Observer B,
/// the `bulk:w:{key}` in-progress marker is cleared only after success, the
/// pinned `d:`/`sv:`/`svf:` triple is written (`svf:w: == [1]`), the cold
/// window is unloaded afterward (OD-12 memory budget), and the completion
/// event fires.
#[test]
fn bulk_valid_snapshot_positive_control() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, mut rx) = make_client(&manager);

    let id = EntityId::now();
    let blob = make_entity_blob(1, LEARNED_AT, b"bulk-benign");
    let server_doc = LoroDoc::new();
    server_doc
        .get_map("entities")
        .insert(&id.to_hex(), blob.as_slice())
        .unwrap();
    server_doc.commit();
    let snapshot = server_doc.export(ExportMode::Snapshot).unwrap();

    // BulkTransfer sets the ARCH-0023b `bulk:w:{key}` in-progress marker.
    let msgpack = rmp_serde::to_vec(&serde_json::json!({})).unwrap();
    let compressed = zstd::stream::encode_all(msgpack.as_slice(), 0).unwrap();
    client
        .handle_server_message(&transport::encode_bulk_transfer(WINDOW, &compressed))
        .unwrap();
    assert_eq!(
        vault
            .sync_state_get(&format!("bulk:w:{WINDOW}"))
            .unwrap()
            .as_deref(),
        Some([1u8].as_slice())
    );

    client
        .handle_server_message(&transport::encode_bulk_transfer_done(WINDOW, &snapshot))
        .unwrap();

    // Observer B materialized the entity (the old raw-write arm never did).
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(b"bulk-benign".as_slice()),
        "benign bulk snapshot must materialize through Observer B"
    );
    // Marker cleared only after success.
    assert!(
        vault
            .sync_state_get(&format!("bulk:w:{WINDOW}"))
            .unwrap()
            .is_none()
    );
    // Pinned persistence triple via persist_state; svf fresh literal.
    assert_eq!(
        vault
            .sync_state_get(&format!("svf:w:{WINDOW}"))
            .unwrap()
            .as_deref(),
        Some([1u8].as_slice())
    );
    let persisted = vault
        .sync_state_get(&format!("d:w:{WINDOW}"))
        .unwrap()
        .expect("d:w: snapshot written");
    let reimported = LoroDoc::new();
    reimported.import(&persisted).unwrap();
    assert_eq!(
        map_get_bytes(&reimported.get_map("entities"), &id.to_hex()).as_deref(),
        Some(blob.as_slice())
    );
    // OD-12: bulk targets cold historical windows — unloaded after persist.
    assert!(
        manager.window(&WindowKey::new(WINDOW)).is_none(),
        "bulk-cold window must be unloaded after the persist"
    );
    assert_matches!(rx.try_recv(), Ok(SyncEvent::BulkTransferComplete { .. }));
}

// ─── (c) Tombstone-removal re-assertion (OD-11) ──────────────────────────────

/// ONE-1156(c) † delete-safety — round trip on a LIVE doc: a hostile
/// tombstone-REMOVAL delta (with body + carrier-edge re-adds) is quarantined
/// AND enqueues the durable marker under the LITERAL key
/// `ra:w:{window}:{entity_hex}` with value == the `dt:` row's exact 25 B;
/// `drain_reassert_markers` then re-asserts at a safe commit point — the doc
/// tombstone is back verbatim, the zombie body and carrier edge are swept,
/// the re-assert delta is queued delete-bearing (`q:` + `d:{seq:8BE}`
/// sidecar), and the marker is consumed in the same success txn.
#[test]
fn tombstone_removal_enqueues_ra_marker_and_drain_reasserts() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);

    // Seed LMDB, then open the window: reverse remat mirrors the entities
    // + edge into the live doc, and the delete below routes through it
    // (the manager attaches as the vault's delete router on open).
    let id = EntityId::now();
    let nbr = EntityId::now();
    put_task(&vault, &id, b"hard-delete-me");
    put_task(&vault, &nbr, b"survivor");
    vault.put_edge(&id, EdgeKind::Supports, &nbr, 0.5).unwrap();
    let window = manager.open_window(&WindowKey::new(WINDOW)).unwrap();

    vault
        .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
        .unwrap();
    let dt_value = vault
        .sync_state_get(&dt_key(&id))
        .unwrap()
        .expect("dt: row");

    // Hostile peer: synced copy, then removes the tombstone and re-adds
    // the deleted body + a carrier edge.
    let hostile = LoroDoc::new();
    hostile
        .import(&window.doc.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    hostile.get_map("tombstones").delete(&id.to_hex()).unwrap();
    hostile
        .get_map("entities")
        .insert(
            &id.to_hex(),
            make_entity_blob(1, LEARNED_AT, b"zombie").as_slice(),
        )
        .unwrap();
    let edge_key = format_edge_key(&id, EdgeKind::Supports, &nbr);
    hostile
        .get_map("edges")
        .insert(
            edge_key.as_str(),
            encode_edge_value_for_crdt(
                EdgeKind::Supports,
                0.5,
                LEARNED_AT,
                Some(Vad::NEUTRAL),
                None,
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();
    hostile.commit();
    let delta = hostile
        .export(ExportMode::updates(&window.doc.oplog_vv()))
        .unwrap();

    let d_sidecars_before = vault.sync_queue_rows_with_prefix(b"d:").unwrap().len();

    // Import through the live OBSERVED doc — Observer B fires.
    window.doc.import(&delta).unwrap();

    // Quarantined (x: row, typed literal) — never silently dropped.
    let records = quarantined_records(&vault).unwrap();
    assert!(
        records
            .iter()
            .any(|(_, r)| r.container == QuarantineContainer::Tombstones
                && r.reason_code == "SyncProtocolError"
                && r.crdt_key_hash == xxh3_64(id.to_hex().as_bytes())),
        "tombstone removal must quarantine"
    );
    // Marker grammar literals (OD-11): ASCII key `ra:w:{window}:{hex}`,
    // value = the dt: row's exact 25 B (LE in the opaque value).
    assert_eq!(
        vault.sync_state_get(&ra_key(&id)).unwrap().as_deref(),
        Some(dt_value.as_slice()),
        "ra: marker must carry the dt: row's exact bytes"
    );
    assert_eq!(
        pending_reassert_windows(&vault).unwrap(),
        vec![WINDOW.to_string()]
    );
    // LMDB: the dt: gate refused the body re-put.
    assert!(vault.get_raw(&id).unwrap().is_none());

    // Drain at the safe commit point (outside observer callbacks).
    let report = drain_reassert_markers(&vault, "test-user", &manager).unwrap();
    assert_eq!(report.drained, vec![WINDOW.to_string()]);
    assert!(report.still_pending.is_empty());

    // Doc: tombstone re-asserted verbatim; zombie body + carrier edge
    // swept in the same commit; the unrelated neighbor survives.
    assert_eq!(
        map_get_bytes(&window.doc.get_map("tombstones"), &id.to_hex()).as_deref(),
        Some(dt_value.as_slice()),
        "re-asserted tombstone = dt: bytes verbatim"
    );
    assert!(map_get_bytes(&window.doc.get_map("entities"), &id.to_hex()).is_none());
    assert!(
        window.doc.get_map("edges").get(&edge_key).is_none(),
        "re-added carrier edge must be swept by the hard re-assert"
    );
    assert!(map_get_bytes(&window.doc.get_map("entities"), &nbr.to_hex()).is_some());

    // Propagation: exactly one new delete-bearing row (`q:` row +
    // `d:{seq:8BE}` sidecar) for the re-assert delta.
    assert_eq!(
        vault.sync_queue_rows_with_prefix(b"d:").unwrap().len(),
        d_sidecars_before + 1,
        "the re-assert delta must be queued delete-bearing"
    );

    // Marker consumed only in the success txn.
    assert!(vault.sync_state_get(&ra_key(&id)).unwrap().is_none());
    assert!(pending_reassert_windows(&vault).unwrap().is_empty());
}

/// ONE-1156(c) — double-drain idempotence: after a successful drain the
/// second pass is a strict no-op (empty report, no duplicate `q:`/`d:` rows,
/// doc version vector unchanged).
#[test]
fn ra_drain_is_idempotent_on_double_drain() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);

    let id = EntityId::now();
    put_task(&vault, &id, b"double-drain");
    let window = manager.open_window(&WindowKey::new(WINDOW)).unwrap();
    vault
        .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
        .unwrap();

    // Hostile soft-over-hard downgrade delta (Some-arm producer).
    let hostile = LoroDoc::new();
    hostile
        .import(&window.doc.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    hostile
        .get_map("tombstones")
        .insert(&id.to_hex(), soft_value(0x22).as_slice())
        .unwrap();
    hostile.commit();
    let delta = hostile
        .export(ExportMode::updates(&window.doc.oplog_vv()))
        .unwrap();
    window.doc.import(&delta).unwrap();
    assert!(vault.sync_state_get(&ra_key(&id)).unwrap().is_some());

    let report = drain_reassert_markers(&vault, "test-user", &manager).unwrap();
    assert_eq!(report.drained, vec![WINDOW.to_string()]);
    let d_rows_after_first = vault.sync_queue_rows_with_prefix(b"d:").unwrap().len();
    let q_rows_after_first = vault.sync_queue_rows_with_prefix(b"q:").unwrap().len();
    let vv_after_first = window.doc.oplog_vv();

    // Second drain: nothing pending — strict no-op.
    let report = drain_reassert_markers(&vault, "test-user", &manager).unwrap();
    assert!(report.drained.is_empty(), "second drain must be a no-op");
    assert!(report.still_pending.is_empty());
    assert_eq!(
        vault.sync_queue_rows_with_prefix(b"d:").unwrap().len(),
        d_rows_after_first,
        "no duplicate delete-bearing sidecars"
    );
    assert_eq!(
        vault.sync_queue_rows_with_prefix(b"q:").unwrap().len(),
        q_rows_after_first,
        "no duplicate q: rows"
    );
    assert_eq!(
        window.doc.oplog_vv(),
        vv_after_first,
        "doc state unchanged by the second drain"
    );
}

/// ONE-1156(c) † delete-safety — the Some-arm producer (§8c.1 doc residue):
/// a SOFT tombstone delta over a dt:-hard id wins the Loro map merge
/// (crafted causally-after), LMDB stays untouched (the replay primitive
/// never downgrades), the `ra:` marker is enqueued with the dt: bytes, and
/// the drain restores the doc to HARD — closing the residue a raw map merge
/// leaves behind.
#[test]
fn hard_soft_downgrade_delta_enqueues_ra_marker() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);

    let id = EntityId::now();
    put_task(&vault, &id, b"downgrade-me");
    let window = manager.open_window(&WindowKey::new(WINDOW)).unwrap();
    vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let dt_value = vault
        .sync_state_get(&dt_key(&id))
        .unwrap()
        .expect("dt: row");

    let hostile = LoroDoc::new();
    hostile
        .import(&window.doc.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    hostile
        .get_map("tombstones")
        .insert(&id.to_hex(), soft_value(0xEE).as_slice())
        .unwrap();
    hostile.commit();
    let delta = hostile
        .export(ExportMode::updates(&window.doc.oplog_vv()))
        .unwrap();
    window.doc.import(&delta).unwrap();

    // Residue precondition: the soft value WON the raw map merge — the
    // exact §8c.1 vector this family closes. (If Loro arbitration ever
    // changes, this assert flags the test as vacuous.)
    let merged = map_get_bytes(&window.doc.get_map("tombstones"), &id.to_hex()).unwrap();
    assert!(
        !decode_tombstone_value(&merged).is_hard(),
        "precondition: hostile soft value must win the map merge"
    );

    // LMDB unchanged + marker enqueued with the dt: bytes.
    assert!(vault.get_raw(&id).unwrap().is_none());
    assert_eq!(
        vault.sync_state_get(&dt_key(&id)).unwrap().as_deref(),
        Some(dt_value.as_slice()),
        "dt: row must stay byte-identical"
    );
    assert_eq!(
        vault.sync_state_get(&ra_key(&id)).unwrap().as_deref(),
        Some(dt_value.as_slice()),
        "Some-arm must enqueue ra: with the dt: row's exact 25 B"
    );

    // Drain: the doc decodes HARD again (8c.1 closed); marker consumed.
    let report = drain_reassert_markers(&vault, "test-user", &manager).unwrap();
    assert_eq!(report.drained, vec![WINDOW.to_string()]);
    let value = map_get_bytes(&window.doc.get_map("tombstones"), &id.to_hex()).unwrap();
    assert!(
        decode_tombstone_value(&value).is_hard(),
        "post-drain doc tombstone must decode HARD"
    );
    assert_eq!(value.as_slice(), dt_value.as_slice());
    assert!(vault.sync_state_get(&ra_key(&id)).unwrap().is_none());
}
