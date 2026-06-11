//! ONE-1135 — delete propagation transport (M4-10).
//!
//! Pinned OWNER-DECISIONS under test:
//! - Delete routing: `Vault::delete_entity_with_reason` commits the CRDT
//!   tombstone through the REGISTRY-OWNED live window doc when the window
//!   is open (manager attached via `WindowManager::attach_to_vault`);
//!   the transient-doc path remains only for windows not currently open,
//!   and import-merges the persisted snapshot rather than blind-overwrite.
//! - Clobber guard: `LoadedWindow::persist_state` import-merges the
//!   persisted state (`d:w:` + `u:` rows) before exporting, so a live doc
//!   that never saw a transiently-written tombstone can no longer
//!   overwrite the only durable record of a GDPR delete.
//! - Delete-bearing queue rows: the tombstone-commit delta is pushed to
//!   the offline queue with a `d:{seq:8BE}` sidecar marker; it replays on
//!   reconnect and is EXEMPT from the optimistic `clear_through` until
//!   VV-confirmed (M4-12).
//! - Carrier-15 scrub (ARCH-0038 #15, hard reasons): pending `q:` rows and
//!   persisted `u:w:` rows for the affected window are dropped (fail-closed
//!   over-drop) and the window is marked for full resync (`fr:w:{key}`).

#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::queue::SyncQueue;
use oneiron::sync::transport::{decode_window_sync, encode_window_sync, window_sub_tags};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::LoadedWindow;
use oneiron::types::{ENTITY_TYPE_REDACTION_AUDIT, TimeRange};
use oneiron::{DeleteReason, EntityId, HnswConfig, TOMBSTONE_VALUE_V2_LEN, Vault, VaultConfig};

/// 2026-02-15 ≈ unix 1_771_027_200 ⇒ window "2026-02".
const LEARNED_AT: u64 = 1_771_027_200;
const WINDOW: &str = "2026-02";

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = Some("test-model-v1".to_owned());
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
    (dir, vault)
}

fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

fn time_range(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn receipt_request_id(vault: &Vault, receipt_id: &EntityId) -> String {
    let raw = vault.get_raw(receipt_id).unwrap().expect("receipt raw");
    let body: serde_json::Value = rmp_serde::from_slice(&raw[25..]).expect("receipt body");
    body["request_id"]
        .as_str()
        .expect("request_id string")
        .to_owned()
}

/// Opens a vault with an ATTACHED window manager and the `WINDOW` month
/// open, holding `id` (put BEFORE open so step-4 reverse remat mirrors it
/// into the live doc with no observer side effects).
fn open_routed_window(
    vault: &Arc<Vault>,
    user: &str,
    id: &EntityId,
    body: &[u8],
) -> (Arc<WindowManager>, Arc<LoadedWindow>) {
    vault
        .batch()
        .put(id, 1, time_range(LEARNED_AT), LEARNED_AT, body)
        .text(id, &[("body", std::str::from_utf8(body).unwrap())])
        .commit()
        .unwrap();

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(Arc::clone(vault), materializer, user));
    manager.attach_to_vault();
    let window = manager.open_window(&WindowKey::new(WINDOW)).unwrap();
    assert!(
        map_get_bytes(&window.doc.get_map("entities"), &id.to_hex()).is_some(),
        "fixture: reverse remat must mirror the entity into the live doc"
    );
    (manager, window)
}

/// Returns the seqs (u64 BE suffix) of all `d:{seq:8BE}` sidecar markers.
fn delete_bearing_seqs(vault: &Vault) -> Vec<u64> {
    vault
        .sync_queue_rows_with_prefix(b"d:")
        .unwrap()
        .into_iter()
        .filter_map(|(key, _)| {
            (key.len() == 10).then(|| u64::from_be_bytes(key[2..10].try_into().unwrap()))
        })
        .collect()
}

/// Wire-level shuttle: a queued update replayed exactly the way the
/// reconnect path transmits it (`encode_window_sync` → wire →
/// `decode_window_sync` → import into the replica's observed window doc).
fn shuttle_update_to(window_key: &str, encoded: &[u8], replica: &LoadedWindow) {
    let wire = encode_window_sync(window_key, window_sub_tags::UPDATE, encoded);
    assert_eq!(wire[0], 10, "TAG_WINDOW_SYNC");
    let (decoded_key, sub_tag, payload) = decode_window_sync(&wire[1..]).unwrap();
    assert_eq!(decoded_key, window_key);
    assert_eq!(sub_tag, window_sub_tags::UPDATE);
    replica.doc.import(payload).unwrap();
}

/// AC1 + AC3 + AC4: with the manager attached and the window OPEN, a hard
/// delete commits through the LIVE doc (a transient-snapshot implementation
/// FAILS the live-doc assertions), Observer A persists the tombstone
/// commit's `u:` row, the carrier-15 scrub drops the window's prior `q:`
/// and `u:w:` payload rows, the window is marked `fr:w:` for full resync,
/// and the tombstone-commit delta is queued as a delete-bearing row.
#[test]
fn hard_delete_routes_through_live_window_doc_with_carrier_15_scrub() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    let (manager, window) = open_routed_window(&vault, "node-a", &id, b"live-route-secret");
    let hex_id = id.to_hex();

    // A post-open commit so the window has a payload-carrying `u:` row to
    // scrub (Observer A persists it) plus pre-existing queue rows: one for
    // this window (must be scrubbed) and one for another window (must
    // survive).
    let bystander = EntityId::now();
    let mut blob = Vec::with_capacity(25 + 14);
    blob.push(1u8);
    for _ in 0..3 {
        blob.extend_from_slice(&LEARNED_AT.to_be_bytes());
    }
    blob.extend_from_slice(b"bystander-body");
    window
        .doc
        .get_map("entities")
        .insert(bystander.to_hex().as_str(), blob.as_slice())
        .unwrap();
    window.doc.commit();
    let u_prefix = format!("u:w:{WINDOW}:");
    let pre_delete_u_keys = vault.sync_state_keys_with_prefix(&u_prefix).unwrap();
    assert_eq!(pre_delete_u_keys.len(), 1, "fixture: one payload u: row");

    let queue = SyncQueue::new(Arc::clone(&vault)).unwrap();
    let scrubbed_q_seq = queue.push(WINDOW, &[0xAA, 0xBB]).unwrap();
    let surviving_q_seq = queue.push("2026-03", &[0xCC]).unwrap();

    // Pre-delete snapshot: the delta-verification doc below needs the
    // causal deps of the tombstone commit.
    let pre_delete_snapshot = window.doc.export(ExportMode::Snapshot).unwrap();

    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    assert!(outcome.existed);
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let request_id_hex = receipt_request_id(&vault, &receipt_id).replace('-', "");

    // THE LIVE DOC saw the delete: v2 tombstone literal in the registry
    // instance, entities key removed in the same commit. A transient-path
    // implementation leaves this doc untouched and FAILS here.
    let live_tombstones = window.doc.get_map("tombstones");
    let value = map_get_bytes(&live_tombstones, &hex_id).expect("live doc tombstone");
    assert_eq!(value.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(value[0], 3, "gdpr_delete wire byte");
    assert_eq!(
        hex(&value[9..25]),
        request_id_hex,
        "tombstone request_id correlates with the receipt"
    );
    assert!(
        map_get_bytes(&window.doc.get_map("entities"), &hex_id).is_none(),
        "live entities-map copy removed in the delete commit"
    );

    // Observer A persisted the tombstone commit (the registry doc is the
    // observed doc): a `u:` row exists that postdates the scrub.
    let post_delete_u_keys = vault.sync_state_keys_with_prefix(&u_prefix).unwrap();
    assert!(
        !post_delete_u_keys.contains(&pre_delete_u_keys[0]),
        "carrier-15: the pre-delete payload u: row must be scrubbed"
    );
    assert_eq!(
        post_delete_u_keys.len(),
        1,
        "the tombstone commit's own u: row survives (it is payload-free)"
    );

    // Durable: d:w: + surviving u: rows reload with the tombstone AND the
    // bystander entity the scrubbed u: row used to carry (the snapshot
    // subsumed it — over-drop without data loss).
    let reloaded =
        oneiron::sync::window::load_window_from_state(&vault, "node-a", &WindowKey::new(WINDOW))
            .unwrap();
    assert_eq!(
        map_get_bytes(&reloaded.get_map("tombstones"), &hex_id).as_deref(),
        Some(value.as_slice()),
        "tombstone durable in sync_state"
    );
    assert_eq!(
        map_get_bytes(&reloaded.get_map("entities"), &bystander.to_hex()).as_deref(),
        Some(blob.as_slice()),
        "the scrubbed u: row's ops were subsumed by the snapshot"
    );

    // pt: cleared (CRDT record durable), fr: full-resync marker set.
    assert!(
        vault
            .sync_state_get(&format!("pt:{WINDOW}:{hex_id}"))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        vault
            .sync_state_get(&format!("fr:w:{WINDOW}"))
            .unwrap()
            .as_deref(),
        Some([1u8].as_slice()),
        "hard delete must mark the window for full resync (carriers 13-14)"
    );

    // Carrier-15 queue scrub + delete-bearing row.
    let updates = queue.drain_updates().unwrap();
    let seqs: Vec<u64> = updates.iter().map(|u| u.seq).collect();
    assert!(
        !seqs.contains(&scrubbed_q_seq),
        "pending q: row for the deleted window must be scrubbed before any replay"
    );
    assert!(
        seqs.contains(&surviving_q_seq),
        "q: rows of other windows survive"
    );
    let markers = delete_bearing_seqs(&vault);
    assert_eq!(markers.len(), 1, "exactly one delete-bearing row queued");
    let delete_row = updates
        .iter()
        .find(|u| u.seq == markers[0])
        .expect("delete-bearing q: row present");
    assert_eq!(delete_row.window_key, WINDOW);

    // The queued delta really carries the delete: imported over the
    // pre-delete state it produces the tombstone.
    let verify_doc = LoroDoc::from_snapshot(&pre_delete_snapshot).unwrap();
    verify_doc.import(&delete_row.encoded).unwrap();
    assert_eq!(
        map_get_bytes(&verify_doc.get_map("tombstones"), &hex_id).as_deref(),
        Some(value.as_slice()),
        "the delete-bearing update must replay the tombstone"
    );

    // Registry unload (persist_state) cannot clobber any of it.
    drop(window);
    assert!(manager.unload_window(&WindowKey::new(WINDOW)).unwrap());
    let reloaded =
        oneiron::sync::window::load_window_from_state(&vault, "node-a", &WindowKey::new(WINDOW))
            .unwrap();
    assert!(
        map_get_bytes(&reloaded.get_map("tombstones"), &hex_id).is_some(),
        "unload persist must keep the tombstone"
    );
}

/// AC2 regression — the exact clobber vector from the spec: live doc loaded
/// (constructed OUTSIDE the registry, so the vault routes the delete
/// through the transient path) → delete via vault → live doc
/// `persist_state` → `d:w:` still contains the tombstone. The pre-fix
/// `persist_state` exported the live doc verbatim over `d:w:` and FAILS
/// here: the only durable record of the GDPR delete vanished while the
/// receipt claimed it happened.
#[test]
fn persist_state_cannot_clobber_transient_tombstone() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    vault
        .put_entity(&id, 1, time_range(LEARNED_AT), LEARNED_AT, b"clobber-me")
        .unwrap();

    // Live window WITHOUT manager attachment — the historical setup every
    // pre-M4-08 caller had.
    let materializer = Arc::new(Materializer::new());
    let window = LoadedWindow::new("node-a", WindowKey::new(WINDOW), &vault, &materializer);

    // The live doc diverges with its own commit (an unrelated entity).
    let unrelated = EntityId::now();
    let mut blob = Vec::with_capacity(25 + 9);
    blob.push(1u8);
    for _ in 0..3 {
        blob.extend_from_slice(&LEARNED_AT.to_be_bytes());
    }
    blob.extend_from_slice(b"unrelated");
    window
        .doc
        .get_map("entities")
        .insert(unrelated.to_hex().as_str(), blob.as_slice())
        .unwrap();
    window.doc.commit();

    // Delete via vault: no registry → transient path persists the
    // tombstone into d:w: — a record this live doc has never seen.
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    assert!(outcome.existed);
    assert!(
        map_get_bytes(&window.doc.get_map("tombstones"), &id.to_hex()).is_none(),
        "fixture: the live doc must NOT have seen the transient tombstone yet"
    );

    // The clobber vector: the live doc persists over the same d:w: key.
    window.persist_state(&vault).unwrap();

    let reloaded =
        oneiron::sync::window::load_window_from_state(&vault, "node-a", &WindowKey::new(WINDOW))
            .unwrap();
    let tombstone = map_get_bytes(&reloaded.get_map("tombstones"), &id.to_hex())
        .expect("d:w: must still contain the tombstone after a live persist_state");
    assert_eq!(tombstone.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(tombstone[0], 3, "gdpr_delete wire byte survives");
    assert_eq!(
        map_get_bytes(&reloaded.get_map("entities"), &unrelated.to_hex()).as_deref(),
        Some(blob.as_slice()),
        "persist is a MERGE: the live doc's own ops persist alongside the tombstone"
    );

    // The merge replayed the tombstone into the (observed) live doc; the
    // local store was already purged, so the idempotent replay must not
    // mint a second receipt.
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .len(),
        1,
        "exactly the delete path's receipt — the merge replay is receipt-free"
    );
}

/// AC3 + AC5 (hard): entity synced A→B over the wire → hard delete on A
/// while 'offline' → the delete-bearing row survives the OPTIMISTIC
/// `clear_through` → reconnect replay (wire-level shuttle) → B's LMDB is
/// purged, B's tombstones map holds the v2 value, and B writes its OWN
/// `h:` sweep row + REDACTION_AUDIT receipt correlated to A's request_id.
#[test]
fn offline_hard_delete_is_delivered_on_reconnect_replay() {
    // --- Node A: routed live window holding the entity ---
    let (_dir_a, vault_a) = open_vault();
    let id = EntityId::now();
    let (_manager_a, window_a) = open_routed_window(&vault_a, "node-a", &id, b"offline-secret");

    // --- initial sync A → B (wire-level snapshot shuttle) ---
    let (_dir_b, vault_b) = open_vault();
    let materializer_b = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer_b);
    let snapshot = window_a.doc.export(ExportMode::Snapshot).unwrap();
    shuttle_update_to(WINDOW, &snapshot, &window_b);
    assert_eq!(
        vault_b.get(&id).unwrap().as_deref(),
        Some(b"offline-secret".as_slice()),
        "initial sync must materialize the entity on B"
    );
    // B indexes the body locally (so the purge assertion below is real).
    vault_b
        .batch()
        .text(&id, &[("body", "offline-secret")])
        .commit()
        .unwrap();
    assert_eq!(vault_b.search_text("offline-secret", 10).unwrap().len(), 1);

    // --- A deletes while OFFLINE ---
    let outcome = vault_a
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_a = outcome.receipt_id.expect("node A receipt");
    let request_id_a = receipt_request_id(&vault_a, &receipt_a);

    // --- reconnect: optimistic replay + optimistic clear ---
    let queue_a = SyncQueue::new(Arc::clone(&vault_a)).unwrap();
    let queued = queue_a.drain_updates().unwrap();
    assert_eq!(queued.len(), 1, "the delete-bearing row is queued");
    let max_seq = queued.last().unwrap().seq;
    // connection.rs runs the OPTIMISTIC clear after replay — the
    // delete-bearing row must survive it (the server may never have
    // applied the replayed bytes).
    queue_a.clear_through(max_seq).unwrap();
    let still_queued = queue_a.drain_updates().unwrap();
    assert_eq!(
        still_queued.len(),
        1,
        "delete-bearing update must survive the optimistic clear_through"
    );
    assert_eq!(still_queued[0].seq, max_seq);

    // --- the replay actually reaches B (wire-level shuttle) ---
    for update in &still_queued {
        shuttle_update_to(&update.window_key, &update.encoded, &window_b);
    }

    // B's LMDB purged…
    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "replayed hard delete must purge the replica's active store"
    );
    assert!(
        vault_b
            .search_text("offline-secret", 10)
            .unwrap()
            .is_empty()
    );

    // …B's tombstones map holds the v2 value…
    let value = map_get_bytes(&window_b.doc.get_map("tombstones"), &id.to_hex())
        .expect("replica tombstone");
    assert_eq!(value.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(value[0], 3, "gdpr_delete wire byte");

    // …and B holds its OWN local accountability artifacts, request_id
    // correlated with node A's receipt (M4-06 semantics).
    let sweeps_b = vault_b.sync_queue_rows_with_prefix(b"h:").unwrap();
    assert_eq!(
        sweeps_b.len(),
        1,
        "node B must enqueue a LOCAL h: sweep row"
    );
    let receipts_b = vault_b
        .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
        .unwrap();
    assert_eq!(receipts_b.len(), 1, "node B must write a LOCAL receipt");
    assert_eq!(
        receipt_request_id(&vault_b, &receipts_b[0]),
        request_id_a,
        "the replica receipt's request_id must come from the wire value"
    );
}

/// AC5 (SoftErase variant): a `user_delete` on A replays to B over the same
/// transport and leaves B the 25 B shell — no purge, no receipt, no sweep
/// row — and on A no carrier-15 scrub runs (soft deletes keep the window's
/// pending rows and set no full-resync marker).
#[test]
fn offline_soft_delete_replay_leaves_replica_shell() {
    // --- Node A: routed live window holding the entity ---
    let (_dir_a, vault_a) = open_vault();
    let id = EntityId::now();
    let (_manager_a, window_a) = open_routed_window(&vault_a, "node-a", &id, b"soft-secret");

    // --- initial sync A → B ---
    let (_dir_b, vault_b) = open_vault();
    let materializer_b = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer_b);
    let snapshot = window_a.doc.export(ExportMode::Snapshot).unwrap();
    shuttle_update_to(WINDOW, &snapshot, &window_b);
    vault_b
        .batch()
        .text(&id, &[("body", "soft-secret")])
        .commit()
        .unwrap();

    // A bystander queue row for the SAME window: soft deletes must NOT
    // scrub it (the carrier-15 simplification is pinned to hard reasons).
    let queue_a = SyncQueue::new(Arc::clone(&vault_a)).unwrap();
    let bystander_seq = queue_a.push(WINDOW, &[0xEE]).unwrap();

    let outcome = vault_a
        .delete_entity_with_reason(&id, DeleteReason::UserDelete)
        .unwrap();
    assert!(outcome.existed);
    assert!(
        outcome.receipt_id.is_none(),
        "soft delete writes no receipt"
    );

    // No scrub, no full-resync marker — but the delete IS queued.
    let queued = queue_a.drain_updates().unwrap();
    let seqs: Vec<u64> = queued.iter().map(|u| u.seq).collect();
    assert!(
        seqs.contains(&bystander_seq),
        "soft delete must not scrub the window's pending rows"
    );
    assert!(
        vault_a
            .sync_state_get(&format!("fr:w:{WINDOW}"))
            .unwrap()
            .is_none(),
        "soft delete must not mark the window for full resync"
    );
    let markers = delete_bearing_seqs(&vault_a);
    assert_eq!(markers.len(), 1, "the soft tombstone is delete-bearing too");

    // --- replay the delete-bearing row to B ---
    let delete_row = queued
        .iter()
        .find(|u| u.seq == markers[0])
        .expect("delete-bearing row");
    shuttle_update_to(&delete_row.window_key, &delete_row.encoded, &window_b);

    // Shell-preserving SoftErase on the replica.
    let raw = vault_b
        .get_raw(&id)
        .unwrap()
        .expect("user_delete replay must keep the 25 B shell on the replica");
    assert_eq!(raw.len(), 25);
    assert_eq!(vault_b.get(&id).unwrap().as_deref(), Some([].as_slice()));
    assert!(vault_b.search_text("soft-secret", 10).unwrap().is_empty());
    let value = map_get_bytes(&window_b.doc.get_map("tombstones"), &id.to_hex())
        .expect("replica tombstone");
    assert_eq!(value[0], 1, "user_delete wire byte (soft)");

    // Soft = no accountability artifacts on the replica.
    assert!(
        vault_b
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .is_empty(),
        "a soft replay must not write a receipt"
    );
    assert!(
        vault_b
            .sync_queue_rows_with_prefix(b"h:")
            .unwrap()
            .is_empty(),
        "a soft replay must not enqueue an h: sweep row"
    );
}
