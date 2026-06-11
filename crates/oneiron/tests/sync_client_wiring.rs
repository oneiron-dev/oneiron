//! Integration tests for SyncClient lifecycle wiring (ONE-1126).
//!
//! Pins the M4-09 acceptance criteria against ARCH-0023b contract literals:
//! - AC1: SyncClient windows are manager-owned `LoadedWindow`s; opening
//!   consults sync_state first (`d:w:` + pending `u:w:` replay).
//! - AC2: remote WindowSync UPDATE → Observer B materializes into the
//!   vault; remote tombstone → vault purged (hard-purge per the decode on
//!   this branch — M4-06 reason-aware semantics are not merged here).
//! - AC3: Observer A updates flow outbound — live connection channel when
//!   attached, durable SyncQueue otherwise.
//! - AC5: root doc persisted to `d:root` on change + reloaded on restart
//!   (with `u:root:*` replay); `m:client_id` minted once (u64 LE).
//! - AC6: `sv:`/`svf:` fast-reconnect reader — fresh flag answers the VV
//!   exchange from the persisted StateVector without a doc load.
//! - AC7: BulkTransfer routes into sync_state persistence (`bulk:w:` marker
//!   + `d:w:` write), fail-closed on invalid doc state.

#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer, VersionVector};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::{SyncClient, SyncClientConfig, SyncEvent};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::queue::SyncQueue;
use oneiron::sync::schema::{add_window_to_root, create_root_doc, create_window_doc};
use oneiron::sync::transport::{
    self, TAG_SYNC_UPDATE, TAG_WINDOW_SYNC, TransportError, window_sub_tags,
};
use oneiron::sync::types::WindowKey;
use oneiron::{EntityId, HnswConfig, Vault, VaultConfig};
use tokio::sync::mpsc::UnboundedReceiver;

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

fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// 2026-01-15 00:00:00 UTC — inside window 2026-01, OUTSIDE 2026-03. Tests
/// use the mismatch deliberately: restart assertions then can only pass via
/// the persisted `u:w:` replay, never via reverse re-materialization of the
/// window's learned_at range.
const LEARNED_JAN_2026: u64 = 1_768_435_200;

// ─── AC1 + AC2: remote update → Observer B → vault; survives restart ────────

#[test]
fn remote_window_update_materializes_entity_and_survives_restart() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, _rx) = make_client(&manager);

    let id = EntityId::now();
    let blob = make_entity_blob(1, LEARNED_JAN_2026, b"remote-entity");

    // Server-side doc for window 2026-03 carrying the entity.
    let server_doc = create_window_doc("server", &WindowKey::new("2026-03"));
    server_doc
        .get_map("entities")
        .insert(&id.to_hex(), blob.as_slice())
        .unwrap();
    server_doc.commit();
    let update = server_doc.export(ExportMode::all_updates()).unwrap();

    let msg = transport::encode_window_sync("2026-03", window_sub_tags::UPDATE, &update);
    let responses = client.handle_server_message(&msg).unwrap();
    assert!(responses.is_empty());

    // Observer B materialized the remote entity into the vault.
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(b"remote-entity".as_slice()),
        "remote WindowSync UPDATE must reach LMDB via Observer B"
    );

    // The accepted remote update was persisted under the contract row
    // format `u:w:{key}:{seq:08x}` (ARCH-0023b key table).
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some(),
        "accepted remote update must persist as a u:w: row"
    );

    // Manager-owned registry: the client's window IS the manager's window.
    let via_client = client.ensure_window("2026-03").unwrap();
    let via_manager = manager.open_window(&WindowKey::new("2026-03")).unwrap();
    assert!(
        Arc::ptr_eq(&via_client, &via_manager),
        "SyncClient and manager must share the same live doc instance"
    );
    drop(via_client);
    drop(via_manager);

    // "Restart": a fresh manager over the same vault. The entity's
    // learned_at (January) is OUTSIDE window 2026-03, so reverse remat
    // cannot reconstruct the doc — only the persisted u:w: replay can.
    let manager2 = make_manager(&vault);
    let reopened = manager2.open_window(&WindowKey::new("2026-03")).unwrap();
    assert_eq!(
        map_get_bytes(&reopened.doc.get_map("entities"), &id.to_hex()).as_deref(),
        Some(blob.as_slice()),
        "remote update must survive restart through d:w: + u:w: replay"
    );
}

#[test]
fn remote_tombstone_purges_entity_and_survives_restart() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, _rx) = make_client(&manager);

    let id = EntityId::now();
    let hex_id = id.to_hex();
    let blob = make_entity_blob(1, LEARNED_JAN_2026, b"to-be-deleted");

    let server_doc = create_window_doc("server", &WindowKey::new("2026-03"));
    server_doc
        .get_map("entities")
        .insert(&hex_id, blob.as_slice())
        .unwrap();
    server_doc.commit();
    let v1 = server_doc.export(ExportMode::all_updates()).unwrap();
    client
        .handle_server_message(&transport::encode_window_sync(
            "2026-03",
            window_sub_tags::UPDATE,
            &v1,
        ))
        .unwrap();
    assert!(vault.get(&id).unwrap().is_some());

    // v2: the server tombstones the entity. Current decode on this branch
    // is reason-less hard purge (M4-06 reason-aware semantics not merged):
    // Observer B routes every tombstone through purge_entity_active_store.
    server_doc
        .get_map("tombstones")
        .insert(&hex_id, &LEARNED_JAN_2026.to_le_bytes())
        .unwrap();
    server_doc.commit();
    let v2 = server_doc.export(ExportMode::all_updates()).unwrap();
    client
        .handle_server_message(&transport::encode_window_sync(
            "2026-03",
            window_sub_tags::UPDATE,
            &v2,
        ))
        .unwrap();

    assert!(
        vault.get(&id).unwrap().is_none(),
        "remote tombstone must purge the entity from the vault"
    );
    assert!(!vault.entity_exists(&id).unwrap());

    // Delete survival across restart: the tombstone lives ONLY in the CRDT
    // (LMDB row is purged), so it must come back through the u:w: replay.
    // Losing it would weaken delete semantics — fail-closed.
    let manager2 = make_manager(&vault);
    let reopened = manager2.open_window(&WindowKey::new("2026-03")).unwrap();
    assert!(
        map_get_bytes(&reopened.doc.get_map("tombstones"), &hex_id).is_some(),
        "remote tombstone must survive restart through the u:w: replay"
    );
    assert!(
        vault.get(&id).unwrap().is_none(),
        "reopening the window must not resurrect the purged entity"
    );
}

// ─── AC3: Observer A → outbound (channel when attached, queue otherwise) ────

#[test]
fn local_commit_flows_to_attached_outbound_channel_as_window_sync_update() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);

    // "Connected": the test harness channel plays the connection's local_rx.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.outbound().attach(tx);

    let window = manager.open_window(&WindowKey::new("2026-03")).unwrap();
    let id = EntityId::now();
    let blob = make_entity_blob(1, LEARNED_JAN_2026, b"outbound-entity");
    window
        .doc
        .get_map("entities")
        .insert(&id.to_hex(), blob.as_slice())
        .unwrap();
    window.doc.commit();

    // The entity was written to the vault (Observer B)...
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(b"outbound-entity".as_slice())
    );

    // ...and Observer A routed the persisted update to the live channel.
    let update = rx
        .try_recv()
        .expect("Observer A must feed the attached outbound channel");
    assert_eq!(update.window_key, "2026-03");

    // The connection's send path wire-encodes it as a WindowSync UPDATE.
    let wire = transport::encode_window_sync(
        &update.window_key,
        window_sub_tags::UPDATE,
        &update.update_bytes,
    );
    assert_eq!(wire[0], TAG_WINDOW_SYNC);
    let (key, sub_tag, payload) = transport::decode_window_sync(&wire[1..]).unwrap();
    assert_eq!(key, "2026-03");
    assert_eq!(sub_tag, window_sub_tags::UPDATE);

    // The update bytes are a valid Loro update carrying the entity.
    let receiver_doc = LoroDoc::new();
    receiver_doc.import(payload).unwrap();
    assert_eq!(
        map_get_bytes(&receiver_doc.get_map("entities"), &id.to_hex()).as_deref(),
        Some(blob.as_slice()),
        "outbound update must reproduce the entity on the receiving side"
    );

    // Connected → the durable queue is NOT used.
    let queue = SyncQueue::new(Arc::clone(&vault)).unwrap();
    assert!(queue.is_empty().unwrap());
}

#[test]
fn local_commit_buffers_to_sync_queue_when_disconnected() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let window = manager.open_window(&WindowKey::new("2026-03")).unwrap();
    let queue = SyncQueue::new(Arc::clone(&vault)).unwrap();

    // (a) Never attached → durable queue.
    let first = EntityId::now();
    window
        .doc
        .get_map("entities")
        .insert(
            &first.to_hex(),
            make_entity_blob(1, LEARNED_JAN_2026, b"offline-1").as_slice(),
        )
        .unwrap();
    window.doc.commit();

    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 1, "offline update must land in sync_queue");
    assert_eq!(updates[0].window_key, "2026-03");
    let receiver_doc = LoroDoc::new();
    receiver_doc.import(&updates[0].encoded).unwrap();
    assert!(map_get_bytes(&receiver_doc.get_map("entities"), &first.to_hex()).is_some());

    // (b) Attached but the receiver is gone (connection died) → fall back
    // to the durable queue instead of dropping the update on the floor.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    manager.outbound().attach(tx);
    drop(rx);

    let second = EntityId::now();
    window
        .doc
        .get_map("entities")
        .insert(
            &second.to_hex(),
            make_entity_blob(1, LEARNED_JAN_2026, b"offline-2").as_slice(),
        )
        .unwrap();
    window.doc.commit();

    let updates = queue.drain_updates().unwrap();
    assert_eq!(
        updates.len(),
        2,
        "update with a dead receiver must fall back to sync_queue"
    );
    // Replay in sequence order, as connect_and_sync does — Loro local
    // updates are deltas, so the second depends on the first.
    let receiver_doc = LoroDoc::new();
    receiver_doc.import(&updates[0].encoded).unwrap();
    receiver_doc.import(&updates[1].encoded).unwrap();
    assert!(map_get_bytes(&receiver_doc.get_map("entities"), &first.to_hex()).is_some());
    assert!(map_get_bytes(&receiver_doc.get_map("entities"), &second.to_hex()).is_some());
}

// ─── AC5: root doc persistence + client id ──────────────────────────────────

#[test]
fn root_doc_persists_on_change_and_reloads_on_restart_with_u_root_replay() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, _rx) = make_client(&manager);

    assert!(vault.sync_state_get("d:root").unwrap().is_none());

    let server_root = create_root_doc(
        "user-1",
        "vault-1",
        &[WindowKey::new("2026-01"), WindowKey::new("2026-02")],
    );
    let snapshot = server_root.export(ExportMode::Snapshot).unwrap();
    let mut msg = vec![TAG_SYNC_UPDATE];
    msg.extend_from_slice(&snapshot);
    client.handle_server_message(&msg).unwrap();
    assert_eq!(client.server_windows(), vec!["2026-01", "2026-02"]);

    // Contract rows (ARCH-0023b key table): d:root snapshot, sv:root
    // (StateVector V1 — must decode), svf:root freshness byte.
    assert!(
        vault.sync_state_get("d:root").unwrap().is_some(),
        "root import must persist d:root"
    );
    let sv_root = vault
        .sync_state_get("sv:root")
        .unwrap()
        .expect("root import must persist sv:root");
    VersionVector::decode(&sv_root).expect("sv:root must be StateVector V1 encoded");
    assert_eq!(
        vault.sync_state_get("svf:root").unwrap().as_deref(),
        Some([1u8].as_slice())
    );

    // Restart: a fresh client reloads the windows without any server help.
    let (client2, _rx2) = make_client(&manager);
    assert_eq!(
        client2.server_windows(),
        vec!["2026-01", "2026-02"],
        "root doc must reload from d:root on restart"
    );

    // Pending u:root: rows apply on top of d:root (startup step 1).
    add_window_to_root(&server_root, &WindowKey::new("2026-03"));
    let pending = server_root.export(ExportMode::all_updates()).unwrap();
    vault.sync_state_put("u:root:00000001", &pending).unwrap();
    let (client3, _rx3) = make_client(&manager);
    assert_eq!(
        client3.server_windows(),
        vec!["2026-01", "2026-02", "2026-03"],
        "pending u:root: updates must replay on top of d:root"
    );
}

// ─── AC6: sv:/svf: fast-reconnect reader ────────────────────────────────────

#[test]
fn fast_reconnect_reuses_persisted_sv_without_doc_load_when_svf_fresh() {
    let (_temp, vault) = test_vault();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let current = WindowKey::from_timestamp(now_secs);

    // Session A: write into the current window, then unload (persists
    // d:w: + sv:w: + svf:w: = fresh).
    let manager_a = make_manager(&vault);
    let window = manager_a.open_window(&current).unwrap();
    let id = EntityId::now();
    window
        .doc
        .get_map("entities")
        .insert(
            &id.to_hex(),
            make_entity_blob(1, now_secs, b"sv-entity").as_slice(),
        )
        .unwrap();
    window.doc.commit();
    let expected_vv: serde_json::Value = serde_json::to_value(window.doc.oplog_vv()).unwrap();
    drop(window);
    assert!(manager_a.unload_window(&current).unwrap());
    assert_eq!(
        vault
            .sync_state_get(&format!("svf:w:{current}"))
            .unwrap()
            .as_deref(),
        Some([1u8].as_slice()),
        "unload must leave the state vector fresh"
    );

    // Session B (fast reconnect): nothing loaded. The initial sync answers
    // the VV exchange for the current window from sv:w: alone.
    let manager_b = make_manager(&vault);
    let (client, _rx) = make_client(&manager_b);
    let messages = client.generate_initial_sync();

    let mut found = None;
    for msg in &messages {
        if msg[0] != TAG_WINDOW_SYNC {
            continue;
        }
        let (key, sub_tag, payload) = transport::decode_window_sync(&msg[1..]).unwrap();
        if key == current.as_str() {
            assert_eq!(sub_tag, window_sub_tags::VV_REQUEST);
            found = Some(serde_json::from_slice::<serde_json::Value>(payload).unwrap());
        }
    }
    assert_eq!(
        found.expect("initial sync must include the current window VV"),
        expected_vv,
        "fast-reconnect VV must equal the persisted doc's version vector"
    );
    assert!(
        manager_b.window(&current).is_none(),
        "fresh svf must answer the VV exchange WITHOUT loading the window doc"
    );

    // Stale flag → full manager open instead of trusting sv:w:.
    vault
        .sync_state_put(&format!("svf:w:{current}"), &[0u8])
        .unwrap();
    let manager_c = make_manager(&vault);
    let (client_c, _rx_c) = make_client(&manager_c);
    let _ = client_c.generate_initial_sync();
    assert!(
        manager_c.window(&current).is_some(),
        "stale svf must fall back to a full window open"
    );
}

// ─── AC7: BulkTransfer → sync_state persistence, fail-closed ────────────────

#[test]
fn bulk_transfer_done_persists_unloaded_window_state_for_next_open() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, mut rx) = make_client(&manager);

    // 2025-11-15 — inside historical window 2025-11.
    let learned_at = 1_763_164_800u64;
    let id = EntityId::now();
    let blob = make_entity_blob(1, learned_at, b"historical-entity");
    let state_doc = create_window_doc("server", &WindowKey::new("2025-11"));
    state_doc
        .get_map("entities")
        .insert(&id.to_hex(), blob.as_slice())
        .unwrap();
    state_doc.commit();
    let snapshot = state_doc.export(ExportMode::Snapshot).unwrap();

    let done = transport::encode_bulk_transfer_done("2025-11", &snapshot);
    client.handle_server_message(&done).unwrap();
    assert!(matches!(
        rx.try_recv(),
        Ok(SyncEvent::BulkTransferComplete { window_key }) if window_key == "2025-11"
    ));

    // Stays ON-DISK (Phase-3 historical window), with the contract rows set.
    assert!(client.window("2025-11").is_none());
    assert_eq!(
        vault.sync_state_get("d:w:2025-11").unwrap().as_deref(),
        Some(snapshot.as_slice())
    );
    let sv = vault
        .sync_state_get("sv:w:2025-11")
        .unwrap()
        .expect("BulkTransferDone must persist sv:w:");
    VersionVector::decode(&sv).expect("sv:w: must be StateVector V1 encoded");
    assert_eq!(
        vault.sync_state_get("svf:w:2025-11").unwrap().as_deref(),
        Some([1u8].as_slice())
    );

    // The next open loads the persisted state and forward remat
    // materializes it into the vault.
    let reopened = manager.open_window(&WindowKey::new("2025-11")).unwrap();
    assert!(map_get_bytes(&reopened.doc.get_map("entities"), &id.to_hex()).is_some());
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(b"historical-entity".as_slice()),
        "bulk-transferred window state must materialize on first open"
    );
}

#[test]
fn bulk_transfer_done_rejects_invalid_doc_state_and_keeps_marker() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, _rx) = make_client(&manager);

    // BulkTransfer sets the in-progress marker.
    let msgpack = rmp_serde::to_vec(&serde_json::json!({})).unwrap();
    let compressed = zstd::stream::encode_all(msgpack.as_slice(), 0).unwrap();
    let bulk = transport::encode_bulk_transfer("2025-11", &compressed);
    client.handle_server_message(&bulk).unwrap();
    assert_eq!(
        vault.sync_state_get("bulk:w:2025-11").unwrap().as_deref(),
        Some([1u8].as_slice())
    );

    // Garbage doc state must be rejected (a trusted door still validates
    // structure) and the in-progress marker must STAY for retry.
    let done = transport::encode_bulk_transfer_done("2025-11", b"doc-state");
    let err = client.handle_server_message(&done).unwrap_err();
    assert!(
        matches!(
            err,
            TransportError::InvalidPayload("bulk doc state invalid")
        ),
        "invalid bulk doc state must fail closed, got {err:?}"
    );
    assert_eq!(
        vault.sync_state_get("bulk:w:2025-11").unwrap().as_deref(),
        Some([1u8].as_slice()),
        "failed persistence must leave the in-progress marker set"
    );
    assert!(
        vault.sync_state_get("d:w:2025-11").unwrap().is_none(),
        "invalid doc state must never reach d:w:"
    );
}

#[test]
fn bulk_transfer_done_imports_into_live_window_when_loaded() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, mut rx) = make_client(&manager);

    // Window already live — bulk state must flow through the observed doc.
    let live = client.ensure_window("2025-11").unwrap();

    let learned_at = 1_763_164_800u64;
    let id = EntityId::now();
    let blob = make_entity_blob(1, learned_at, b"live-bulk-entity");
    let state_doc = create_window_doc("server", &WindowKey::new("2025-11"));
    state_doc
        .get_map("entities")
        .insert(&id.to_hex(), blob.as_slice())
        .unwrap();
    state_doc.commit();
    let snapshot = state_doc.export(ExportMode::Snapshot).unwrap();

    let done = transport::encode_bulk_transfer_done("2025-11", &snapshot);
    client.handle_server_message(&done).unwrap();
    assert!(matches!(
        rx.try_recv(),
        Ok(SyncEvent::BulkTransferComplete { window_key }) if window_key == "2025-11"
    ));

    // Observer B materialized the imported state into the vault...
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(b"live-bulk-entity".as_slice()),
        "bulk state imported into a live window must materialize via Observer B"
    );
    // ...the live doc carries it...
    assert!(map_get_bytes(&live.doc.get_map("entities"), &id.to_hex()).is_some());
    // ...and the merged state was persisted.
    assert!(vault.sync_state_get("d:w:2025-11").unwrap().is_some());
}
