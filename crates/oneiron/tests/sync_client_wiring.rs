// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
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

mod sync_harness;

use core::assert_matches;
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
use sync_harness::make_entity_blob;
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

/// Review rider (PR #104 bot finding #17): the UPDATE arm imports into the
/// live doc BEFORE persisting the `u:w:` row (deliberate — persist-first
/// would brick window load on a malformed frame). On a FAILED persist,
/// though, the import has already advanced the live doc's version vector;
/// pre-fix the window stayed registered with RAM ahead of durable state,
/// so the next VV exchange told the server we already held the update — it
/// was never re-sent and vanished on restart (tombstones included): the
/// client analog of the ONE-1129 server import-before-persist bug. The fix
/// DISCARDS the live window (no persist — that would durably commit the
/// unconfirmed import) and surfaces a typed Storage error.
#[test]
fn failed_update_persist_discards_live_window_instead_of_running_ahead() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, _rx) = make_client(&manager);

    let id = EntityId::now();
    let blob = make_entity_blob(1, LEARNED_JAN_2026, b"never-durable");

    let server_doc = create_window_doc("server", &WindowKey::new("2026-03"));
    server_doc
        .get_map("entities")
        .insert(&id.to_hex(), blob.as_slice())
        .unwrap();
    server_doc.commit();
    let server_peer = server_doc.peer_id();
    let update = server_doc.export(ExportMode::all_updates()).unwrap();

    // Open the window through the client, then corrupt the u_seq row so
    // persist_window_update fails closed (CorruptedIndex) AFTER the import
    // succeeded — the exact RAM-ahead-of-durable interleaving.
    client.ensure_window("2026-03").unwrap();
    vault
        .sync_state_put("m:u_seq:w:2026-03", &[0xBA, 0xD0])
        .unwrap();

    let err = client
        .handle_server_message(&transport::encode_window_sync(
            "2026-03",
            window_sub_tags::UPDATE,
            &update,
        ))
        .expect_err("a failed u:w: persist must surface, not be swallowed");
    assert!(
        matches!(err, TransportError::Storage(_)),
        "typed Storage error, got: {err:?}"
    );

    // The live window was DISCARDED — not left registered holding the
    // unpersisted import (the pre-fix implementation fails here).
    assert!(
        manager.window(&WindowKey::new("2026-03")).is_none(),
        "failed persist must evict the live window from the registry"
    );
    // The whole persist txn aborted: no u:w: row for the failed update.
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_none()
    );
    // Accepted residual (same shape as the server fix): Observer B already
    // materialized the import into LMDB before the persist failed. LMDB is
    // local truth; the doc heals via re-delivery, not by un-applying.
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(b"never-durable".as_slice())
    );

    // Heal the corrupt row (doctor-shaped repair), reopen through the
    // client: the reloaded doc must NOT contain the failed update — the
    // server's peer is absent from its VV, so the ONE-1127/1128 VV
    // exchange re-delivers the bytes instead of skipping them.
    vault
        .sync_state_put("m:u_seq:w:2026-03", &0u32.to_le_bytes())
        .unwrap();
    let reopened = client.ensure_window("2026-03").unwrap();
    assert!(
        reopened.doc.oplog_vv().get(&server_peer).is_none(),
        "reloaded doc must not claim the never-persisted update in its VV"
    );
    assert!(
        map_get_bytes(&reopened.doc.get_map("entities"), &id.to_hex()).is_none(),
        "the never-durable update must not reappear in the reloaded doc"
    );
}

/// ONE-1151 reconnect dedupe: a server UPDATE frame whose ops the live doc
/// already holds (each reconnect echoes frames the client persisted long
/// ago) must NOT persist again — no new `u:w:{key}:{seq:08x}` row, no
/// `m:u_seq:w:{key}` bump, no `svf:w:{key}` stale flip, no WindowUpdated
/// event. A frame carrying ANY new op still persists in full (the
/// over-skip direction would silently drop accepted remote data).
#[test]
fn reconnect_echo_update_is_not_repersisted_and_svf_stays_fresh() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, mut rx) = make_client(&manager);

    let id_one = EntityId::now();
    let server_doc = create_window_doc("server", &WindowKey::new("2026-03"));
    server_doc
        .get_map("entities")
        .insert(
            &id_one.to_hex(),
            make_entity_blob(1, LEARNED_JAN_2026, b"first-delivery").as_slice(),
        )
        .unwrap();
    server_doc.commit();
    let frame_one = server_doc.export(ExportMode::all_updates()).unwrap();

    // First delivery: persisted under the contract row + svf flipped stale.
    client
        .handle_server_message(&transport::encode_window_sync(
            "2026-03",
            window_sub_tags::UPDATE,
            &frame_one,
        ))
        .unwrap();
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([0u8].as_slice())
    );

    // Snapshot persist: prunes the subsumed row, marks sv:w: fresh.
    let live = client.ensure_window("2026-03").unwrap();
    live.persist_state(&vault).unwrap();
    drop(live);
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([1u8].as_slice())
    );
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_none()
    );
    while rx.try_recv().is_ok() {} // drain pre-echo events

    // Reconnect echo: the SAME frame again. Nothing may change.
    let responses = client
        .handle_server_message(&transport::encode_window_sync(
            "2026-03",
            window_sub_tags::UPDATE,
            &frame_one,
        ))
        .unwrap();
    assert!(responses.is_empty());
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .is_none(),
        "an echoed frame must not append a duplicate u:w: row"
    );
    assert_eq!(
        vault
            .sync_state_get("m:u_seq:w:2026-03")
            .unwrap()
            .as_deref(),
        Some(1u32.to_le_bytes().as_slice()),
        "an echoed frame must not bump the u_seq high-water mark"
    );
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([1u8].as_slice()),
        "svf must not flip when nothing new was persisted"
    );
    assert!(
        rx.try_recv().is_err(),
        "a no-op echo must not announce WindowUpdated"
    );

    // Over-skip guard: a frame with NEW ops (all_updates export — the
    // echoed prefix is included, so this is a partially-known frame) must
    // persist in full and flip svf stale again.
    let id_two = EntityId::now();
    server_doc
        .get_map("entities")
        .insert(
            &id_two.to_hex(),
            make_entity_blob(1, LEARNED_JAN_2026, b"second-delivery").as_slice(),
        )
        .unwrap();
    server_doc.commit();
    let frame_two = server_doc.export(ExportMode::all_updates()).unwrap();
    client
        .handle_server_message(&transport::encode_window_sync(
            "2026-03",
            window_sub_tags::UPDATE,
            &frame_two,
        ))
        .unwrap();
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .as_deref(),
        Some(frame_two.as_slice()),
        "a partially-known frame with new ops must persist verbatim"
    );
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([0u8].as_slice()),
        "new persisted ops must flip svf back to stale"
    );
    assert_matches!(rx.try_recv(), Ok(SyncEvent::WindowUpdated { window_key }) if window_key == "2026-03");
    assert_eq!(
        vault.get(&id_two).unwrap().as_deref(),
        Some(b"second-delivery".as_slice()),
        "the new op must still materialize via Observer B"
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
        .map_or(0, |d| d.as_secs());
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
    let expected_vv = window.doc.oplog_vv();
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
            // ONE-1127: wire VVs are Loro binary `VersionVector::encode()`
            // bytes — the JSON VV encoding is dead.
            found = Some(
                VersionVector::decode(payload)
                    .expect("VV_REQUEST payload must be Loro binary VV (ONE-1127)"),
            );
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

/// ONE-1151 svf-freshness fix (consumer side): when `persist_state` leaves a
/// surviving post-merge `u:w:` row, `svf:w:` is STALE — so the fast-reconnect
/// reader must NOT take the `sv:w:` shortcut. It full-opens the window and
/// ships a VV that INCLUDES the survivor's ops; trusting the bare `sv:w:` VV
/// would silently omit the survivor from the exchange.
#[test]
fn fast_reconnect_omits_nothing_when_a_survivor_exists() {
    use loro::ContainerTrait;

    let (_temp, vault) = test_vault();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let current = WindowKey::from_timestamp(now_secs);

    let manager_a = make_manager(&vault);
    let window = manager_a.open_window(&current).unwrap();

    // Pre-seed `u:w:{current}:00000001` with an op the freshly-opened doc
    // does NOT hold, so persist_state's merge import diffs (firing the
    // injection). This row IS in the merge inventory → pruned.
    let seed = create_window_doc("seed", &current);
    let seed_id = EntityId::now();
    seed.get_map("entities")
        .insert(
            &seed_id.to_hex(),
            make_entity_blob(1, now_secs, b"seed").as_slice(),
        )
        .unwrap();
    seed.commit();
    let seed_bytes = seed.export(ExportMode::all_updates()).unwrap();
    vault
        .sync_state_put(&format!("u:w:{current}:00000001"), &seed_bytes)
        .unwrap();
    vault
        .sync_state_put(&format!("m:u_seq:w:{current}"), &1u32.to_le_bytes())
        .unwrap();

    // The survivor op (transient parallel writer): absent from the merge
    // inventory AND from the exported snapshot.
    let late = create_window_doc("late", &current);
    let late_id = EntityId::now();
    late.get_map("entities")
        .insert(
            &late_id.to_hex(),
            make_entity_blob(1, now_secs, b"late").as_slice(),
        )
        .unwrap();
    late.commit();
    let late_bytes = late.export(ExportMode::all_updates()).unwrap();

    // Inject the survivor row DURING the merge import (after the prune
    // inventory was captured, before the write txn).
    let injected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cb_vault = Arc::clone(&vault);
    let cb_key = current.to_string();
    let cb_bytes = late_bytes;
    let cb_flag = Arc::clone(&injected);
    let entities_cid = window.doc.get_map("entities").id();
    let _inj = window.doc.subscribe(
        &entities_cid,
        Arc::new(move |_event| {
            if cb_flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            cb_vault
                .sync_state_put(&format!("u:w:{cb_key}:00000002"), &cb_bytes)
                .unwrap();
            cb_vault
                .sync_state_put(&format!("m:u_seq:w:{cb_key}"), &2u32.to_le_bytes())
                .unwrap();
        }),
    );

    // Release the test's window handle before unload: #114 (ONE-1150) arc-guard
    // refuses to unload a window with an outstanding `Arc<LoadedWindow>`. The
    // manager keeps the doc alive via its registry ref, so the `_inj`
    // subscription still fires during persist_state.
    drop(window);

    // Drive persistence through the manager's unload (persist_state inside).
    assert!(manager_a.unload_window(&current).unwrap());
    assert!(
        injected.load(std::sync::atomic::Ordering::SeqCst),
        "injection must have fired during the merge import"
    );
    drop(_inj);

    // The survivor remains and svf is STALE.
    assert!(
        vault
            .sync_state_get(&format!("u:w:{current}:00000002"))
            .unwrap()
            .is_some(),
        "the post-merge survivor row must remain after the prune"
    );
    assert_eq!(
        vault
            .sync_state_get(&format!("svf:w:{current}"))
            .unwrap()
            .as_deref(),
        Some([0u8].as_slice()),
        "a surviving post-merge u:w: row must leave svf STALE"
    );

    // The bare sv:w: VV (snapshot only) versus the full recovered VV (snapshot
    // + survivor replay). The two MUST differ — that's the whole point.
    let bare_vv = VersionVector::decode(
        &vault
            .sync_state_get(&format!("sv:w:{current}"))
            .unwrap()
            .expect("sv:w: persisted"),
    )
    .unwrap();
    let full_vv = oneiron::sync::window::load_window_from_state(&vault, "test-user", &current)
        .unwrap()
        .oplog_vv();
    assert_ne!(
        full_vv, bare_vv,
        "the survivor's ops must extend the doc VV beyond the bare sv:w:"
    );

    // Consumer: a fresh client's initial sync must full-open (NOT trust svf)
    // and ship the FULL VV, not the bare sv:w: VV.
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
            found = Some(VersionVector::decode(payload).unwrap());
        }
    }
    let shipped = found.expect("initial sync must include the current window VV");
    assert!(
        manager_b.window(&current).is_some(),
        "stale svf must full-open the window instead of trusting sv:w:"
    );
    assert_eq!(
        shipped, full_vv,
        "the shipped VV must include the survivor's ops (full doc VV)"
    );
    assert_ne!(
        shipped, bare_vv,
        "the shipped VV must NOT be the bare sv:w: VV that omits the survivor"
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
    assert_matches!(rx.try_recv(), Ok(SyncEvent::BulkTransferComplete { window_key }) if window_key == "2025-11");

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

    // Garbage doc state must be rejected and the in-progress marker must
    // STAY for retry. ONE-1156 (WAVE-C OD-12): the ON-DISK arm now routes
    // through the OBSERVED import — the rejection literal is the import
    // failure (`doc_from_snapshot`'s structure-only pre-check arm was
    // deleted; Observer B's doors are the validation now).
    let done = transport::encode_bulk_transfer_done("2025-11", b"doc-state");
    let err = client.handle_server_message(&done).unwrap_err();
    assert!(
        matches!(
            err,
            TransportError::InvalidPayload("bulk doc state import failed")
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
    // OD-12 fail-closed discard: the window opened for the import must not
    // stay registered holding the failed state.
    assert!(
        client.window("2025-11").is_none(),
        "a failed bulk import must discard the just-opened window"
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
    assert_matches!(rx.try_recv(), Ok(SyncEvent::BulkTransferComplete { window_key }) if window_key == "2025-11");

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

/// ONE-1154: the live-window BulkTransferDone arm imports BEFORE persisting
/// (same deliberate ordering as the UPDATE arm). On a FAILED persist the
/// import has already advanced the live doc's version vector; pre-fix the
/// window stayed registered with RAM ahead of durable state — the next VV
/// exchange told the server we already held the bulk ops, so they were
/// never re-sent and vanished on restart. The fix mirrors the UPDATE arm:
/// DISCARD the live window (no persist — that would durably commit the
/// unconfirmed import), surface the typed Storage error, and leave the
/// `bulk:w:` in-progress marker set for retry.
#[test]
fn failed_bulk_persist_discards_live_window_instead_of_running_ahead() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, mut rx) = make_client(&manager);

    // Window live BEFORE the bulk transfer — routes Done into the
    // live-window arm. learned_at (January 2026) is OUTSIDE window
    // 2026-03, so the recovery assertions below can only pass via
    // persisted doc state, never via reverse re-materialization.
    client.ensure_window("2026-03").unwrap();

    let id = EntityId::now();
    let blob = make_entity_blob(1, LEARNED_JAN_2026, b"never-durable-bulk");
    let state_doc = create_window_doc("server", &WindowKey::new("2026-03"));
    state_doc
        .get_map("entities")
        .insert(&id.to_hex(), blob.as_slice())
        .unwrap();
    state_doc.commit();
    let server_peer = state_doc.peer_id();
    let snapshot = state_doc.export(ExportMode::Snapshot).unwrap();

    // BulkTransfer sets the `bulk:w:` in-progress marker (ARCH-0023b).
    let msgpack = rmp_serde::to_vec(&serde_json::json!({})).unwrap();
    let compressed = zstd::stream::encode_all(msgpack.as_slice(), 0).unwrap();
    client
        .handle_server_message(&transport::encode_bulk_transfer("2026-03", &compressed))
        .unwrap();

    // Corrupt d:w: so persist_state's anti-clobber merge (ONE-1135) fails
    // closed AFTER the live import succeeded — the exact
    // RAM-ahead-of-durable interleaving.
    vault
        .sync_state_put("d:w:2026-03", b"corrupt-snapshot")
        .unwrap();

    let done = transport::encode_bulk_transfer_done("2026-03", &snapshot);
    let err = client
        .handle_server_message(&done)
        .expect_err("a failed bulk persist must surface, not be swallowed");
    assert!(
        matches!(err, TransportError::Storage(_)),
        "typed Storage error, got: {err:?}"
    );

    // The live window was DISCARDED — not left registered holding the
    // unpersisted import (the pre-fix implementation fails here).
    assert!(
        manager.window(&WindowKey::new("2026-03")).is_none(),
        "failed bulk persist must evict the live window from the registry"
    );
    // Fail-closed marker ordering: the `bulk:w:` clear only runs after a
    // successful persist, so the marker must STAY set for retry.
    assert_eq!(
        vault.sync_state_get("bulk:w:2026-03").unwrap().as_deref(),
        Some([1u8].as_slice()),
        "failed bulk persist must leave the in-progress marker set"
    );
    // No completion event for a failed transfer.
    assert!(
        rx.try_recv().is_err(),
        "BulkTransferComplete must not fire on a failed persist"
    );
    // Accepted residual (same shape as the UPDATE-arm fix): Observer B
    // already materialized the import into LMDB before the persist failed.
    // LMDB is local truth; the doc heals via re-delivery, not un-applying.
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(b"never-durable-bulk".as_slice())
    );

    // Heal the corrupt row (doctor-shaped repair: durable state never held
    // the bulk ops, so a valid empty-window snapshot IS the durable
    // truth), reopen through the client: the reloaded doc must NOT contain
    // the failed bulk import — the server's peer is absent from its VV, so
    // the ONE-1127/1128 VV exchange re-delivers the bytes instead of
    // skipping them.
    let empty_doc = create_window_doc("test-user", &WindowKey::new("2026-03"));
    let empty_snapshot = empty_doc.export(ExportMode::Snapshot).unwrap();
    vault
        .sync_state_put("d:w:2026-03", &empty_snapshot)
        .unwrap();
    let reopened = client.ensure_window("2026-03").unwrap();
    assert!(
        reopened.doc.oplog_vv().get(&server_peer).is_none(),
        "reloaded doc must not claim the never-persisted bulk ops in its VV"
    );
    assert!(
        map_get_bytes(&reopened.doc.get_map("entities"), &id.to_hex()).is_none(),
        "the never-durable bulk import must not reappear in the reloaded doc"
    );
}

/// ONE-1151 fail-closed echo durability (R3): a LOCAL op that Observer A
/// committed to the live doc but could NOT persist as a `u:w:` row (e.g. a
/// corrupt `m:u_seq` row failing closed) leaves durable state behind the live
/// doc. A later no-op reconnect echo (a frame whose ops the live doc already
/// holds → `oplog_vv` unchanged) must rebuild the durable witness and persist
/// the missing live-doc delta, so the op gets its durable `u:w:` row instead
/// of vanishing on the next restart. The buggy plain-early-return impl
/// persists nothing → no `u:w:` row → fails.
#[test]
fn persist_failed_local_op_survives_via_echo_no_op() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, _rx) = make_client(&manager);

    let live = client.ensure_window("2026-03").unwrap();

    // Corrupt the u_seq counter (2 bytes != 4) so the NEXT Observer A persist
    // fails closed (CorruptedIndex) AFTER the CRDT op is already committed:
    // the exact "op in the live doc, no durable u:w: row" interleaving the
    // durable-coverage gate exists for.
    vault
        .sync_state_put("m:u_seq:w:2026-03", &[0xBA, 0xD0])
        .unwrap();
    let id = EntityId::now();
    live.doc
        .get_map("entities")
        .insert(
            &id.to_hex(),
            make_entity_blob(1, LEARNED_JAN_2026, b"persist-failed-local").as_slice(),
        )
        .unwrap();
    live.doc.commit(); // fires Observer A -> persist fails, live doc is ahead

    // Precondition: the op is in the doc, NO durable u:w: row.
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_none(),
        "the failed local persist must leave no u:w: row"
    );

    // Heal the corrupt counter so the coverage-gate persist can succeed.
    vault
        .sync_state_put("m:u_seq:w:2026-03", &0u32.to_le_bytes())
        .unwrap();

    // No-op echo: feed the live doc its OWN current state back as an UPDATE
    // frame. The import adds no new ops (oplog_vv unchanged), so the handler
    // takes the no-op path, where durable coverage is still checked.
    let echo = live.doc.export(ExportMode::all_updates()).unwrap();
    let vv_before = live.doc.oplog_vv();
    let responses = client
        .handle_server_message(&transport::encode_window_sync(
            "2026-03",
            window_sub_tags::UPDATE,
            &echo,
        ))
        .unwrap();
    assert!(responses.is_empty(), "a no-op echo returns no responses");
    assert_eq!(
        client.window("2026-03").unwrap().doc.oplog_vv(),
        vv_before,
        "precondition: the echo carried no new ops (true no-op path)"
    );

    // The live-doc delta now has its durable u:w: row.
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some(),
        "the missing live-doc delta must be persisted by the no-op echo coverage gate"
    );
}

/// ONE-1151 regression guard (R3, load-bearing): once the coverage gate
/// heals a missing local op, a SECOND no-op echo must append NO additional
/// `u:w:` row. A row-presence/dirty-flag impl re-grows the `u:w:` log on the
/// second echo (duplicate row + u_seq bump) = exactly the over-persist bug
/// ONE-1151 closed.
#[test]
fn coverage_heal_second_echo_appends_no_uw_row() {
    let (_temp, vault) = test_vault();
    let manager = make_manager(&vault);
    let (mut client, _rx) = make_client(&manager);

    let live = client.ensure_window("2026-03").unwrap();

    // Reproduce the durable-behind-live precondition (corrupt counter ->
    // failed Observer A persist -> no durable u:w row).
    vault
        .sync_state_put("m:u_seq:w:2026-03", &[0xBA, 0xD0])
        .unwrap();
    let id = EntityId::now();
    live.doc
        .get_map("entities")
        .insert(
            &id.to_hex(),
            make_entity_blob(1, LEARNED_JAN_2026, b"persist-failed-local").as_slice(),
        )
        .unwrap();
    live.doc.commit();
    vault
        .sync_state_put("m:u_seq:w:2026-03", &0u32.to_le_bytes())
        .unwrap();

    let echo = live.doc.export(ExportMode::all_updates()).unwrap();
    let echo_msg = transport::encode_window_sync("2026-03", window_sub_tags::UPDATE, &echo);

    // First echo heals the durable gap -> exactly one u:w: row.
    client.handle_server_message(&echo_msg).unwrap();
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some(),
        "first echo persists the missing live-doc delta into a u:w: row"
    );
    assert_eq!(
        vault
            .sync_state_keys_with_prefix("u:w:2026-03:")
            .unwrap()
            .len(),
        1,
        "exactly one u:w: row after the coverage heal"
    );

    // Second echo: durable now covers the live doc. NO additional u:w: row,
    // no u_seq bump.
    client.handle_server_message(&echo_msg).unwrap();
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .is_none(),
        "a covered echo must NOT append a second u:w: row (dedupe preserved)"
    );
    assert_eq!(
        vault
            .sync_state_keys_with_prefix("u:w:2026-03:")
            .unwrap()
            .len(),
        1,
        "the u:w: log must not re-grow on a re-echo"
    );
    assert_eq!(
        vault
            .sync_state_get("m:u_seq:w:2026-03")
            .unwrap()
            .as_deref(),
        Some(1u32.to_le_bytes().as_slice()),
        "the u_seq high-water mark must not bump on a re-echo"
    );
}
