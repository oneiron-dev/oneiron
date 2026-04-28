//! Integration tests for the sync entity bridge.

#![cfg(feature = "sync")]

use std::sync::Arc;
use std::sync::atomic::Ordering;

use loro::{ExportMode, LoroDoc};
use oneiron::sync::bridge::{
    BRIDGE_ORIGIN, Materializer, encode_edge_value_for_crdt, format_edge_key, parse_edge_value,
};
use oneiron::sync::client::{SyncClient, SyncClientConfig, SyncEvent};
use oneiron::sync::engine::{CrdtDoc, CrdtMap};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::transport::{
    self, TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE, TAG_SYNC_UPDATE, TAG_WINDOW_SYNC,
    TransportError, window_sub_tags,
};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, LoadedWindow};
use oneiron::types::{EdgeKind, TimeRange, Vad};
use oneiron::{EntityId, HnswConfig, Vault, VaultConfig};

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

fn make_entity_blob(entity_type: u8, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&learned_at.to_be_bytes()); // occurred_start
    blob.extend_from_slice(&learned_at.to_be_bytes()); // occurred_end
    blob.extend_from_slice(&learned_at.to_be_bytes()); // learned_at
    blob.extend_from_slice(data);
    blob
}

const ROOT_VV_TAG: u8 = 2;

fn put_entity_in_window(window: &LoadedWindow, id: &EntityId, learned_at: u64, data: &[u8]) {
    let blob = make_entity_blob(0, learned_at, data);
    let entities = window.doc.get_or_create_map("entities");
    entities.insert(id.to_hex().as_str(), &blob).unwrap();
    window.doc.commit();
}

fn put_edge_in_window(
    window: &LoadedWindow,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
    weight: f32,
    created_at: u64,
    vad: Vad,
) {
    let edge_key = format_edge_key(src, kind, tgt);
    let edge_val = encode_edge_value_for_crdt(weight, created_at, vad);
    let edges = window.doc.get_or_create_map("edges");
    edges.insert(edge_key.as_str(), &edge_val).unwrap();
    window.doc.commit();
}

#[test]
fn entity_written_to_crdt_materializes_in_lmdb() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new("test-user", key, &vault, &materializer);

    let id = EntityId::now();
    let hex_id = id.to_hex();
    let learned_at = 1_772_000_000u64;
    let blob = make_entity_blob(0, learned_at, b"test-entity-data");

    let entities = window.doc.get_or_create_map("entities");
    entities.insert(hex_id.as_str(), &blob).unwrap();
    window.doc.commit();

    let got = vault.get(&id).unwrap();
    assert!(got.is_some(), "entity should be materialized in LMDB");
    assert_eq!(got.unwrap(), b"test-entity-data");
}

#[test]
fn tombstone_deletes_entity_from_lmdb() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new("test-user", key, &vault, &materializer);

    let id = EntityId::now();
    let hex_id = id.to_hex();
    let learned_at = 1_772_000_000u64;
    let blob = make_entity_blob(0, learned_at, b"to-be-deleted");

    let entities = window.doc.get_or_create_map("entities");
    entities.insert(hex_id.as_str(), &blob).unwrap();
    window.doc.commit();

    assert!(vault.get(&id).unwrap().is_some());

    let tombstones = window.doc.get_or_create_map("tombstones");
    // Tombstone value is a timestamp marker (any binary value)
    tombstones
        .insert(hex_id.as_str(), &1_772_000_100u64.to_le_bytes())
        .unwrap();
    window.doc.commit();

    assert!(
        vault.get(&id).unwrap().is_none(),
        "entity should be deleted after tombstone"
    );
}

#[test]
fn edge_materializes_when_both_endpoints_exist() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new("test-user", key, &vault, &materializer);

    let src = EntityId::now();
    let tgt = EntityId::now();
    let learned_at = 1_772_000_000u64;

    let src_blob = make_entity_blob(0, learned_at, b"source");
    let tgt_blob = make_entity_blob(0, learned_at, b"target");

    let entities = window.doc.get_or_create_map("entities");
    entities.insert(src.to_hex().as_str(), &src_blob).unwrap();
    entities.insert(tgt.to_hex().as_str(), &tgt_blob).unwrap();
    window.doc.commit();

    let edge_key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    let edge_val = encode_edge_value_for_crdt(0.75, 12345, Vad::NEUTRAL);

    let edges = window.doc.get_or_create_map("edges");
    edges.insert(edge_key.as_str(), &edge_val).unwrap();
    window.doc.commit();

    assert!(
        vault.edge_exists(&src, EdgeKind::Mentions, &tgt).unwrap(),
        "edge should be materialized when both endpoints exist"
    );
}

#[test]
fn edge_skipped_when_endpoint_missing() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new("test-user", key, &vault, &materializer);

    let src = EntityId::now();
    let tgt = EntityId::now();
    let learned_at = 1_772_000_000u64;

    let src_blob = make_entity_blob(0, learned_at, b"source-only");
    let entities = window.doc.get_or_create_map("entities");
    entities.insert(src.to_hex().as_str(), &src_blob).unwrap();
    window.doc.commit();

    let edge_key = format_edge_key(&src, EdgeKind::Supports, &tgt);
    let edge_val = encode_edge_value_for_crdt(0.5, 12345, Vad::NEUTRAL);

    let edges = window.doc.get_or_create_map("edges");
    edges.insert(edge_key.as_str(), &edge_val).unwrap();
    window.doc.commit();

    assert!(
        !vault.edge_exists(&src, EdgeKind::Supports, &tgt).unwrap(),
        "edge should be skipped when endpoint is missing"
    );
}

#[test]
fn bridge_origin_writes_dont_trigger_observer_b() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new("test-user", key, &vault, &materializer);

    let id = EntityId::now();
    let hex_id = id.to_hex();
    let learned_at = 1_772_000_000u64;
    let blob = make_entity_blob(0, learned_at, b"bridge-written");

    // Write under bridge origin — Observer B should skip this
    let entities = window.doc.get_or_create_map("entities");
    entities.insert(hex_id.as_str(), &blob).unwrap();
    window.doc.commit_with_origin(BRIDGE_ORIGIN);

    assert!(
        vault.get(&id).unwrap().is_none(),
        "bridge-origin writes should not trigger Observer B materialization"
    );

    // Observer A should have persisted the update
    let keys = vault.sync_state_keys_with_prefix("u:w:2026-03:").unwrap();
    assert!(
        !keys.is_empty(),
        "Observer A should persist even bridge-origin updates"
    );
}

#[test]
fn observer_a_sequence_overflow_preserves_zero_update_slot() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new("test-user", key.clone(), &vault, &materializer);
    let seq_key = format!("m:u_seq:w:{key}");
    let zero_key = format!("u:w:{key}:00000000");
    let max_key = format!("u:w:{key}:ffffffff");
    vault
        .sync_state_put(&seq_key, &u32::MAX.to_le_bytes())
        .unwrap();
    vault.sync_state_put(&zero_key, b"sentinel").unwrap();
    let pending_before = window
        .observer_a_state
        .pending_bytes
        .load(Ordering::Relaxed);

    let id = EntityId::now();
    let blob = make_entity_blob(0, 1_772_000_000, b"overflow-test");
    let entities = window.doc.get_or_create_map("entities");
    entities.insert(id.to_hex().as_str(), &blob).unwrap();
    window.doc.commit();

    let pending_after = window
        .observer_a_state
        .pending_bytes
        .load(Ordering::Relaxed);
    assert!(pending_after > pending_before);
    let seq = vault.sync_state_get(&seq_key).unwrap().unwrap();
    assert_eq!(seq.as_slice(), &u32::MAX.to_le_bytes());
    assert_eq!(
        vault.sync_state_get(&zero_key).unwrap().unwrap(),
        b"sentinel"
    );
    assert!(vault.sync_state_get(&max_key).unwrap().is_none());
}

#[test]
fn window_persist_and_load_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new("test-user", key.clone(), &vault, &materializer);

    let id = EntityId::now();
    let hex_id = id.to_hex();
    let learned_at = 1_772_000_000u64;
    let blob = make_entity_blob(0, learned_at, b"persist-test");

    let entities = window.doc.get_or_create_map("entities");
    entities.insert(hex_id.as_str(), &blob).unwrap();
    window.doc.commit_with_origin(BRIDGE_ORIGIN);

    window.persist_state(&vault).unwrap();
    drop(window);

    let loaded_doc = window::load_window_from_state(&vault, "test-user", &key).unwrap();

    let entities = loaded_doc.get_or_create_map("entities");
    assert!(
        entities.get(&hex_id).is_some(),
        "entity should survive persist/load cycle"
    );
}

#[test]
fn crash_recovery_pm_markers() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let key = WindowKey::new("2026-03");

    let id = EntityId::now();
    let hex_id = id.to_hex();
    let learned_at = 1_772_000_000u64;

    vault
        .put_entity(
            &id,
            0,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"crash-test",
        )
        .unwrap();

    let pm_key = format!("pm:{key}:{hex_id}");
    vault.sync_state_put(&pm_key, &[1u8]).unwrap();

    let doc = create_window_doc("test-user", &key);

    assert!(doc.get_or_create_map("entities").get(&hex_id).is_none());

    let replayed = window::replay_pending_mirrors(&vault, &doc, &key).unwrap();
    assert_eq!(replayed, 1, "should replay one pm marker");

    assert!(
        doc.get_or_create_map("entities").get(&hex_id).is_some(),
        "entity should be mirrored to CRDT after pm replay"
    );

    assert!(
        vault.sync_state_get(&pm_key).unwrap().is_none(),
        "pm marker should be cleared after replay"
    );
}

#[test]
fn forward_rematerialize_materializes_entities_with_single_read_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let materializer = Materializer::new();
    let key = WindowKey::new("2026-03");
    let doc = create_window_doc("test-user", &key);
    let id = EntityId::now();
    let hex_id = id.to_hex();
    let blob = make_entity_blob(0, 1_772_000_000, b"forward-remat");

    let entities = doc.get_or_create_map("entities");
    entities.insert(hex_id.as_str(), &blob).unwrap();
    doc.commit();

    let materialized = window::forward_rematerialize(&vault, &doc, &materializer).unwrap();
    assert_eq!(materialized, 1);
    assert_eq!(vault.get(&id).unwrap().unwrap(), b"forward-remat");

    let unchanged = window::forward_rematerialize(&vault, &doc, &materializer).unwrap();
    assert_eq!(unchanged, 0);
}

#[test]
fn forward_rematerialize_deduplicates_same_entity_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let materializer = Materializer::new();
    let key = WindowKey::new("2026-03");
    let doc = create_window_doc("test-user", &key);
    let id = EntityId::from_hex("11111111111111111111111111111111").unwrap();
    let blob = make_entity_blob(0, 1_772_000_000, b"alias");

    let entities = doc.get_or_create_map("entities");
    entities.insert(id.to_hex().as_str(), &blob).unwrap();
    entities
        .insert(id.to_hex().to_uppercase().as_str(), &blob)
        .unwrap();
    doc.commit();

    let materialized = window::forward_rematerialize(&vault, &doc, &materializer).unwrap();
    assert_eq!(materialized, 1);
    assert_eq!(vault.get(&id).unwrap().unwrap(), b"alias");
}

#[test]
fn pm_replay_skips_tombstoned_entities() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let key = WindowKey::new("2026-03");

    let id = EntityId::now();
    let hex_id = id.to_hex();
    let learned_at = 1_772_000_000u64;

    vault
        .put_entity(
            &id,
            0,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"tombstone-test",
        )
        .unwrap();

    let pm_key = format!("pm:{key}:{hex_id}");
    vault.sync_state_put(&pm_key, &[1u8]).unwrap();

    let doc = create_window_doc("test-user", &key);

    // Add tombstone to CRDT
    let tombstones = doc.get_or_create_map("tombstones");
    tombstones
        .insert(hex_id.as_str(), &(learned_at as i64).to_le_bytes())
        .unwrap();
    doc.commit();

    let replayed = window::replay_pending_mirrors(&vault, &doc, &key).unwrap();
    assert_eq!(replayed, 0, "should skip tombstoned entity");

    assert!(
        doc.get_or_create_map("entities").get(&hex_id).is_none(),
        "tombstoned entity should not be resurrected"
    );
}

#[test]
fn forward_rematerialize_restores_lmdb_entities_edges_and_tombstones() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new("test-user", key, &vault, &materializer);
    let learned_at = 1_772_400_000u64;

    let src = EntityId::now();
    let tgt = EntityId::now();
    let lonely = EntityId::now();
    let tombstoned = EntityId::now();

    put_entity_in_window(&window, &src, learned_at, b"remat-source");
    put_entity_in_window(&window, &tgt, learned_at, b"remat-target");
    put_entity_in_window(&window, &lonely, learned_at, b"remat-lonely");
    put_entity_in_window(&window, &tombstoned, learned_at, b"remat-tombstoned");
    put_edge_in_window(
        &window,
        &src,
        EdgeKind::Mentions,
        &tgt,
        0.75,
        learned_at + 1,
        Vad::NEUTRAL,
    );

    let tombstones = window.doc.get_or_create_map("tombstones");
    tombstones
        .insert(tombstoned.to_hex().as_str(), &learned_at.to_le_bytes())
        .unwrap();
    window.doc.commit();
    assert!(vault.get(&tombstoned).unwrap().is_none());

    let snapshot = window.doc.export_snapshot().unwrap();
    drop(window);
    let recovered_doc = oneiron::sync::LoroDocument::from_snapshot(&snapshot).unwrap();

    assert!(vault.delete_entity(&src).unwrap());
    assert!(vault.delete_entity(&tgt).unwrap());
    assert!(vault.delete_entity(&lonely).unwrap());
    assert!(vault.get(&src).unwrap().is_none());
    assert!(!vault.edge_exists(&src, EdgeKind::Mentions, &tgt).unwrap());

    let rematerialized =
        window::forward_rematerialize(&vault, &recovered_doc, &materializer).unwrap();
    assert_eq!(
        rematerialized, 6,
        "should rebuild four entity rows, one edge, then apply one tombstone delete"
    );

    assert_eq!(
        vault.get(&src).unwrap().as_deref(),
        Some(b"remat-source".as_slice())
    );
    assert_eq!(
        vault.get(&tgt).unwrap().as_deref(),
        Some(b"remat-target".as_slice())
    );
    assert_eq!(
        vault.get(&lonely).unwrap().as_deref(),
        Some(b"remat-lonely".as_slice())
    );
    assert!(
        vault.edge_exists(&src, EdgeKind::Mentions, &tgt).unwrap(),
        "edge should be rebuilt after endpoints are restored"
    );
    assert!(
        vault.get(&tombstoned).unwrap().is_none(),
        "tombstone should win over stale entity payload"
    );
}

#[test]
fn reverse_rematerialize_mirrors_lmdb_entities_edges_and_skips_tombstones() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new("test-user", key.clone(), &vault, &materializer);
    let learned_at = 1_772_400_000u64;

    let src = EntityId::now();
    let tgt = EntityId::now();
    let lonely = EntityId::now();
    let tombstoned = EntityId::now();

    put_entity_in_window(&window, &src, learned_at, b"reverse-source");
    put_entity_in_window(&window, &tgt, learned_at, b"reverse-target");
    put_entity_in_window(&window, &lonely, learned_at, b"reverse-lonely");
    put_entity_in_window(&window, &tombstoned, learned_at, b"reverse-tombstoned");
    put_edge_in_window(
        &window,
        &src,
        EdgeKind::Supports,
        &tgt,
        0.5,
        learned_at + 2,
        Vad::NEUTRAL,
    );

    let tombstones = window.doc.get_or_create_map("tombstones");
    tombstones
        .insert(tombstoned.to_hex().as_str(), &learned_at.to_le_bytes())
        .unwrap();
    window.doc.commit();
    assert!(vault.get(&tombstoned).unwrap().is_none());

    vault
        .put_entity(
            &tombstoned,
            0,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"stale-tombstoned",
        )
        .unwrap();

    let reverse_doc = create_window_doc("test-user", &key);
    let reverse_tombstones = reverse_doc.get_or_create_map("tombstones");
    reverse_tombstones
        .insert(tombstoned.to_hex().as_str(), &learned_at.to_le_bytes())
        .unwrap();
    reverse_doc.commit();

    let mirrored = window::reverse_rematerialize(&vault, &reverse_doc, &key).unwrap();
    assert_eq!(mirrored, 3, "should mirror only non-tombstoned entities");

    let entities = reverse_doc.get_or_create_map("entities");
    assert_eq!(
        entities.get(src.to_hex().as_str()).as_deref(),
        vault.get_raw(&src).unwrap().as_deref()
    );
    assert_eq!(
        entities.get(tgt.to_hex().as_str()).as_deref(),
        vault.get_raw(&tgt).unwrap().as_deref()
    );
    assert_eq!(
        entities.get(lonely.to_hex().as_str()).as_deref(),
        vault.get_raw(&lonely).unwrap().as_deref()
    );
    assert!(
        entities.get(tombstoned.to_hex().as_str()).is_none(),
        "tombstone should suppress stale LMDB row"
    );

    let edges = reverse_doc.get_or_create_map("edges");
    let edge_key = format_edge_key(&src, EdgeKind::Supports, &tgt);
    let edge_value = edges.get(edge_key.as_str()).unwrap();
    let (weight, created_at, vad) = parse_edge_value(&edge_value).unwrap();
    assert!((weight - 0.5).abs() < f32::EPSILON);
    assert_eq!(created_at, learned_at + 2);
    assert_eq!(vad, Vad::NEUTRAL);
}

#[test]
fn sync_client_handle_server_message_imports_root_sync_update() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());

    let server_doc = LoroDoc::new();
    let meta = server_doc.get_map("meta");
    meta.insert("windows", "2026-03").unwrap();
    server_doc.commit();
    let update = server_doc.export(ExportMode::all_updates()).unwrap();

    let mut message = vec![TAG_SYNC_UPDATE];
    message.extend_from_slice(&update);
    let responses = client.handle_server_message(&message).unwrap();

    assert!(responses.is_empty());
    assert_eq!(client.server_windows(), vec!["2026-03".to_string()]);
}

#[test]
fn sync_client_handle_server_message_accepts_version_vector() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());
    let initial_sync = client.generate_initial_sync();
    let vv_message = initial_sync
        .first()
        .expect("initial sync should include root VV");
    assert_eq!(vv_message.first().copied(), Some(ROOT_VV_TAG));

    // Root VV handling is currently an intentional no-op.
    let responses = client.handle_server_message(vv_message).unwrap();

    assert!(responses.is_empty());
}

#[test]
fn sync_client_handle_server_message_dispatches_window_sync() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());

    let message = transport::encode_window_sync("2026-03", window_sub_tags::VV_REQUEST, &[]);
    let responses = client.handle_server_message(&message).unwrap();

    assert!(client.window("2026-03").is_some());
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0][0], TAG_WINDOW_SYNC);
    let (window_key, sub_tag, _payload) =
        transport::decode_window_sync(&responses[0][1..]).unwrap();
    assert_eq!(window_key, "2026-03");
    assert_eq!(sub_tag, window_sub_tags::UPDATE);
}

#[test]
fn sync_client_handle_server_message_handles_bulk_transfer_messages() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let (mut client, mut rx) = SyncClient::new(vault, SyncClientConfig::default());

    let msgpack = rmp_serde::to_vec(&serde_json::json!({})).unwrap();
    let compressed = zstd::stream::encode_all(msgpack.as_slice(), 0).unwrap();
    let bulk = transport::encode_bulk_transfer("2026-03", &compressed);
    assert_eq!(bulk[0], TAG_BULK_TRANSFER);
    assert!(client.handle_server_message(&bulk).unwrap().is_empty());

    let done = transport::encode_bulk_transfer_done("2026-03", b"doc-state");
    assert_eq!(done[0], TAG_BULK_TRANSFER_DONE);
    assert!(client.handle_server_message(&done).unwrap().is_empty());

    match rx.try_recv() {
        Ok(SyncEvent::BulkTransferComplete { window_key }) => {
            assert_eq!(window_key, "2026-03");
        }
        other => panic!("expected bulk transfer completion event, got {other:?}"),
    }
}

#[test]
fn sync_client_handle_server_message_rejects_unknown_tag() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());

    match client.handle_server_message(&[222]) {
        Err(TransportError::UnknownTag(222)) => {}
        other => panic!("expected UnknownTag(222), got {other:?}"),
    }
}

#[test]
fn sync_client_handle_server_message_rejects_empty_payload() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());

    match client.handle_server_message(&[]) {
        Err(TransportError::InvalidPayload(_)) => {}
        other => panic!("expected InvalidPayload(_), got {other:?}"),
    }
}

#[test]
fn entity_id_hex_round_trip() {
    let id = EntityId::now();
    let hex = id.to_hex();
    assert_eq!(hex.len(), 32);
    let recovered = EntityId::from_hex(&hex).unwrap();
    assert_eq!(id, recovered);
}

#[test]
fn entity_id_from_hex_rejects_invalid() {
    assert!(EntityId::from_hex("too_short").is_err());
    assert!(EntityId::from_hex("gggggggggggggggggggggggggggggggg").is_err());
}

#[test]
fn learned_at_accessor() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();
    let learned = 1_772_000_000u64;

    vault
        .put_entity(
            &id,
            0,
            TimeRange {
                start: learned,
                end: learned,
            },
            learned,
            b"first",
        )
        .unwrap();

    assert_eq!(vault.get_learned_at(&id).unwrap(), learned);
}

#[test]
fn entity_exists_and_edge_exists() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();
    let other = EntityId::now();

    assert!(!vault.entity_exists(&id).unwrap());

    vault
        .put_entity(&id, 0, TimeRange { start: 1, end: 1 }, 1, b"exists")
        .unwrap();
    vault
        .put_entity(&other, 0, TimeRange { start: 1, end: 1 }, 1, b"other")
        .unwrap();

    assert!(vault.entity_exists(&id).unwrap());
    assert!(!vault.edge_exists(&id, EdgeKind::Mentions, &other).unwrap());

    vault
        .put_edge(&id, EdgeKind::Mentions, &other, 0.5)
        .unwrap();
    assert!(vault.edge_exists(&id, EdgeKind::Mentions, &other).unwrap());
}

#[test]
fn entities_in_learned_range() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();

    let id1 = EntityId::now();
    let id2 = EntityId::now();
    let id3 = EntityId::now();

    vault
        .put_entity(
            &id1,
            0,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"a",
        )
        .unwrap();
    vault
        .put_entity(
            &id2,
            0,
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
            b"b",
        )
        .unwrap();
    vault
        .put_entity(
            &id3,
            0,
            TimeRange {
                start: 300,
                end: 300,
            },
            300,
            b"c",
        )
        .unwrap();

    let range = vault.entities_in_learned_range(100, 300).unwrap();
    assert_eq!(range.len(), 2);
    assert!(range.contains(&id1));
    assert!(range.contains(&id2));
    assert!(!range.contains(&id3));
}

#[test]
fn with_write_txn_and_batch_in() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();

    vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&id, 0, TimeRange { start: 1, end: 1 }, 1, b"atomic")
                .apply(wtxn)?;
            Ok(())
        })
        .unwrap();

    assert_eq!(vault.get(&id).unwrap().unwrap(), b"atomic");
}

#[test]
fn batch_edge_with_created_at() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault
        .batch()
        .put(&src, 0, TimeRange { start: 1, end: 1 }, 1, b"src")
        .put(&tgt, 0, TimeRange { start: 1, end: 1 }, 1, b"tgt")
        .edge_with_created_at(&src, EdgeKind::Mentions, &tgt, 0.8, 99999)
        .commit()
        .unwrap();

    let edges = vault.edges_out(&src).unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].created_at, 99999);
    assert!((edges[0].weight - 0.8).abs() < f32::EPSILON);
}
