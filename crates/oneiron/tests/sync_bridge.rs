//! Integration tests for the sync entity bridge.

#![cfg(feature = "sync")]

use std::sync::Arc;
use std::sync::atomic::Ordering;

use loro::{CommitOptions, ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use oneiron::sync::bridge::{
    BRIDGE_ORIGIN, Materializer, encode_edge_value_for_crdt, format_edge_key, parse_edge_value,
};
use oneiron::sync::client::{SyncClient, SyncClientConfig, SyncEvent};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::transport::{
    self, TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE, TAG_SYNC_UPDATE, TAG_WINDOW_SYNC,
    TransportError, window_sub_tags,
};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, LoadedWindow};
use oneiron::types::{ENTITY_TYPE_REDACTION_AUDIT, EdgeKind, TimeRange, Vad};
use oneiron::{DeleteReason, EntityId, HnswConfig, Vault, VaultConfig};

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

fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

fn map_insert_bytes(map: &LoroMap, key: &str, value: &[u8]) {
    map.insert(key, value).unwrap();
}

fn put_entity_in_window(window: &LoadedWindow, id: &EntityId, learned_at: u64, data: &[u8]) {
    let blob = make_entity_blob(1, learned_at, data);
    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, id.to_hex().as_str(), &blob);
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
    let edge_val = encode_edge_value_for_crdt(kind, weight, created_at, Some(vad), None).unwrap();
    let edges = window.doc.get_map("edges");
    map_insert_bytes(&edges, edge_key.as_str(), &edge_val);
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
    let blob = make_entity_blob(1, learned_at, b"test-entity-data");

    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, hex_id.as_str(), &blob);
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
    let blob = make_entity_blob(1, learned_at, b"to-be-deleted");

    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, hex_id.as_str(), &blob);
    window.doc.commit();

    assert!(vault.get(&id).unwrap().is_some());

    let tombstones = window.doc.get_map("tombstones");
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

    let src_blob = make_entity_blob(1, learned_at, b"source");
    let tgt_blob = make_entity_blob(1, learned_at, b"target");

    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, src.to_hex().as_str(), &src_blob);
    map_insert_bytes(&entities, tgt.to_hex().as_str(), &tgt_blob);
    window.doc.commit();

    let edge_key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    let edge_val =
        encode_edge_value_for_crdt(EdgeKind::Mentions, 0.75, 12345, Some(Vad::NEUTRAL), None)
            .unwrap();

    let edges = window.doc.get_map("edges");
    map_insert_bytes(&edges, edge_key.as_str(), &edge_val);
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

    let src_blob = make_entity_blob(1, learned_at, b"source-only");
    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, src.to_hex().as_str(), &src_blob);
    window.doc.commit();

    let edge_key = format_edge_key(&src, EdgeKind::Supports, &tgt);
    let edge_val =
        encode_edge_value_for_crdt(EdgeKind::Supports, 0.5, 12345, Some(Vad::NEUTRAL), None)
            .unwrap();

    let edges = window.doc.get_map("edges");
    map_insert_bytes(&edges, edge_key.as_str(), &edge_val);
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
    let update_prefix = format!("u:w:{}:", key.as_str());
    let seq_key = format!("m:u_seq:w:{}", key.as_str());
    let window = LoadedWindow::new("test-user", key, &vault, &materializer);

    let id = EntityId::now();
    let hex_id = id.to_hex();
    let learned_at = 1_772_000_000u64;
    let blob = make_entity_blob(1, learned_at, b"bridge-written");

    // Write under bridge origin — Observer B should skip this
    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, hex_id.as_str(), &blob);
    window
        .doc
        .commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));

    assert!(
        vault.get(&id).unwrap().is_none(),
        "bridge-origin writes should not trigger Observer B materialization"
    );

    // Observer A should have persisted the update
    let keys = vault.sync_state_keys_with_prefix(&update_prefix).unwrap();
    assert!(
        !keys.is_empty(),
        "Observer A should persist even bridge-origin updates"
    );
    let seq = vault.sync_state_get(&seq_key).unwrap().unwrap();
    assert_eq!(seq.as_slice(), &1u32.to_le_bytes());
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
    let blob = make_entity_blob(1, 1_772_000_000, b"overflow-test");
    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, id.to_hex().as_str(), &blob);
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
    let blob = make_entity_blob(1, learned_at, b"persist-test");

    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, hex_id.as_str(), &blob);
    window
        .doc
        .commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));

    window.persist_state(&vault).unwrap();
    drop(window);

    let loaded_doc = window::load_window_from_state(&vault, "test-user", &key).unwrap();

    let entities = loaded_doc.get_map("entities");
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
            1,
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

    assert!(doc.get_map("entities").get(&hex_id).is_none());

    let replayed = window::replay_pending_mirrors(&vault, &doc, &key).unwrap();
    assert_eq!(replayed, 1, "should replay one pm marker");

    assert!(
        doc.get_map("entities").get(&hex_id).is_some(),
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
    let blob = make_entity_blob(1, 1_772_000_000, b"forward-remat");

    let entities = doc.get_map("entities");
    map_insert_bytes(&entities, hex_id.as_str(), &blob);
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
    let blob = make_entity_blob(1, 1_772_000_000, b"alias");

    let entities = doc.get_map("entities");
    map_insert_bytes(&entities, id.to_hex().as_str(), &blob);
    map_insert_bytes(&entities, id.to_hex().to_uppercase().as_str(), &blob);
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
            1,
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
    let tombstones = doc.get_map("tombstones");
    tombstones
        .insert(hex_id.as_str(), &(learned_at as i64).to_le_bytes())
        .unwrap();
    doc.commit();

    let replayed = window::replay_pending_mirrors(&vault, &doc, &key).unwrap();
    assert_eq!(replayed, 0, "should skip tombstoned entity");

    assert!(
        doc.get_map("entities").get(&hex_id).is_none(),
        "tombstoned entity should not be resurrected"
    );
}

/// CONTRACT CORRECTION (ONE-1131): the previous version of this test
/// hard-deleted `src`/`tgt`/`lonely` via `delete_entity` and asserted that
/// forward re-materialization from a stale pre-delete snapshot RESTORED
/// them — blessing resurrection of hard-deleted entities. ARCH-0023b's
/// crash-recovery rule is the opposite ("if tombstoned in CRDT → never
/// resurrect"); restore is only legitimate for entities that were never
/// deleted, e.g. after LMDB loss or onto a fresh node. Restore is now
/// asserted on a fresh vault, and the tombstoned entity must never
/// materialize at all.
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

    let tombstones = window.doc.get_map("tombstones");
    tombstones
        .insert(tombstoned.to_hex().as_str(), &learned_at.to_le_bytes())
        .unwrap();
    window.doc.commit();
    assert!(vault.get(&tombstoned).unwrap().is_none());

    let snapshot = window.doc.export(ExportMode::Snapshot).unwrap();
    drop(window);
    let recovered_doc = LoroDoc::from_snapshot(&snapshot).unwrap();

    // Recover into a FRESH vault (crash-lost LMDB / new node): only the
    // never-deleted entities and their edge may materialize.
    let temp_b = tempfile::tempdir().unwrap();
    let vault_b = Vault::open(temp_b.path(), test_config()).unwrap();
    let materializer_b = Materializer::new();

    let rematerialized =
        window::forward_rematerialize(&vault_b, &recovered_doc, &materializer_b).unwrap();
    assert_eq!(
        rematerialized, 4,
        "three live entity rows + one edge; the tombstoned entity must never be written (not even transiently), so no purge runs either"
    );

    assert_eq!(
        vault_b.get(&src).unwrap().as_deref(),
        Some(b"remat-source".as_slice())
    );
    assert_eq!(
        vault_b.get(&tgt).unwrap().as_deref(),
        Some(b"remat-target".as_slice())
    );
    assert_eq!(
        vault_b.get(&lonely).unwrap().as_deref(),
        Some(b"remat-lonely".as_slice())
    );
    assert!(
        vault_b.edge_exists(&src, EdgeKind::Mentions, &tgt).unwrap(),
        "edge should be rebuilt after endpoints are restored"
    );
    assert!(
        vault_b.get_raw(&tombstoned).unwrap().is_none(),
        "tombstoned entity must never resurrect — no row at all, not even a header"
    );

    // ARCH-0023b recovery is idempotent: a second pass over the same doc
    // performs zero LMDB writes.
    let second = window::forward_rematerialize(&vault_b, &recovered_doc, &materializer_b).unwrap();
    assert_eq!(second, 0, "second forward pass must perform zero writes");
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

    let tombstones = window.doc.get_map("tombstones");
    tombstones
        .insert(tombstoned.to_hex().as_str(), &learned_at.to_le_bytes())
        .unwrap();
    window.doc.commit();
    assert!(vault.get(&tombstoned).unwrap().is_none());

    vault
        .put_entity(
            &tombstoned,
            1,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"stale-tombstoned",
        )
        .unwrap();

    let reverse_doc = create_window_doc("test-user", &key);
    let reverse_tombstones = reverse_doc.get_map("tombstones");
    reverse_tombstones
        .insert(tombstoned.to_hex().as_str(), &learned_at.to_le_bytes())
        .unwrap();
    reverse_doc.commit();

    let mirrored = window::reverse_rematerialize(&vault, &reverse_doc, &key).unwrap();
    assert_eq!(mirrored, 3, "should mirror only non-tombstoned entities");

    let entities = reverse_doc.get_map("entities");
    assert_eq!(
        map_get_bytes(&entities, src.to_hex().as_str()).as_deref(),
        vault.get_raw(&src).unwrap().as_deref()
    );
    assert_eq!(
        map_get_bytes(&entities, tgt.to_hex().as_str()).as_deref(),
        vault.get_raw(&tgt).unwrap().as_deref()
    );
    assert_eq!(
        map_get_bytes(&entities, lonely.to_hex().as_str()).as_deref(),
        vault.get_raw(&lonely).unwrap().as_deref()
    );
    assert!(
        entities.get(tombstoned.to_hex().as_str()).is_none(),
        "tombstone should suppress stale LMDB row"
    );

    let edges = reverse_doc.get_map("edges");
    let edge_key = format_edge_key(&src, EdgeKind::Supports, &tgt);
    let edge_value = map_get_bytes(&edges, edge_key.as_str()).unwrap();
    let decoded = parse_edge_value(&edge_value).unwrap();
    assert!((decoded.weight - 0.5).abs() < f32::EPSILON);
    assert_eq!(decoded.created_at, learned_at + 2);
    assert_eq!(decoded.vad, Some(Vad::NEUTRAL));
}

#[test]
fn sync_client_handle_server_message_imports_root_sync_update() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());

    let server_doc = LoroDoc::new();
    let meta = server_doc.get_map("meta");
    // Byte-encode `meta.windows` to match the schema helpers and the server's
    // root-doc init — `read_window_list` only decodes `LoroValue::Binary`.
    meta.insert("windows", "2026-03".as_bytes()).unwrap();
    server_doc.commit();
    let update = server_doc.export(ExportMode::all_updates()).unwrap();

    let mut message = vec![TAG_SYNC_UPDATE];
    message.extend_from_slice(&update);
    let responses = client.handle_server_message(&message).unwrap();

    assert!(responses.is_empty());
    assert_eq!(client.server_windows(), vec!["2026-03".to_string()]);
}

#[test]
fn sync_client_handle_server_message_dispatch() {
    // Three dispatch cases share the same skeleton:
    //   (case_name, payload_builder, expectation)
    // - accepts_version_vector: real root VV from generate_initial_sync,
    //   handler treats it as a no-op (Ok with empty responses).
    // - rejects_empty_payload: zero-byte input returns InvalidPayload.
    // - rejects_unknown_tag: tag 222 has no handler, returns UnknownTag(222).
    enum Expect {
        Ok,
        InvalidPayload,
        UnknownTag(u8),
    }

    let build_root_vv = |client: &mut SyncClient| -> Vec<u8> {
        let initial_sync = client.generate_initial_sync();
        let vv_message = initial_sync
            .first()
            .expect("initial sync should include root VV")
            .clone();
        assert_eq!(vv_message.first().copied(), Some(ROOT_VV_TAG));
        vv_message
    };
    let build_empty = |_client: &mut SyncClient| -> Vec<u8> { Vec::new() };
    let build_unknown = |_client: &mut SyncClient| -> Vec<u8> { vec![222] };

    type Builder = fn(&mut SyncClient) -> Vec<u8>;
    let cases: &[(&str, Builder, Expect)] = &[
        ("accepts_version_vector", build_root_vv, Expect::Ok),
        ("rejects_empty_payload", build_empty, Expect::InvalidPayload),
        (
            "rejects_unknown_tag",
            build_unknown,
            Expect::UnknownTag(222),
        ),
    ];

    for (case_name, build, expect) in cases {
        let temp = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
        let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());

        let message = build(&mut client);
        let result = client.handle_server_message(&message);

        match (expect, result) {
            (Expect::Ok, Ok(responses)) => {
                assert!(
                    responses.is_empty(),
                    "case {case_name}: expected no responses, got {responses:?}"
                );
            }
            (Expect::InvalidPayload, Err(TransportError::InvalidPayload(_))) => {}
            (Expect::UnknownTag(expected_tag), Err(TransportError::UnknownTag(got_tag)))
                if got_tag == *expected_tag => {}
            (_, other) => panic!("case {case_name}: unexpected result {other:?}"),
        }
    }
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

/// GDPR receipt survival across a full CRDT sync round-trip (ONE-1103).
///
/// A REDACTION_AUDIT receipt (type byte 120; ARCH-0038 / contracts.ts
/// `redactionAuditReceipt`) is engine-authored maintenance state. The public
/// write gate must reject user-written maintenance kinds, but the
/// engine-internal CRDT↔LMDB mirror has to carry receipts in BOTH directions
/// or the Art.5(2) audit trail is silently lost on cross-node sync / replay.
///
/// Round-trip: Node A authors a receipt (LMDB) → `reverse_rematerialize`
/// mirrors it into A's CRDT → the CRDT doc syncs to Node B (snapshot import) →
/// Node B's `forward_rematerialize` writes it back into B's LMDB. The receipt
/// must arrive byte-identical and land in the temporal_learned + maintenance
/// type indices it belongs to.
///
/// This FAILS against the pre-fix code: `forward_rematerialize` routed the
/// type-120 receipt through the public `validate_public_entity_type` gate,
/// which rejected it with `MaintenanceKindNotWritable(120)`, so the
/// `if result.is_ok()` guard silently dropped it and the receipt never
/// reached Node B's LMDB.
#[test]
fn redaction_audit_receipt_survives_crdt_sync_round_trip() {
    // --- Node A: author a real GDPR receipt in LMDB via a hard delete ---
    let temp_a = tempfile::tempdir().unwrap();
    let vault_a = Arc::new(Vault::open(temp_a.path(), test_config()).unwrap());

    let subject = EntityId::now();
    // Seed a non-CLAIM subject (TURN = type 1) with a learned_at well outside
    // the receipt's window, then hard-delete it to author the receipt.
    vault_a
        .put_entity(
            &subject,
            1,
            TimeRange {
                start: 301,
                end: 301,
            },
            301,
            b"forget-me",
        )
        .unwrap();
    let outcome = vault_a
        .delete_entity_with_reason(&subject, DeleteReason::UserHardDelete)
        .unwrap();
    let receipt_id = outcome
        .receipt_id
        .expect("user hard delete must author a REDACTION_AUDIT receipt");

    let receipt_raw = vault_a
        .get_raw(&receipt_id)
        .unwrap()
        .expect("receipt must exist in node A LMDB");
    assert_eq!(
        receipt_raw[0], ENTITY_TYPE_REDACTION_AUDIT,
        "authored receipt must be the maintenance band type byte"
    );
    let learned_at = vault_a.get_learned_at(&receipt_id).unwrap();

    // --- Node A: LMDB → CRDT (reverse mirror is unfiltered; already works) ---
    let window_key = WindowKey::from_timestamp(learned_at);
    let doc_a = create_window_doc("node-a", &window_key);
    let mirrored = window::reverse_rematerialize(&vault_a, &doc_a, &window_key).unwrap();
    assert!(
        mirrored >= 1,
        "reverse rematerialize must mirror the receipt into the CRDT"
    );
    assert_eq!(
        map_get_bytes(&doc_a.get_map("entities"), receipt_id.to_hex().as_str()).as_deref(),
        Some(receipt_raw.as_slice()),
        "receipt must be byte-identical in the CRDT mirror"
    );

    // --- wire: doc_a → doc_b (peer sync via snapshot import) ---
    let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
    let doc_b = LoroDoc::from_snapshot(&snapshot).unwrap();

    // --- Node B: CRDT → LMDB (the seam that silently dropped the receipt) ---
    let temp_b = tempfile::tempdir().unwrap();
    let vault_b = Vault::open(temp_b.path(), test_config()).unwrap();
    let materializer = Materializer::new();
    let restored = window::forward_rematerialize(&vault_b, &doc_b, &materializer).unwrap();
    assert!(
        restored >= 1,
        "forward rematerialize must write the receipt back into LMDB"
    );

    // Survives byte-identical: the exact pinned on-disk envelope is preserved.
    assert_eq!(
        vault_b.get_raw(&receipt_id).unwrap().as_deref(),
        Some(receipt_raw.as_slice()),
        "receipt must survive the round-trip byte-identical on node B"
    );
    // Discoverable via the maintenance type index (type byte 120).
    assert!(
        vault_b
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .contains(&receipt_id),
        "receipt must be discoverable via the maintenance type index on node B"
    );
    // Lands in the temporal_learned index it belongs to.
    assert!(
        vault_b
            .entities_in_learned_range(learned_at, learned_at + 1)
            .unwrap()
            .contains(&receipt_id),
        "receipt must land in node B's temporal_learned index"
    );
}
