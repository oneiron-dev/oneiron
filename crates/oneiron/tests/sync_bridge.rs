//! Integration tests for the sync entity bridge.

#![cfg(feature = "sync")]

use std::sync::Arc;

use oneiron::sync::bridge::{
    BRIDGE_ORIGIN, Materializer, encode_edge_value_for_crdt, format_edge_key,
};
use oneiron::sync::engine::{CrdtDoc, CrdtMap};
use oneiron::sync::schema::create_window_doc;
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

    let pm_key = format!("pm:{}:{}", key, hex_id);
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

    let pm_key = format!("pm:{}:{}", key, hex_id);
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
