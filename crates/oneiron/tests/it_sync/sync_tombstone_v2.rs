// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1132 — tombstone wire format v2 + delete-path CRDT correctness.
//!
//! Pinned OWNER-DECISIONS under test (M4-05):
//! - tombstones LoroMap value v2 `[reason:1][deleted_at:8 LE][request_id:16]`;
//!   legacy 8-byte / unknown reason byte decode as HARD (fail-closed).
//! - never-downgrade: a hard tombstone is never replaced by a soft one.
//! - the delete commit removes the live `entities[id]` map copy (and, for
//!   hard reasons, the entity's edges-map keys) in the SAME CRDT commit as
//!   the tombstone insert.
//! - cfg-off durability: the `pt:{window}:{entity_hex}` marker is written in
//!   the purge/scrub txn and cleared only after CRDT persistence; a
//!   sync-enabled boot replays leftovers via `replay_pending_tombstones`.

#![cfg(feature = "sync")]

use std::sync::Arc;

use crate::sync_harness::make_entity_blob;
use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use oneiron::affect::Vad;
use oneiron::edge::EdgeKind;
use oneiron::sync::bridge::{encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, apply_tombstone_to_window_doc};
use oneiron::temporal::TimeRange;
use oneiron::{
    DeleteReason, EntityId, HnswConfig, Vault, VaultConfig, deletion::TOMBSTONE_VALUE_V2_LEN,
    deletion::TombstoneReason, deletion::decode_tombstone_value,
};

/// 2026-02-15 ≈ unix 1_771_027_200 ⇒ window "2026-02".
const LEARNED_AT: u64 = 1_771_027_200;
const WINDOW: &str = "2026-02";

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    // The orphan-residue test (AC6) seeds a vector, and vector writes
    // require an embedding-model identity.
    cfg.embedding_model = Some("test/model@v1".to_owned());
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

/// Persists `doc` into the vault's sync_state as window `WINDOW`, the same
/// way the engine persists window docs (`d:w:` snapshot + `sv:w:` VV).
fn persist_window_doc(vault: &Vault, doc: &LoroDoc, window: &str) {
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();
    vault
        .sync_state_put(&format!("d:w:{window}"), &snapshot)
        .unwrap();
    vault
        .sync_state_put(&format!("sv:w:{window}"), &doc.oplog_vv().encode())
        .unwrap();
    vault
        .sync_state_put(&format!("svf:w:{window}"), &[1_u8])
        .unwrap();
}

fn load_window(vault: &Vault, window: &str) -> LoroDoc {
    window::load_window_from_state(vault, "local", &WindowKey::new(window)).unwrap()
}

fn receipt_request_id_hex(vault: &Vault, receipt_id: &EntityId) -> String {
    let raw = vault.get_raw(receipt_id).unwrap().expect("receipt raw");
    let body: serde_json::Value = rmp_serde::from_slice(&raw[25..]).expect("receipt body");
    body["request_id"]
        .as_str()
        .expect("request_id string")
        .replace('-', "")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Seeds LMDB + a persisted window doc with `id` (payload + edges to/from
/// `nbr`) plus an unrelated `nbr` → `other` edge that must survive deletes.
fn seed_entity_with_edges(vault: &Arc<Vault>) -> (EntityId, EntityId, EntityId) {
    let id = EntityId::now();
    let nbr = EntityId::now();
    let other = EntityId::now();

    for entity in [&id, &nbr, &other] {
        vault
            .put_entity(
                entity,
                1,
                TimeRange {
                    start: LEARNED_AT,
                    end: LEARNED_AT,
                },
                LEARNED_AT,
                b"seeded-body",
            )
            .unwrap();
    }
    vault.put_edge(&id, EdgeKind::Supports, &nbr, 0.5).unwrap();
    vault.put_edge(&nbr, EdgeKind::Mentions, &id, 0.5).unwrap();
    vault
        .put_edge(&nbr, EdgeKind::Mentions, &other, 0.5)
        .unwrap();

    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    for entity in [&id, &nbr, &other] {
        entities
            .insert(
                entity.to_hex().as_str(),
                make_entity_blob(1, LEARNED_AT, b"seeded-body").as_slice(),
            )
            .unwrap();
    }
    let edges = doc.get_map("edges");
    let edge_val = encode_edge_value_for_crdt(
        EdgeKind::Supports,
        0.5,
        LEARNED_AT,
        Some(Vad::NEUTRAL),
        None,
    )
    .unwrap();
    edges
        .insert(
            format_edge_key(&id, EdgeKind::Supports, &nbr).as_str(),
            edge_val.as_slice(),
        )
        .unwrap();
    let edge_val = encode_edge_value_for_crdt(
        EdgeKind::Mentions,
        0.5,
        LEARNED_AT,
        Some(Vad::NEUTRAL),
        None,
    )
    .unwrap();
    edges
        .insert(
            format_edge_key(&nbr, EdgeKind::Mentions, &id).as_str(),
            edge_val.as_slice(),
        )
        .unwrap();
    edges
        .insert(
            format_edge_key(&nbr, EdgeKind::Mentions, &other).as_str(),
            edge_val.as_slice(),
        )
        .unwrap();
    doc.commit();
    persist_window_doc(vault, &doc, WINDOW);

    (id, nbr, other)
}

/// AC1+AC2: a hard delete writes the exact v2 tombstone value AND removes
/// the live entities-map copy plus every edges-map key touching the entity
/// in the same delete commit, leaving unrelated keys intact. The embedded
/// request_id correlates with the REDACTION_AUDIT receipt, and the `pt:`
/// crash marker is cleared after CRDT persistence.
#[test]
fn hard_delete_removes_live_entity_and_edges_from_window_doc() {
    let (_dir, vault) = open_vault();
    let (id, nbr, other) = seed_entity_with_edges(&vault);

    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
        .unwrap();
    assert!(outcome.existed);
    let receipt_id = outcome.receipt_id.expect("receipt id");

    let doc = load_window(&vault, WINDOW);
    let hex_id = id.to_hex();

    // Tombstone: exact v2 layout, pinned reason byte, receipt-correlated
    // request_id. The expectation bytes are literals, not encoder output.
    let tombstones = doc.get_map("tombstones");
    let value = map_get_bytes(&tombstones, &hex_id).expect("tombstone must exist");
    assert_eq!(value.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(value[0], 2, "user_hard_delete wire byte");
    let deleted_at = u64::from_le_bytes(value[1..9].try_into().unwrap());
    let raw = vault.get_raw(&receipt_id).unwrap().expect("receipt raw");
    let body: serde_json::Value = rmp_serde::from_slice(&raw[25..]).expect("receipt body");
    assert_eq!(
        deleted_at,
        body["requested_at"].as_u64().expect("requested_at"),
        "deleted_at u64 LE at offset 1 = deletion request time"
    );
    assert_eq!(
        hex(&value[9..25]),
        receipt_request_id_hex(&vault, &receipt_id),
        "tombstone request_id must equal the receipt's request_id"
    );

    // Entities map: the deleted id's live copy is GONE; the neighbor stays.
    let entities = doc.get_map("entities");
    assert!(
        map_get_bytes(&entities, &hex_id).is_none(),
        "live entities-map copy is an ACTIVE carrier and must be removed in the delete commit"
    );
    assert!(
        map_get_bytes(&entities, &nbr.to_hex()).is_some(),
        "unrelated entities must survive"
    );

    // Edges map: every key touching the deleted id is gone; the unrelated
    // nbr → other edge survives.
    let edges = doc.get_map("edges");
    assert!(
        map_get_bytes(&edges, &format_edge_key(&id, EdgeKind::Supports, &nbr)).is_none(),
        "outgoing edge key must be removed"
    );
    assert!(
        map_get_bytes(&edges, &format_edge_key(&nbr, EdgeKind::Mentions, &id)).is_none(),
        "incoming edge key must be removed"
    );
    assert!(
        map_get_bytes(&edges, &format_edge_key(&nbr, EdgeKind::Mentions, &other)).is_some(),
        "unrelated edge keys must survive"
    );

    // Crash marker cleared once the CRDT record is durable.
    assert!(
        vault
            .sync_state_get(&format!("pt:{WINDOW}:{hex_id}"))
            .unwrap()
            .is_none(),
        "pt: marker must be cleared after CRDT persistence"
    );
}

/// The inverse upgrade IS allowed: a hard delete replaces an existing soft
/// tombstone (and the new value carries the hard reason byte).
#[test]
fn hard_delete_upgrades_existing_soft_tombstone() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            1,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"upgrade-me",
        )
        .unwrap();

    let mut soft = vec![1_u8]; // user_delete
    soft.extend_from_slice(&1_771_000_000_u64.to_le_bytes());
    soft.extend_from_slice(&[0xCC; 16]);

    let doc = LoroDoc::new();
    doc.get_map("tombstones")
        .insert(id.to_hex().as_str(), soft.as_slice())
        .unwrap();
    doc.commit();
    persist_window_doc(&vault, &doc, WINDOW);

    vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();

    let reloaded = load_window(&vault, WINDOW);
    let value =
        map_get_bytes(&reloaded.get_map("tombstones"), &id.to_hex()).expect("tombstone must exist");
    assert_eq!(
        value[0], 3,
        "gdpr_delete wire byte must replace the soft one"
    );
    let decoded = decode_tombstone_value(&value);
    assert_eq!(decoded.reason, Some(TombstoneReason::GdprDelete));
    assert!(decoded.is_hard());
}

/// Edge sweep keys off the EFFECTIVE hardness, not the incoming value's:
/// a soft tombstone arriving over an effective hard one is REJECTED by
/// never-downgrade, but a carrier edge a peer re-added since the original
/// hard sweep must still be swept in that apply — a rejected downgrade must
/// not leave live carrier edges behind (delete semantics never weaken).
#[test]
fn rejected_soft_over_effective_hard_sweeps_readded_carrier_edges() {
    let doc = LoroDoc::new();
    let id = EntityId::now();
    let nbr = EntityId::now();

    // Effective HARD tombstone.
    let mut hard = vec![2_u8]; // user_hard_delete
    hard.extend_from_slice(&1_771_000_000_u64.to_le_bytes());
    hard.extend_from_slice(&[0xDD; 16]);
    apply_tombstone_to_window_doc(&doc, &id, &hard).unwrap();
    doc.commit();

    // A peer that missed the delete re-adds a carrier edge.
    let edge_key = format_edge_key(&id, EdgeKind::Supports, &nbr);
    let edge_val = encode_edge_value_for_crdt(
        EdgeKind::Supports,
        0.5,
        LEARNED_AT,
        Some(Vad::NEUTRAL),
        None,
    )
    .unwrap();
    doc.get_map("edges")
        .insert(edge_key.as_str(), edge_val.as_slice())
        .unwrap();
    doc.commit();

    // A SOFT value arrives over the effective hard tombstone…
    let mut soft = vec![1_u8]; // user_delete
    soft.extend_from_slice(&1_771_100_000_u64.to_le_bytes());
    soft.extend_from_slice(&[0xEE; 16]);
    apply_tombstone_to_window_doc(&doc, &id, &soft).unwrap();
    doc.commit();

    // …the downgrade is rejected (hard bytes untouched)…
    let value = map_get_bytes(&doc.get_map("tombstones"), &id.to_hex())
        .expect("tombstone must still exist");
    assert_eq!(value.as_slice(), hard.as_slice(), "never-downgrade holds");

    // …but the re-added carrier edge is swept anyway.
    assert!(
        doc.get_map("edges").get(&edge_key).is_none(),
        "a rejected soft over an effective hard must still sweep carrier edges"
    );
}

/// AC6: a headerless residue (orphan vector, no entities row) previously
/// left NO CRDT record — the orphan id could re-sync forever. It now mints
/// a v2 tombstone under `WindowKey::from_timestamp(now)` — a propagation
/// address, not a truth claim — with the receipt-correlated request_id.
#[test]
fn delete_without_header_mints_tombstone_under_now_window() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();

    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4]).unwrap();
    assert!(vault.get(&id).unwrap().is_none());

    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    assert!(!outcome.existed);
    let receipt_id = outcome.receipt_id.expect("receipt id");

    // The window is addressed by the request time recorded in the receipt.
    let raw = vault.get_raw(&receipt_id).unwrap().expect("receipt raw");
    let body: serde_json::Value = rmp_serde::from_slice(&raw[25..]).expect("receipt body");
    let requested_at = body["requested_at"].as_u64().expect("requested_at");
    let window_key = WindowKey::from_timestamp(requested_at);

    let doc = load_window(&vault, window_key.as_str());
    let value = map_get_bytes(&doc.get_map("tombstones"), &id.to_hex())
        .expect("orphan residue delete must mint a tombstone");
    assert_eq!(value.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(value[0], 3, "gdpr_delete wire byte");
    assert_eq!(
        hex(&value[9..25]),
        receipt_request_id_hex(&vault, &receipt_id),
        "request_id must correlate with the receipt"
    );
    assert!(
        vault
            .sync_state_get(&format!("pt:{window_key}:{}", id.to_hex()))
            .unwrap()
            .is_none(),
        "pt: marker cleared after CRDT persistence"
    );

    // Deleting a fully-missing id stays a strict no-op: no tombstone.
    let missing = EntityId::now();
    let outcome = vault
        .delete_entity_with_reason(&missing, DeleteReason::UserHardDelete)
        .unwrap();
    assert!(!outcome.existed);
    assert!(outcome.receipt_id.is_none());
    let doc = load_window(&vault, window_key.as_str());
    assert!(
        map_get_bytes(&doc.get_map("tombstones"), &missing.to_hex()).is_none(),
        "a delete of a nonexistent id must not mint a tombstone"
    );
}
