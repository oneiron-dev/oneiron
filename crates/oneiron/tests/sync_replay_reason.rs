//! ONE-1133 — reason-aware tombstone replay across nodes (M4-06).
//!
//! Pinned OWNER-DECISIONS under test:
//! - Replay routes through a reason-aware delete primitive, never bare
//!   purge: soft (`user_delete`) = shell-preserving SoftErase; hard /
//!   legacy / unknown = destructive purge (fail-closed: ambiguity resolves
//!   to MORE deletion, never less).
//! - Remote HARD tombstone apply enqueues a LOCAL `h:{seq:8BE}` sweep row
//!   (the ≤30 d Art. 12(3) clock must run on EVERY replica, not only the
//!   origin device) and writes a LOCAL REDACTION_AUDIT receipt whose
//!   `request_id` comes from the wire value (Art. 5(2) accountability
//!   attaches to each replica actually erasing).
//! - Never-downgrade on receive: a soft tombstone for an id already
//!   hard-purged locally is a no-op.
//! - A tombstone always wins over concurrent entities-map state.

#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, LoadedWindow};
use oneiron::types::{
    ENTITY_TYPE_MACHINE, ENTITY_TYPE_REDACTION_AUDIT, EdgeActorClass, EdgeConfirmationStatus,
    EdgeKind, EdgeProvenanceFlags, TimeRange,
};
use oneiron::{
    DeleteReason, EdgeProvenanceClaimBody, EdgeRef, EntityId, HnswConfig, SupersessionStatus,
    TOMBSTONE_VALUE_V2_LEN, Vault, VaultConfig,
};

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

/// Builds a v2 tombstone wire value from LITERAL parts — these bytes are
/// test INPUT; the layout under test is the pinned
/// `[reason:1][deleted_at:8 LE][request_id:16]`.
fn wire_tombstone(reason_byte: u8, deleted_at: u64, request_byte: u8) -> Vec<u8> {
    let mut value = vec![reason_byte];
    value.extend_from_slice(&deleted_at.to_le_bytes());
    value.extend_from_slice(&[request_byte; 16]);
    value
}

/// Returns the hyphenated `request_id` string of the receipt body.
fn receipt_request_id(vault: &Vault, receipt_id: &EntityId) -> String {
    let raw = vault.get_raw(receipt_id).unwrap().expect("receipt raw");
    let body: serde_json::Value = rmp_serde::from_slice(&raw[25..]).expect("receipt body");
    body["request_id"]
        .as_str()
        .expect("request_id string")
        .to_owned()
}

fn redaction_audit_receipts(vault: &Vault) -> Vec<EntityId> {
    vault.entities_by_type(ENTITY_TYPE_REDACTION_AUDIT).unwrap()
}

fn hard_erase_sweep_rows(vault: &Vault) -> Vec<(Vec<u8>, Vec<u8>)> {
    vault.sync_queue_rows_with_prefix(b"h:").unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// AC6 (a): hard delete on node A → replay on node B (full wire path: A's
/// persisted window doc imported into B's observed window) → B's active
/// store is purged AND node B holds its OWN `h:` sweep row + REDACTION_AUDIT
/// receipt with the request_id from the wire (= node A's receipt
/// request_id).
#[test]
fn remote_hard_tombstone_purges_replica_with_local_receipt_and_sweep_row() {
    // --- Node A: author the hard delete ---
    let (_dir_a, vault_a) = open_vault();
    let id = EntityId::now();
    vault_a
        .put_entity(
            &id,
            1,
            time_range(LEARNED_AT),
            LEARNED_AT,
            b"cross-node-secret",
        )
        .unwrap();
    let outcome_a = vault_a
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_a = outcome_a.receipt_id.expect("node A receipt");
    let request_id_a = receipt_request_id(&vault_a, &receipt_a);

    // The wire value the delete persisted into A's window doc.
    let doc_a = window::load_window_from_state(&vault_a, "local", &WindowKey::new(WINDOW)).unwrap();
    let wire_value =
        map_get_bytes(&doc_a.get_map("tombstones"), &id.to_hex()).expect("node A tombstone");
    assert_eq!(wire_value.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(wire_value[0], 3, "gdpr_delete wire byte");

    // --- Node B: a replica that materialized the entity earlier ---
    let (_dir_b, vault_b) = open_vault();
    vault_b
        .batch()
        .put(
            &id,
            1,
            time_range(LEARNED_AT),
            LEARNED_AT,
            b"cross-node-secret",
        )
        .text(&id, &[("body", "cross-node-secret")])
        .commit()
        .unwrap();
    assert_eq!(
        vault_b.search_text("cross-node-secret", 10).unwrap().len(),
        1
    );

    let materializer = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer);

    // --- wire: A's window doc → B's observed window doc ---
    let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
    window_b.doc.import(&snapshot).unwrap();

    // B purged its active store…
    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "remote hard tombstone must purge the replica's active store"
    );
    assert!(
        vault_b
            .search_text("cross-node-secret", 10)
            .unwrap()
            .is_empty()
    );

    // …holds its OWN h: sweep row (deadline ≤ queued_at + 30 d)…
    let rows = hard_erase_sweep_rows(&vault_b);
    assert_eq!(rows.len(), 1, "node B must enqueue a LOCAL h: sweep row");
    assert!(rows[0].0.starts_with(b"h:"));
    let job: serde_json::Value = rmp_serde::from_slice(&rows[0].1).expect("decode sweep job");
    assert_eq!(job["scope"]["entity_ids"][0], id.to_hex());
    let queued_at = job["retry_state"]["queued_at"].as_u64().unwrap();
    let deadline_at = job["retry_state"]["deadline_at"].as_u64().unwrap();
    assert!(deadline_at >= queued_at);
    assert!(deadline_at <= queued_at + 30 * 86_400);

    // …and its OWN receipt, request_id-correlated with node A's.
    let receipts_b = redaction_audit_receipts(&vault_b);
    assert_eq!(receipts_b.len(), 1, "node B must write a LOCAL receipt");
    let request_id_b = receipt_request_id(&vault_b, &receipts_b[0]);
    assert_eq!(
        request_id_b, request_id_a,
        "the replica receipt's request_id must come from the wire value"
    );
    assert_eq!(
        hex(&wire_value[9..25]),
        request_id_b.replace('-', ""),
        "wire request_id bytes and replica receipt must agree"
    );
}

/// AC6 (b): SoftErase (`user_delete`) on node A → replay on node B → B
/// holds the 25 B shell (NOT a purge), B's text/vector indexes drop the
/// entity, and NO `h:` row / NO receipt is written (contracts.ts
/// user_delete: activeStoreHardPurgeV1 = false, receipt = false).
#[test]
fn remote_soft_tombstone_keeps_shell_and_drops_indexes_without_receipt() {
    // --- Node A: author the soft delete ---
    let (_dir_a, vault_a) = open_vault();
    let id = EntityId::now();
    vault_a
        .put_entity(
            &id,
            1,
            time_range(LEARNED_AT),
            LEARNED_AT,
            b"soft-cross-secret",
        )
        .unwrap();
    vault_a
        .delete_entity_with_reason(&id, DeleteReason::UserDelete)
        .unwrap();
    let doc_a = window::load_window_from_state(&vault_a, "local", &WindowKey::new(WINDOW)).unwrap();
    let wire_value =
        map_get_bytes(&doc_a.get_map("tombstones"), &id.to_hex()).expect("node A tombstone");
    assert_eq!(wire_value[0], 1, "user_delete wire byte (soft)");

    // --- Node B: replica with body + text + vector materialized ---
    let (_dir_b, vault_b) = open_vault();
    vault_b
        .batch()
        .put(
            &id,
            1,
            time_range(LEARNED_AT),
            LEARNED_AT,
            b"soft-cross-secret",
        )
        .text(&id, &[("body", "soft-cross-secret")])
        .commit()
        .unwrap();
    vault_b.put_vector(&id, &[0.1, 0.2, 0.3, 0.4]).unwrap();

    let materializer = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer);
    let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
    window_b.doc.import(&snapshot).unwrap();

    // Shell-preserving SoftErase on the replica: 25 B header row survives
    // (an unconditional-hard replay — the pre-ONE-1133 behavior — FAILS
    // here), payload + retrieval indexes are gone.
    let raw = vault_b
        .get_raw(&id)
        .unwrap()
        .expect("user_delete replay must keep the 25 B shell on the replica");
    assert_eq!(raw.len(), 25);
    assert_eq!(vault_b.get(&id).unwrap().as_deref(), Some([].as_slice()));
    assert!(
        vault_b
            .search_text("soft-cross-secret", 10)
            .unwrap()
            .is_empty()
    );
    assert!(vault_b.get_vector(&id).unwrap().is_none());
    assert!(vault_b.entities_by_type(1).unwrap().contains(&id));

    // Soft = no accountability artifacts.
    assert!(
        redaction_audit_receipts(&vault_b).is_empty(),
        "a soft replay must not write a receipt"
    );
    assert!(
        hard_erase_sweep_rows(&vault_b).is_empty(),
        "a soft replay must not enqueue an h: sweep row"
    );
}

/// AC6 (c): never-downgrade on receive — a soft tombstone arriving AFTER
/// this replica already hard-purged the id is a strict no-op: no shell is
/// recreated, no second receipt, no second sweep row. The downgrading value
/// is delivered by a misbehaving/legacy peer that overwrites the tombstone
/// raw (bypassing the write-side guard), causally after the hard value, so
/// the merged map value really is the soft one.
#[test]
fn remote_soft_tombstone_after_local_hard_purge_is_noop() {
    let (_dir_b, vault_b) = open_vault();
    let id = EntityId::now();
    vault_b
        .put_entity(
            &id,
            1,
            time_range(LEARNED_AT),
            LEARNED_AT,
            b"downgrade-target",
        )
        .unwrap();

    let materializer = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer);

    // Peer 1 delivers a HARD tombstone (user_hard_delete).
    let doc_r1 = LoroDoc::new();
    doc_r1
        .get_map("tombstones")
        .insert(
            id.to_hex().as_str(),
            wire_tombstone(2, 1_771_100_000, 0xDD).as_slice(),
        )
        .unwrap();
    doc_r1.commit();
    let update_1 = doc_r1.export(ExportMode::Snapshot).unwrap();
    window_b.doc.import(&update_1).unwrap();

    assert!(vault_b.get_raw(&id).unwrap().is_none(), "hard apply purges");
    assert_eq!(redaction_audit_receipts(&vault_b).len(), 1);
    assert_eq!(hard_erase_sweep_rows(&vault_b).len(), 1);

    // Misbehaving peer 2 forks B's state and overwrites the tombstone with
    // a SOFT value (raw map insert — no never-downgrade guard), causally
    // later, so the soft value deterministically wins the map merge.
    let doc_r2 = LoroDoc::new();
    doc_r2
        .import(&window_b.doc.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    doc_r2
        .get_map("tombstones")
        .insert(
            id.to_hex().as_str(),
            wire_tombstone(1, 1_771_200_000, 0x99).as_slice(),
        )
        .unwrap();
    doc_r2.commit();
    let update_2 = doc_r2.export(ExportMode::Snapshot).unwrap();
    window_b.doc.import(&update_2).unwrap();

    // The downgrade really arrived in the merged map…
    let merged = map_get_bytes(&window_b.doc.get_map("tombstones"), &id.to_hex())
        .expect("tombstone present");
    assert_eq!(merged[0], 1, "the soft value won the CRDT map merge");

    // …but the LOCAL apply is a strict no-op: hard-once-seen is
    // irreversible on this replica.
    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "soft-after-hard must not recreate a shell"
    );
    assert_eq!(
        redaction_audit_receipts(&vault_b).len(),
        1,
        "no second receipt for the downgraded value"
    );
    assert_eq!(
        hard_erase_sweep_rows(&vault_b).len(),
        1,
        "no second sweep row for the downgraded value"
    );
}

/// AC6 (d): a remote hard tombstone on an `edge.provenance` Claim restamps
/// the subject edge on the replica in the same apply (ARCH-0038 D16 — the
/// M2-flagged bug where remote-origin deletes left the replica's 26 B stamp
/// stale). The D14 winner among the SURVIVING live Claims stamps; a
/// bare-purge replay leaves (confirmed, system) and FAILS here.
#[test]
fn remote_hard_tombstone_on_provenance_claim_restamps_subject_edge() {
    let (_dir_b, vault_b) = open_vault();

    // Replica-local graph: actors + subject edge + two live Claims.
    let person = EntityId::now();
    let machine = EntityId::now();
    let a = EntityId::now();
    let b = EntityId::now();
    vault_b
        .put_entity(&person, 4, time_range(1), 1, b"person")
        .unwrap();
    vault_b
        .put_entity(&machine, ENTITY_TYPE_MACHINE, time_range(1), 1, b"machine")
        .unwrap();
    vault_b.put_entity(&a, 4, time_range(1), 1, b"a").unwrap();
    vault_b.put_entity(&b, 4, time_range(1), 1, b"b").unwrap();
    vault_b.put_edge(&a, EdgeKind::Mentions, &b, 0.875).unwrap();
    let subject = EdgeRef::new(a, EdgeKind::Mentions, b);

    // `winner` (conf 0.6, confirmed/system) outranks `runner_up`
    // (conf 0.4, disputed/agent) under D14.
    let winner = EntityId::now();
    vault_b
        .put_edge_provenance(
            &winner,
            &subject,
            &EdgeProvenanceClaimBody::new(machine, 0.6, SupersessionStatus::Confirmed),
            EdgeActorClass::System,
            2_000,
        )
        .unwrap();
    let runner_up = EntityId::now();
    vault_b
        .put_edge_provenance(
            &runner_up,
            &subject,
            &EdgeProvenanceClaimBody::new(person, 0.4, SupersessionStatus::Disputed),
            EdgeActorClass::Agent,
            2_000,
        )
        .unwrap();

    let stamped = |vault: &Vault| -> Option<EdgeProvenanceFlags> {
        vault
            .edges_out(&a)
            .unwrap()
            .into_iter()
            .find(|info| info.kind == EdgeKind::Mentions && info.target == b)
            .expect("subject edge")
            .provenance
    };
    assert_eq!(
        stamped(&vault_b),
        Some(EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::System,
        }),
        "winner stamps before the replay"
    );

    // Remote HARD tombstone for the WINNER claim arrives.
    let materializer = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer);
    let doc_r = LoroDoc::new();
    doc_r
        .get_map("tombstones")
        .insert(
            winner.to_hex().as_str(),
            wire_tombstone(2, 1_771_300_000, 0xCD).as_slice(),
        )
        .unwrap();
    doc_r.commit();
    window_b
        .doc
        .import(&doc_r.export(ExportMode::Snapshot).unwrap())
        .unwrap();

    // Claim purged; subject edge restamped from the surviving runner-up in
    // the same apply — never left stale.
    assert!(vault_b.get_raw(&winner).unwrap().is_none(), "claim purged");
    assert_eq!(
        stamped(&vault_b),
        Some(EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Disputed,
            actor_class: EdgeActorClass::Agent,
        }),
        "subject edge must restamp from the D14 winner among the survivors"
    );

    // The hard apply still carries the replica accountability artifacts.
    let receipts = redaction_audit_receipts(&vault_b);
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipt_request_id(&vault_b, &receipts[0]),
        "cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd",
        "receipt request_id comes from the wire value"
    );
    assert_eq!(hard_erase_sweep_rows(&vault_b).len(), 1);
}

/// AC5: a tombstone always wins over concurrent entities-map state. A
/// re-put of the entity merged AFTER its tombstone (a concurrent writer
/// that never saw the delete) must NOT rematerialize the body on the
/// replica — no later tombstone event would fire to scrub it. The pre-fix
/// observer (no tombstone check on the entities phase) FAILS here.
#[test]
fn concurrent_entity_reput_after_tombstone_does_not_resurrect() {
    let (_dir_b, vault_b) = open_vault();
    let id = EntityId::now();

    let materializer = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer);

    // Entity arrives and materializes.
    let mut blob = Vec::with_capacity(25 + 11);
    blob.push(1_u8);
    blob.extend_from_slice(&LEARNED_AT.to_be_bytes());
    blob.extend_from_slice(&LEARNED_AT.to_be_bytes());
    blob.extend_from_slice(&LEARNED_AT.to_be_bytes());
    blob.extend_from_slice(b"resurrect-me");
    let entities = window_b.doc.get_map("entities");
    entities
        .insert(id.to_hex().as_str(), blob.as_slice())
        .unwrap();
    window_b.doc.commit();
    assert!(vault_b.get_raw(&id).unwrap().is_some());

    // Hard tombstone arrives and purges.
    let tombstones = window_b.doc.get_map("tombstones");
    tombstones
        .insert(
            id.to_hex().as_str(),
            wire_tombstone(2, 1_771_100_000, 0xEE).as_slice(),
        )
        .unwrap();
    window_b.doc.commit();
    assert!(vault_b.get_raw(&id).unwrap().is_none());

    // A concurrent writer's re-put merges AFTER the tombstone.
    entities
        .insert(id.to_hex().as_str(), blob.as_slice())
        .unwrap();
    window_b.doc.commit();

    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "a tombstoned id must never rematerialize from a late entities-map update"
    );
    assert!(
        vault_b.search_text("resurrect-me", 10).unwrap().is_empty(),
        "no index entry may come back either"
    );
}
