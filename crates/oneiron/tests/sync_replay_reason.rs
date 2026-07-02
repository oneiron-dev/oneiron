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
    ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_REDACTION_AUDIT, EdgeActorClass,
    EdgeConfirmationStatus, EdgeKind, EdgeProvenanceFlags, TimeRange,
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
    clear_policy_manifests(&vault);
    (dir, vault)
}

fn clear_policy_manifests(vault: &Vault) {
    // The seeded default policy manifest is local-only engine state for sync
    // windows; public deletion of it is rejected.
    assert!(
        vault
            .count_entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
            .expect("count policy manifests")
            <= 1
    );
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
    let a = EntityId::now();
    let b = EntityId::now();
    vault_b
        .put_entity(&person, 4, time_range(1), 1, b"person")
        .unwrap();
    vault_b.put_entity(&a, 4, time_range(1), 1, b"a").unwrap();
    vault_b.put_entity(&b, 4, time_range(1), 1, b"b").unwrap();
    vault_b.put_edge(&a, EdgeKind::Mentions, &b, 0.875).unwrap();
    let subject = EdgeRef::new(a, EdgeKind::Mentions, b);

    // `winner` (conf 0.6, confirmed) outranks `runner_up`
    // (conf 0.4, disputed) under D14.
    let winner = EntityId::now();
    vault_b
        .put_edge_provenance(
            &winner,
            &subject,
            &EdgeProvenanceClaimBody::new(person, 0.6, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            2_000,
        )
        .unwrap();
    let runner_up = EntityId::now();
    vault_b
        .put_edge_provenance(
            &runner_up,
            &subject,
            &EdgeProvenanceClaimBody::new(person, 0.4, SupersessionStatus::Disputed),
            EdgeActorClass::Human,
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
            actor_class: EdgeActorClass::Human,
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
            actor_class: EdgeActorClass::Human,
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

/// Builds the 25 B header + payload blob the CRDT entities map carries:
/// `[type:1][occurred_start:8 BE][occurred_end:8 BE][learned_at:8 BE]`.
fn make_entity_blob(entity_type: u8, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

fn dt_marker(vault: &Vault, id: &EntityId) -> Option<Vec<u8>> {
    vault
        .sync_state_get(&format!("dt:{}", id.to_hex()))
        .unwrap()
}

/// Fail-closed remat (boot shape): a peer ships a STRING tombstone and
/// LEAVES the body in the entities map (buggy/hostile writer that skipped
/// the same-commit entities-map removal). Boot recovery must treat the
/// non-binary tombstone as HARD: the lingering body never re-materializes
/// (entity-pass gate), the local body is purged with a receipt + `h:` sweep
/// row + permanent `dt:` marker, and a SECOND boot over the same doc is a
/// strict no-op (no receipt multiplication, no resurrection).
///
/// The pre-fix code FAILS here twice over: `map_for_each_bytes` skipped the
/// string tombstone entirely (no purge at all), and the ungated entity pass
/// re-puts the lingering body on every boot.
#[test]
fn string_tombstone_with_lingering_body_purges_on_boot_and_stays_dead() {
    let (_dir_b, vault_b) = open_vault();
    let id = EntityId::now();
    vault_b
        .batch()
        .put(
            &id,
            1,
            time_range(LEARNED_AT),
            LEARNED_AT,
            b"string-doom-body",
        )
        .text(&id, &[("body", "string-doom-body")])
        .commit()
        .unwrap();

    // Peer doc: STRING tombstone + body still in the entities map.
    let blob = make_entity_blob(1, LEARNED_AT, b"string-doom-body");
    let doc_peer = LoroDoc::new();
    doc_peer
        .get_map("entities")
        .insert(id.to_hex().as_str(), blob.as_slice())
        .unwrap();
    doc_peer
        .get_map("tombstones")
        .insert(id.to_hex().as_str(), "deleted-by-peer")
        .unwrap();
    doc_peer.commit();

    // Boot shape: plain doc (no observers), then the recovery passes.
    let doc = LoroDoc::new();
    doc.import(&doc_peer.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    let materializer = Arc::new(Materializer::new());
    window::forward_rematerialize(&vault_b, &doc, &materializer, &WindowKey::new(WINDOW)).unwrap();

    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "a string tombstone must replay as HARD and purge the body"
    );
    assert!(
        vault_b
            .search_text("string-doom-body", 10)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        redaction_audit_receipts(&vault_b).len(),
        1,
        "the fail-closed hard apply must write the local receipt"
    );
    assert_eq!(hard_erase_sweep_rows(&vault_b).len(), 1);
    assert!(
        dt_marker(&vault_b, &id).is_some(),
        "the hard apply must leave the permanent dt: marker"
    );

    // Reverse remat must not ship anything back (body purged, id
    // tombstoned), and a SECOND boot over the same doc — entities map still
    // carrying the peer's lingering body — must not resurrect it or write a
    // second receipt.
    window::reverse_rematerialize(&vault_b, &doc, &WindowKey::new(WINDOW)).unwrap();
    window::forward_rematerialize(&vault_b, &doc, &materializer, &WindowKey::new(WINDOW)).unwrap();
    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "the lingering entities-map body must never re-materialize"
    );
    assert!(
        vault_b
            .search_text("string-doom-body", 10)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        redaction_audit_receipts(&vault_b).len(),
        1,
        "every-boot replay must not multiply receipts"
    );
    assert_eq!(hard_erase_sweep_rows(&vault_b).len(), 1);
}

/// Reverse remat fail-closed gate: a peer's STRING tombstone (entities map
/// clean) arrives while the local body is still live — worst-case boot
/// ordering runs reverse remat BEFORE the forward tombstone pass. The
/// still-live body must NOT be re-inserted into the CRDT entities map (that
/// would ship a hard-deleted payload fleet-wide); the forward pass then
/// applies the fail-closed HARD purge. The pre-fix `map_contains_binary`
/// gate FAILS here (string tombstone reads as absent).
#[test]
fn reverse_remat_does_not_reinsert_live_body_over_string_tombstone() {
    let (_dir_b, vault_b) = open_vault();
    let id = EntityId::now();
    vault_b
        .put_entity(&id, 1, time_range(LEARNED_AT), LEARNED_AT, b"live-local")
        .unwrap();

    let doc_peer = LoroDoc::new();
    doc_peer
        .get_map("tombstones")
        .insert(id.to_hex().as_str(), "deleted-by-peer")
        .unwrap();
    doc_peer.commit();

    let doc = LoroDoc::new();
    doc.import(&doc_peer.export(ExportMode::Snapshot).unwrap())
        .unwrap();

    window::reverse_rematerialize(&vault_b, &doc, &WindowKey::new(WINDOW)).unwrap();
    assert!(
        doc.get_map("entities").get(&id.to_hex()).is_none(),
        "reverse remat must not re-insert a live body over a string tombstone"
    );

    let materializer = Arc::new(Materializer::new());
    window::forward_rematerialize(&vault_b, &doc, &materializer, &WindowKey::new(WINDOW)).unwrap();
    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "the forward pass must hard-apply the string tombstone"
    );
    assert_eq!(redaction_audit_receipts(&vault_b).len(), 1);
    assert!(dt_marker(&vault_b, &id).is_some());
}

/// Receiver-side `dt:` marker (pinned format): a replayed HARD tombstone
/// leaves the permanent `dt:{entity_hex}` row (GLOBAL key, 25 B
/// informational value, written in the purge txn); a replayed SOFT
/// tombstone does not.
#[test]
fn replayed_hard_tombstone_writes_dt_marker_soft_does_not() {
    let (_dir_b, vault_b) = open_vault();
    let hard_id = EntityId::now();
    let soft_id = EntityId::now();
    for (id, body) in [
        (&hard_id, b"hard-target".as_slice()),
        (&soft_id, b"soft-target"),
    ] {
        vault_b
            .put_entity(id, 1, time_range(LEARNED_AT), LEARNED_AT, body)
            .unwrap();
    }

    let materializer = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer);
    let doc_r = LoroDoc::new();
    doc_r
        .get_map("tombstones")
        .insert(
            hard_id.to_hex().as_str(),
            wire_tombstone(2, 1_771_100_000, 0xAB).as_slice(),
        )
        .unwrap();
    doc_r
        .get_map("tombstones")
        .insert(
            soft_id.to_hex().as_str(),
            wire_tombstone(1, 1_771_100_000, 0xAC).as_slice(),
        )
        .unwrap();
    doc_r.commit();
    window_b
        .doc
        .import(&doc_r.export(ExportMode::Snapshot).unwrap())
        .unwrap();

    let marker = dt_marker(&vault_b, &hard_id).expect("hard replay must write the dt: marker");
    assert_eq!(
        marker.len(),
        TOMBSTONE_VALUE_V2_LEN,
        "dt: value is the pinned 25 B [reason:1][deleted_at:8 LE][request_id:16]"
    );
    assert_eq!(marker[0], 2, "informational reason byte from the wire");
    assert_eq!(&marker[1..9], &1_771_100_000_u64.to_le_bytes());
    assert_eq!(&marker[9..25], &[0xAB; 16]);

    assert!(
        vault_b.get_raw(&soft_id).unwrap().is_some(),
        "soft replay keeps the shell"
    );
    assert!(
        dt_marker(&vault_b, &soft_id).is_none(),
        "a soft replay must NOT write a dt: marker"
    );
}

/// Local delete truth survives CRDT-map manipulation: after a hard apply, a
/// hostile peer REMOVES the tombstone from the map and re-puts the body,
/// causally later — so the merged map really has no tombstone and a live
/// entities value. The permanent `dt:` marker must still suppress the
/// resurrection on BOTH surfaces: Observer B (live path) and forward remat
/// (boot path). A tombstone-presence-only gate FAILS here.
#[test]
fn dt_marker_blocks_resurrection_after_hostile_tombstone_removal() {
    let (_dir_b, vault_b) = open_vault();
    let id = EntityId::now();
    vault_b
        .put_entity(&id, 1, time_range(LEARNED_AT), LEARNED_AT, b"never-again")
        .unwrap();

    let materializer = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer);

    // Hard tombstone arrives → purge + receipt + dt: marker.
    let doc_r1 = LoroDoc::new();
    doc_r1
        .get_map("tombstones")
        .insert(
            id.to_hex().as_str(),
            wire_tombstone(2, 1_771_100_000, 0xAD).as_slice(),
        )
        .unwrap();
    doc_r1.commit();
    window_b
        .doc
        .import(&doc_r1.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    assert!(vault_b.get_raw(&id).unwrap().is_none());
    assert!(dt_marker(&vault_b, &id).is_some());

    // Hostile peer forks B's state, deletes the tombstone key, re-puts the
    // body — causally later, so the manipulation wins the merge.
    let doc_r2 = LoroDoc::new();
    doc_r2
        .import(&window_b.doc.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    doc_r2.get_map("tombstones").delete(&id.to_hex()).unwrap();
    doc_r2
        .get_map("entities")
        .insert(
            id.to_hex().as_str(),
            make_entity_blob(1, LEARNED_AT, b"never-again").as_slice(),
        )
        .unwrap();
    doc_r2.commit();
    window_b
        .doc
        .import(&doc_r2.export(ExportMode::Snapshot).unwrap())
        .unwrap();

    // The manipulation really merged…
    assert!(
        window_b
            .doc
            .get_map("tombstones")
            .get(&id.to_hex())
            .is_none(),
        "the hostile tombstone removal must win the map merge for this test"
    );
    // …but Observer B refused to re-materialize (dt: gate).
    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "observer B must suppress the re-put via the dt: marker"
    );

    // Boot path over the manipulated doc: forward remat must hold the line
    // too — no resurrection, no extra receipt.
    let receipts_before = redaction_audit_receipts(&vault_b).len();
    let boot_doc = LoroDoc::new();
    boot_doc
        .import(&window_b.doc.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    window::forward_rematerialize(&vault_b, &boot_doc, &materializer, &WindowKey::new(WINDOW))
        .unwrap();
    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "forward remat must suppress the re-put via the dt: marker"
    );
    assert_eq!(redaction_audit_receipts(&vault_b).len(), receipts_before);
}

/// Casing canonicalization (M4 fix wave), HARD leg: `EntityId::from_hex`
/// is case-insensitive while `to_hex` emits lowercase, so a crafted
/// UPPERCASE-hex tombstone key must gate the entity pass exactly like the
/// canonical key. Pre-fix, the exact-string gate missed the alias: the
/// lingering body materialized into LMDB first and the tombstone pass then
/// purged it again — observable as a receipt + sweep row this replica
/// (which never held the entity) must not write. Post-fix the body never
/// lands: no receipt, no sweep row, and the never-materialized hard apply
/// still pins the permanent canonical-lowercase `dt:` marker.
#[test]
fn uppercase_hard_tombstone_gates_forward_remat_without_receipt_churn() {
    let (_dir_b, vault_b) = open_vault();
    let id = EntityId::from_hex("abcdefabcdefabcdefabcdefabcdefab").unwrap();
    let upper = id.to_hex().to_uppercase();
    assert_ne!(upper, id.to_hex());

    // Peer doc: UPPERCASE hard tombstone + lingering lowercase body.
    let doc_peer = LoroDoc::new();
    doc_peer
        .get_map("entities")
        .insert(
            id.to_hex().as_str(),
            make_entity_blob(1, LEARNED_AT, b"case-doom").as_slice(),
        )
        .unwrap();
    doc_peer
        .get_map("tombstones")
        .insert(
            upper.as_str(),
            wire_tombstone(2, 1_771_100_000, 0xAE).as_slice(),
        )
        .unwrap();
    doc_peer.commit();

    let doc = LoroDoc::new();
    doc.import(&doc_peer.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    let materializer = Arc::new(Materializer::new());
    window::forward_rematerialize(&vault_b, &doc, &materializer, &WindowKey::new(WINDOW)).unwrap();

    assert!(
        vault_b.get_raw(&id).unwrap().is_none(),
        "the lingering body must never materialize past an uppercase tombstone alias"
    );
    assert!(
        redaction_audit_receipts(&vault_b).is_empty(),
        "nothing was erased locally — the gate must block BEFORE materialization, not purge after"
    );
    assert!(hard_erase_sweep_rows(&vault_b).is_empty());
    assert!(
        dt_marker(&vault_b, &id).is_some(),
        "the hard apply still pins the canonical lowercase dt: marker"
    );
}

/// Casing canonicalization, SOFT leg: an uppercase-hex soft tombstone has
/// NO `dt:` marker to fall back on (soft correctly writes none), so the
/// alias-aware map probe is the ONLY thing between a crafted casing and
/// indefinite resurrection of a soft-deleted body. The soft apply itself
/// already canonicalizes (the delta key is PARSED into an id), so the
/// shell lands correctly — but a later canonical-lowercase re-put must be
/// suppressed by the alias-aware Observer-B gate.
#[test]
fn uppercase_soft_tombstone_suppresses_lowercase_reput() {
    let (_dir_b, vault_b) = open_vault();
    let id = EntityId::from_hex("0123456789abcdef0123456789abcdef").unwrap();
    let upper = id.to_hex().to_uppercase();
    vault_b
        .batch()
        .put(
            &id,
            1,
            time_range(LEARNED_AT),
            LEARNED_AT,
            b"soft-case-body",
        )
        .text(&id, &[("body", "soft-case-body")])
        .commit()
        .unwrap();

    let materializer = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer);

    // Peer ships the soft tombstone under an UPPERCASE alias.
    let doc_r1 = LoroDoc::new();
    doc_r1
        .get_map("tombstones")
        .insert(
            upper.as_str(),
            wire_tombstone(1, 1_771_100_000, 0xAF).as_slice(),
        )
        .unwrap();
    doc_r1.commit();
    window_b
        .doc
        .import(&doc_r1.export(ExportMode::Snapshot).unwrap())
        .unwrap();

    // Soft path respected: shell kept, indexes dropped, no receipt, no dt:.
    let shell = vault_b
        .get_raw(&id)
        .unwrap()
        .expect("soft apply keeps the 25 B shell");
    assert_eq!(shell.len(), 25);
    assert!(
        vault_b
            .search_text("soft-case-body", 10)
            .unwrap()
            .is_empty()
    );
    assert!(redaction_audit_receipts(&vault_b).is_empty());
    assert!(
        dt_marker(&vault_b, &id).is_none(),
        "a soft replay must NOT write a dt: marker"
    );

    // Hostile/buggy peer re-puts the body at the canonical lowercase key —
    // causally later, so the entity delta fires against the live doc.
    let doc_r2 = LoroDoc::new();
    doc_r2
        .import(&window_b.doc.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    doc_r2
        .get_map("entities")
        .insert(
            id.to_hex().as_str(),
            make_entity_blob(1, LEARNED_AT, b"soft-case-body").as_slice(),
        )
        .unwrap();
    doc_r2.commit();
    window_b
        .doc
        .import(&doc_r2.export(ExportMode::Snapshot).unwrap())
        .unwrap();

    let raw = vault_b.get_raw(&id).unwrap().expect("shell stays");
    assert_eq!(
        raw.len(),
        25,
        "observer B must suppress the re-put via the uppercase tombstone alias"
    );
    assert!(
        vault_b
            .search_text("soft-case-body", 10)
            .unwrap()
            .is_empty()
    );
}

/// Reverse-remat casing leg: a live local body whose ONLY tombstone is an
/// UPPERCASE-hex soft alias must not be re-inserted into the CRDT entities
/// map (delete wins on every alias; shipping the body would resurrect it
/// fleet-wide). The forward pass then soft-applies the shell.
#[test]
fn uppercase_soft_tombstone_blocks_reverse_remat_reinsert() {
    let (_dir_b, vault_b) = open_vault();
    let id = EntityId::from_hex("00ff00ff00ff00ff00ff00ff00ff00fa").unwrap();
    let upper = id.to_hex().to_uppercase();
    vault_b
        .put_entity(&id, 1, time_range(LEARNED_AT), LEARNED_AT, b"live-local")
        .unwrap();

    let doc_peer = LoroDoc::new();
    doc_peer
        .get_map("tombstones")
        .insert(
            upper.as_str(),
            wire_tombstone(1, 1_771_100_000, 0xB0).as_slice(),
        )
        .unwrap();
    doc_peer.commit();

    let doc = LoroDoc::new();
    doc.import(&doc_peer.export(ExportMode::Snapshot).unwrap())
        .unwrap();

    window::reverse_rematerialize(&vault_b, &doc, &WindowKey::new(WINDOW)).unwrap();
    assert!(
        doc.get_map("entities").get(&id.to_hex()).is_none(),
        "reverse remat must not re-insert a live body over an uppercase tombstone alias"
    );

    let materializer = Arc::new(Materializer::new());
    window::forward_rematerialize(&vault_b, &doc, &materializer, &WindowKey::new(WINDOW)).unwrap();
    let raw = vault_b
        .get_raw(&id)
        .unwrap()
        .expect("the soft apply keeps the shell");
    assert_eq!(raw.len(), 25);
    assert!(dt_marker(&vault_b, &id).is_none());
}

/// Never-downgrade across casing aliases: an existing UPPERCASE-hex HARD
/// tombstone must block a soft write for the same id exactly like a
/// canonical one — otherwise the canonical lowercase key would carry a
/// soft value and a replica reading only that key would under-delete.
#[test]
fn soft_tombstone_does_not_downgrade_uppercase_hard_alias() {
    let id = EntityId::from_hex("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    let upper = id.to_hex().to_uppercase();

    let doc = LoroDoc::new();
    doc.get_map("tombstones")
        .insert(
            upper.as_str(),
            wire_tombstone(2, 1_771_100_000, 0xB1).as_slice(),
        )
        .unwrap();
    doc.commit();

    window::apply_tombstone_to_window_doc(&doc, &id, &wire_tombstone(1, 1_771_200_000, 0xB2))
        .unwrap();

    assert!(
        doc.get_map("tombstones").get(&id.to_hex()).is_none(),
        "the soft value must not land under the canonical key while a hard alias exists"
    );
    assert!(
        map_get_bytes(&doc.get_map("tombstones"), &upper).is_some(),
        "the hard alias stays untouched"
    );
}

/// Origin headerless leg of the `dt:` marker (M4 fix wave): a hard delete
/// routed through `delete_entity_without_header` (active residue — an
/// orphan vector — with no entities row / 25 B header) must write the
/// permanent `dt:{id_hex}` marker in the same txn as the purge, exactly
/// like the headerful and replay paths. Without it, the Observer-B OR-gate
/// has no local truth for this id: the minted CRDT tombstone lives in the
/// NOW-window, so a window-shuffled re-put (different window doc, no
/// tombstone present) would resurrect the id — the GLOBAL, windowless dt:
/// key exists precisely to refuse that.
#[test]
fn headerless_hard_delete_writes_dt_marker_and_blocks_window_shuffled_reput() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4]).unwrap();
    assert!(
        vault.get_raw(&id).unwrap().is_none(),
        "headerless residue precondition: no entities row"
    );

    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    assert!(outcome.receipt_id.is_some());
    let marker = dt_marker(&vault, &id)
        .expect("headerless hard delete must write the dt: marker in the purge txn");
    assert_eq!(
        marker.len(),
        TOMBSTONE_VALUE_V2_LEN,
        "pinned 25 B [reason:1][deleted_at:8 LE][request_id:16] value"
    );
    assert_eq!(marker[0], 3, "gdpr_delete reason byte");

    // A soft headerless delete of another orphan writes NO marker.
    let soft_id = EntityId::now();
    vault.put_vector(&soft_id, &[0.4, 0.3, 0.2, 0.1]).unwrap();
    vault
        .delete_entity_with_reason(&soft_id, DeleteReason::UserDelete)
        .unwrap();
    assert!(
        dt_marker(&vault, &soft_id).is_none(),
        "a soft headerless delete must not write a dt: marker"
    );

    // Window-shuffled re-put: the body re-appears in a DIFFERENT window
    // whose doc holds no tombstone for the id at all — only the GLOBAL dt:
    // marker can refuse it.
    let materializer = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault, &materializer);
    let doc_r = LoroDoc::new();
    doc_r
        .get_map("entities")
        .insert(
            id.to_hex().as_str(),
            make_entity_blob(1, LEARNED_AT, b"reput-attempt").as_slice(),
        )
        .unwrap();
    doc_r.commit();
    window_b
        .doc
        .import(&doc_r.export(ExportMode::Snapshot).unwrap())
        .unwrap();
    assert!(
        vault.get_raw(&id).unwrap().is_none(),
        "the dt: gate must refuse the window-shuffled re-put of a headerless hard delete"
    );
}
