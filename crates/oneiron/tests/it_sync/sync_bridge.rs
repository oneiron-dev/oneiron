// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! Integration tests for the sync entity bridge.
//!
//! Shared two-vault fixtures (`test_config`, `make_entity_blob`, map
//! helpers) live in `tests/sync_harness` (ONE-1136).

#![cfg(feature = "sync")]

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::sync_harness::{
    clear_policy_manifests, make_entity_blob, map_get_bytes, map_insert_bytes, test_config,
};
use loro::{ExportMode, LoroDoc};
use oneiron::affect::Vad;
use oneiron::edge::{EdgeActorClass, EdgeConfirmationStatus, EdgeKind, EdgeProvenanceFlags};
use oneiron::registry::ENTITY_TYPE_REDACTION_AUDIT;
use oneiron::sync::bridge::{
    Materializer, encode_edge_value_for_crdt, format_edge_key, parse_edge_value,
};
use oneiron::sync::client::{SyncClient, SyncClientConfig, SyncEvent, SyncResidenceMode};
use oneiron::sync::lease;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::transport::TAG_SYNC_UPDATE;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, LoadedWindow};
use oneiron::temporal::TimeRange;
use oneiron::{
    DeleteReason, EntityId, Vault, provenance::EdgeProvenanceClaimBody, provenance::EdgeRef,
    provenance::SupersessionStatus,
};
use tokio::sync::mpsc::UnboundedReceiver;

/// Window-owner user id shared by every fixture in this file (ONE-1160).
const TEST_USER: &str = "test-user";
const TEST_LEASE_VAULT_ID: u64 = 0;

/// SyncClient over a manager-owned window registry (ONE-1126).
fn make_client(vault: &Arc<Vault>) -> (SyncClient, UnboundedReceiver<SyncEvent>) {
    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        materializer,
        TEST_USER,
    ));
    SyncClient::new(
        manager,
        SyncClientConfig {
            residence_mode: SyncResidenceMode::All,
            ..Default::default()
        },
    )
    .unwrap()
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

/// ONE-1130: a malformed tombstone key in the delta is quarantined
/// (`x:` row, ONE-1124) and must not block the valid purges sharing the
/// same Observer B event.
#[test]
fn invalid_tombstone_id_does_not_block_other_purges_in_same_commit() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new(TEST_USER, key, &vault, &materializer);

    let learned_at = 1_772_000_000u64;
    let id = EntityId::now();
    let entities = window.doc.get_map("entities");
    map_insert_bytes(
        &entities,
        id.to_hex().as_str(),
        &make_entity_blob(1, learned_at, b"valid"),
    );
    window.doc.commit();
    assert!(vault.get(&id).unwrap().is_some());

    let tombstones = window.doc.get_map("tombstones");
    tombstones
        .insert("not-a-hex-entity-id", &1_772_000_100u64.to_le_bytes())
        .unwrap();
    tombstones
        .insert(id.to_hex().as_str(), &1_772_000_100u64.to_le_bytes())
        .unwrap();
    window.doc.commit();

    assert!(
        vault.get(&id).unwrap().is_none(),
        "valid tombstone must purge even when a malformed key shares the delta"
    );
}

#[test]
fn observer_a_sequence_overflow_preserves_zero_update_slot() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new(TEST_USER, key.clone(), &vault, &materializer);
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

    let doc = create_window_doc(TEST_USER, &key);

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
    let window = LoadedWindow::new(TEST_USER, key.clone(), &vault, &materializer);
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
        window::forward_rematerialize(&vault_b, &recovered_doc, &materializer_b, &key).unwrap();
    assert_eq!(
        rematerialized, 4,
        "should rebuild three entity rows and one edge; the tombstoned id is \
         gated out of the entity pass (never rebuilt-then-purged — that churn \
         multiplied receipts on every boot) and its tombstone replay is a \
         receipt-free no-op (already purged on the live path)"
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
    let second =
        window::forward_rematerialize(&vault_b, &recovered_doc, &materializer_b, &key).unwrap();
    assert_eq!(second, 0, "second forward pass must perform zero writes");
}

#[test]
fn reverse_rematerialize_mirrors_lmdb_entities_edges_and_skips_tombstones() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let key = WindowKey::new("2026-03");
    let window = LoadedWindow::new(TEST_USER, key.clone(), &vault, &materializer);
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

    let reverse_doc = create_window_doc(TEST_USER, &key);
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
    let (mut client, _rx) = make_client(&vault);

    let server_doc = LoroDoc::new();
    let meta = server_doc.get_map("meta");
    // Byte-encode `meta.windows` to match the schema helpers and the server's
    // root-doc init — `read_window_list` only decodes `LoroValue::Binary`.
    meta.insert("windows", "2026-03".as_bytes()).unwrap();
    // ONE-1140 (OD-3): the root doc also carries the `leases` registry —
    // one valid pinned 66 B record plus one malformed entry. The import
    // must full-mirror the valid record into its `ls:` row in the same
    // persist and QUARANTINE the malformed one (kept out of ls:, never
    // silently dropped).
    let leases = server_doc.get_map("leases");
    let mut lease_record = vec![0x02u8, 0x01];
    lease_record.extend_from_slice(&[0xAB; 32]);
    lease_record.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    lease_record.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    lease_record.extend_from_slice(&(1_700_000_000u64 + 7_776_000).to_le_bytes());
    lease_record.extend_from_slice(&TEST_LEASE_VAULT_ID.to_be_bytes());
    assert_eq!(lease_record.len(), 66, "OD-4 lease record length literal");
    leases
        .insert("00000000000000aa", lease_record.as_slice())
        .unwrap();
    leases
        .insert("00000000000000bb", b"garbage".as_slice())
        .unwrap();
    server_doc.commit();
    let update = server_doc.export(ExportMode::all_updates()).unwrap();

    let mut message = vec![TAG_SYNC_UPDATE];
    message.extend_from_slice(&update);
    let responses = client.handle_server_message(&message).unwrap();

    assert!(responses.is_empty());
    assert_eq!(client.server_windows(), vec!["2026-03".to_string()]);
    assert_eq!(
        vault
            .sync_state_get(&lease::lease_key(TEST_LEASE_VAULT_ID, 0xaa))
            .unwrap()
            .as_deref(),
        Some(lease_record.as_slice()),
        "root import must mirror valid lease records into ls: rows byte-identical (OD-3)"
    );
    assert!(
        vault
            .sync_state_get(&lease::lease_key(TEST_LEASE_VAULT_ID, 0xbb))
            .unwrap()
            .is_none(),
        "a malformed lease record must never be upserted into ls:"
    );
    let records = oneiron::sync::quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1, "the malformed lease entry quarantines");
    assert_eq!(records[0].1.reason_code, "CorruptedIndex");
    assert_eq!(records[0].1.window_key, "root");
}

/// GDPR receipt survival across a full CRDT sync round-trip (ONE-1103).
///
/// A REDACTION_AUDIT receipt (type byte 64; ARCH-0038 / contracts.ts
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
/// REDACTION_AUDIT receipt through the public `validate_public_entity_type` gate,
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

    // ONE-1140 (OD-3/OD-4): node B's door verifies the receipt's origin
    // attestation against its `ls:` lease-registry mirror, so B registers
    // node A's binding first (in production the server's full root-doc
    // mirror does this). The row is the pinned 66 B layout, hand-built:
    // `[ver 0x02][status 0x01][pubkey:32][granted:8 LE][renewed:8 LE]
    // [expires:8 LE][vault_id:8 BE]`, key `ls:{vault_id:016x}:{client_id:016x}`.
    let author_client_id = u64::from_le_bytes(
        vault_a
            .sync_state_get("m:client_id")
            .unwrap()
            .expect("receipt mint provisions the device identity (OD-2)")
            .try_into()
            .unwrap(),
    );
    let author_pk: [u8; 32] = vault_a
        .sync_state_get("m:device_pk")
        .unwrap()
        .expect("receipt mint provisions the attestation keypair (OD-2)")
        .try_into()
        .unwrap();
    let mut lease_row = Vec::with_capacity(66);
    lease_row.push(0x02); // version
    lease_row.push(0x01); // status: active
    lease_row.extend_from_slice(&author_pk);
    lease_row.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    lease_row.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    lease_row.extend_from_slice(&(1_700_000_000u64 + 7_776_000).to_le_bytes());
    lease_row.extend_from_slice(&TEST_LEASE_VAULT_ID.to_be_bytes());
    assert_eq!(lease_row.len(), 66, "OD-4 lease record length literal");
    vault_b
        .sync_state_put(
            &lease::lease_key(TEST_LEASE_VAULT_ID, author_client_id),
            &lease_row,
        )
        .unwrap();

    let materializer = Materializer::new();
    let restored =
        window::forward_rematerialize(&vault_b, &doc_b, &materializer, &window_key).unwrap();
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
    // Discoverable via the system-zone type index (REDACTION_AUDIT).
    assert!(
        vault_b
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .contains(&receipt_id),
        "receipt must be discoverable via the maintenance type index on node B"
    );
    // Lands in the temporal_learned index it belongs to.
    // (+1: `entities_in_learned_range` is half-open `[start, end)` —
    // this is a point lookup at exactly `learned_at`.)
    assert!(
        vault_b
            .entities_in_learned_range(learned_at, learned_at + 1)
            .unwrap()
            .contains(&receipt_id),
        "receipt must land in node B's temporal_learned index"
    );
}

/// `edge.provenance` truth-Claim survival across a full CRDT sync
/// round-trip (ONE-1123; deferred from M2 #79/#81).
///
/// contracts.ts `edgeProvenanceClaim`: the 26 B edge value's two hot flags
/// are "a DERIVED CACHE of that Claim, and the Claim is truth"; the Claim is
/// stored as a "Normal CLAIM entity" with predicate `edge.provenance` and a
/// `claim_of` link edge to the subject edge's SOURCE entity. The flag cache
/// already crossed sync bit-exact, but both replay doors hard-coded
/// `allow_reserved_predicate: false`, so the truth-Claim itself was REJECTED
/// on replica replay (warn-skipped by Observer B, silently dropped by
/// `forward_rematerialize`) — inverting the contract: the replica kept the
/// cache and lost the truth. Any later flag refresh on the replica would
/// find no surviving Claim and downgrade the edge to bare 24 B, re-admitting
/// withdrawn provenance into PPR (the failure M2 #83 keep-26B prevents).
///
/// Round-trip: Node A authors the Claim through the REAL provenance unit
/// (`put_edge_provenance`) → `reverse_rematerialize` mirrors A's LMDB into
/// the CRDT → snapshot import to Node B → B's `forward_rematerialize`. The
/// Claim must arrive byte-identical, its `claim_of` edge must exist, and the
/// subject edge's 26 B stamp must match A's.
///
/// FAILS against pre-fix code: `forward_rematerialize` routed the type-0
/// reserved-predicate Claim through `put_internal`
/// (`allow_reserved_predicate: false`), `validate_claim_body_bytes` rejected
/// it with ReservedPredicate, and the `if result.is_ok()` guard silently
/// dropped it — the Claim never reached Node B's LMDB, and without it the
/// `claim_of` edge's source did not exist so that edge was dropped too.
#[test]
fn edge_provenance_claim_survives_crdt_sync_round_trip() {
    // --- Node A: subject edge + provenance through the real unit ---
    let temp_a = tempfile::tempdir().unwrap();
    let vault_a = Arc::new(Vault::open(temp_a.path(), test_config()).unwrap());
    clear_policy_manifests(&vault_a);

    let person = EntityId::now();
    let src = EntityId::now();
    let tgt = EntityId::now();
    vault_a
        .put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: 301,
                end: 301,
            },
            301,
            b"person",
        )
        .unwrap();
    vault_a
        .put_entity(
            &src,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: 302,
                end: 302,
            },
            302,
            b"src",
        )
        .unwrap();
    vault_a
        .put_entity(
            &tgt,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: 303,
                end: 303,
            },
            303,
            b"tgt",
        )
        .unwrap();
    vault_a
        .put_edge(&src, EdgeKind::Mentions, &tgt, 0.875)
        .unwrap();

    let claim_id = EntityId::now();
    let subject = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    let body = EdgeProvenanceClaimBody::new(person, 0.75, SupersessionStatus::Confirmed);
    vault_a
        .put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 1_000)
        .unwrap();

    // The Claim is a normal type-0 CLAIM entity (contracts.ts storedAs).
    let claim_raw = vault_a
        .get_raw(&claim_id)
        .unwrap()
        .expect("claim must exist in node A LMDB");
    assert_eq!(
        claim_raw[0], 0,
        "edge.provenance Claim must carry type byte 0 (CLAIM)"
    );

    // A's subject edge carries the derived 26 B stamp: confirmed=1, human=0.
    let expected_stamp = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Confirmed,
        actor_class: EdgeActorClass::Human,
    };
    let edge_a = vault_a
        .edges_out(&src)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == EdgeKind::Mentions && e.target == tgt)
        .expect("subject edge on node A");
    assert_eq!(
        edge_a.provenance,
        Some(expected_stamp),
        "node A's subject edge must carry the derived provenance stamp"
    );

    // --- Node A: LMDB → CRDT (all learned_at values land in one window) ---
    let window_key = WindowKey::from_timestamp(1_000);
    let doc_a = create_window_doc("node-a", &window_key);
    let mirrored = window::reverse_rematerialize(&vault_a, &doc_a, &window_key).unwrap();
    assert!(
        mirrored >= 4,
        "person, src, tgt, and the Claim must mirror into the CRDT (got {mirrored})"
    );
    assert_eq!(
        map_get_bytes(&doc_a.get_map("entities"), claim_id.to_hex().as_str()).as_deref(),
        Some(claim_raw.as_slice()),
        "truth-Claim must be byte-identical in the CRDT mirror"
    );

    // --- wire: doc_a → doc_b (peer sync via snapshot import) ---
    let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
    let doc_b = LoroDoc::from_snapshot(&snapshot).unwrap();

    // --- Node B: CRDT → LMDB (the seam that silently dropped the Claim) ---
    let temp_b = tempfile::tempdir().unwrap();
    let vault_b = Vault::open(temp_b.path(), test_config()).unwrap();
    let materializer = Materializer::new();
    let restored =
        window::forward_rematerialize(&vault_b, &doc_b, &materializer, &window_key).unwrap();
    assert!(
        restored >= 4,
        "forward rematerialize must restore entities and edges (got {restored})"
    );

    // Truth-Claim byte-identical on B (the pre-fix silent drop).
    assert_eq!(
        vault_b.get_raw(&claim_id).unwrap().as_deref(),
        Some(claim_raw.as_slice()),
        "edge.provenance truth-Claim must survive replay byte-identical on node B"
    );
    // …and readable as a Claim with the contract predicate literal.
    let read = vault_b
        .get_claim(&claim_id)
        .unwrap()
        .expect("replicated Claim must read back through get_claim");
    assert_eq!(read.predicate, "edge.provenance");

    // claim_of edge present: Claim → subject edge's SOURCE entity (D12).
    assert!(
        vault_b
            .edge_exists(&claim_id, EdgeKind::ClaimOf, &src)
            .unwrap(),
        "claim_of edge must tie the replicated Claim to its subject's source"
    );

    // Subject edge 26 B stamp matches A: cache AND truth agree on B.
    let edge_b = vault_b
        .edges_out(&src)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == EdgeKind::Mentions && e.target == tgt)
        .expect("subject edge on node B");
    assert_eq!(
        edge_b.provenance,
        Some(expected_stamp),
        "node B's subject edge stamp must match node A's"
    );
    assert_eq!(
        edge_b.weight.to_bits(),
        edge_a.weight.to_bits(),
        "subject edge weight must cross bit-exact"
    );
    assert_eq!(edge_b.created_at, edge_a.created_at);
    assert_eq!(edge_b.vad, edge_a.vad);
}
