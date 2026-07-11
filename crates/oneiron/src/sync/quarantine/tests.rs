use std::sync::Arc;

use super::*;
use crate::Vault;
use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::off_record::OffRecordBackendClass;
use crate::registry::ENTITY_TYPE_TASK;
use crate::sync::bridge::Materializer;
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::schema::create_window_doc;
use crate::sync::window::{LoadedWindow, forward_rematerialize, reverse_rematerialize};
use crate::temporal::TimeRange;
use loro::LoroDoc;

/// `learned_at` inside the 2026-03 window used throughout.
const LEARNED_AT: u64 = 1_772_400_000;
const WINDOW: &str = "2026-03";
const GITHUB_PAT_SECRET_FIXTURE: &[u8] = b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// Small map_size + tempdir held for the vault's lifetime — macOS LMDB
/// flake isolation. NOTE: the lib test binary sits near a per-process
/// LMDB env-open budget on macOS (each test_vault is one env); the
/// env-heavy observer table tests live in `tests/sync_quarantine.rs`
/// (their own process) for exactly this reason. Keep in-lib env count
/// minimal.
fn test_vault_with_dir() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    let vault = Arc::new(Vault::open(dir.path(), cfg).unwrap());
    (dir, vault)
}

/// 25-byte envelope: type u8 + occurred_start/end + learned_at u64 BE.
fn entity_blob(entity_type: u8, occurred: TimeRange, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&occurred.start.to_be_bytes());
    blob.extend_from_slice(&occurred.end.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

fn task_body() -> Vec<u8> {
    crate::habit::task_body_for_test(crate::habit::TaskRole::Task)
}

/// Hand-built 24-byte SemanticBare edge value (weight + created_at +
/// VAD), bypassing `encode_edge_value`'s own validation.
fn semantic_edge_value(weight: f32) -> Vec<u8> {
    let mut value = Vec::with_capacity(24);
    value.extend_from_slice(&weight.to_le_bytes());
    value.extend_from_slice(&10u64.to_le_bytes());
    for _ in 0..3 {
        value.extend_from_slice(&0.5f32.to_le_bytes());
    }
    value
}

fn valid_time_range() -> TimeRange {
    TimeRange { start: 1, end: 2 }
}

// ─── Key family + record shape ───────────────────────────────────────────

/// AC1 — `x:{seq:8BE}` literal layout: prefix byte-for-byte, big-endian
/// sequence. A little-endian or differently-prefixed implementation
/// fails here.
#[test]
fn quarantine_key_encoding_is_x_prefix_with_8be_seq() {
    assert_eq!(
        encode_quarantine_key(0x0102_0304_0506_0708),
        *b"x:\x01\x02\x03\x04\x05\x06\x07\x08"
    );
    assert_eq!(
        decode_quarantine_seq(b"x:\x00\x00\x00\x00\x00\x00\x00\x2a"),
        Some(42)
    );
    // Wrong family prefix and wrong lengths never decode.
    assert_eq!(
        decode_quarantine_seq(b"q:\x00\x00\x00\x00\x00\x00\x00\x2a"),
        None
    );
    assert_eq!(
        decode_quarantine_seq(b"x:\x00\x00\x00\x00\x00\x00\x2a"),
        None
    );
    for seq in [0u64, 1, 255, 65_535, u64::MAX] {
        assert_eq!(
            decode_quarantine_seq(&encode_quarantine_key(seq)),
            Some(seq)
        );
    }
}

#[test]
fn remote_rejection_reason_classifies_secret_scan_denials_only() {
    let secret_scan = Error::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec!["gate.secret_scan.detected", "gate.secret_scan.github_token"],
    };
    let other_gate = Error::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec!["gate.policy.denied"],
    };
    let pending_secret_scan = Error::GateWriteRejected {
        outcome: "pending",
        reason_codes: vec!["gate.secret_scan.detected"],
    };

    assert_eq!(
        remote_rejection_reason(&secret_scan).as_deref(),
        Some("GateWriteRejected")
    );
    assert_eq!(remote_rejection_reason(&other_gate), None);
    assert_eq!(remote_rejection_reason(&pending_secret_scan), None);
    assert_eq!(
        remote_rejection_reason(&Error::CompanionRecordAlreadyExists).as_deref(),
        Some("CompanionRecordAlreadyExists")
    );
    assert_eq!(
        remote_rejection_reason(&Error::InvalidPsychProfileBody("bad profile")).as_deref(),
        Some("InvalidPsychProfileBody")
    );
    assert_eq!(
        remote_rejection_reason(&Error::InvalidSkillBody("bad skill")).as_deref(),
        Some("InvalidSkillBody")
    );
    assert_eq!(
        remote_rejection_reason(&Error::InvalidAgentDefBody("bad agent def")).as_deref(),
        Some("InvalidAgentDefBody")
    );
    assert_eq!(
        remote_rejection_reason(&Error::InvalidTaskBody("missing task role")).as_deref(),
        Some("InvalidTaskBody")
    );
}

/// Pinned retention decision: 4096 rows, ≤30 days.
#[test]
fn retention_constants_match_pinned_decision() {
    assert_eq!(MAX_QUARANTINE_ROWS, 4096);
    assert_eq!(QUARANTINE_MAX_AGE_SECS, 2_592_000);
}

/// AC1/OWNER-DECISION — the record is GDPR-inert: it stores the xxh3_64
/// HASH of the rejected bytes, never the bytes. An implementation that
/// embeds the payload (full-bytes alternative) fails the windows scan.
/// Also pins the literal `x:` + 8BE row addressing in the raw store.
#[test]
fn quarantine_record_is_hash_only_never_payload_bytes() {
    let (_dir, vault) = test_vault_with_dir();
    // 24 bytes (< 25-byte envelope → undecodable blob) and distinctive.
    let payload = b"SECRET-PII-PAYLOAD-BYTES";
    assert_eq!(payload.len(), 24);

    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = crate::sync::bridge::register_observer_b(&doc, &vault, &materializer, WINDOW);
    let id = EntityId::now();
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), payload).unwrap();
    doc.commit();

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let (seq, rec) = &records[0];
    assert_eq!(*seq, 1);
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.container, QuarantineContainer::Entities);
    assert_eq!(rec.crdt_key_hash, xxh3_64(id.to_hex().as_bytes()));
    assert_eq!(rec.crdt_key_len, 32);
    assert_eq!(rec.reason_code, "CorruptedIndex");
    assert_eq!(
        rec.payload_hash,
        xxh3_64(payload),
        "record must carry the xxh3_64 of the rejected bytes"
    );

    let rtxn = vault.store.env.read_txn().unwrap();
    let raw = vault
        .store
        .sync_queue
        .get(&rtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x01")
        .unwrap()
        .expect("row must live under the literal x: + 8BE key");
    assert!(
        !raw.windows(payload.len()).any(|w| w == payload),
        "x: row must never carry the rejected payload bytes (GDPR-inert)"
    );
}

// ─── Retention + doctor surface (AC5) ────────────────────────────────────

/// Row-cap + age-bound retention (oldest evicted first, counter
/// persists) and the doctor surface over the same vault.
#[test]
fn retention_evicts_oldest_first_and_doctor_reports_state() {
    let (_dir, vault) = test_vault_with_dir();
    for i in 0..5u64 {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        record_in_txn(
            &vault,
            &mut wtxn,
            &QuarantineRecord {
                window_key: WINDOW.to_string(),
                container: QuarantineContainer::Entities,
                crdt_key_hash: i,
                crdt_key_len: 2,
                reason_code: "InvalidKey".to_string(),
                payload_hash: i,
                quarantined_at: 1_000 + i,
            },
        )
        .unwrap();
        wtxn.commit().unwrap();
    }

    // Cap sweep: 5 rows, cap 3 → the two oldest go.
    let mut wtxn = vault.store.env.write_txn().unwrap();
    let evicted = enforce_retention_in_txn(&vault, &mut wtxn, 3, u64::MAX, 2_000).unwrap();
    wtxn.commit().unwrap();
    assert_eq!(evicted, 2);
    let remaining: Vec<u64> = quarantined_records(&vault)
        .unwrap()
        .into_iter()
        .map(|(seq, _)| seq)
        .collect();
    assert_eq!(remaining, vec![3, 4, 5], "oldest rows must go first");

    // Age sweep through the production write path: a record older than
    // 30 days is evicted when the next record lands.
    let fresh_hash = 0xF8E5_u64;
    let mut wtxn = vault.store.env.write_txn().unwrap();
    record_in_txn(
        &vault,
        &mut wtxn,
        &QuarantineRecord {
            window_key: WINDOW.to_string(),
            container: QuarantineContainer::Edges,
            crdt_key_hash: fresh_hash,
            crdt_key_len: 5,
            reason_code: "InvalidEdgeWeight".to_string(),
            payload_hash: 9,
            quarantined_at: 1_004 + QUARANTINE_MAX_AGE_SECS + 1,
        },
    )
    .unwrap();
    wtxn.commit().unwrap();
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1, "rows past the age bound are evicted");
    assert_eq!(records[0].1.crdt_key_hash, fresh_hash);

    // Doctor surface: count, newest-first reasons, evictions, rm:.
    set_remat_marker(&vault, WINDOW, &EntityId::now()).unwrap();
    let report = sync_doctor(&vault).unwrap();
    assert_eq!(report.quarantine_count, 1);
    assert_eq!(
        report.recent_reason_codes,
        vec!["InvalidEdgeWeight".to_string()],
        "newest reason first"
    );
    assert_eq!(
        report.eviction_count,
        2 + 3,
        "cap sweep + age sweep evictions"
    );
    assert_eq!(report.rm_pending_windows, vec![WINDOW.to_string()]);

    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, QUARANTINE_EVICTIONS_KEY)
            .unwrap(),
        Some(5u64.to_le_bytes().as_slice()),
        "eviction counter must persist (doctor-visible)"
    );
}

// ─── AC4 + AC7 — rm: round trip ──────────────────────────────────────────

/// AC4/AC7 — full rm: round trip: injected purge failure on Observer B
/// → `rm:w:{window}:{entity_hex}` marker (literal entity-scoped key +
/// 1-byte value) → a failing drain keeps the marker (ERROR-grade in
/// doctor) → a healthy drain purges, clears the marker, and reports it
/// drained.
#[test]
fn rm_marker_round_trip_purge_failure_then_drain() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        )
        .unwrap();

    let window_key = WindowKey::new(WINDOW);
    let window = LoadedWindow::new("test-user", window_key.clone(), &vault, &materializer);
    let mirrored = reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
    assert_eq!(mirrored, 1);

    // Remote tombstone arrives; the active-store purge fails.
    INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
    map_insert_bytes(&window.doc.get_map("tombstones"), &id.to_hex(), b"1").unwrap();
    window.doc.commit();

    assert!(
        vault.get(&id).unwrap().is_some(),
        "precondition: failed purge left hard-deleted content live"
    );
    // Pinned literal grammar: rm:w:{window}:{entity_hex} → 1 byte.
    let marker_key = format!("rm:w:2026-03:{}", id.to_hex());
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &marker_key).unwrap(),
        Some([1u8].as_slice()),
        "purge failure must set the entity-scoped rm:w marker"
    );
    drop(rtxn);
    assert_eq!(
        sync_doctor(&vault).unwrap().rm_pending_windows,
        vec![WINDOW.to_string()]
    );

    // Persist the doc (with the tombstone) so the drain can load it.
    window.persist_state(&vault).unwrap();
    drop(window);

    // Drain while the purge KEEPS failing: marker survives (ERROR).
    INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
    let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
    assert_eq!(report.still_pending, vec![WINDOW.to_string()]);
    assert!(report.drained.is_empty());
    assert!(vault.get(&id).unwrap().is_some());

    // Healthy drain: purge succeeds, marker cleared only now.
    let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
    assert_eq!(report.drained, vec![WINDOW.to_string()]);
    assert!(report.still_pending.is_empty());
    assert!(
        vault.get(&id).unwrap().is_none(),
        "drain must complete the purge"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &marker_key).unwrap(),
        None,
        "marker cleared only on successful purge"
    );
    drop(rtxn);
    assert!(sync_doctor(&vault).unwrap().rm_pending_windows.is_empty());
}

/// AC4 — the forward-remat tombstone pass is itself an rm: producer, and
/// (fail-closed) a doc with NO tombstones never vacuously discharges an
/// rm: marker (the persisted state may predate the failed tombstone).
#[test]
fn forward_remat_tombstone_purge_failure_flags_rm_then_clears_on_success() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        )
        .unwrap();

    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);
    map_insert_bytes(&doc.get_map("tombstones"), &id.to_hex(), b"1").unwrap();
    doc.commit();

    INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert!(vault.get(&id).unwrap().is_some());
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()],
        "forward-remat purge failure must flag rm:w"
    );

    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert!(vault.get(&id).unwrap().is_none());
    assert!(
        pending_remat_windows(&vault).unwrap().is_empty(),
        "marker cleared after the purge pass fully succeeds"
    );

    // Stale-state guard: re-flag the entity, then run a doc carrying
    // ZERO tombstones — the marker must survive (clearing requires the
    // entity's own tombstone to succeed in the pass).
    set_remat_marker(&vault, WINDOW, &id).unwrap();
    let empty_doc = create_window_doc("test-user", &window_key);
    forward_rematerialize(&vault, &empty_doc, &materializer, &window_key).unwrap();
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()],
        "empty-tombstone doc must not clear the marker"
    );

    // A doc whose tombstones are ALL malformed must not clear the
    // marker either: only VALIDATED tombstones count toward the purge
    // pass that discharges it (a malformed-only doc would otherwise
    // vacuously discharge the GDPR retry).
    let malformed_doc = create_window_doc("test-user", &window_key);
    map_insert_bytes(&malformed_doc.get_map("tombstones"), "zzz-not-hex", b"1").unwrap();
    malformed_doc.commit();
    forward_rematerialize(&vault, &malformed_doc, &materializer, &window_key).unwrap();
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()],
        "malformed-only tombstone doc must not clear the marker"
    );
}

/// rm: drain for a flagged window with NO persisted snapshot (`d:w:`
/// absent): the doc is rebuilt from Observer A's durable `u:w:` update
/// rows, so the failed purge still drains — a hard-deleted entity must
/// not stay live indefinitely behind a missing snapshot row.
#[test]
fn rm_drain_rebuilds_doc_from_pending_updates_when_snapshot_missing() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        )
        .unwrap();

    let window_key = WindowKey::new(WINDOW);
    let window = LoadedWindow::new("test-user", window_key.clone(), &vault, &materializer);
    let mirrored = reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
    assert_eq!(mirrored, 1);

    // Remote tombstone arrives; the active-store purge fails → rm: set.
    INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
    map_insert_bytes(&window.doc.get_map("tombstones"), &id.to_hex(), b"1").unwrap();
    window.doc.commit();
    assert!(vault.get(&id).unwrap().is_some());
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()]
    );

    // Drop WITHOUT persist_state: no d:w: snapshot, but Observer A
    // persisted the update rows durably.
    drop(window);
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_state.get(&rtxn, "d:w:2026-03").unwrap(),
        None,
        "precondition: no persisted snapshot"
    );
    let pending_updates = vault
        .store
        .sync_state
        .prefix_iter(&rtxn, "u:w:2026-03:")
        .unwrap()
        .count();
    assert!(pending_updates > 0, "precondition: u:w: rows persisted");
    drop(rtxn);

    // Drain rebuilds the doc from u:w: rows; the purge now succeeds.
    let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
    assert_eq!(report.drained, vec![WINDOW.to_string()]);
    assert!(report.still_pending.is_empty());
    assert!(
        vault.get(&id).unwrap().is_none(),
        "hard-deleted entity purged via the rebuilt doc"
    );
    assert!(pending_remat_windows(&vault).unwrap().is_empty());
}

/// ONE-1147 — Observer-B ENTITY batch whole-txn failure parity with the
/// hardened tombstone path: a failed batch commit must set the durable
/// entity-scoped marker under the LITERAL key `rm:w:{window}:{entity_hex}`
/// with the LITERAL 1-byte value `[1u8]` for EVERY entity the dead txn
/// had applied (never a bare error log), and a later
/// `drain_remat_markers` must heal the divergence (entities present in
/// LMDB) and clear the markers via the actual healing writes.
#[test]
fn rm_marker_round_trip_entity_batch_commit_failure_then_drain() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());
    let window_key = WindowKey::new(WINDOW);
    let window = LoadedWindow::new("test-user", window_key, &vault, &materializer);

    let a = EntityId::now();
    let b = EntityId::now();
    let body_a = task_body();
    let body_b = task_body();
    let blob_a = entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, &body_a);
    let blob_b = entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, &body_b);

    // One commit → one delta → ONE batch txn carrying BOTH ops; the
    // injected LOCAL error aborts it post-batch, hitting the Observer-B
    // swallow site (the whole-txn failure class: no surviving
    // per-entity failure point).
    crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, &a.to_hex(), &blob_a).unwrap();
    map_insert_bytes(&entities, &b.to_hex(), &blob_b).unwrap();
    window.doc.commit();

    // Divergence precondition: ops live in the CRDT doc, absent from LMDB.
    assert!(vault.get(&a).unwrap().is_none());
    assert!(vault.get(&b).unwrap().is_none());

    // Pinned literal grammar: `rm:w:{window}:{entity_hex}` → `[1u8]`,
    // one marker per batched entity.
    let rtxn = vault.store.env.read_txn().unwrap();
    for id in [&a, &b] {
        let marker_key = format!("rm:w:2026-03:{}", id.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &marker_key).unwrap(),
            Some([1u8].as_slice()),
            "entity batch commit failure must set the entity-scoped rm:w marker"
        );
    }
    drop(rtxn);
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()]
    );

    // Persist (Observer A kept the ops durably) and drain: forward
    // remat performs the healing writes, which discharge the markers.
    window.persist_state(&vault).unwrap();
    drop(window);
    let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
    assert_eq!(report.drained, vec![WINDOW.to_string()]);
    assert!(report.still_pending.is_empty());
    assert_eq!(
        vault.get(&a).unwrap().as_deref(),
        Some(body_a.as_slice()),
        "drain must heal the lost entity write"
    );
    assert_eq!(
        vault.get(&b).unwrap().as_deref(),
        Some(body_b.as_slice()),
        "drain must heal the lost entity write"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    for id in [&a, &b] {
        let marker_key = format!("rm:w:2026-03:{}", id.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &marker_key).unwrap(),
            None,
            "the healing write must clear the marker"
        );
    }
    drop(rtxn);
    assert!(pending_remat_windows(&vault).unwrap().is_empty());
}

/// ONE-1147 — Observer-B EDGE batch whole-txn failure parity: the
/// marker is scoped to the edge's SOURCE entity (LITERAL
/// `rm:w:{window}:{src_hex}` → `[1u8]`, and NO marker for the target),
/// and the drain's healing edge write re-materializes the lost edge
/// bytes verbatim and discharges the source marker — the byte-identical
/// endpoint entities must NOT discharge it (parity never clears).
#[test]
fn rm_marker_round_trip_edge_batch_commit_failure_then_drain() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());
    let window_key = WindowKey::new(WINDOW);
    let window = LoadedWindow::new("test-user", window_key, &vault, &materializer);

    // Endpoints first, in their own SUCCESSFUL commit: Observer B
    // materializes them into LMDB so only the EDGE batch sees the
    // injected failure.
    let src = EntityId::now();
    let tgt = EntityId::now();
    let entities = window.doc.get_map("entities");
    map_insert_bytes(
        &entities,
        &src.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    )
    .unwrap();
    map_insert_bytes(
        &entities,
        &tgt.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    )
    .unwrap();
    window.doc.commit();
    assert!(
        vault.get(&src).unwrap().is_some() && vault.get(&tgt).unwrap().is_some(),
        "precondition: endpoints materialized"
    );

    let kind = crate::edge::EdgeKind::Mentions;
    let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
    let edge_val = crate::sync::bridge::encode_edge_value_for_crdt(
        kind,
        0.75,
        12_345,
        Some(crate::affect::Vad::NEUTRAL),
        None,
    )
    .unwrap();
    crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
    map_insert_bytes(&window.doc.get_map("edges"), &edge_key, &edge_val).unwrap();
    window.doc.commit();

    // Divergence precondition: the edge op lives in the CRDT doc,
    // absent from LMDB.
    let lmdb_edge_key = crate::store::Store::encode_edge_key(&src, kind, &tgt);
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.edges_out.get(&rtxn, &lmdb_edge_key).unwrap(),
        None,
        "precondition: failed batch left the edge unmaterialized"
    );
    // Pinned literal grammar, SOURCE-scoped.
    let src_marker = format!("rm:w:2026-03:{}", src.to_hex());
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &src_marker).unwrap(),
        Some([1u8].as_slice()),
        "edge batch commit failure must set the SOURCE-scoped rm:w marker"
    );
    let tgt_marker = format!("rm:w:2026-03:{}", tgt.to_hex());
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &tgt_marker).unwrap(),
        None,
        "edge markers are source-scoped — no marker for the target"
    );
    drop(rtxn);

    window.persist_state(&vault).unwrap();
    drop(window);

    // Drain: the endpoint entities are byte-identical (parity must not
    // discharge anything); the EDGE healing write does, and it restores
    // the lost edge bytes verbatim.
    let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
    assert_eq!(report.drained, vec![WINDOW.to_string()]);
    assert!(report.still_pending.is_empty());
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.edges_out.get(&rtxn, &lmdb_edge_key).unwrap(),
        Some(edge_val.as_slice()),
        "drain must re-materialize the lost edge bytes verbatim"
    );
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &src_marker).unwrap(),
        None,
        "the healing edge write must clear the source marker"
    );
    drop(rtxn);
    assert!(pending_remat_windows(&vault).unwrap().is_empty());
}

/// Inserts `src` + `tgt` entity blobs into a bare window doc and commits
/// them BEFORE Observer B attaches, so they live in the CRDT entities map
/// but never reached LMDB (forward remat is deliberately skipped — the
/// `from_doc` doc-comment notes LMDB may lag a freshly-attached doc). This
/// is the exact CRDT-present / LMDB-absent divergence the edge-batch
/// endpoint-hydration path exists to repair: the FIRST edge referencing
/// these endpoints is what hydrates-and-writes them. Mirrors the proven
/// pre-registration pattern in `bridge.rs`'s fail-closed split test.
fn window_with_unmaterialized_endpoints(
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
    endpoints: &[(EntityId, &[u8])],
) -> LoadedWindow {
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);
    let entities = doc.get_map("entities");
    for (id, _data) in endpoints {
        map_insert_bytes(
            &entities,
            &id.to_hex(),
            &entity_blob(
                ENTITY_TYPE_TASK,
                valid_time_range(),
                LEARNED_AT,
                &task_body(),
            ),
        )
        .unwrap();
    }
    doc.commit();
    // Attach observers only NOW — the endpoints above are already
    // committed, so the entity observer never sees them; only future
    // (edge) commits fire.
    let window = LoadedWindow::from_doc(doc, window_key, vault, materializer);
    for (id, _) in endpoints {
        assert!(
            vault.get(id).unwrap().is_none(),
            "precondition: endpoint is CRDT-only, absent from LMDB"
        );
    }
    window
}

fn one_1147_edge_value() -> Vec<u8> {
    crate::sync::bridge::encode_edge_value_for_crdt(
        crate::edge::EdgeKind::Mentions,
        0.75,
        12_345,
        Some(crate::affect::Vad::NEUTRAL),
        None,
    )
    .unwrap()
}

/// ONE-1147 fix-wave (BLOCKER) — an Observer-B edge batch whose endpoints
/// it HYDRATES-AND-WRITES inside the txn, then rolls back as a whole,
/// must flag a durable entity-scoped `rm:` marker for the rolled-back
/// hydration write under the LITERAL key `rm:w:{window}:{hex}` → `[1u8]`.
/// Pre-fix the swallow site iterated only `applied_edges` (edge SOURCES),
/// so a hydrated endpoint's lost write was silently unmarked.
#[test]
fn edge_batch_in_txn_endpoint_hydration_rollback_marks_endpoint() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());

    let src = EntityId::now();
    let tgt = EntityId::now();
    let window = window_with_unmaterialized_endpoints(
        &vault,
        &materializer,
        &[(src, b"src"), (tgt, b"tgt")],
    );

    // The edge commit hydrates BOTH endpoints inside the batch txn, then
    // the injected failure rolls the whole txn back.
    let kind = crate::edge::EdgeKind::Mentions;
    let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
    crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
    map_insert_bytes(
        &window.doc.get_map("edges"),
        &edge_key,
        &one_1147_edge_value(),
    )
    .unwrap();
    window.doc.commit();

    // (a) Precondition: the rolled-back hydration left BOTH endpoints
    // absent from LMDB.
    assert!(
        vault.get(&src).unwrap().is_none(),
        "rolled-back endpoint hydration: src absent from LMDB"
    );
    assert!(
        vault.get(&tgt).unwrap().is_none(),
        "rolled-back endpoint hydration: tgt absent from LMDB"
    );

    // (b) Both hydrated-and-rolled-back endpoints carry the LITERAL
    // marker. The SOURCE is also an `applied_edges` source, but the
    // shared `seen` set marks it exactly once.
    let rtxn = vault.store.env.read_txn().unwrap();
    for id in [&src, &tgt] {
        let marker = format!("rm:w:2026-03:{}", id.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &marker).unwrap(),
            Some([1u8].as_slice()),
            "a hydrated-and-rolled-back edge endpoint must carry the rm:w marker"
        );
    }
    drop(rtxn);
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()]
    );
}

/// ONE-1147 fix-wave (DISCRIMINATING) — the SOURCE endpoint's hydration
/// fails LOCALLY (injected) FIRST (bridge.rs:591), aborting the batch at
/// the local-abort arm BEFORE `applied_edges.push`; the TARGET endpoint
/// (hydrated second, bridge.rs:598) was already hydrated-and-WRITTEN, and
/// that write is rolled back. The target must still be flagged for remat
/// even though NO edge was ever tracked. A subset-only (applied_edges-
/// only) implementation marks NOTHING here and FAILS this test.
///
/// NB hydration order is src(:591) → tgt(:598); arming the LOCAL failure
/// on `src` (so the partner `tgt` is the written-then-rolled-back
/// endpoint) realizes the brief's role intent — target hydrated-and-
/// marked, src carries the injected error — under the verified order.
#[test]
fn edge_batch_hydrated_target_only_rollback_marks_target() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());

    let src = EntityId::now();
    let tgt = EntityId::now();
    // Only TGT is in the CRDT-but-not-LMDB state; SRC's hydration is
    // injected to fail LOCALLY before it reads or writes anything.
    let window = window_with_unmaterialized_endpoints(&vault, &materializer, &[(tgt, b"tgt")]);

    let kind = crate::edge::EdgeKind::Mentions;
    let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
    // Arm SRC (first-hydrated): its LOCAL failure aborts the batch at the
    // `(Err(e), _) if remote_rejection_reason(&e).is_none()` arm — AFTER
    // TGT (second-hydrated) was hydrated-and-written, BEFORE any
    // `applied_edges.push`.
    crate::sync::bridge::INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| cell.set(Some(src)));
    map_insert_bytes(
        &window.doc.get_map("edges"),
        &edge_key,
        &one_1147_edge_value(),
    )
    .unwrap();
    window.doc.commit();

    assert!(
        crate::sync::bridge::INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| cell.get().is_none()),
        "precondition: the local src failure was actually hit"
    );
    assert!(
        vault.get(&tgt).unwrap().is_none(),
        "rolled-back tgt hydration: absent from LMDB"
    );

    let rtxn = vault.store.env.read_txn().unwrap();
    // The TARGET — hydrated-and-written, then rolled back — is marked
    // even though no edge was tracked (applied_edges was empty).
    let tgt_marker = format!("rm:w:2026-03:{}", tgt.to_hex());
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &tgt_marker).unwrap(),
        Some([1u8].as_slice()),
        "hydrated-and-rolled-back TARGET must carry the rm:w marker with NO edge tracked"
    );
    // SRC never hydrated (errored first) and never reached applied_edges.
    let src_marker = format!("rm:w:2026-03:{}", src.to_hex());
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &src_marker).unwrap(),
        None,
        "src never hydrated nor tracked — no marker"
    );
    drop(rtxn);
}

/// ONE-1147 fix-wave (anti-over-mark) — an endpoint already PRESENT in
/// LMDB takes the no-write `Ready` path (nothing lost) and must NOT be
/// flagged by the hydration loop. Here SRC is hydrated-and-rolled-back
/// (marked) while TGT is already present (must stay unmarked): a buggy
/// impl that recorded `Ready` endpoints into `hydrated_endpoints` would
/// over-mark TGT and FAIL.
#[test]
fn edge_batch_already_present_endpoint_not_overmarked() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());

    let src = EntityId::now();
    let tgt = EntityId::now();
    // SRC is CRDT-only (will be hydrated by the edge batch).
    let window = window_with_unmaterialized_endpoints(&vault, &materializer, &[(src, b"src")]);
    // TGT materializes SUCCESSFULLY through the now-attached observer →
    // already-present (no-write `Ready`) when the edge batch runs.
    map_insert_bytes(
        &window.doc.get_map("entities"),
        &tgt.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    )
    .unwrap();
    window.doc.commit();
    assert!(
        vault.get(&tgt).unwrap().is_some(),
        "precondition: tgt already present in LMDB"
    );
    assert!(
        vault.get(&src).unwrap().is_none(),
        "precondition: src CRDT-only"
    );

    let kind = crate::edge::EdgeKind::Mentions;
    let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
    crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
    map_insert_bytes(
        &window.doc.get_map("edges"),
        &edge_key,
        &one_1147_edge_value(),
    )
    .unwrap();
    window.doc.commit();

    let rtxn = vault.store.env.read_txn().unwrap();
    // SRC: hydrated-and-rolled-back → marked.
    let src_marker = format!("rm:w:2026-03:{}", src.to_hex());
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &src_marker).unwrap(),
        Some([1u8].as_slice()),
        "hydrated-and-rolled-back src is marked"
    );
    // TGT: already present, no in-batch write, nothing lost → the
    // hydration loop must NOT mark it (and it is not an edge source).
    let tgt_marker = format!("rm:w:2026-03:{}", tgt.to_hex());
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &tgt_marker).unwrap(),
        None,
        "an already-present endpoint (no write, nothing lost) must NOT be marked by the hydration loop"
    );
    drop(rtxn);
}

/// ONE-1147 fix-wave (heal round-trip) — after an endpoint-hydration
/// rollback flags the markers, `drain_remat_markers` re-runs forward
/// remat: the ENTITY pass performs the actual healing write for each
/// endpoint (its body is in the CRDT entities map) and discharges that
/// endpoint's marker on the write only (never on parity). Pins that the
/// hydrated-endpoint markers route to a real heal.
#[test]
fn edge_batch_hydration_rollback_drain_heals() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());

    let src = EntityId::now();
    let tgt = EntityId::now();
    let window = window_with_unmaterialized_endpoints(
        &vault,
        &materializer,
        &[(src, b"src"), (tgt, b"tgt")],
    );

    let kind = crate::edge::EdgeKind::Mentions;
    let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
    crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
    map_insert_bytes(
        &window.doc.get_map("edges"),
        &edge_key,
        &one_1147_edge_value(),
    )
    .unwrap();
    window.doc.commit();

    // Precondition: both endpoints flagged, absent from LMDB.
    assert!(vault.get(&src).unwrap().is_none() && vault.get(&tgt).unwrap().is_none());
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()]
    );

    // Persist (the CRDT doc carries the endpoint bodies) and drain.
    window.persist_state(&vault).unwrap();
    drop(window);
    let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
    assert_eq!(report.drained, vec![WINDOW.to_string()]);
    assert!(report.still_pending.is_empty());

    // The entity pass re-materialized BOTH endpoints (the actual healing
    // writes) and discharged their markers.
    assert!(
        vault.get(&src).unwrap().is_some(),
        "drain heals the lost src hydration"
    );
    assert!(
        vault.get(&tgt).unwrap().is_some(),
        "drain heals the lost tgt hydration"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    for id in [&src, &tgt] {
        let marker = format!("rm:w:2026-03:{}", id.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &marker).unwrap(),
            None,
            "the healing entity write discharges the endpoint marker"
        );
    }
    drop(rtxn);
    assert!(pending_remat_windows(&vault).unwrap().is_empty());
}

/// ONE-1167 — an Observer-B replay batch whose only durable outcome is
/// `x:` quarantine must still leave entity-scoped `rm:w:` markers, so
/// the next drain has a replayable window to retry instead of a silent
/// marker gap.
#[test]
fn x_only_entity_quarantine_batch_sets_replayable_rm_marker() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());
    let window_key = WindowKey::new(WINDOW);
    let window = LoadedWindow::new("test-user", window_key, &vault, &materializer);

    let a = EntityId::now();
    let b = EntityId::now();
    let entities = window.doc.get_map("entities");
    map_insert_bytes(&entities, &a.to_hex(), b"short-a").unwrap();
    map_insert_bytes(&entities, &b.to_hex(), b"short-b").unwrap();
    window.doc.commit();

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 2, "both rejected ops must persist x: rows");
    assert!(records.iter().all(|(_, rec)| {
        rec.window_key == WINDOW && rec.container == QuarantineContainer::Entities
    }));
    assert!(vault.get(&a).unwrap().is_none());
    assert!(vault.get(&b).unwrap().is_none());

    let mut pending_entities = pending_remat_entities(&vault, WINDOW).unwrap();
    pending_entities.sort();
    let mut expected = vec![a.to_hex(), b.to_hex()];
    expected.sort();
    assert_eq!(
        pending_entities, expected,
        "x-only entity batch must set entity-scoped rm:w markers"
    );
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()]
    );

    let rtxn = vault.store.env.read_txn().unwrap();
    for id in [&a, &b] {
        let marker_key = format!("rm:w:{WINDOW}:{}", id.to_hex());
        let provenance_key = replay_remat_marker_provenance_key(WINDOW, id);
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &marker_key).unwrap(),
            Some([1u8].as_slice()),
            "marker encoding must remain rm:w:{{window}}:{{entity_hex}}"
        );
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &provenance_key).unwrap(),
            Some([1u8].as_slice()),
            "x-only replay quarantine markers must prove non-delete provenance"
        );
    }
    drop(rtxn);

    window.persist_state(&vault).unwrap();
    drop(window);

    let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
    assert_eq!(
        report.drained,
        vec![WINDOW.to_string()],
        "drain must re-run forward remat for the x-only window"
    );
    assert!(report.still_pending.is_empty());
    assert!(pending_remat_windows(&vault).unwrap().is_empty());
    let rtxn = vault.store.env.read_txn().unwrap();
    for id in [&a, &b] {
        assert_eq!(
            vault
                .store
                .sync_state
                .get(&rtxn, &replay_remat_marker_provenance_key(WINDOW, id))
                .unwrap(),
            None,
            "terminal replay quarantine discharge must clear provenance sidecar"
        );
    }
}

/// ONE-1167 — a source-scoped edge retry marker must not stay pending
/// forever when the source endpoint itself resolves into terminal
/// quarantine. The `x:` row is the durable/queryable outcome; after it is
/// written, the source `rm:` marker can converge to discharged.
#[test]
fn edge_source_quarantine_terminally_discharges_source_rm_marker() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    let src = EntityId::now();
    let tgt = EntityId::now();
    let src_blob = entity_blob(200, valid_time_range(), LEARNED_AT, b"bad-src");
    let tgt_blob = entity_blob(
        ENTITY_TYPE_TASK,
        valid_time_range(),
        LEARNED_AT,
        &task_body(),
    );
    let entities = doc.get_map("entities");
    map_insert_bytes(&entities, &src.to_hex(), &src_blob).unwrap();
    map_insert_bytes(&entities, &tgt.to_hex(), &tgt_blob).unwrap();

    let kind = crate::edge::EdgeKind::Mentions;
    let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
    let edge_value = one_1147_edge_value();
    map_insert_bytes(&doc.get_map("edges"), &edge_key, &edge_value).unwrap();
    doc.commit();

    set_replay_remat_marker(&vault, WINDOW, &src).unwrap();
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()],
        "precondition: source-scoped edge marker is pending"
    );

    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 1, "only the valid target endpoint materializes");
    assert!(
        vault.get(&src).unwrap().is_none(),
        "invalid source endpoint stays absent"
    );
    assert!(
        !vault.edge_exists(&src, kind, &tgt).unwrap(),
        "edge must not materialize while source is quarantined"
    );
    assert!(
        pending_remat_windows(&vault).unwrap().is_empty(),
        "source marker must discharge once the source has a durable x: row"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault
            .store
            .sync_state
            .get(&rtxn, &replay_remat_marker_provenance_key(WINDOW, &src))
            .unwrap(),
        None,
        "terminal source quarantine must clear replay provenance"
    );
    drop(rtxn);

    let src_hex = src.to_hex();
    let records = quarantined_records(&vault).unwrap();
    let (seq, rec) = records
        .iter()
        .find(|(_, rec)| {
            rec.container == QuarantineContainer::Entities
                && rec.crdt_key_hash == xxh3_64(src_hex.as_bytes())
        })
        .expect("source endpoint quarantine row");
    assert_eq!(rec.crdt_key_len, 32);
    assert_eq!(rec.reason_code, "InvalidEntityType");
    assert_eq!(
        rec.payload_hash,
        xxh3_64(&src_blob),
        "x: row stores the rejected bytes hash only"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let raw = vault
        .store
        .sync_queue
        .get(&rtxn, &encode_quarantine_key(*seq))
        .unwrap()
        .expect("x: row raw bytes");
    assert!(
        !raw.windows(src_hex.len())
            .any(|window| window == src_hex.as_bytes()),
        "raw x: row must not persist the source key string"
    );
    drop(rtxn);

    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert!(
        pending_remat_windows(&vault).unwrap().is_empty(),
        "repeated passes with the source still quarantined must stay converged"
    );
}

/// Reviewer regression for ONE-1167 — terminal `x:` quarantine must not
/// clear a stale delete-safety `rm:` marker unless the marker already
/// proves replay/quarantine provenance. A live local payload plus no
/// loaded tombstone is exactly the unsafe stale-GDPR-purge shape.
#[test]
fn terminal_quarantine_preserves_unproven_delete_safety_rm_marker() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    let delete_safety = EntityId::now();
    let replay = EntityId::now();
    let delete_safety_body = task_body();
    let replay_body = task_body();
    vault
        .put_entity(
            &delete_safety,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &delete_safety_body,
        )
        .unwrap();
    vault
        .put_entity(
            &replay,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &replay_body,
        )
        .unwrap();

    let entities = doc.get_map("entities");
    map_insert_bytes(&entities, &delete_safety.to_hex(), b"short-delete").unwrap();
    map_insert_bytes(&entities, &replay.to_hex(), b"short-replay").unwrap();
    doc.commit();

    set_remat_marker(&vault, WINDOW, &delete_safety).unwrap();
    set_replay_remat_marker(&vault, WINDOW, &replay).unwrap();
    let mut tombstone_count = 0usize;
    doc.get_map("tombstones").for_each(|_, _| {
        tombstone_count += 1;
    });
    assert_eq!(
        tombstone_count, 0,
        "precondition: loaded doc has no tombstone to prove purge success"
    );

    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 0, "both CRDT rows terminate in x: quarantine");
    assert_eq!(
        vault.get(&delete_safety).unwrap().as_deref(),
        Some(delete_safety_body.as_slice()),
        "stale delete-safety payload remains live without a tombstone pass"
    );
    assert_eq!(
        vault.get(&replay).unwrap().as_deref(),
        Some(replay_body.as_slice())
    );

    let delete_marker = remat_marker_key(WINDOW, &delete_safety);
    let replay_marker = remat_marker_key(WINDOW, &replay);
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &delete_marker).unwrap(),
        Some([1u8].as_slice()),
        "unproven rm: marker must survive terminal quarantine"
    );
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &replay_marker).unwrap(),
        None,
        "replay-proven rm: marker can discharge on terminal quarantine"
    );
    assert_eq!(
        vault
            .store
            .sync_state
            .get(
                &rtxn,
                &replay_remat_marker_provenance_key(WINDOW, &delete_safety),
            )
            .unwrap(),
        None,
        "current terminal quarantine must not add replay provenance to an existing unproven marker"
    );
    assert_eq!(
        vault
            .store
            .sync_state
            .get(&rtxn, &replay_remat_marker_provenance_key(WINDOW, &replay))
            .unwrap(),
        None,
        "clearing replay-proven marker also clears sidecar"
    );
    drop(rtxn);

    assert_eq!(
        pending_remat_entities(&vault, WINDOW).unwrap(),
        vec![delete_safety.to_hex()],
        "only the stale delete-safety marker remains pending"
    );
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()]
    );
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(
        records.len(),
        2,
        "both terminal rows are queryable x: records"
    );
}

/// Forward remat quarantines gate-rejected CRDT rows instead of
/// silently skipping them (window.rs silent-site inventory).
#[test]
fn forward_remat_quarantines_rejected_rows() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    let good = EntityId::now();
    let good_body = task_body();
    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        &good.to_hex(),
        &entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, &good_body),
    )
    .unwrap();
    // Undecodable blob + unknown type byte + bad edge key.
    map_insert_bytes(&entities, &EntityId::now().to_hex(), b"short").unwrap();
    map_insert_bytes(
        &entities,
        &EntityId::now().to_hex(),
        &entity_blob(200, valid_time_range(), LEARNED_AT, b"bad"),
    )
    .unwrap();
    map_insert_bytes(
        &doc.get_map("edges"),
        "garbage-edge-key",
        &semantic_edge_value(0.5),
    )
    .unwrap();
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 1, "only the good entity materializes");
    assert_eq!(
        vault.get(&good).unwrap().as_deref(),
        Some(good_body.as_slice())
    );

    let mut reasons: Vec<String> = quarantined_records(&vault)
        .unwrap()
        .into_iter()
        .map(|(_, rec)| rec.reason_code)
        .collect();
    reasons.sort();
    assert_eq!(
        reasons,
        vec![
            "CorruptedIndex".to_string(),
            "InvalidEntityType".to_string(),
            "InvalidKey".to_string()
        ]
    );
}

/// A late remote turn for a closed off-record fence is a terminal remote
/// rejection: persist its x: evidence and continue materializing unrelated
/// CRDT rows instead of failing the whole pass.
#[test]
fn forward_remat_quarantines_closed_off_record_fence_rejection_and_continues() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let fenced = EntityId::now();
    let good = EntityId::now();

    vault
        .enter_off_record_session("sess-remote-fence", OffRecordBackendClass::Local)
        .unwrap();
    vault
        .tag_turn_off_record("sess-remote-fence", &fenced)
        .unwrap();
    let log = vault.off_record_receipt_log("sess-remote-fence").unwrap();
    vault
        .close_off_record_session("sess-remote-fence", log)
        .unwrap();

    let doc = create_window_doc("test-user", &window_key);
    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        &fenced.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    )
    .unwrap();
    let good_body = task_body();
    map_insert_bytes(
        &entities,
        &good.to_hex(),
        &entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, &good_body),
    )
    .unwrap();
    doc.commit();

    assert_eq!(
        forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap(),
        1,
        "the unrelated remote entity must still materialize"
    );
    assert!(vault.get(&fenced).unwrap().is_none());
    assert_eq!(
        vault.get(&good).unwrap().as_deref(),
        Some(good_body.as_slice())
    );
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1.reason_code, "OffRecordFencedTurnWriteRejected");
}

#[test]
fn forward_remat_quarantines_secret_scan_rejection() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    let secret = EntityId::now();
    map_insert_bytes(
        &doc.get_map("entities"),
        &secret.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            GITHUB_PAT_SECRET_FIXTURE,
        ),
    )
    .unwrap();
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(
        count, 0,
        "secret-bearing remote entity must not materialize"
    );
    assert!(vault.get(&secret).unwrap().is_none());

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1.reason_code, "GateWriteRejected");
}

/// ONE-1124 fix wave 2 (item 3) — rm: retry markers are ENTITY-scoped:
/// an unrelated entity's successful tombstone must NOT clear another
/// entity's marker (pre-fix, any validated tombstone discharged the
/// window-level marker, losing the GDPR purge retry); the entity's OWN
/// success does clear it — here via a STRING-valued tombstone, pinning
/// that the rm: bookkeeping runs through the tombstone-aware iterator
/// (item 4: non-Binary = HARD input).
#[test]
fn unrelated_tombstone_success_does_not_clear_entity_scoped_rm_marker() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let x = EntityId::now();
    let y = EntityId::now();
    for id in [&x, &y] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                valid_time_range(),
                LEARNED_AT,
                &task_body(),
            )
            .unwrap();
    }

    // Pass 1: X's tombstone, purge fails → rm:w:{window}:{x_hex} set.
    let doc_x = create_window_doc("test-user", &window_key);
    map_insert_bytes(&doc_x.get_map("tombstones"), &x.to_hex(), b"1").unwrap();
    doc_x.commit();
    INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
    forward_rematerialize(&vault, &doc_x, &materializer, &window_key).unwrap();

    let x_marker = format!("rm:w:{WINDOW}:{}", x.to_hex());
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &x_marker).unwrap(),
        Some([1u8].as_slice()),
        "X's purge failure must set X's entity-scoped marker"
    );
    drop(rtxn);

    // Pass 2: a doc carrying ONLY Y's (valid, succeeding) tombstone —
    // Y purges, but X's marker MUST survive.
    let doc_y = create_window_doc("test-user", &window_key);
    map_insert_bytes(&doc_y.get_map("tombstones"), &y.to_hex(), b"1").unwrap();
    doc_y.commit();
    forward_rematerialize(&vault, &doc_y, &materializer, &window_key).unwrap();
    assert!(vault.get(&y).unwrap().is_none(), "Y's tombstone purges Y");
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &x_marker).unwrap(),
        Some([1u8].as_slice()),
        "unrelated Y success must NOT clear X's marker"
    );
    drop(rtxn);
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_string()]
    );

    // Pass 3: X's own tombstone — as a STRING value (non-Binary = HARD
    // input through the tombstone-aware iterator). X purges and X's
    // marker clears.
    let doc_x2 = create_window_doc("test-user", &window_key);
    doc_x2
        .get_map("tombstones")
        .insert(&x.to_hex(), "string-valued-tombstone")
        .unwrap();
    doc_x2.commit();
    forward_rematerialize(&vault, &doc_x2, &materializer, &window_key).unwrap();
    assert!(
        vault.get(&x).unwrap().is_none(),
        "string-valued tombstone is HARD delete input"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &x_marker).unwrap(),
        None,
        "X's own success clears X's marker"
    );
    drop(rtxn);
    assert!(pending_remat_windows(&vault).unwrap().is_empty());
}

/// ONE-1124 fix wave 2 (item 3, fail-closed leg) — rm: rows that do not
/// parse as `rm:w:{window}:{entity_hex}` are needs-remat, never
/// dropped: the drain still re-runs the window's purge pass (the real
/// retry drains: entity purged, its marker cleared), the malformed rows
/// survive untouched, and the window stays ERROR-visible in the doctor
/// report.
#[test]
fn malformed_rm_marker_rows_are_never_dropped_and_window_still_drains() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Arc::new(Materializer::new());
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        )
        .unwrap();

    let window_key = WindowKey::new(WINDOW);
    let window = LoadedWindow::new("test-user", window_key.clone(), &vault, &materializer);
    assert_eq!(
        reverse_rematerialize(&vault, &window.doc, &window_key).unwrap(),
        1
    );

    // Real retry: tombstone arrives, purge fails → entity marker set.
    INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
    map_insert_bytes(&window.doc.get_map("tombstones"), &id.to_hex(), b"1").unwrap();
    window.doc.commit();
    let real_marker = format!("rm:w:{WINDOW}:{}", id.to_hex());

    // Plant rows that do not parse: an entity-less row and one with a
    // garbage entity segment.
    vault
        .with_write_txn(|wtxn| {
            vault.store.sync_state.put(wtxn, "rm:w:2026-03", &[1u8])?;
            vault
                .store
                .sync_state
                .put(wtxn, "rm:w:2026-03:zzz-not-hex", &[1u8])?;
            Ok(())
        })
        .unwrap();

    window.persist_state(&vault).unwrap();
    drop(window);

    let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
    // The real retry drained despite the malformed siblings…
    assert!(
        vault.get(&id).unwrap().is_none(),
        "the flagged entity's purge must still drain"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_state.get(&rtxn, &real_marker).unwrap(),
        None,
        "the drained entity's marker clears"
    );
    // …but the unparsable rows are never dropped (fail closed).
    assert_eq!(
        vault.store.sync_state.get(&rtxn, "rm:w:2026-03").unwrap(),
        Some([1u8].as_slice())
    );
    assert_eq!(
        vault
            .store
            .sync_state
            .get(&rtxn, "rm:w:2026-03:zzz-not-hex")
            .unwrap(),
        Some([1u8].as_slice())
    );
    drop(rtxn);
    assert_eq!(report.still_pending, vec![WINDOW.to_string()]);
    assert!(report.drained.is_empty());
    assert_eq!(
        sync_doctor(&vault).unwrap().rm_pending_windows,
        vec![WINDOW.to_string()],
        "doctor keeps the window ERROR-visible"
    );
}

/// ONE-1124 fix wave 2 (item 23) — the CRDT map key is
/// attacker-controlled content: the x: row stores xxh3_64(key) + byte
/// length ONLY. A crafted key string must be absent from the serialized
/// record — no verbatim retention, no prefix.
#[test]
fn quarantine_record_never_retains_the_crdt_key_string() {
    let (_dir, vault) = test_vault_with_dir();
    let attacker_key = format!("SMUGGLED-CONTENT-Alice-deleted-this-{}", "x".repeat(256));
    let seq = quarantine_rejected_op(
        &vault,
        WINDOW,
        QuarantineContainer::Tombstones,
        &attacker_key,
        &Error::InvalidKey,
        &[],
    )
    .unwrap();
    assert_eq!(seq, 1);

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let (_, rec) = &records[0];
    assert_eq!(rec.crdt_key_hash, xxh3_64(attacker_key.as_bytes()));
    assert_eq!(rec.crdt_key_len, u32::try_from(attacker_key.len()).unwrap());

    let rtxn = vault.store.env.read_txn().unwrap();
    let raw = vault
        .store
        .sync_queue
        .get(&rtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x01")
        .unwrap()
        .expect("x: row present");
    let needle = b"SMUGGLED-CONTENT";
    assert!(
        !raw.windows(needle.len()).any(|w| w == needle),
        "no fragment of the crdt key may reach the persisted x: row"
    );
}
