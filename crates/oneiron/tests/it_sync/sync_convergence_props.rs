//! ONE-1136 (M4-14) — two-vault convergence property suite.
//!
//! Every test runs over the real dual-storage stack: CRDT window docs with
//! Observer A + B attached, LMDB vaults, and raw Loro delta exchange
//! (`sync_harness::exchange`, bounded 5 rounds per ARCH-0023b). The
//! contract sources are pinned in `tests/sync_harness/mod.rs`; tests here
//! assert contract LITERALS (envelope bytes, edge value[24]/[25], tombstone
//! wire bytes, receipt fields) — never round-tripped engine output.
//!
//! Suite map (spec deliverable 2):
//! (a) `two_vault_entity_convergence_both_directions`
//! (b) `concurrent_edit_same_entity_lww_*`
//! (c) `idempotent_reimport_is_byte_stable` (LMDB-internal version/posting
//!     asserts live in `src/sync/convergence_props_internal.rs` — store
//!     internals are unreachable from integration tests)
//! (d) `structural_edge_carrying_provenance_*`
//! (f) ONE-1135 live-doc transport: carrier-15 scrub
//! (h) `hard_delete_round_trip_and_rebootstrap_preserves_h_m_rows`
//! including the audit-divergence quarantine property (live since M4-07 merged).

#![cfg(feature = "sync")]

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::sync_harness::{
    T0, TestNode, WINDOW, assert_converged, edge_bytes_out, entity_blob, exchange, map_entries,
    map_get_bytes, time_range, vault_pair,
};
use loro::ExportMode;
use oneiron::edge::{EdgeActorClass, EdgeConfirmationStatus, EdgeProvenanceFlags};
use oneiron::habit::TaskRole;
use oneiron::registry::{ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_TASK};
use oneiron::sync::bridge::{OutboundSink, encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::lease;
use oneiron::sync::queue::SyncQueue;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, LoadedWindow};
use oneiron::{DeleteReason, EdgeKind, EntityId, Vault};
use proptest::prelude::*;

const TEST_LEASE_VAULT_ID: u64 = 0;

fn task_body(role: TaskRole) -> Vec<u8> {
    let body = rmpv::Value::Map(vec![(
        rmpv::Value::from("role"),
        rmpv::Value::from(role.role_byte()),
    )]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &body)
        .expect("writing MessagePack TASK body to Vec cannot fail");
    out
}

// ─── (a) entity convergence, both directions ────────────────────────────────

#[test]
fn two_vault_entity_convergence_both_directions() {
    let (a, b) = vault_pair();

    // Divergent offline writes on BOTH sides: entity + edge per node.
    let a_src = EntityId::now();
    let a_tgt = EntityId::now();
    let b_src = EntityId::now();
    let b_tgt = EntityId::now();

    // Expectations are LITERAL envelope bytes built by the test, not engine
    // output: type u8 | occurred u64 BE ×2 | learned_at u64 BE | body.
    let a_src_blob = entity_blob(1, time_range(T0 + 10), T0 + 10, b"a-source");
    let a_tgt_blob = entity_blob(
        oneiron::registry::ENTITY_TYPE_PERSON,
        time_range(T0 + 11),
        T0 + 11,
        b"a-target",
    );
    let b_src_blob = entity_blob(1, time_range(T0 + 20), T0 + 20, b"b-source");
    let b_tgt_blob = entity_blob(
        oneiron::registry::ENTITY_TYPE_PERSON,
        time_range(T0 + 21),
        T0 + 21,
        b"b-target",
    );

    a.put_entity_in_window(WINDOW, &a_src, &a_src_blob);
    a.put_entity_in_window(WINDOW, &a_tgt, &a_tgt_blob);
    a.put_edge_in_window(
        WINDOW,
        &a_src,
        EdgeKind::Mentions,
        &a_tgt,
        0.75,
        T0 + 12,
        oneiron::Vad::NEUTRAL,
    );
    b.put_entity_in_window(WINDOW, &b_src, &b_src_blob);
    b.put_entity_in_window(WINDOW, &b_tgt, &b_tgt_blob);
    b.put_edge_in_window(
        WINDOW,
        &b_src,
        EdgeKind::Supports,
        &b_tgt,
        0.5,
        T0 + 22,
        oneiron::Vad::NEUTRAL,
    );

    let rounds = exchange(&a, &b, WINDOW);
    assert!(rounds <= 5, "bounded by the ARCH-0023b convergence cap");

    // BOTH directions materialized byte-exact against the literal blobs.
    for (node_name, vault) in [("node-a", &a.vault), ("node-b", &b.vault)] {
        for (id, blob) in [
            (&a_src, &a_src_blob),
            (&a_tgt, &a_tgt_blob),
            (&b_src, &b_src_blob),
            (&b_tgt, &b_tgt_blob),
        ] {
            assert_eq!(
                vault.get_raw(id).unwrap().as_deref(),
                Some(blob.as_slice()),
                "{node_name}: entity must materialize byte-exact"
            );
        }
        assert!(
            vault
                .edge_exists(&a_src, EdgeKind::Mentions, &a_tgt)
                .unwrap()
        );
        assert!(
            vault
                .edge_exists(&b_src, EdgeKind::Supports, &b_tgt)
                .unwrap()
        );
    }

    assert_converged(&a, &b, WINDOW);

    // A second exchange after convergence is a zero-round no-op.
    assert_eq!(exchange(&a, &b, WINDOW), 0);
}

/// `day * 86_400 + offset` — a check-in timestamp whose UTC day bucket is
/// `day`. The offset proves the reducer buckets rather than compares seconds.
fn checkin_at(day: u64, offset: u64) -> u64 {
    day * 86_400 + offset
}

/// The stored `(currentStreak, longestStreak)` pair of a Habit TASK row.
fn stored_streak(vault: &Vault, id: &EntityId) -> (u64, u64) {
    let raw = vault
        .get_raw(id)
        .expect("habit row read")
        .expect("habit row must exist");
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&raw[25..]))
        .expect("stored TASK body must decode");
    let entries = value.as_map().expect("stored TASK body is a map").to_vec();
    let field = |name: &str| {
        let (_, value) = entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .unwrap_or_else(|| panic!("{name} must be stored on a Habit row"));
        value
            .as_u64()
            .expect("streak counters are unsigned integers")
    };
    (field("currentStreak"), field("longestStreak"))
}

/// A Habit body carrying counters a peer minted locally. The replicated door
/// accepts the envelope; the derived counters must NOT survive it.
fn forged_habit_body(current: u64, longest: u64) -> Vec<u8> {
    let body = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("role"),
            rmpv::Value::from(TaskRole::Habit.role_byte()),
        ),
        (
            rmpv::Value::from("currentStreak"),
            rmpv::Value::from(current),
        ),
        (
            rmpv::Value::from("longestStreak"),
            rmpv::Value::from(longest),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &body).expect("encode forged habit body");
    out
}

#[test]
fn two_replicas_same_streak() {
    let (a, b) = vault_pair();
    let habit = EntityId::now();
    let created = checkin_at(20_000, 0);
    let habit_blob = entity_blob(
        ENTITY_TYPE_TASK,
        time_range(created),
        created,
        &task_body(TaskRole::Habit),
    );

    a.put_entity_in_window(WINDOW, &habit, &habit_blob);
    exchange(&a, &b, WINDOW);

    // OFFLINE on both replicas. Day 20_002 is authored TWICE — once per node,
    // as two distinct entities — so the merge has to count it once for the
    // arithmetic while keeping both rows. Day 20_005 is past a gap, so
    // `current` (1) and `longest` (3) cannot be confused for each other, and
    // neither can be "the run ending today".
    let checkins = [
        (&a, EntityId::now(), checkin_at(20_001, 3_600)),
        (&a, EntityId::now(), checkin_at(20_002, 60)),
        (&b, EntityId::now(), checkin_at(20_002, 7_200)),
        (&b, EntityId::now(), checkin_at(20_003, 45)),
        (&b, EntityId::now(), checkin_at(20_005, 10)),
    ];
    for (node, checkin, occurred) in checkins {
        let checkin_blob = entity_blob(
            ENTITY_TYPE_TASK,
            time_range(occurred),
            occurred,
            &task_body(TaskRole::HabitCheckin),
        );
        node.put_entity_in_window(WINDOW, &checkin, &checkin_blob);
        node.put_edge_in_window(
            WINDOW,
            &checkin,
            EdgeKind::ChildOf,
            &habit,
            1.0,
            occurred,
            oneiron::Vad::NEUTRAL,
        );
    }

    // A peer ALSO ships a Habit envelope carrying counters of its own, stamped
    // late enough to win LWW on the body. Accepting the envelope is fine;
    // inheriting its arithmetic is not.
    let forged = created + 1;
    b.put_entity_in_window(
        WINDOW,
        &habit,
        &entity_blob(
            ENTITY_TYPE_TASK,
            time_range(forged),
            forged,
            &forged_habit_body(99, 99),
        ),
    );

    let rounds = exchange(&a, &b, WINDOW);
    assert!(rounds <= 5, "bounded by the ARCH-0023b convergence cap");

    for (node_name, vault) in [(a.name, &a.vault), (b.name, &b.vault)] {
        assert_eq!(
            vault
                .sources(&habit, EdgeKind::ChildOf, None)
                .unwrap()
                .len(),
            checkins.len(),
            "{node_name}: every check-in stays its own append-only entity"
        );
        assert_eq!(
            stored_streak(vault, &habit),
            (1, 3),
            "{node_name}: the parent counters must be derived from the merged child set"
        );
    }

    // Same bytes on both replicas, parent row included — the property this
    // test exists for.
    assert_eq!(
        a.vault.get_raw(&habit).unwrap(),
        b.vault.get_raw(&habit).unwrap()
    );
    assert_converged(&a, &b, WINDOW);
}

// ─── (b) concurrent same-entity edit → LWW, loser displaced ────────────────

#[test]
fn concurrent_edit_same_entity_lww_converges_and_displaces_loser_metadata_rows() {
    let (a, b) = vault_pair();

    // Same entity id, divergent payloads, written OFFLINE on both nodes.
    // Type byte must agree (EntityTypeImmutable is the typed write-gate for
    // divergent types); learned_at and occurred diverge so the loser's
    // temporal rows are observable.
    let id = EntityId::now();
    let learned_a = T0 + 100;
    let learned_b = T0 + 200;
    let blob_a = entity_blob(1, time_range(learned_a), learned_a, b"payload-from-a");
    let blob_b = entity_blob(1, time_range(learned_b), learned_b, b"payload-from-b");

    a.put_entity_in_window(WINDOW, &id, &blob_a);
    b.put_entity_in_window(WINDOW, &id, &blob_b);

    // Pre-merge: each vault holds its own divergent row.
    assert_eq!(
        a.vault.get_raw(&id).unwrap().as_deref(),
        Some(blob_a.as_slice())
    );
    assert_eq!(
        b.vault.get_raw(&id).unwrap().as_deref(),
        Some(blob_b.as_slice())
    );

    exchange(&a, &b, WINDOW);

    // SAME winner on both vaults, and the winner is one of the two inputs.
    let winner = map_get_bytes(&a.doc(WINDOW).get_map("entities"), &id.to_hex())
        .expect("converged CRDT value");
    assert!(
        winner == blob_a || winner == blob_b,
        "LWW winner must be one of the divergent inputs"
    );
    let (winner_learned, loser_learned) = if winner == blob_a {
        (learned_a, learned_b)
    } else {
        (learned_b, learned_a)
    };
    for (name, vault) in [("node-a", &a.vault), ("node-b", &b.vault)] {
        assert_eq!(
            vault.get_raw(&id).unwrap().as_deref(),
            Some(winner.as_slice()),
            "{name}: vault row must equal the converged CRDT winner"
        );
        // temporal_learned: winner row present, loser row fully displaced.
        assert!(
            vault
                .entities_in_learned_range(winner_learned, winner_learned + 1)
                .unwrap()
                .contains(&id),
            "{name}: winner learned_at row must exist"
        );
        assert!(
            !vault
                .entities_in_learned_range(loser_learned, loser_learned + 1)
                .unwrap()
                .contains(&id),
            "{name}: loser learned_at row must be displaced (no orphan temporal_learned row)"
        );
        assert_eq!(vault.get_learned_at(&id).unwrap(), winner_learned, "{name}");
        // type_index: exactly one membership, under the (immutable) type.
        assert_eq!(
            vault.entities_by_type(1).unwrap(),
            vec![id],
            "{name}: type_index must hold exactly the winner row"
        );
    }

    assert_converged(&a, &b, WINDOW);
}

// ─── (c) idempotent re-import ───────────────────────────────────────────────

#[test]
fn idempotent_reimport_is_byte_stable() {
    let (a, b) = vault_pair();

    let src = EntityId::now();
    let tgt = EntityId::now();
    let src_blob = entity_blob(1, time_range(T0 + 1), T0 + 1, b"idempotent-src");
    let tgt_blob = entity_blob(
        oneiron::registry::ENTITY_TYPE_PERSON,
        time_range(T0 + 2),
        T0 + 2,
        b"idempotent-tgt",
    );
    a.put_entity_in_window(WINDOW, &src, &src_blob);
    a.put_entity_in_window(WINDOW, &tgt, &tgt_blob);
    a.put_edge_in_window(
        WINDOW,
        &src,
        EdgeKind::Mentions,
        &tgt,
        0.875,
        T0 + 3,
        oneiron::Vad::NEUTRAL,
    );

    // One delta, captured once, imported twice.
    let update = a
        .doc(WINDOW)
        .export(ExportMode::updates(&b.doc(WINDOW).oplog_vv()))
        .unwrap();
    b.doc(WINDOW).import(&update).unwrap();

    let snapshot_entities = |node: &TestNode| {
        [
            node.vault.get_raw(&src).unwrap(),
            node.vault.get_raw(&tgt).unwrap(),
        ]
    };
    // Every sync_queue family, snapshot per prefix (LMDB rejects
    // zero-length keys, so no single full-scan prefix exists).
    let queue_rows = |node: &TestNode| {
        [b"q:", b"e:", b"h:", b"m:", b"x:"]
            .map(|prefix: &[u8; 2]| node.vault.sync_queue_rows_with_prefix(prefix).unwrap())
    };
    let before_rows = snapshot_entities(&b);
    let before_edges = edge_bytes_out(&b.vault, &src);
    let before_learned = b.vault.entities_in_learned_range(0, u64::MAX).unwrap();
    let before_queue = queue_rows(&b);

    // Same bytes again — Loro dedups by version vector, the bridge must not
    // double-materialize.
    b.doc(WINDOW).import(&update).unwrap();

    assert_eq!(
        before_rows,
        snapshot_entities(&b),
        "entity rows must be byte-identical"
    );
    assert_eq!(
        before_edges,
        edge_bytes_out(&b.vault, &src),
        "edge values must be byte-identical"
    );
    assert_eq!(
        before_learned,
        b.vault.entities_in_learned_range(0, u64::MAX).unwrap(),
        "temporal_learned membership must not change"
    );
    assert_eq!(
        before_queue,
        queue_rows(&b),
        "sync_queue rows must be byte-identical"
    );

    // Forward re-materialization over the same doc is also write-free
    // (ARCH-0023b step 5 byte-compare): second pass performs zero writes.
    let remat = window::forward_rematerialize(
        &b.vault,
        b.doc(WINDOW),
        &b.materializer,
        &WindowKey::new(WINDOW),
    )
    .unwrap();
    assert_eq!(
        remat, 0,
        "forward remat after convergence must write nothing"
    );

    assert_converged(&a, &b, WINDOW);
}

// ─── (d) 26 B retracted flags cross bit-exact; structural+provenance rejected ─

#[test]
fn structural_edge_carrying_provenance_bytes_is_rejected_without_poisoning_batch() {
    let (a, b) = vault_pair();

    let src = EntityId::now();
    let tgt = EntityId::now();
    a.put_entity_in_window(
        WINDOW,
        &src,
        &entity_blob(
            oneiron::registry::ENTITY_TYPE_PERSON,
            time_range(T0 + 1),
            T0 + 1,
            b"src",
        ),
    );
    a.put_entity_in_window(
        WINDOW,
        &tgt,
        &entity_blob(
            oneiron::registry::ENTITY_TYPE_PERSON,
            time_range(T0 + 2),
            T0 + 2,
            b"tgt",
        ),
    );

    // The write-side gate already refuses to ENCODE this shape (ARCH-0034:
    // structural kinds carry no provenance flags) — pin that literal.
    let flags = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Confirmed,
        actor_class: EdgeActorClass::Human,
    };
    assert!(
        encode_edge_value_for_crdt(EdgeKind::ClaimOf, 0.5, T0, None, Some(flags)).is_err(),
        "structural kind + provenance flags must be unencodable"
    );

    // A hostile/buggy peer ships the bytes anyway: hand-built 26 B value
    // under a STRUCTURAL kind key (claim_of = 5, contract layout 12 B), in
    // the SAME commit as a valid semantic edge.
    let mut poisoned = Vec::with_capacity(26);
    poisoned.extend_from_slice(&0.5_f32.to_le_bytes());
    poisoned.extend_from_slice(&(T0 + 3).to_le_bytes());
    poisoned.extend_from_slice(&[0u8; 12]); // VAD slot (neutral)
    poisoned.push(1); // confirmation_status = confirmed
    poisoned.push(0); // actor_class = human
    let bad_key = format_edge_key(&src, EdgeKind::ClaimOf, &tgt);
    let good_key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    let good_value = encode_edge_value_for_crdt(
        EdgeKind::Mentions,
        0.25,
        T0 + 4,
        Some(oneiron::Vad::NEUTRAL),
        None,
    )
    .unwrap();
    {
        let edges = a.doc(WINDOW).get_map("edges");
        edges.insert(bad_key.as_str(), poisoned.as_slice()).unwrap();
        edges
            .insert(good_key.as_str(), good_value.as_slice())
            .unwrap();
        a.doc(WINDOW).commit();
    }

    exchange(&a, &b, WINDOW);

    for (name, vault) in [("node-a", &a.vault), ("node-b", &b.vault)] {
        assert!(
            !vault.edge_exists(&src, EdgeKind::ClaimOf, &tgt).unwrap(),
            "{name}: structural edge with provenance suffix must be rejected"
        );
        assert!(
            vault.edge_exists(&src, EdgeKind::Mentions, &tgt).unwrap(),
            "{name}: the valid edge sharing the batch must still materialize"
        );
    }
}

// ─── (h) composite h:/m: survival ───────────────────────────────────────────

#[test]
fn hard_delete_round_trip_and_rebootstrap_preserve_h_and_m_rows_byte_identical() {
    let (mut a, b) = vault_pair();

    let id = EntityId::now();
    a.put_entity_in_window(
        WINDOW,
        &id,
        &entity_blob(1, time_range(T0 + 5), T0 + 5, b"gdpr"),
    );
    exchange(&a, &b, WINDOW);

    // Hard delete on A (gdpr_delete: receipt + h: sweep row + m: cursor).
    a.close_window(WINDOW);
    let outcome = a
        .vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    assert!(outcome.receipt_id.is_some());
    let h_rows_a = a.sweep_rows();
    let m_rows_a = a.counter_rows();
    let x_rows_a = a.quarantine_rows();
    assert_eq!(h_rows_a.len(), 1);
    assert!(!m_rows_a.is_empty(), "the m: sweep-seq cursor must exist");
    a.recover(WINDOW);

    // Sync round-trip.
    exchange(&a, &b, WINDOW);
    assert!(b.vault.get_raw(&id).unwrap().is_none());
    assert_eq!(
        a.sweep_rows(),
        h_rows_a,
        "A's h: rows must survive the round-trip byte-identical"
    );
    assert_eq!(
        a.counter_rows(),
        m_rows_a,
        "A's m: rows must survive the round-trip byte-identical"
    );

    // Queue-overflow re-bootstrap (ARCH-0023b: drop Docs + queue): the
    // documented re-bootstrap clear is SyncQueue::clear_all, which must
    // preserve h:/m: (contracts.ts dbManifest #25 / ONE-1091) — the GDPR
    // sweep clock cannot be reset by an unrelated overflow — and, post
    // ONE-1135, the delete-bearing q: rows + their d: sidecars (a GDPR
    // delete must not be lost to an overflow either).
    let delete_bearing_before = (
        a.vault.sync_queue_rows_with_prefix(b"d:").unwrap(),
        a.queued_update_rows(),
    );
    let queue_a = SyncQueue::new(Arc::clone(&a.vault)).unwrap();
    for i in 0..4u8 {
        queue_a.push(WINDOW, &[i]).unwrap();
    }
    queue_a.push_embed_job(&EntityId::now(), 1).unwrap();
    queue_a.clear_all().unwrap();

    assert_eq!(
        (
            a.vault.sync_queue_rows_with_prefix(b"d:").unwrap(),
            a.queued_update_rows(),
        ),
        delete_bearing_before,
        "re-bootstrap must keep exactly the delete-bearing q:/d: rows, byte-identical"
    );
    assert!(
        a.vault
            .sync_queue_rows_with_prefix(b"e:")
            .unwrap()
            .is_empty(),
        "e: rows cleared by re-bootstrap"
    );
    assert_eq!(
        a.sweep_rows(),
        h_rows_a,
        "h: sweep rows must survive re-bootstrap byte-identical"
    );
    let m_after = a.counter_rows();
    for (key, value) in &m_rows_a {
        if key == b"m:last_update_seq" {
            continue; // legitimately advanced by the q: pushes above
        }
        assert!(
            m_after.contains(&(key.clone(), value.clone())),
            "m: row {:?} must survive re-bootstrap byte-identical",
            String::from_utf8_lossy(key)
        );
    }
    assert_eq!(
        a.quarantine_rows(),
        x_rows_a,
        "x: rows (reserved, M4-04) must never be touched by harness resets"
    );

    // Re-bootstrap of the docs: recover A's window from persisted state and
    // confirm the tombstone is still honored (no resurrection).
    a.recover(WINDOW);
    assert!(a.vault.get_raw(&id).unwrap().is_none());
    assert_eq!(
        a.sweep_rows(),
        h_rows_a,
        "h: rows untouched by window recovery"
    );
}

// ─── audit-class divergence (M4-07 semantics, quarantine) ───────────────────

/// ARCH-0023b stream-class split (generated md:59-72): "audit / guardrail"
/// streams are fail-closed — "QUARANTINE divergent same-identity payloads
/// for human/guardrail review; never silent LWW". For a REDACTION_AUDIT
/// receipt id present on both nodes with DIVERGENT bytes, the replica must
/// KEEP its local bytes and persist a quarantine record (M4-04 `x:` row);
/// silent overwrite would let a hostile peer rewrite the Art. 5(2) audit
/// trail.
#[test]
fn redaction_audit_same_identity_divergence_is_quarantined_not_lww() {
    let (mut a, mut b) = vault_pair();

    // A real receipt, authored by A's hard delete. Receipts are learned at
    // wall-clock time, so they live in the CURRENT month's window — open
    // and exchange THAT window for the replication leg.
    let id = EntityId::now();
    a.put_entity_in_window(
        WINDOW,
        &id,
        &entity_blob(1, time_range(T0 + 5), T0 + 5, b"x"),
    );
    exchange(&a, &b, WINDOW);
    a.close_window(WINDOW);
    let receipt_id = a
        .vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap()
        .receipt_id
        .unwrap();
    let receipt_window = WindowKey::from_timestamp(a.vault.get_learned_at(&receipt_id).unwrap())
        .as_str()
        .to_owned();
    a.recover(&receipt_window); // reverse remat mirrors the receipt into the CRDT

    // ONE-1140: B's replay door verifies NEW-receipt origin attestation
    // against its `ls:` lease mirror, so B registers A's binding (pinned
    // 66 B OD-4 row) before the replication leg — the server's root-doc
    // full mirror does this in production.
    let author_client_id = u64::from_le_bytes(
        a.vault
            .sync_state_get("m:client_id")
            .unwrap()
            .expect("receipt mint provisions the device identity")
            .try_into()
            .unwrap(),
    );
    let author_pk = a
        .vault
        .sync_state_get("m:device_pk")
        .unwrap()
        .expect("receipt mint provisions the attestation keypair");
    let mut lease_row = vec![0x02u8, 0x01];
    lease_row.extend_from_slice(&author_pk);
    lease_row.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    lease_row.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    lease_row.extend_from_slice(&(1_700_000_000u64 + 7_776_000).to_le_bytes());
    lease_row.extend_from_slice(&TEST_LEASE_VAULT_ID.to_be_bytes());
    assert_eq!(lease_row.len(), 66);
    b.vault
        .sync_state_put(
            &lease::lease_key(TEST_LEASE_VAULT_ID, author_client_id),
            &lease_row,
        )
        .unwrap();

    b.open_window(&receipt_window);
    exchange(&a, &b, &receipt_window);
    let receipt_raw_b = b
        .vault
        .get_raw(&receipt_id)
        .unwrap()
        .expect("receipt must replicate to B before the divergence");

    // A hostile peer ships DIVERGENT bytes under the SAME receipt id.
    let mut forged = receipt_raw_b.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0xFF;
    {
        let entities = b.doc(&receipt_window).get_map("entities");
        entities
            .insert(receipt_id.to_hex().as_str(), forged.as_slice())
            .unwrap();
        b.doc(&receipt_window).commit();
    }
    exchange(&a, &b, &receipt_window);
    b.recover(&receipt_window);

    // M4-07 semantics: local bytes KEPT, divergence quarantined — on BOTH
    // holders of the prior receipt copy.
    for (name, node) in [("node-a", &a), ("node-b", &b)] {
        assert_eq!(
            node.vault.get_raw(&receipt_id).unwrap().as_deref(),
            Some(receipt_raw_b.as_slice()),
            "{name}: divergent same-identity audit payload must never overwrite local receipt bytes"
        );
    }
    assert!(
        !a.quarantine_rows().is_empty() || !b.quarantine_rows().is_empty(),
        "the divergence must persist an x: quarantine record, not a bare log line"
    );
    // The receipt id stays singular in the maintenance type index.
    assert!(
        b.vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .contains(&receipt_id),
        "the original receipt must stay discoverable in the maintenance index"
    );
}

// ─── ONE-1135 delete-propagation transport, at the property level ───────────

/// ONE-1135 AC4 / ARCH-0038 carrier 15: "Pending sync ops in the outgoing
/// queue: drop ops within the redacted span before transmission." After a
/// hard delete, no queued `q:` row (nor persisted `u:w:` row) may still
/// carry the deleted payload bytes — over-dropping is fine, leaking is not.
/// The fail-closed simplification also marks the window for full resync.
#[test]
fn carrier15_outgoing_queue_scrubbed_on_hard_delete() {
    let a = TestNode::new("node-a", 1);
    let doc = oneiron::sync::schema::create_window_doc(a.name, &WindowKey::new(WINDOW));
    doc.set_peer_id(a.peer_id).unwrap();
    let offline_window = LoadedWindow::from_doc_with_outbound(
        doc,
        WindowKey::new(WINDOW),
        &a.vault,
        &a.materializer,
        Some(Arc::new(OutboundSink::new())),
    );

    let id = EntityId::now();
    let payload: &[u8] = b"redact-this-payload-from-the-queue";
    let blob = entity_blob(1, time_range(T0 + 5), T0 + 5, payload);
    {
        let entities = offline_window.doc.get_map("entities");
        entities
            .insert(id.to_hex().as_str(), blob.as_slice())
            .unwrap();
        offline_window.doc.commit();
    }
    // The offline q: row now carries the payload bytes.
    let leaked_before = a
        .queued_update_rows()
        .iter()
        .any(|(_, v)| v.windows(payload.len()).any(|w| w == payload));
    assert!(
        leaked_before,
        "precondition: the queued update carries the payload"
    );

    drop(offline_window);
    a.vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();

    let q_leak = a
        .queued_update_rows()
        .iter()
        .any(|(_, v)| v.windows(payload.len()).any(|w| w == payload));
    assert!(
        !q_leak,
        "no q: row may carry the deleted payload after a hard delete"
    );

    let u_keys = a
        .vault
        .sync_state_keys_with_prefix(&format!("u:w:{WINDOW}:"))
        .unwrap();
    let u_leak = u_keys.iter().any(|key| {
        a.vault
            .sync_state_get(key)
            .unwrap()
            .is_some_and(|v| v.windows(payload.len()).any(|w| w == payload))
    });
    assert!(
        !u_leak,
        "no u:w: row may carry the deleted payload after a hard delete"
    );

    // Fail-closed companions of the scrub (ONE-1135): full-resync marker
    // set for the window, and the tombstone delta queued as the only
    // remaining (delete-bearing) q: row.
    assert_eq!(
        a.vault
            .sync_state_get(&format!("fr:w:{WINDOW}"))
            .unwrap()
            .as_deref(),
        Some([1u8].as_slice()),
        "hard delete must mark the window for full resync"
    );
    let remaining_q = a.queued_update_rows();
    let d_markers = a.vault.sync_queue_rows_with_prefix(b"d:").unwrap();
    assert_eq!(
        remaining_q.len(),
        d_markers.len(),
        "every surviving q: row must be delete-bearing (have a d: sidecar)"
    );
    assert!(
        !d_markers.is_empty(),
        "the tombstone delta must be queued as a delete-bearing row"
    );
}

// ─── ONE-1148: env-level write failures fail loud at the write site ─────────

/// ONE-1148 loud-fail probe. An env-level Storage error inside Observer
/// B's single batch write txn — here MDB_MAP_FULL, forced by a value
/// larger than the harness' entire 16 MiB `map_size` — is swallowed by
/// the bridge into a `tracing::error` (the ONE-1147 surface), leaving
/// LMDB silently missing the row. Storage/Io is NEVER remote-rejectable
/// (`remote_rejection_reason` → None), so this is the abort-the-batch
/// path, not write-gate quarantine. The harness write helper must convert
/// that silence into an immediate panic AT THE WRITE SITE instead of a
/// confusing convergence divergence hundreds of lines later.
#[test]
#[should_panic(expected = "env-level write failure (see ONE-1148)")]
fn env_level_write_failure_fails_loud_at_the_write_site() {
    let mut a = TestNode::new("node-a", 1);
    a.open_window(WINDOW);

    let id = EntityId::now();
    // 20 MiB body > 16 MiB map: LMDB cannot allocate the pages, the whole
    // Observer B txn aborts, and the entity never reaches LMDB.
    let big = vec![0xA5u8; 20 * 1024 * 1024];
    let blob = entity_blob(1, time_range(T0 + 1), T0 + 1, &big);
    a.put_entity_in_window(WINDOW, &id, &blob);
}

// ─── (i) ONE-1871 / F5: concurrent ChildOf reparent of ONE parent slot ──────
//
// ARCH-0016 **I6** — "concurrent reparent (CRDT) = LWW" — is the anchor for
// this family. The ticket cites I7; that is off by one (I7 is derived-state
// repair). ARCH-0023b `scour:A192` pins the deterministic, order-independent
// edge projection the property test below asserts.
//
// Pre-fix, both replicas converged in the CRDT `edges` map and then projected
// OPPOSITE parents into LMDB: each kept the parent it had authored locally,
// because the already-stored parent wins by being on disk and the incoming
// valid edge is rejected `ChildOfCardinality` and quarantined (ONE-1124).

/// A pinned entity id: one byte repeated 16 times. Non-reserved for every
/// byte except `0x00`/`0xFF`, and its ORDER is decided by the test rather
/// than by `EntityId::now()`'s minting sequence — which is what lets these
/// tests separate the `learned_at` clock from the parent-id tiebreak.
fn fixed_id(byte: u8) -> EntityId {
    EntityId::from_hex(&format!("{byte:02x}").repeat(16)).expect("pinned test id")
}

fn plain_node(node: &TestNode, id: &EntityId, tag: &[u8]) {
    node.put_entity_in_window(WINDOW, id, &entity_blob(1, time_range(T0 + 1), T0 + 1, tag));
}

/// Removes an edge key from the window's CRDT `edges` map — the CRDT-first
/// device delete Observer B lowers into `BatchOp::DeleteEdge`. The shared
/// harness exposes no delete helper and is not owned by this ticket.
fn delete_edge_in_window(node: &TestNode, src: &EntityId, kind: EdgeKind, tgt: &EntityId) {
    let window = node.window(WINDOW);
    window
        .doc
        .get_map("edges")
        .delete(format_edge_key(src, kind, tgt).as_str())
        .expect("CRDT edge delete");
    window.doc.commit();
    assert!(
        !node
            .vault
            .edge_exists(src, kind, tgt)
            .expect("edge existence read"),
        "{}: the reparent's delete leg must materialize before its add leg",
        node.name
    );
}

/// Commits one batch of `ChildOf` candidates straight into the CRDT `edges`
/// map. Unlike [`TestNode::put_edge_in_window`] it asserts NOTHING about
/// materialization: a lower-precedence candidate legitimately stays in the
/// CRDT map with no LMDB row, which is exactly the F5 contract.
fn deliver_child_of_candidates(node: &TestNode, child: &EntityId, batch: &[(EntityId, u64)]) {
    let window = node.window(WINDOW);
    let edges = window.doc.get_map("edges");
    for (parent, learned_at) in batch {
        let value = encode_edge_value_for_crdt(EdgeKind::ChildOf, 1.0, *learned_at, None, None)
            .expect("structural ChildOf value");
        edges
            .insert(
                format_edge_key(child, EdgeKind::ChildOf, parent).as_str(),
                value.as_slice(),
            )
            .expect("CRDT edge insert");
    }
    window.doc.commit();
}

fn child_of_parents(vault: &Vault, child: &EntityId) -> Vec<EntityId> {
    vault
        .targets(child, EdgeKind::ChildOf, None)
        .expect("ChildOf projection read")
}

/// Both replicas start from the same `child -> root`, go offline, and reparent
/// that one slot to two different parents. The later-stamped link must win on
/// BOTH replicas.
///
/// The winner here carries the SMALLER parent-id bytes, so a projection that
/// merely sorted by id would pick the other one: `learned_at` dominates, and
/// the id is only the tiebreak.
#[test]
fn concurrent_child_of_reparent_lww_converges() {
    let (a, b) = vault_pair();

    let child = fixed_id(0x33);
    let root = fixed_id(0x44);
    let a_parent = fixed_id(0xcc); // greater bytes, EARLIER clock -> loses
    let b_parent = fixed_id(0x11); // smaller bytes, LATER clock -> wins

    for (id, tag) in [
        (&child, &b"child"[..]),
        (&root, &b"root"[..]),
        (&a_parent, &b"a-parent"[..]),
        (&b_parent, &b"b-parent"[..]),
    ] {
        plain_node(&a, id, tag);
    }
    a.put_edge_in_window(
        WINDOW,
        &child,
        EdgeKind::ChildOf,
        &root,
        1.0,
        T0 + 10,
        oneiron::Vad::NEUTRAL,
    );
    exchange(&a, &b, WINDOW);

    // OFFLINE on both replicas, same slot, different parents.
    delete_edge_in_window(&a, &child, EdgeKind::ChildOf, &root);
    a.put_edge_in_window(
        WINDOW,
        &child,
        EdgeKind::ChildOf,
        &a_parent,
        1.0,
        T0 + 100,
        oneiron::Vad::NEUTRAL,
    );
    delete_edge_in_window(&b, &child, EdgeKind::ChildOf, &root);
    b.put_edge_in_window(
        WINDOW,
        &child,
        EdgeKind::ChildOf,
        &b_parent,
        1.0,
        T0 + 200,
        oneiron::Vad::NEUTRAL,
    );

    let rounds = exchange(&a, &b, WINDOW);
    assert!(rounds <= 5, "bounded by the ARCH-0023b convergence cap");

    // The CRDT map keeps BOTH candidates on both replicas — this ticket moves
    // only the deterministic LMDB projection.
    for (name, node) in [(a.name, &a), (b.name, &b)] {
        let edges = map_entries(&node.doc(WINDOW).get_map("edges"));
        for parent in [&a_parent, &b_parent] {
            assert!(
                edges.contains_key(&format_edge_key(&child, EdgeKind::ChildOf, parent)),
                "{name}: every candidate stays in the CRDT edge map"
            );
        }
    }

    for (name, vault) in [(a.name, &a.vault), (b.name, &b.vault)] {
        assert_eq!(
            child_of_parents(vault, &child),
            vec![b_parent],
            "{name}: the later-stamped reparent wins the slot regardless of \
             which replica authored it or which parent id sorts higher"
        );
        // Atomic swap: the winner add and the stored loser's delete are ONE
        // strict batch, so no zero-parent or two-parent state is observable —
        // and the loser is gone from BOTH edge directions.
        assert_eq!(
            edge_bytes_out(vault, &child).len(),
            1,
            "{name}: exactly one ChildOf row survives the swap"
        );
        for stale in [&root, &a_parent] {
            assert!(
                vault
                    .sources(stale, EdgeKind::ChildOf, None)
                    .expect("reverse ChildOf read")
                    .is_empty(),
                "{name}: the losing parent keeps no reverse edge"
            );
        }
    }

    // A valid lower-precedence reparent is NOT a quarantine record.
    for (name, node) in [(a.name, &a), (b.name, &b)] {
        assert!(
            node.quarantine_rows().is_empty(),
            "{name}: a valid LWW loser must not produce an x: row"
        );
    }

    assert_converged(&a, &b, WINDOW);
}

/// ARCH-0023b `scour:A192` order-independence, asserted against the REAL LMDB
/// materialization (not a detached sorting helper): permuting candidate
/// arrival order and batch grouping must project the same winner and the same
/// edge bytes. Both regimes are covered every case — the pre-stored parent
/// winning, and a replicated parent winning.
fn project_child_of_arrangement(
    child: &EntityId,
    parents: &[EntityId; 4],
    stamps: &[u64; 4],
    stored: usize,
    delivery: &[Vec<usize>],
) -> BTreeMap<String, Vec<u8>> {
    let mut node = TestNode::new("node-p", 1);
    node.open_window(WINDOW);
    plain_node(&node, child, b"child");
    for (index, parent) in parents.iter().enumerate() {
        plain_node(&node, parent, format!("parent-{index}").as_bytes());
    }

    // The pre-stored contender lands first and alone, so every later batch
    // meets it as a `Stored` candidate read back out of `edges_out`.
    deliver_child_of_candidates(&node, child, &[(parents[stored], stamps[stored])]);
    assert_eq!(
        child_of_parents(&node.vault, child),
        vec![parents[stored]],
        "the pre-stored candidate must materialize before the race starts"
    );
    for group in delivery {
        let batch: Vec<(EntityId, u64)> = group
            .iter()
            .map(|index| (parents[*index], stamps[*index]))
            .collect();
        deliver_child_of_candidates(&node, child, &batch);
    }
    edge_bytes_out(&node.vault, child)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn child_of_lww_projection_is_order_independent(
        raw_stamps in prop::array::uniform4(1u64..=4u64),
        stored in 0usize..4,
        order in Just(vec![0usize, 1, 2, 3]).prop_shuffle(),
        cuts in prop::array::uniform3(any::<bool>()),
        stored_wins in any::<bool>(),
    ) {
        let child = fixed_id(0x33);
        let parents = [fixed_id(0x41), fixed_id(0x52), fixed_id(0x63), fixed_id(0x74)];
        let mut stamps = raw_stamps;
        // Force the regime: the pre-stored contender is either the unique
        // maximum, or strictly below every replicated one.
        stamps[stored] = if stored_wins { 9 } else { 0 };

        let winner = (0..4)
            .max_by_key(|index| (stamps[*index], *parents[*index].as_bytes()))
            .expect("four candidates");
        prop_assert_eq!(
            winner == stored,
            stored_wins,
            "the forced regime must decide the winner"
        );

        // Arrangement A: generated permutation, cut into generated batches.
        let rest: Vec<usize> = order.iter().copied().filter(|i| *i != stored).collect();
        let mut grouped: Vec<Vec<usize>> = vec![Vec::new()];
        for (position, index) in rest.iter().enumerate() {
            if position > 0 && cuts[position - 1] {
                grouped.push(Vec::new());
            }
            grouped
                .last_mut()
                .expect("grouped always holds one batch")
                .push(*index);
        }
        // Arrangement B: exact reverse order, delivered as ONE batch.
        let mut reversed = rest;
        reversed.reverse();

        let projection_a =
            project_child_of_arrangement(&child, &parents, &stamps, stored, &grouped);
        let projection_b =
            project_child_of_arrangement(&child, &parents, &stamps, stored, &[reversed]);

        let expected_key = format_edge_key(&child, EdgeKind::ChildOf, &parents[winner]);
        let expected_value =
            encode_edge_value_for_crdt(EdgeKind::ChildOf, 1.0, stamps[winner], None, None)
                .expect("structural ChildOf value");
        let expected: BTreeMap<String, Vec<u8>> =
            BTreeMap::from([(expected_key, expected_value)]);

        prop_assert_eq!(&projection_a, &projection_b);
        prop_assert_eq!(&projection_a, &expected);
    }
}

/// ONE-1871 F5 residual (HOLE-1871-F2, repaired) — the projection follows the
/// LIVE candidate set, not the delta history.
///
/// Slot resolution sees the candidates that are IN the batch plus the one row
/// LMDB currently projects. A candidate that lost an earlier round is still
/// live in the CRDT edge map — F5's own contract keeps it there — but it left
/// no LMDB trace, so before the repair a later delta could not see it:
///
/// 1. `A@100` and `B@90` arrive together; `A` projects, `B` stays CRDT-only.
/// 2. A later delta deletes `A` and adds `C@80`.
/// 3. Live candidates are now `{B@90, C@80}`, so the projection must be `B`.
///    It was `C`, because `B` was in neither the batch nor `edges_out`.
///
/// Two replicas that agree on the edge map disagreed on the projection whenever
/// their deltas were cut differently — the exact F5 class, one delivery
/// grouping over. `sync::bridge::replayed_child_of_candidates` closes it: a
/// delta that removes a child's STORED `ChildOf` winner re-presents that
/// child's remaining live CRDT candidates in the same batch, so the resolver
/// arbitrates over the full set it is specified to arbitrate over. The resolver
/// itself is byte-identical — the hole was presentation, not arbitration.
#[test]
fn child_of_projection_follows_live_candidates_not_delta_history() {
    let mut node = TestNode::new("node-h", 1);
    node.open_window(WINDOW);

    let child = fixed_id(0x33);
    let early_winner = fixed_id(0x41); // A@100 — projects, then is deleted
    let live_loser = fixed_id(0x52); // B@90  — CRDT-only survivor, the answer
    let late_arrival = fixed_id(0x63); // C@80  — what the projection takes today
    plain_node(&node, &child, b"child");
    for (parent, tag) in [
        (&early_winner, &b"a"[..]),
        (&live_loser, &b"b"[..]),
        (&late_arrival, &b"c"[..]),
    ] {
        plain_node(&node, parent, tag);
    }

    deliver_child_of_candidates(
        &node,
        &child,
        &[(early_winner, T0 + 100), (live_loser, T0 + 90)],
    );
    assert_eq!(
        child_of_parents(&node.vault, &child),
        vec![early_winner],
        "round one projects the maximum"
    );

    // ONE delta: the stored winner leaves the map, a lower-stamped candidate
    // joins it. `live_loser` is untouched, so it appears in neither.
    let window = node.window(WINDOW);
    let edges = window.doc.get_map("edges");
    edges
        .delete(format_edge_key(&child, EdgeKind::ChildOf, &early_winner).as_str())
        .expect("CRDT edge delete");
    edges
        .insert(
            format_edge_key(&child, EdgeKind::ChildOf, &late_arrival).as_str(),
            encode_edge_value_for_crdt(EdgeKind::ChildOf, 1.0, T0 + 80, None, None)
                .expect("structural ChildOf value")
                .as_slice(),
        )
        .expect("CRDT edge insert");
    window.doc.commit();

    assert_eq!(
        child_of_parents(&node.vault, &child),
        vec![live_loser],
        "the projection must be the maximum over the LIVE candidates, not over \
         whichever ones this delta happened to name"
    );
}

/// HOLE-1871-F2, delete-only face — the worse one: dropping the stored winner
/// alone left the child with ZERO parents while a perfectly valid live
/// candidate sat in the edge map on both replicas.
///
/// The projection must fall to the live maximum, and keep falling as the live
/// set is consumed one candidate at a time — a repair that fired once and then
/// went blind would leave the second delete parentless again. Only an empty
/// live set is an empty slot.
#[test]
fn child_of_delete_only_delta_falls_to_the_live_candidate() {
    let mut node = TestNode::new("node-i", 1);
    node.open_window(WINDOW);

    let child = fixed_id(0x33);
    let winner = fixed_id(0x41); // A@100
    let live_loser = fixed_id(0x52); // B@90
    let deeper_loser = fixed_id(0x63); // C@80
    plain_node(&node, &child, b"child");
    for (parent, tag) in [
        (&winner, &b"a"[..]),
        (&live_loser, &b"b"[..]),
        (&deeper_loser, &b"c"[..]),
    ] {
        plain_node(&node, parent, tag);
    }

    deliver_child_of_candidates(
        &node,
        &child,
        &[
            (winner, T0 + 100),
            (live_loser, T0 + 90),
            (deeper_loser, T0 + 80),
        ],
    );
    assert_eq!(child_of_parents(&node.vault, &child), vec![winner]);

    // Delete-only: nothing arrives to claim the slot, so only the live set can.
    delete_edge_in_window(&node, &child, EdgeKind::ChildOf, &winner);
    assert_eq!(
        child_of_parents(&node.vault, &child),
        vec![live_loser],
        "a delete-only delta must fall to the live maximum, never to zero parents"
    );

    delete_edge_in_window(&node, &child, EdgeKind::ChildOf, &live_loser);
    assert_eq!(
        child_of_parents(&node.vault, &child),
        vec![deeper_loser],
        "the repair is repeatable: the NEW stored winner's removal strands the \
         next candidate exactly the same way"
    );

    delete_edge_in_window(&node, &child, EdgeKind::ChildOf, &deeper_loser);
    assert!(
        child_of_parents(&node.vault, &child).is_empty(),
        "an exhausted live set is the one honest empty slot"
    );
}

/// HOLE-1871-F2, DISPLACEMENT face — the stored winner keeps its key and loses
/// its clock. Nothing leaves the map, so a removal-only repair sleeps through
/// it while the projection goes stale: `A@100` is re-stamped `A@80` in place,
/// and the CRDT-only `B@90` that never had an LMDB row to be found by now
/// outranks the row LMDB still projects.
///
/// The seam is "removes **or displaces** the stored winner", and an in-place
/// re-stamp downward IS a displacement — of the stored row's CLOCK rather than
/// of its key. The replica cross-check closes the argument: a peer handed the
/// very same final map in ONE batch projects `B`, so a replica that learned it
/// incrementally must too, or the two disagree on the projection while agreeing
/// on the edge map — the F5 class exactly.
#[test]
fn child_of_projection_follows_a_restamped_stored_winner_down() {
    let mut node = TestNode::new("node-k", 1);
    node.open_window(WINDOW);

    let child = fixed_id(0x33);
    let restamped = fixed_id(0x41); // A@100, later re-stamped down to A@80
    let live_loser = fixed_id(0x52); // B@90 — CRDT-only, and the answer
    plain_node(&node, &child, b"child");
    plain_node(&node, &restamped, b"a");
    plain_node(&node, &live_loser, b"b");

    deliver_child_of_candidates(
        &node,
        &child,
        &[(restamped, T0 + 100), (live_loser, T0 + 90)],
    );
    assert_eq!(child_of_parents(&node.vault, &child), vec![restamped]);

    // Same key, lower clock: no removal, no new parent — and yet the slot
    // changes hands, because the live maximum did.
    deliver_child_of_candidates(&node, &child, &[(restamped, T0 + 80)]);
    assert_eq!(
        child_of_parents(&node.vault, &child),
        vec![live_loser],
        "a stored winner re-stamped BELOW a live candidate must yield the slot"
    );

    let mut peer = TestNode::new("node-k-peer", 2);
    peer.open_window(WINDOW);
    plain_node(&peer, &child, b"child");
    plain_node(&peer, &restamped, b"a");
    plain_node(&peer, &live_loser, b"b");
    deliver_child_of_candidates(
        &peer,
        &child,
        &[(restamped, T0 + 80), (live_loser, T0 + 90)],
    );
    assert_eq!(
        child_of_parents(&node.vault, &child),
        child_of_parents(&peer.vault, &child),
        "the incremental replica and the one-batch replica hold the same edge \
         map, so they must project the same parent"
    );
}

/// A re-stamp downward that STILL leads keeps the slot. The repair discounts
/// the stale row by deleting it, so the winning re-add must land after that
/// delete — a repair that fired in the wrong order would demolish the slot it
/// exists to correct and leave the child parentless with a live candidate in
/// hand.
#[test]
fn child_of_restamp_that_still_leads_keeps_the_slot() {
    let mut node = TestNode::new("node-m", 1);
    node.open_window(WINDOW);

    let child = fixed_id(0x33);
    let restamped = fixed_id(0x41); // A@100, re-stamped down to A@80 — still max
    let live_loser = fixed_id(0x52); // B@70 — stranded, and outranked either way
    plain_node(&node, &child, b"child");
    plain_node(&node, &restamped, b"a");
    plain_node(&node, &live_loser, b"b");

    deliver_child_of_candidates(
        &node,
        &child,
        &[(restamped, T0 + 100), (live_loser, T0 + 70)],
    );
    assert_eq!(child_of_parents(&node.vault, &child), vec![restamped]);

    deliver_child_of_candidates(&node, &child, &[(restamped, T0 + 80)]);
    assert_eq!(
        child_of_parents(&node.vault, &child),
        vec![restamped],
        "a re-stamped winner that still outranks the live set keeps its slot"
    );

    let window = node.window(WINDOW);
    let edges = window.doc.get_map("edges");
    assert_eq!(
        map_get_bytes(
            &edges,
            &format_edge_key(&child, EdgeKind::ChildOf, &live_loser)
        ),
        Some(
            encode_edge_value_for_crdt(EdgeKind::ChildOf, 1.0, T0 + 70, None, None)
                .expect("structural ChildOf value")
        ),
        "the stranded candidate is read, never rewritten"
    );
}

/// HARD LAW: the public write path is never absorbed by replicated-slot LWW.
///
/// A public `edge_with_created_at` (`BatchOp::PublicEdgeWithCreatedAt`) that
/// adds a second parent without deleting the first is stamped LATER than the
/// stored link — so if it were treated as a replicated candidate it would WIN
/// and silently reparent. It must still return `oneiron::error::RegistryError::ChildOfCardinality` and
/// leave the stored parent untouched.
#[test]
fn public_child_of_second_parent_is_never_lww_normalized() {
    let (a, _b) = vault_pair();

    let child = fixed_id(0x33);
    let stored_parent = fixed_id(0x44);
    let public_parent = fixed_id(0x55);
    for (id, tag) in [
        (&child, &b"child"[..]),
        (&stored_parent, &b"stored"[..]),
        (&public_parent, &b"public"[..]),
    ] {
        plain_node(&a, id, tag);
    }
    a.put_edge_in_window(
        WINDOW,
        &child,
        EdgeKind::ChildOf,
        &stored_parent,
        1.0,
        T0 + 10,
        oneiron::Vad::NEUTRAL,
    );

    let err = a
        .vault
        .batch()
        .edge_with_created_at(&child, EdgeKind::ChildOf, &public_parent, 1.0, T0 + 9_999)
        .commit()
        .expect_err("a public second parent must still be rejected");
    assert!(
        matches!(
            err,
            oneiron::Error::Registry(oneiron::error::RegistryError::ChildOfCardinality)
        ),
        "public timestamped ChildOf writes keep strict cardinality, got {err:?}"
    );
    assert_eq!(child_of_parents(&a.vault, &child), vec![stored_parent]);

    // Same for the untimestamped public arm, whose op is `BatchOp::Edge`.
    let err = a
        .vault
        .batch()
        .edge(&child, EdgeKind::ChildOf, &public_parent, 1.0)
        .commit()
        .expect_err("a public second parent must still be rejected");
    assert!(matches!(
        err,
        oneiron::Error::Registry(oneiron::error::RegistryError::ChildOfCardinality)
    ));
    assert_eq!(child_of_parents(&a.vault, &child), vec![stored_parent]);
}

/// The post-E1 validator runs against the SELECTED winner: a replicated
/// candidate that wins precedence but violates the ONE-1376 TASK role matrix
/// is rejected as a unit — nothing is staged, the stored parent survives, and
/// the rejection is quarantined rather than aborting the window.
#[test]
fn replicated_child_of_winner_still_faces_the_role_matrix() {
    let mut a = TestNode::new("node-a", 1);
    a.open_window(WINDOW);

    let child = fixed_id(0x33); // Task
    let milestone = fixed_id(0x44); // legal parent for a Task
    let goal = fixed_id(0x55); // Goal parents Milestones only

    for (id, role) in [
        (&child, TaskRole::Task),
        (&milestone, TaskRole::Milestone),
        (&goal, TaskRole::Goal),
    ] {
        a.put_entity_in_window(
            WINDOW,
            id,
            &entity_blob(
                ENTITY_TYPE_TASK,
                time_range(T0 + 1),
                T0 + 1,
                &task_body(role),
            ),
        );
    }
    deliver_child_of_candidates(&a, &child, &[(milestone, T0 + 10)]);
    assert_eq!(child_of_parents(&a.vault, &child), vec![milestone]);

    // Later clock => this candidate WINS the slot, and then fails the matrix.
    deliver_child_of_candidates(&a, &child, &[(goal, T0 + 500)]);

    assert_eq!(
        child_of_parents(&a.vault, &child),
        vec![milestone],
        "a role-illegal winner must not displace the stored parent"
    );
    assert_eq!(
        a.quarantine_rows().len(),
        1,
        "the rejected replicated op is quarantined, not silently dropped"
    );
}
