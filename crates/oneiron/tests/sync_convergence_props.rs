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
//! (b) `concurrent_edit_same_entity_lww_*` (+ text-displacement probe)
//! (c) `idempotent_reimport_is_byte_stable` (LMDB-internal version/posting
//!     asserts live in `src/sync/convergence_props_internal.rs` — store
//!     internals are unreachable from integration tests)
//! (d) `retracted_provenance_*` + `structural_edge_carrying_provenance_*`
//! (e) `edge_provenance_claim_convergence_both_directions`
//! (f) `hard_delete_propagates_*` / `soft_delete_propagates_*`
//!     (+ ONE-1135 live-doc transport properties: live-doc routing,
//!     persist_state clobber guard, carrier-15 scrub)
//! (g) `offline_catchup_replays_queued_updates_into_peer`
//! (h) `hard_delete_round_trip_and_rebootstrap_preserves_h_m_rows`
//! including the audit-divergence quarantine property (live since M4-07 merged).

#![cfg(feature = "sync")]

mod sync_harness;

use std::sync::Arc;

use loro::ExportMode;
use oneiron::sync::bridge::{
    Materializer, OutboundSink, encode_edge_value_for_crdt, format_edge_key,
};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::queue::SyncQueue;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, LoadedWindow};
use oneiron::types::{
    ENTITY_TYPE_REDACTION_AUDIT, EdgeActorClass, EdgeConfirmationStatus, EdgeProvenanceFlags,
};
use oneiron::{
    DeleteReason, EdgeKind, EntityId, SupersessionStatus, TOMBSTONE_VALUE_V2_LEN, Vault,
};
use sync_harness::{
    T0, TestNode, WINDOW, assert_converged, edge_bytes_out, entity_blob, exchange, exchange_docs,
    hex, make_entity_blob, map_entries, map_get_bytes, provenanced_edge, receipt_request_id,
    redaction_audit_receipts, reencode_edge_value, time_range, vault_pair,
};

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
    let a_tgt_blob = entity_blob(4, time_range(T0 + 11), T0 + 11, b"a-target");
    let b_src_blob = entity_blob(1, time_range(T0 + 20), T0 + 20, b"b-source");
    let b_tgt_blob = entity_blob(4, time_range(T0 + 21), T0 + 21, b"b-target");

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

/// Spec 2(b) text leg: after the LWW merge replaces the loser's body, the
/// loser node's text postings for its OWN losing payload must be displaced
/// — a stale posting would keep serving content the converged vault no
/// longer holds.
///
/// IGNORED (ONE-1141) — exposes a real seam in the current engine:
/// replicated overwrite (`put_replicated` → `apply_put`) displaces
/// temporal/type/short-id rows but never touches the BM25F text index
/// (text is a separate LOCAL `BatchOp::Text` family that sync does not
/// carry), so the losing node keeps serving its pre-merge terms. Prod
/// fixes are out of scope for this unit; ONE-1141 carries the owner
/// ruling: either contract-bless lazy staleness (ARCH-0035
/// derived-artifact refresh) or deindex-on-replicated-overwrite.
#[test]
#[ignore = "ONE-1141: put_replicated overwrite leaves the loser's local BM25F postings in place — text displacement on LWW loss is not implemented; owner ruling pending (lazy-stale per ARCH-0035 vs deindex-on-overwrite)"]
fn concurrent_edit_same_entity_lww_displaces_loser_text_postings() {
    let (a, b) = vault_pair();

    let id = EntityId::now();
    let blob_a = entity_blob(1, time_range(T0 + 100), T0 + 100, b"payload-from-a");
    let blob_b = entity_blob(1, time_range(T0 + 200), T0 + 200, b"payload-from-b");

    a.put_entity_in_window(WINDOW, &id, &blob_a);
    b.put_entity_in_window(WINDOW, &id, &blob_b);
    // Each node text-indexes its OWN divergent body locally.
    a.vault
        .batch()
        .text(&id, &[("body", "alphaonlyterm")])
        .commit()
        .unwrap();
    b.vault
        .batch()
        .text(&id, &[("body", "betaonlyterm")])
        .commit()
        .unwrap();

    exchange(&a, &b, WINDOW);

    let winner = map_get_bytes(&a.doc(WINDOW).get_map("entities"), &id.to_hex()).unwrap();
    let (loser_node, loser_term) = if winner == blob_a {
        (&b, "betaonlyterm")
    } else {
        (&a, "alphaonlyterm")
    };
    assert!(
        loser_node
            .vault
            .search_text(loser_term, 10)
            .unwrap()
            .is_empty(),
        "{}: loser's text postings must be displaced after the LWW merge",
        loser_node.name
    );
}

// ─── (c) idempotent re-import ───────────────────────────────────────────────

#[test]
fn idempotent_reimport_is_byte_stable() {
    let (a, b) = vault_pair();

    let src = EntityId::now();
    let tgt = EntityId::now();
    let src_blob = entity_blob(1, time_range(T0 + 1), T0 + 1, b"idempotent-src");
    let tgt_blob = entity_blob(4, time_range(T0 + 2), T0 + 2, b"idempotent-tgt");
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
fn retracted_provenance_crosses_bit_exact_and_edge_is_kept() {
    let (mut a, mut b) = vault_pair();

    // Author through the REAL unit on A: edge + truth-Claim, then the real
    // retraction lifecycle (contracts.ts retractionRules RETRACT).
    let actor = EntityId::now();
    let src = EntityId::now();
    let tgt = EntityId::now();
    a.vault
        .put_entity(&actor, 4, time_range(T0 + 1), T0 + 1, b"actor")
        .unwrap();
    a.vault
        .put_entity(&src, 4, time_range(T0 + 2), T0 + 2, b"src")
        .unwrap();
    a.vault
        .put_entity(&tgt, 4, time_range(T0 + 3), T0 + 3, b"tgt")
        .unwrap();
    let _claim = provenanced_edge(
        &a,
        &actor,
        &src,
        EdgeKind::Mentions,
        &tgt,
        0.875,
        SupersessionStatus::Retracted,
        T0 + 4,
    );

    // Mirror A's LMDB into the CRDT (reverse remat inside recover).
    a.recover(WINDOW);

    // RAW contract literal on the wire bytes (ARCH-0034 semantic
    // provenanced layout): 26 B value, value[24] = confirmation_status
    // (retracted = 3), value[25] = actor_class (human = 0).
    let edge_key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    let wire = map_get_bytes(&a.doc(WINDOW).get_map("edges"), &edge_key)
        .expect("provenanced edge must mirror into the CRDT");
    assert_eq!(wire.len(), 26, "semantic provenanced layout is 26 B");
    assert_eq!(
        wire[24], 3,
        "value[24] must carry confirmation_status = retracted (3)"
    );
    assert_eq!(wire[25], 0, "value[25] must carry actor_class = human (0)");

    exchange(&a, &b, WINDOW);
    b.recover(WINDOW);

    // The edge is KEPT on the replica (contracts.ts retractionRules:
    // "The edge is KEPT with confirmation_status = retracted … not
    // physically removed on retraction") with the flags bit-exact.
    assert!(b.vault.edge_exists(&src, EdgeKind::Mentions, &tgt).unwrap());
    let edge_b = b
        .vault
        .edges_out(&src)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == EdgeKind::Mentions && e.target == tgt)
        .expect("edge on node B");
    assert_eq!(
        edge_b.provenance,
        Some(EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Retracted,
            actor_class: EdgeActorClass::Human,
        })
    );
    assert_eq!(
        reencode_edge_value(&edge_b),
        wire,
        "node B's stored edge value must match A's wire bytes exactly (incl. [24]/[25])"
    );

    assert_converged(&a, &b, WINDOW);
}

#[test]
fn structural_edge_carrying_provenance_bytes_is_rejected_without_poisoning_batch() {
    let (a, b) = vault_pair();

    let src = EntityId::now();
    let tgt = EntityId::now();
    a.put_entity_in_window(
        WINDOW,
        &src,
        &entity_blob(4, time_range(T0 + 1), T0 + 1, b"src"),
    );
    a.put_entity_in_window(
        WINDOW,
        &tgt,
        &entity_blob(4, time_range(T0 + 2), T0 + 2, b"tgt"),
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

// ─── (e) edge.provenance Claim convergence, both directions ─────────────────

#[test]
fn edge_provenance_claim_convergence_both_directions() {
    let (mut a, mut b) = vault_pair();

    // A and B each author a provenanced edge + truth-Claim over their own
    // entity triple, through the real unit.
    let mut authored = Vec::new();
    for (node, status) in [
        (&a, SupersessionStatus::Confirmed),
        (&b, SupersessionStatus::Disputed),
    ] {
        let actor = EntityId::now();
        let src = EntityId::now();
        let tgt = EntityId::now();
        node.vault
            .put_entity(&actor, 4, time_range(T0 + 1), T0 + 1, b"actor")
            .unwrap();
        node.vault
            .put_entity(&src, 4, time_range(T0 + 2), T0 + 2, b"src")
            .unwrap();
        node.vault
            .put_entity(&tgt, 4, time_range(T0 + 3), T0 + 3, b"tgt")
            .unwrap();
        let claim = provenanced_edge(
            node,
            &actor,
            &src,
            EdgeKind::Mentions,
            &tgt,
            0.875,
            status,
            T0 + 4,
        );
        authored.push((
            claim,
            src,
            tgt,
            node.vault.get_raw(&claim).unwrap().unwrap(),
        ));
    }

    a.recover(WINDOW);
    b.recover(WINDOW);
    exchange(&a, &b, WINDOW);
    // Forward pass after the merge (recover = the production replay door
    // for anything Observer B skipped while the doc was bare).
    a.recover(WINDOW);
    b.recover(WINDOW);

    for (claim_id, src, _tgt, claim_raw) in &authored {
        for (name, vault) in [("node-a", &a.vault), ("node-b", &b.vault)] {
            // Truth-Claim byte-identical on both nodes…
            assert_eq!(
                vault.get_raw(claim_id).unwrap().as_deref(),
                Some(claim_raw.as_slice()),
                "{name}: edge.provenance Claim must replicate byte-identical"
            );
            // …readable as a Claim with the contract predicate literal…
            let read = vault.get_claim(claim_id).unwrap().expect("claim readable");
            assert_eq!(read.predicate, "edge.provenance");
            // …with its claim_of link edge (contracts.ts edgeProvenanceClaim
            // linkEdge: claim_of ties the Claim to its subject's source).
            assert!(
                vault.edge_exists(claim_id, EdgeKind::ClaimOf, src).unwrap(),
                "{name}: claim_of link edge must exist"
            );
        }
    }

    assert_converged(&a, &b, WINDOW);
}

// ─── (f) delete propagation, hard + soft, end-to-end ───────────────────────

#[test]
fn hard_delete_propagates_end_to_end_with_replica_receipt_and_sweep_row() {
    let (mut a, b) = vault_pair();

    let id = EntityId::now();
    let blob = entity_blob(1, time_range(T0 + 5), T0 + 5, b"forget-me-everywhere");
    a.put_entity_in_window(WINDOW, &id, &blob);
    exchange(&a, &b, WINDOW);
    assert_eq!(
        b.vault.get_raw(&id).unwrap().as_deref(),
        Some(blob.as_slice())
    );

    // Until ONE-1135 lands, the delete path writes the tombstone through a
    // TRANSIENT doc persisted to d:w: — persist + close the live window
    // first (so the transient doc sees the entities-map carrier), then
    // recover so the live doc reloads the tombstone-bearing state.
    a.close_window(WINDOW);
    let outcome = a
        .vault
        .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
        .unwrap();
    let receipt_a = outcome.receipt_id.expect("hard delete writes a receipt");
    assert!(
        outcome.sweep_key.is_some(),
        "hard delete queues an h: sweep row"
    );
    let request_id_a = receipt_request_id(&a.vault, &receipt_a);
    a.recover(WINDOW);

    // Pinned tombstone wire v2 literals (ONE-1132 OWNER-DECISION):
    // [reason:1][deleted_at:8 LE][request_id:16], user_hard_delete = 2.
    let wire = map_get_bytes(&a.doc(WINDOW).get_map("tombstones"), &id.to_hex())
        .expect("tombstone in A's live doc after recovery");
    assert_eq!(wire.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(wire[0], 2, "user_hard_delete wire byte");
    assert_eq!(
        hex(&wire[9..25]),
        request_id_a.replace('-', ""),
        "tombstone request_id must correlate with the receipt"
    );
    assert!(
        a.doc(WINDOW)
            .get_map("entities")
            .get(&id.to_hex())
            .is_none(),
        "hard delete must remove the live entities-map carrier"
    );

    exchange(&a, &b, WINDOW);

    // Replica purged (ARCH-0038 tombstone-first; ONE-1133 replay).
    assert!(
        b.vault.get_raw(&id).unwrap().is_none(),
        "replica must purge the entity"
    );
    assert!(!b.vault.entities_by_type(1).unwrap().contains(&id));
    assert!(
        !b.vault
            .entities_in_learned_range(T0 + 5, T0 + 6)
            .unwrap()
            .contains(&id)
    );

    // Replica accountability (ONE-1133): LOCAL receipt with the WIRE
    // request_id + LOCAL h: sweep row with the ≤30 d Art. 12(3) deadline.
    let receipts_b = redaction_audit_receipts(&b.vault);
    assert_eq!(
        receipts_b.len(),
        1,
        "replica must author its own local receipt"
    );
    assert_eq!(receipt_request_id(&b.vault, &receipts_b[0]), request_id_a);
    let sweeps_b = b.sweep_rows();
    assert_eq!(sweeps_b.len(), 1, "replica must queue its own h: sweep row");
    let job: serde_json::Value = rmp_serde::from_slice(&sweeps_b[0].1).unwrap();
    assert_eq!(job["scope"]["entity_ids"][0], id.to_hex());
    let queued_at = job["retry_state"]["queued_at"].as_u64().unwrap();
    let deadline_at = job["retry_state"]["deadline_at"].as_u64().unwrap();
    assert_eq!(deadline_at, queued_at + 30 * 86_400, "30-day SLA literal");

    // The two nodes' RECEIPTS intentionally differ (each node erases
    // locally; Art. 5(2) attaches per replica) — so full assert_converged
    // does not apply here. CRDT-layer parity must still hold.
    assert_eq!(
        map_entries(&a.doc(WINDOW).get_map("tombstones")),
        map_entries(&b.doc(WINDOW).get_map("tombstones")),
        "tombstone maps must converge"
    );
    assert_eq!(
        map_entries(&a.doc(WINDOW).get_map("entities")),
        map_entries(&b.doc(WINDOW).get_map("entities")),
        "entities maps must converge"
    );
}

#[test]
fn soft_delete_propagates_end_to_end_keeping_shell_without_receipt() {
    let (mut a, b) = vault_pair();

    let id = EntityId::now();
    let other = EntityId::now();
    let blob = entity_blob(1, time_range(T0 + 5), T0 + 5, b"soft-delete-me");
    let other_blob = entity_blob(4, time_range(T0 + 6), T0 + 6, b"bystander");
    a.put_entity_in_window(WINDOW, &id, &blob);
    a.put_entity_in_window(WINDOW, &other, &other_blob);
    a.put_edge_in_window(
        WINDOW,
        &id,
        EdgeKind::Mentions,
        &other,
        0.5,
        T0 + 7,
        oneiron::Vad::NEUTRAL,
    );
    exchange(&a, &b, WINDOW);
    assert_eq!(
        b.vault.get_raw(&id).unwrap().as_deref(),
        Some(blob.as_slice())
    );

    a.close_window(WINDOW);
    let outcome = a
        .vault
        .delete_entity_with_reason(&id, DeleteReason::UserDelete)
        .unwrap();
    assert!(outcome.existed);
    assert!(
        outcome.receipt_id.is_none(),
        "user_delete writes NO receipt (contracts.ts)"
    );
    assert!(outcome.sweep_key.is_none(), "user_delete queues NO sweep");
    a.recover(WINDOW);

    // Soft wire literal: reason byte 1 (user_delete), 25 B value.
    let wire = map_get_bytes(&a.doc(WINDOW).get_map("tombstones"), &id.to_hex()).unwrap();
    assert_eq!(wire.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(wire[0], 1, "user_delete wire byte");
    // Soft deletes KEEP edge keys in the CRDT (ARCH-0038 user_delete keeps
    // the message shell; only hard deletes scrub edge carriers).
    let edge_key = format_edge_key(&id, EdgeKind::Mentions, &other);
    assert!(
        a.doc(WINDOW).get_map("edges").get(&edge_key).is_some(),
        "soft delete must keep CRDT edge carriers"
    );

    exchange(&a, &b, WINDOW);

    for (name, vault) in [("node-a", &a.vault), ("node-b", &b.vault)] {
        let raw = vault
            .get_raw(&id)
            .unwrap()
            .unwrap_or_else(|| panic!("{name}: soft delete must keep the 25 B shell, not purge"));
        assert_eq!(
            raw.len(),
            25,
            "{name}: shell must be exactly the envelope header"
        );
        assert_eq!(raw[0], 1, "{name}: shell keeps the type byte");
    }
    // No receipt, no sweep row on the replica for a soft delete.
    assert!(redaction_audit_receipts(&b.vault).is_empty());
    assert!(b.sweep_rows().is_empty());

    assert_converged(&a, &b, WINDOW);
}

// ─── (g) offline catch-up via queue replay ──────────────────────────────────

#[test]
fn offline_catchup_replays_queued_updates_into_peer() {
    let (mut a, b) = vault_pair();

    // Re-open A's window with a DETACHED outbound sink: every local commit
    // falls back to the durable SyncQueue (`q:` rows) — the offline path.
    a.windows.remove(WINDOW);
    let doc = oneiron::sync::schema::create_window_doc(a.name, &WindowKey::new(WINDOW));
    doc.set_peer_id(a.peer_id).unwrap();
    let offline_window = LoadedWindow::from_doc_with_outbound(
        doc,
        WindowKey::new(WINDOW),
        &a.vault,
        &a.materializer,
        Some(Arc::new(OutboundSink::new())),
    );

    let ids: Vec<EntityId> = (0..3).map(|_| EntityId::now()).collect();
    let blobs: Vec<Vec<u8>> = ids
        .iter()
        .enumerate()
        .map(|(i, _)| make_entity_blob(1, T0 + 10 + i as u64, format!("offline-{i}").as_bytes()))
        .collect();
    for (id, blob) in ids.iter().zip(&blobs) {
        let entities = offline_window.doc.get_map("entities");
        entities
            .insert(id.to_hex().as_str(), blob.as_slice())
            .unwrap();
        offline_window.doc.commit();
    }

    let queue_a = SyncQueue::new(Arc::clone(&a.vault)).unwrap();
    let queued = queue_a.drain_updates().unwrap();
    assert_eq!(
        queued.len(),
        3,
        "every offline commit must buffer one q: row"
    );
    assert!(queued.iter().all(|u| u.window_key == WINDOW));

    // "Reconnect": replay the queued updates into the peer in sequence
    // order (ARCH-0023b startup step 7: replay q:* on next connect).
    let mut max_seq = 0;
    for update in &queued {
        b.doc(WINDOW).import(&update.encoded).unwrap();
        max_seq = max_seq.max(update.seq);
    }
    for (id, blob) in ids.iter().zip(&blobs) {
        assert_eq!(
            b.vault.get_raw(id).unwrap().as_deref(),
            Some(blob.as_slice()),
            "queued update must materialize byte-exact on the peer"
        );
    }

    // Convergence confirmed → clear through the replayed sequence; the
    // monotonic m: counter survives (ONE-1091 family preservation).
    queue_a.clear_through(max_seq).unwrap();
    assert!(queue_a.is_empty().unwrap());
    assert!(
        a.vault
            .sync_queue_rows_with_prefix(b"m:last_update_seq")
            .unwrap()
            .len()
            == 1,
        "the m: sequence cursor must survive the clear"
    );

    // Bring A's harness window back in line with the offline doc before the
    // final cross-check (same vault state; fresh doc converges via B).
    drop(offline_window);
    a.open_window(WINDOW);
    exchange(&b, &a, WINDOW);
    assert_converged(&a, &b, WINDOW);
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
    // 58 B OD-4 row) before the replication leg — the server's root-doc
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
    let mut lease_row = vec![0x01u8, 0x01];
    lease_row.extend_from_slice(&author_pk);
    lease_row.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    lease_row.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    lease_row.extend_from_slice(&(1_700_000_000u64 + 7_776_000).to_le_bytes());
    assert_eq!(lease_row.len(), 58);
    b.vault
        .sync_state_put(&format!("ls:{author_client_id:016x}"), &lease_row)
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

/// ONE-1135 AC1, cross-node property: with the window OPEN under an
/// ATTACHED `WindowManager`, a hard delete commits through the LIVE
/// registry doc, so the very next exchange carries the tombstone — no
/// recovery cycle required on either side. The replica purges and authors
/// its own accountability artifacts (ONE-1133).
#[test]
fn hard_delete_through_live_window_doc_reaches_peer_without_recovery() {
    // Node A: manager-routed live window (the ONE-1135 registry seam).
    let dir_a = tempfile::tempdir().unwrap();
    let vault_a = Arc::new(Vault::open(dir_a.path(), sync_harness::test_config()).unwrap());
    let id = EntityId::now();
    let blob = entity_blob(1, time_range(T0 + 5), T0 + 5, b"live-doc-delete");
    vault_a
        .put_entity(&id, 1, time_range(T0 + 5), T0 + 5, b"live-doc-delete")
        .unwrap();
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault_a),
        Arc::new(Materializer::new()),
        "node-a",
    ));
    manager.attach_to_vault();
    let window_a = manager.open_window(&WindowKey::new(WINDOW)).unwrap();
    assert_eq!(
        map_get_bytes(&window_a.doc.get_map("entities"), &id.to_hex()).as_deref(),
        Some(blob.as_slice()),
        "reverse remat must mirror the entity into the live doc"
    );

    let mut b = TestNode::new("node-b", 2);
    b.open_window(WINDOW);
    exchange_docs("node-a", &window_a.doc, "node-b", b.doc(WINDOW));
    assert_eq!(
        b.vault.get_raw(&id).unwrap().as_deref(),
        Some(blob.as_slice())
    );

    // Window stays LIVE during the delete — no close, no recover.
    let outcome = vault_a
        .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
        .unwrap();
    let receipt_a = outcome.receipt_id.expect("hard delete writes a receipt");
    let wire = map_get_bytes(&window_a.doc.get_map("tombstones"), &id.to_hex())
        .expect("the LIVE doc must carry the tombstone immediately after the delete");
    assert_eq!(wire.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(wire[0], 2, "user_hard_delete wire byte");
    assert_eq!(
        hex(&wire[9..25]),
        receipt_request_id(&vault_a, &receipt_a).replace('-', ""),
        "live tombstone request_id correlates with the receipt"
    );
    assert!(
        map_get_bytes(&window_a.doc.get_map("entities"), &id.to_hex()).is_none(),
        "the live entities-map carrier is removed in the delete commit"
    );

    // The next exchange alone delivers the delete.
    exchange_docs("node-a", &window_a.doc, "node-b", b.doc(WINDOW));
    assert!(
        b.vault.get_raw(&id).unwrap().is_none(),
        "the replica must purge from the live-doc exchange alone"
    );
    assert_eq!(
        redaction_audit_receipts(&b.vault).len(),
        1,
        "the replica authors its own local receipt (ONE-1133)"
    );
    assert_eq!(b.sweep_rows().len(), 1, "replica h: sweep row queued");
}

/// ONE-1135 AC2: a live doc that never saw a delete must not clobber the
/// persisted tombstone when it persists its own state over `d:w:{key}` —
/// the tombstone is the only durable record of a GDPR delete.
/// `persist_state` import-merges the persisted state before exporting.
#[test]
fn persist_state_cannot_clobber_persisted_tombstone() {
    let mut a = TestNode::new("node-a", 1);
    a.open_window(WINDOW);

    let id = EntityId::now();
    a.put_entity_in_window(
        WINDOW,
        &id,
        &entity_blob(1, time_range(T0 + 5), T0 + 5, b"clobber"),
    );

    // Transient-doc delete path (no manager attached to this TestNode)
    // writes the tombstone into d:w: while the live doc knows nothing of
    // it.
    a.vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();

    // The stale live doc persists its own state over the same key.
    a.window(WINDOW).persist_state(&a.vault).unwrap();

    let reloaded =
        window::load_window_from_state(&a.vault, a.name, &WindowKey::new(WINDOW)).unwrap();
    let wire = map_get_bytes(&reloaded.get_map("tombstones"), &id.to_hex())
        .expect("d:w: must still contain the tombstone after a stale live-doc persist_state");
    assert_eq!(wire.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(wire[0], 3, "gdpr_delete wire byte survives the persist");
}

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
