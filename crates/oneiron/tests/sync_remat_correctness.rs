//! ONE-1131 — window.rs re-materialization correctness.
//!
//! Contract sources:
//! * ARCH-0023b crash-recovery steps 3–5: "If tombstoned in CRDT → never
//!   resurrect" (step 3, binding on every recovery write), "Mirror anything
//!   present in LMDB but missing from CRDT" (step 4), "Byte-compare against
//!   LMDB; write any that differ" (step 5 — edges included).
//! * contracts.ts `retractionRules`: "the edge is KEPT with
//!   confirmation_status = retracted so PPR/retrieval can dampen it".
//! * contracts.ts `deleteReasons.user_delete`: "Tombstone revision (empty
//!   content); keep the message shell".
//!
//! Helpers are intentionally self-contained (no shared sync test harness —
//! that is M4-14).

#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::{LoroMap, LoroValue, ValueOrContainer};
use oneiron::affect::{Vad, VadAnnotation, VadAnnotationSource};
use oneiron::registry::{ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_TURN};
use oneiron::sync::bridge::{
    Materializer, encode_edge_value_for_crdt, format_edge_key, parse_edge_value,
};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, LoadedWindow};
use oneiron::types::{EdgeKind, TimeRange};
use oneiron::{
    EdgeActorClass, EdgeConfirmationStatus, EdgeProvenanceFlags, EntityId, HnswConfig, Vault,
    VaultConfig,
};

/// `learned_at` inside the 2026-03 window used throughout.
const LEARNED_AT: u64 = 1_772_400_000;

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

fn window_key() -> WindowKey {
    WindowKey::new("2026-03")
}

fn clear_policy_manifests(vault: &Vault) {
    // The default policy manifest is local engine state and is skipped by
    // reverse rematerialization, so fixtures must not delete it publicly.
    assert!(
        vault
            .count_entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
            .expect("count policy manifests")
            <= 1
    );
}

/// Builds the pinned 25 B envelope + body, matching what `apply_put` stores
/// (type byte, occurred_start/end + learned_at as u64 BE, then the body).
fn make_entity_blob(entity_type: u8, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&learned_at.to_be_bytes()); // occurred_start
    blob.extend_from_slice(&learned_at.to_be_bytes()); // occurred_end
    blob.extend_from_slice(&learned_at.to_be_bytes()); // learned_at
    blob.extend_from_slice(data);
    blob
}

fn map_insert_bytes(map: &LoroMap, key: &str, value: &[u8]) {
    map.insert(key, value).unwrap();
}

fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

fn map_keys(map: &LoroMap) -> Vec<String> {
    let mut keys = Vec::new();
    map.for_each(|k, _| keys.push(k.to_string()));
    keys
}

fn put_local_entity(vault: &Vault, id: &EntityId, data: &[u8]) {
    vault
        .put_entity(
            id,
            1,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            data,
        )
        .unwrap();
}

#[test]
fn vad_annotation_claim_survives_reverse_and_forward_remat() {
    let temp_a = tempfile::tempdir().unwrap();
    let vault_a = Vault::open(temp_a.path(), test_config()).unwrap();
    clear_policy_manifests(&vault_a);

    let turn = EntityId::now();
    vault_a
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"turn-body",
        )
        .unwrap();

    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.25,
            arousal: 0.5,
            dominance: 0.75,
        },
        VadAnnotationSource::ModelInference,
        LEARNED_AT,
    )
    .unwrap();
    vault_a
        .annotate_turn_vad(&turn, annotation)
        .expect("annotation write");

    let doc = create_window_doc("test-user", &window_key());
    let mirrored = window::reverse_rematerialize(&vault_a, &doc, &window_key()).unwrap();
    assert_eq!(
        mirrored, 2,
        "turn and replicated annotation claim must both enter the CRDT mirror"
    );

    let temp_b = tempfile::tempdir().unwrap();
    let vault_b = Vault::open(temp_b.path(), test_config()).unwrap();
    let materializer = Materializer::new();
    window::forward_rematerialize(&vault_b, &doc, &materializer, &window_key()).unwrap();

    assert_eq!(
        vault_b.get_turn_vad_annotation(&turn).unwrap(),
        Some(annotation),
        "annotation must survive the replicated entity/edge rematerialization path"
    );
}

/// AC1 — ARCH-0023b "if tombstoned in CRDT → never resurrect": an entity
/// present in BOTH the `entities` and `tombstones` maps must never have its
/// bytes written to LMDB, not even transiently. Pre-fix code re-put the
/// entity (durable per-entity commit) and re-purged it in the tombstone
/// pass, so the write count exposes the transient resurrection: it must be
/// exactly 1 (the live control entity), never 3 (put + control + purge).
#[test]
fn forward_remat_never_writes_tombstoned_entity_even_transiently() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let materializer = Materializer::new();

    let tombstoned = EntityId::now();
    let live = EntityId::now();

    let doc = create_window_doc("test-user", &window_key());
    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        tombstoned.to_hex().as_str(),
        &make_entity_blob(1, LEARNED_AT, b"deleted-body"),
    );
    map_insert_bytes(
        &entities,
        live.to_hex().as_str(),
        &make_entity_blob(1, LEARNED_AT, b"live-body"),
    );
    doc.get_map("tombstones")
        .insert(tombstoned.to_hex().as_str(), &LEARNED_AT.to_le_bytes())
        .unwrap();
    doc.commit();

    let written =
        window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(
        written, 1,
        "only the live entity may be written; a tombstoned entity must not be put-then-purged"
    );
    assert!(
        vault.get_raw(&tombstoned).unwrap().is_none(),
        "tombstoned entity must never reach LMDB"
    );
    assert_eq!(
        vault.get(&live).unwrap().as_deref(),
        Some(b"live-body".as_slice())
    );

    let second = window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(second, 0, "second pass must perform zero LMDB writes");
}

/// AC2 — the edge phase must never re-add an edge whose src or tgt is
/// tombstoned in the CRDT, even while the stale local row still exists.
/// Pre-fix code added the edge (both endpoints still present in LMDB) and
/// only afterwards purged the tombstoned endpoint — 2 writes instead of 1.
#[test]
fn forward_remat_never_readds_edge_with_tombstoned_endpoint() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let materializer = Materializer::new();

    let src = EntityId::now();
    let tgt = EntityId::now();
    put_local_entity(&vault, &src, b"src-body");
    put_local_entity(&vault, &tgt, b"tgt-body"); // stale local row for the deleted id

    let doc = create_window_doc("test-user", &window_key());
    let entities = doc.get_map("entities");
    // Byte-equal mirrors so the entity loop has nothing to write.
    map_insert_bytes(
        &entities,
        src.to_hex().as_str(),
        &vault.get_raw(&src).unwrap().unwrap(),
    );
    map_insert_bytes(
        &entities,
        tgt.to_hex().as_str(),
        &vault.get_raw(&tgt).unwrap().unwrap(),
    );
    doc.get_map("tombstones")
        .insert(tgt.to_hex().as_str(), &LEARNED_AT.to_le_bytes())
        .unwrap();
    map_insert_bytes(
        &doc.get_map("edges"),
        &format_edge_key(&src, EdgeKind::Mentions, &tgt),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, 10, Some(Vad::NEUTRAL), None).unwrap(),
    );
    doc.commit();

    let written =
        window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(
        written, 1,
        "exactly one write: the tombstone purge — the edge to the tombstoned target must never be added"
    );
    assert!(
        !vault.edge_exists(&src, EdgeKind::Mentions, &tgt).unwrap(),
        "edge with tombstoned endpoint must not exist after recovery"
    );
    assert!(
        vault.get_raw(&tgt).unwrap().is_none(),
        "stale local row of the tombstoned entity must be purged"
    );
    assert_eq!(
        vault.get(&src).unwrap().as_deref(),
        Some(b"src-body".as_slice())
    );

    let second = window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(second, 0, "second pass must perform zero LMDB writes");
}

/// AC4 (F18) — ARCH-0023b step 5 byte-compares edges ("write any that
/// differ"), and contracts.ts retractionRules keeps a retracted edge with
/// confirmation_status = retracted so PPR can dampen it. A CRDT edge whose
/// value\[24\] == 3 (retracted) must overwrite a stale local Active stamp
/// (value\[24\] == 1, confirmed) in BOTH edges_out and edges_in, flags
/// verbatim, and the PPR retracted gate must then exclude the edge.
/// Pre-fix code skipped any edge that already existed, so the stale stamp
/// kept propagating withdrawn provenance.
#[test]
fn forward_remat_overwrites_stale_active_stamp_with_retracted_crdt_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();
    let blob_a = make_entity_blob(1, LEARNED_AT, b"src");
    let blob_b = make_entity_blob(1, LEARNED_AT, b"retracted-target");
    let blob_c = make_entity_blob(1, LEARNED_AT, b"live-target");

    let confirmed = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Confirmed,
        actor_class: EdgeActorClass::Agent,
    };
    let retracted = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Retracted,
        actor_class: EdgeActorClass::Agent,
    };

    // Stamp the STALE local state through the real engine path: observer B
    // materializes a 26 B provenanced edge with value[24] == 1 (confirmed)
    // plus a live bare control edge a→c.
    {
        let live_window = LoadedWindow::new("test-user", window_key(), &vault, &materializer);
        let entities = live_window.doc.get_map("entities");
        map_insert_bytes(&entities, a.to_hex().as_str(), &blob_a);
        map_insert_bytes(&entities, b.to_hex().as_str(), &blob_b);
        map_insert_bytes(&entities, c.to_hex().as_str(), &blob_c);
        live_window.doc.commit();

        let edges = live_window.doc.get_map("edges");
        map_insert_bytes(
            &edges,
            &format_edge_key(&a, EdgeKind::Mentions, &b),
            &encode_edge_value_for_crdt(
                EdgeKind::Mentions,
                0.6,
                10,
                Some(Vad::NEUTRAL),
                Some(confirmed),
            )
            .unwrap(),
        );
        map_insert_bytes(
            &edges,
            &format_edge_key(&a, EdgeKind::Mentions, &c),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, 11, Some(Vad::NEUTRAL), None)
                .unwrap(),
        );
        live_window.doc.commit();
    }

    let stale = vault
        .edges_out(&a)
        .unwrap()
        .into_iter()
        .find(|e| e.target == b)
        .expect("stale stamped edge");
    assert_eq!(
        stale.provenance,
        Some(confirmed),
        "precondition: local stamp is confirmed (value[24] == 1)"
    );

    // Recovery doc: byte-equal entities, byte-equal control edge, but the
    // a→b edge now carries confirmation_status = retracted (value[24] == 3).
    let recovery_doc = create_window_doc("test-user", &window_key());
    let entities = recovery_doc.get_map("entities");
    map_insert_bytes(&entities, a.to_hex().as_str(), &blob_a);
    map_insert_bytes(&entities, b.to_hex().as_str(), &blob_b);
    map_insert_bytes(&entities, c.to_hex().as_str(), &blob_c);
    let edges = recovery_doc.get_map("edges");
    map_insert_bytes(
        &edges,
        &format_edge_key(&a, EdgeKind::Mentions, &b),
        &encode_edge_value_for_crdt(
            EdgeKind::Mentions,
            0.6,
            10,
            Some(Vad::NEUTRAL),
            Some(retracted),
        )
        .unwrap(),
    );
    map_insert_bytes(
        &edges,
        &format_edge_key(&a, EdgeKind::Mentions, &c),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, 11, Some(Vad::NEUTRAL), None).unwrap(),
    );
    recovery_doc.commit();

    let materializer_b = Materializer::new();
    let written =
        window::forward_rematerialize(&vault, &recovery_doc, &materializer_b, &window_key())
            .unwrap();
    assert_eq!(
        written, 1,
        "exactly one write: the differing retracted edge value"
    );

    // Flags verbatim in edges_out…
    let out = vault
        .edges_out(&a)
        .unwrap()
        .into_iter()
        .find(|e| e.target == b)
        .expect("edge survives — retraction keeps the edge");
    assert_eq!(
        out.provenance,
        Some(retracted),
        "edges_out must carry value[24] == 3 after recovery"
    );
    assert_eq!(out.weight.to_bits(), 0.6_f32.to_bits(), "weight verbatim");
    assert_eq!(out.created_at, 10, "created_at verbatim");
    // …and mirrored in edges_in.
    let inn = vault
        .edges_in(&b)
        .unwrap()
        .into_iter()
        .find(|e| e.target == a)
        .expect("edges_in mirror");
    assert_eq!(
        inn.provenance,
        Some(retracted),
        "edges_in must carry value[24] == 3 after recovery"
    );

    // PPR retracted gate (D8): the withdrawn edge propagates nothing while
    // the live control edge still does.
    let scores = vault.query().search_ppr(&[a], 1).run().unwrap();
    assert!(
        scores.iter().any(|s| s.id == c && s.score > 0.0),
        "live control edge must keep propagating"
    );
    assert!(
        !scores.iter().any(|s| s.id == b && s.score > 0.0),
        "ppr gate must exclude the retracted edge"
    );

    // The overwrite stored the CRDT bytes verbatim: a second pass byte-
    // compares equal everywhere and performs zero writes.
    let second =
        window::forward_rematerialize(&vault, &recovery_doc, &materializer_b, &window_key())
            .unwrap();
    assert_eq!(second, 0, "second pass must perform zero LMDB writes");
}

/// AC5 (F19) — ARCH-0023b step 4 mirrors "anything present in LMDB but
/// missing from CRDT"; edge backfill is NOT gated on the entity being
/// absent. An entity already mirrored in the CRDT must still have its
/// missing `edges_out` rows backfilled (insert-missing only: a CRDT edge
/// that exists with different bytes is left untouched).
#[test]
fn reverse_remat_backfills_missing_edges_for_entity_already_in_crdt() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();

    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();
    put_local_entity(&vault, &a, b"a");
    put_local_entity(&vault, &b, b"b");
    put_local_entity(&vault, &c, b"c");
    vault.put_edge(&a, EdgeKind::Mentions, &b, 0.7).unwrap();
    vault.put_edge(&a, EdgeKind::Mentions, &c, 0.5).unwrap();

    let doc = create_window_doc("test-user", &window_key());
    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        a.to_hex().as_str(),
        &vault.get_raw(&a).unwrap().unwrap(),
    );
    map_insert_bytes(
        &entities,
        b.to_hex().as_str(),
        &vault.get_raw(&b).unwrap().unwrap(),
    );
    map_insert_bytes(
        &entities,
        c.to_hex().as_str(),
        &vault.get_raw(&c).unwrap().unwrap(),
    );
    // a→c already exists in the CRDT with DIFFERENT bytes — must be left
    // alone (insert-missing only); a→b is missing — must be backfilled.
    let divergent_ac =
        encode_edge_value_for_crdt(EdgeKind::Mentions, 0.9, 99, Some(Vad::NEUTRAL), None).unwrap();
    let edges = doc.get_map("edges");
    map_insert_bytes(
        &edges,
        &format_edge_key(&a, EdgeKind::Mentions, &c),
        &divergent_ac,
    );
    doc.commit();

    let mirrored = window::reverse_rematerialize(&vault, &doc, &window_key()).unwrap();
    assert_eq!(
        mirrored, 0,
        "no entity was missing from the CRDT — the backfill must still run"
    );

    let backfilled = map_get_bytes(&edges, &format_edge_key(&a, EdgeKind::Mentions, &b)).expect(
        "missing edge must be backfilled even though its source entity was already mirrored",
    );
    let decoded = parse_edge_value(&backfilled).unwrap();
    assert!((decoded.weight - 0.7).abs() < f32::EPSILON);

    let untouched = map_get_bytes(&edges, &format_edge_key(&a, EdgeKind::Mentions, &c)).unwrap();
    assert_eq!(
        untouched, divergent_ac,
        "existing CRDT edge with differing bytes must be left untouched (insert-missing only)"
    );
}

/// AC6 (F37) — a `pm:` marker whose entity bytes are already byte-equal in
/// the CRDT may still cover a crash between the entity insert and its edge
/// inserts. The byte-equal path must replay missing `edges_out` entries
/// BEFORE clearing the marker; pre-fix code cleared the marker and lost the
/// edges.
#[test]
fn pm_replay_byte_equal_entity_still_replays_missing_edges() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());

    let a = EntityId::now();
    let b = EntityId::now();
    put_local_entity(&vault, &a, b"pm-src");
    put_local_entity(&vault, &b, b"pm-tgt");
    vault.put_edge(&a, EdgeKind::Supports, &b, 0.4).unwrap();

    let key = window_key();
    let doc = create_window_doc("test-user", &key);
    let entities = doc.get_map("entities");
    // Entity bytes already mirrored (byte-equal) — only the edge is missing.
    map_insert_bytes(
        &entities,
        a.to_hex().as_str(),
        &vault.get_raw(&a).unwrap().unwrap(),
    );
    map_insert_bytes(
        &entities,
        b.to_hex().as_str(),
        &vault.get_raw(&b).unwrap().unwrap(),
    );
    doc.commit();

    let marker_key = format!("pm:{}:{}", key.as_str(), a.to_hex());
    vault.sync_state_put(&marker_key, &[1u8]).unwrap();

    let replayed = window::replay_pending_mirrors(&vault, &doc, &key).unwrap();
    assert_eq!(replayed, 1, "edge replay work must be reported");

    let edge_val = map_get_bytes(
        &doc.get_map("edges"),
        &format_edge_key(&a, EdgeKind::Supports, &b),
    )
    .expect("byte-equal pm replay must mirror the missing edge before clearing the marker");
    let decoded = parse_edge_value(&edge_val).unwrap();
    assert!((decoded.weight - 0.4).abs() < f32::EPSILON);

    assert!(
        vault.sync_state_get(&marker_key).unwrap().is_none(),
        "marker must be cleared after the edges are replayed"
    );

    let again = window::replay_pending_mirrors(&vault, &doc, &key).unwrap();
    assert_eq!(again, 0, "no markers remain");
}

/// AC8 — forward re-materialization is idempotent on mixed state: live
/// entities + a live edge + a tombstoned-but-in-entities entry + a
/// tombstoned id with a stale local row. The first pass converges LMDB; the
/// second pass performs zero LMDB writes.
#[test]
fn forward_remat_is_idempotent_across_mixed_state() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let materializer = Materializer::new();

    let live_src = EntityId::now();
    let live_tgt = EntityId::now();
    let ghost = EntityId::now(); // in entities + tombstones, no local row
    let stale = EntityId::now(); // tombstoned with a stale local row
    put_local_entity(&vault, &stale, b"stale-row");

    let doc = create_window_doc("test-user", &window_key());
    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        live_src.to_hex().as_str(),
        &make_entity_blob(1, LEARNED_AT, b"live-src"),
    );
    map_insert_bytes(
        &entities,
        live_tgt.to_hex().as_str(),
        &make_entity_blob(1, LEARNED_AT, b"live-tgt"),
    );
    map_insert_bytes(
        &entities,
        ghost.to_hex().as_str(),
        &make_entity_blob(1, LEARNED_AT, b"ghost"),
    );
    let tombstones = doc.get_map("tombstones");
    tombstones
        .insert(ghost.to_hex().as_str(), &LEARNED_AT.to_le_bytes())
        .unwrap();
    tombstones
        .insert(stale.to_hex().as_str(), &LEARNED_AT.to_le_bytes())
        .unwrap();
    map_insert_bytes(
        &doc.get_map("edges"),
        &format_edge_key(&live_src, EdgeKind::Mentions, &live_tgt),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 12, Some(Vad::NEUTRAL), None).unwrap(),
    );
    doc.commit();

    let first = window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(
        first, 4,
        "two live entities + one edge + one stale-row purge; the ghost is never written"
    );
    assert!(vault.get_raw(&ghost).unwrap().is_none());
    assert!(vault.get_raw(&stale).unwrap().is_none());
    assert!(
        vault
            .edge_exists(&live_src, EdgeKind::Mentions, &live_tgt)
            .unwrap()
    );

    let second = window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(second, 0, "second pass must perform zero LMDB writes");
}

/// Crash-shaped regression — ARCH-0023b runs pm replay and reverse remat
/// BEFORE forward remat's tombstone pass. Shape: the delete commit reached
/// the CRDT (tombstone present, E's entities/edges keys removed) but the
/// purge txn never ran (crash between the two, or a failed Observer-B
/// purge), so E's LMDB row and the S→E `edges_out` rows survive with no
/// `pt:` marker. Neither the pm edge backfills (byte-equal AND full-mirror
/// paths) nor the reverse-remat backfill may re-insert any edge key
/// referencing E into the replicated edges map; forward remat then purges
/// the surviving rows. Pre-fix code gated only the marker/source id and
/// re-inserted S→E fleet-wide.
#[test]
fn pm_and_reverse_remat_never_backfill_edges_to_tombstoned_target() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());

    let s1 = EntityId::now(); // pm marker, byte-equal in CRDT → edge-backfill path
    let s2 = EntityId::now(); // pm marker, missing from CRDT → full-mirror path
    let s3 = EntityId::now(); // no marker, byte-equal in CRDT → reverse-remat path
    let e = EntityId::now(); // hard-tombstoned target; LMDB rows survive
    let l = EntityId::now(); // live control target — must still backfill

    for (id, body) in [
        (&s1, b"s1".as_slice()),
        (&s2, b"s2".as_slice()),
        (&s3, b"s3".as_slice()),
        (&e, b"deleted-target".as_slice()),
        (&l, b"live-target".as_slice()),
    ] {
        put_local_entity(&vault, id, body);
    }
    vault.put_edge(&s1, EdgeKind::Mentions, &e, 0.5).unwrap();
    vault.put_edge(&s1, EdgeKind::Mentions, &l, 0.6).unwrap();
    vault.put_edge(&s2, EdgeKind::Supports, &e, 0.4).unwrap();
    vault.put_edge(&s2, EdgeKind::Mentions, &l, 0.7).unwrap();
    vault.put_edge(&s3, EdgeKind::Mentions, &e, 0.3).unwrap();

    let key = window_key();
    let doc = create_window_doc("test-user", &key);
    let entities = doc.get_map("entities");
    // Post-delete-commit doc: S1/S3/L mirrored byte-equal, S2 not yet
    // mirrored, E's entities/edges keys already removed by the delete
    // commit, only the (legacy hard) tombstone remains.
    for id in [&s1, &s3, &l] {
        map_insert_bytes(
            &entities,
            id.to_hex().as_str(),
            &vault.get_raw(id).unwrap().unwrap(),
        );
    }
    doc.get_map("tombstones")
        .insert(e.to_hex().as_str(), &LEARNED_AT.to_le_bytes())
        .unwrap();
    doc.commit();

    let marker_s1 = format!("pm:{}:{}", key.as_str(), s1.to_hex());
    let marker_s2 = format!("pm:{}:{}", key.as_str(), s2.to_hex());
    vault.sync_state_put(&marker_s1, &[1u8]).unwrap();
    vault.sync_state_put(&marker_s2, &[1u8]).unwrap();

    // 1. pm replay — both backfill paths must skip the tombstoned target
    //    while still mirroring everything live.
    let replayed = window::replay_pending_mirrors(&vault, &doc, &key).unwrap();
    assert_eq!(replayed, 2, "S1 edge backfill + S2 full mirror");

    let edges = doc.get_map("edges");
    let e_hex = e.to_hex();
    assert!(
        map_keys(&edges).iter().all(|k| !k.contains(&e_hex)),
        "pm replay must not re-insert any edge key referencing the tombstoned target"
    );
    assert!(
        map_get_bytes(&edges, &format_edge_key(&s1, EdgeKind::Mentions, &l)).is_some(),
        "live-target edge of the byte-equal path must still backfill"
    );
    assert!(
        map_get_bytes(&edges, &format_edge_key(&s2, EdgeKind::Mentions, &l)).is_some(),
        "live-target edge of the full-mirror path must still backfill"
    );
    assert_eq!(
        map_get_bytes(&entities, &s2.to_hex()).as_deref(),
        vault.get_raw(&s2).unwrap().as_deref(),
        "full-mirror path must still mirror the live entity body"
    );
    assert!(vault.sync_state_get(&marker_s1).unwrap().is_none());
    assert!(vault.sync_state_get(&marker_s2).unwrap().is_none());

    // 2. reverse remat — the backfill sweep over ALL in-range entities must
    //    skip S→E rows too, and must not re-insert E's surviving body.
    let mirrored = window::reverse_rematerialize(&vault, &doc, &key).unwrap();
    assert_eq!(mirrored, 0, "everything live is already mirrored");
    assert!(
        map_keys(&edges).iter().all(|k| !k.contains(&e_hex)),
        "reverse remat must not re-insert any edge key referencing the tombstoned target"
    );
    assert!(
        entities.get(e_hex.as_str()).is_none(),
        "reverse remat must not re-insert the tombstoned entity body"
    );

    // 3. forward remat — purges the surviving LMDB rows (entity + edges).
    let materializer = Materializer::new();
    let written =
        window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(written, 1, "exactly one write: the tombstone purge");
    assert!(vault.get_raw(&e).unwrap().is_none(), "stale row purged");
    assert!(!vault.edge_exists(&s1, EdgeKind::Mentions, &e).unwrap());
    assert!(!vault.edge_exists(&s2, EdgeKind::Supports, &e).unwrap());
    assert!(!vault.edge_exists(&s3, EdgeKind::Mentions, &e).unwrap());
    assert!(vault.edge_exists(&s1, EdgeKind::Mentions, &l).unwrap());
    assert!(vault.edge_exists(&s2, EdgeKind::Mentions, &l).unwrap());

    let second_pass =
        window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(second_pass, 0, "second pass must perform zero LMDB writes");
}

/// Fail-closed gates — a NON-BINARY tombstone value must gate every remat
/// path exactly like a binary one (malformed/unknown ⇒ HARD): the pm
/// byte-equal edge backfill, the reverse-remat body re-insert and edge
/// backfill, and forward remat's entity + edge passes. Pre-fix code used
/// Binary-only presence checks, so a string tombstone was invisible and
/// every one of these paths resurrected deleted state.
#[test]
fn remat_gates_fail_closed_on_non_binary_tombstone() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());

    let s = EntityId::now();
    let e2 = EntityId::now(); // string tombstone, NOT in entities map, row survives
    let e3 = EntityId::now(); // string tombstone, differing CRDT body, row survives
    put_local_entity(&vault, &s, b"s");
    put_local_entity(&vault, &e2, b"e2-old");
    put_local_entity(&vault, &e3, b"old");
    vault.put_edge(&s, EdgeKind::Mentions, &e2, 0.5).unwrap();

    let key = window_key();
    let doc = create_window_doc("test-user", &key);
    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        s.to_hex().as_str(),
        &vault.get_raw(&s).unwrap().unwrap(),
    );
    // E3's CRDT mirror differs from the local row — without the entity-pass
    // gate, forward remat would write the pre-delete body back to LMDB.
    map_insert_bytes(
        &entities,
        e3.to_hex().as_str(),
        &make_entity_blob(1, LEARNED_AT, b"resurrected-body"),
    );
    let tombstones = doc.get_map("tombstones");
    tombstones
        .insert(e2.to_hex().as_str(), "not-binary")
        .unwrap();
    tombstones
        .insert(e3.to_hex().as_str(), "not-binary")
        .unwrap();
    // S→E3 exists only in the CRDT; both endpoints have local rows, so only
    // the tombstone gate stops the forward edge pass from writing it.
    let edges = doc.get_map("edges");
    map_insert_bytes(
        &edges,
        &format_edge_key(&s, EdgeKind::Mentions, &e3),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.9, 9, Some(Vad::NEUTRAL), None).unwrap(),
    );
    doc.commit();

    let marker = format!("pm:{}:{}", key.as_str(), s.to_hex());
    vault.sync_state_put(&marker, &[1u8]).unwrap();

    // pm replay: byte-equal path must skip S→E2.
    let replayed = window::replay_pending_mirrors(&vault, &doc, &key).unwrap();
    assert_eq!(
        replayed, 0,
        "the only candidate edge has a string-tombstoned target — nothing to mirror"
    );
    assert!(
        vault.sync_state_get(&marker).unwrap().is_none(),
        "marker still cleared"
    );
    assert!(map_get_bytes(&edges, &format_edge_key(&s, EdgeKind::Mentions, &e2)).is_none());

    // reverse remat: must not re-insert E2's surviving body or the S→E2 edge.
    let mirrored = window::reverse_rematerialize(&vault, &doc, &key).unwrap();
    assert_eq!(mirrored, 0);
    assert!(
        entities.get(e2.to_hex().as_str()).is_none(),
        "string-tombstoned body must not re-enter the entities map"
    );
    assert!(map_get_bytes(&edges, &format_edge_key(&s, EdgeKind::Mentions, &e2)).is_none());

    // forward remat: the entity pass must not write E3's differing CRDT
    // body and the edge pass must not add S→E3. ONE-1133's reason-aware
    // tombstone replay now SEES non-binary tombstones (empty slice decodes
    // HARD — fail closed), so the two string-tombstoned survivors are
    // hard-purged: the only writes are delete propagation, never
    // resurrection.
    let materializer = Materializer::new();
    let written =
        window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(
        written, 2,
        "exactly two writes: the string-tombstoned survivors hard-purged \
         by the reason-aware replay (non-binary decodes HARD); no write may \
         pass a non-binary tombstone gate"
    );
    assert!(
        vault.get_raw(&e3).unwrap().is_none(),
        "E3's stale row is purged — and the differing CRDT body must never \
         have been written back"
    );
    assert!(
        vault.get_raw(&e2).unwrap().is_none(),
        "E2's surviving row is purged by the fail-closed hard replay"
    );
    assert!(!vault.edge_exists(&s, EdgeKind::Mentions, &e3).unwrap());

    let second_pass =
        window::forward_rematerialize(&vault, &doc, &materializer, &window_key()).unwrap();
    assert_eq!(
        second_pass, 0,
        "replay is idempotent — nothing local remains to erase"
    );
}
