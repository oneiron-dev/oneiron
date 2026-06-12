//! ONE-1124 — quarantine (`x:` family) gate-rejection table over Observer B.
//!
//! Contract sources:
//! * ARCH-0023b stream-class split: REMOTE divergent/malformed state is
//!   "QUARANTINED … never silent LWW"; sync must not be DoS-able by one bad
//!   op (per-op isolation).
//! * contracts.ts `edgeKinds` weight pin: weight ∈ [0, 1] "enforced on
//!   every write path".
//!
//! Lives in its own integration binary (fresh process): the lib test binary
//! sits near a per-process LMDB env-open budget on macOS, and this table
//! opens one vault per rejection class.

#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::LoroDoc;
use oneiron::sync::WindowKey;
use oneiron::sync::bridge::{
    Materializer, encode_edge_value_for_crdt, format_edge_key, register_observer_b,
};
use oneiron::sync::quarantine::{QuarantineContainer, quarantined_records};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::forward_rematerialize;
use oneiron::types::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, EdgeKind, TimeRange,
};
use oneiron::{EntityId, Vault, VaultConfig};
use xxhash_rust::xxh3::xxh3_64;

/// `learned_at` inside the 2026-03 window used throughout.
const LEARNED_AT: u64 = 1_772_400_000;
const WINDOW: &str = "2026-03";

fn test_vault_with_dir() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
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

/// Hand-built 24-byte SemanticBare edge value (weight + created_at + VAD),
/// bypassing the engine's own encoder validation so out-of-range and
/// non-finite weights can reach the replay gates.
fn semantic_edge_value(weight: f32) -> Vec<u8> {
    let mut value = Vec::with_capacity(24);
    value.extend_from_slice(&weight.to_le_bytes());
    value.extend_from_slice(&10u64.to_le_bytes());
    for _ in 0..3 {
        value.extend_from_slice(&0.5f32.to_le_bytes());
    }
    value
}

/// Hand-crafted type-0 CLAIM body (pinned MessagePack ABI, encoded
/// independently of the engine's own encoder): valid except the predicate,
/// which violates the D17 ≥2-dot-joined-segments grammar.
fn claim_body_with_bad_predicate() -> Vec<u8> {
    let body = rmpv::Value::Map(vec![
        (rmpv::Value::from("pred"), rmpv::Value::from("nodots")),
        (rmpv::Value::from("val"), rmpv::Value::from("v")),
        (rmpv::Value::from("conf"), rmpv::Value::F32(0.5)),
        (
            rmpv::Value::from("subj"),
            rmpv::Value::Binary(EntityId::now().as_bytes().to_vec()),
        ),
        (rmpv::Value::from("appr"), rmpv::Value::from("auto")),
        (rmpv::Value::from("life"), rmpv::Value::from("active")),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &body).unwrap();
    out
}

fn valid_time_range() -> TimeRange {
    TimeRange { start: 1, end: 2 }
}

fn insert_bytes(map: &loro::LoroMap, key: &str, value: &[u8]) {
    map.insert(key, value).unwrap();
}

struct GateCase {
    name: &'static str,
    container: QuarantineContainer,
    expected_reason: &'static str,
    setup: fn(&Arc<Vault>, &LoroDoc) -> (String, Vec<u8>),
}

/// ONE-1124 AC2/AC7 — every write-gate rejection class of a REMOTE op
/// persists exactly one `x:` record carrying the typed error name, the
/// window key, the container, the CRDT key's hash + byte length (never the
/// key itself), and the xxh3_64 payload hash. Reason codes are asserted as
/// string literals so a renamed or reused error kind fails.
#[test]
fn each_gate_rejection_class_produces_exactly_one_quarantine_record() {
    let cases: &[GateCase] = &[
        GateCase {
            name: "entity_undecodable_blob",
            container: QuarantineContainer::Entities,
            expected_reason: "CorruptedIndex",
            setup: |_vault, doc| {
                let id = EntityId::now();
                let blob = b"short".to_vec();
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        GateCase {
            name: "entity_invalid_hex_key",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidKey",
            setup: |_vault, doc| {
                let blob = entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, b"x");
                insert_bytes(&doc.get_map("entities"), "not-a-hex-entity-id", &blob);
                ("not-a-hex-entity-id".to_string(), blob)
            },
        },
        GateCase {
            name: "entity_unknown_type_byte",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidEntityType",
            setup: |_vault, doc| {
                let id = EntityId::now();
                let blob = entity_blob(200, valid_time_range(), LEARNED_AT, b"x");
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        GateCase {
            name: "entity_reversed_time_range",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidTimeRange",
            setup: |_vault, doc| {
                let id = EntityId::now();
                let blob = entity_blob(
                    ENTITY_TYPE_TASK,
                    TimeRange { start: 9, end: 3 },
                    LEARNED_AT,
                    b"x",
                );
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        GateCase {
            name: "entity_type_immutable",
            container: QuarantineContainer::Entities,
            expected_reason: "EntityTypeImmutable",
            setup: |vault, doc| {
                let id = EntityId::now();
                vault
                    .put_entity(&id, ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, b"a")
                    .unwrap();
                let blob = entity_blob(ENTITY_TYPE_PERSON, valid_time_range(), LEARNED_AT, b"b");
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        GateCase {
            name: "entity_invalid_claim_body",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidClaimBody",
            setup: |_vault, doc| {
                let id = EntityId::now();
                let blob = entity_blob(
                    ENTITY_TYPE_CLAIM,
                    valid_time_range(),
                    LEARNED_AT,
                    b"garbage-claim-bytes",
                );
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        GateCase {
            name: "entity_invalid_claim_predicate",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidPredicate",
            setup: |_vault, doc| {
                let id = EntityId::now();
                let blob = entity_blob(
                    ENTITY_TYPE_CLAIM,
                    valid_time_range(),
                    LEARNED_AT,
                    &claim_body_with_bad_predicate(),
                );
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        GateCase {
            name: "edge_invalid_key_format",
            container: QuarantineContainer::Edges,
            expected_reason: "InvalidKey",
            setup: |_vault, doc| {
                let value = semantic_edge_value(0.5);
                insert_bytes(&doc.get_map("edges"), "garbage-edge-key", &value);
                ("garbage-edge-key".to_string(), value)
            },
        },
        GateCase {
            name: "edge_undecodable_value",
            container: QuarantineContainer::Edges,
            expected_reason: "CorruptedIndex",
            setup: |_vault, doc| {
                let key = format_edge_key(
                    &EntityId::from_hex("11111111111111111111111111111111").unwrap(),
                    EdgeKind::Mentions,
                    &EntityId::from_hex("22222222222222222222222222222222").unwrap(),
                );
                let value = vec![1u8, 2, 3];
                insert_bytes(&doc.get_map("edges"), &key, &value);
                (key, value)
            },
        },
        GateCase {
            name: "edge_non_finite_weight",
            container: QuarantineContainer::Edges,
            expected_reason: "CorruptedIndex",
            setup: |_vault, doc| {
                let key = format_edge_key(
                    &EntityId::from_hex("11111111111111111111111111111111").unwrap(),
                    EdgeKind::Mentions,
                    &EntityId::from_hex("22222222222222222222222222222222").unwrap(),
                );
                let value = semantic_edge_value(f32::NAN);
                insert_bytes(&doc.get_map("edges"), &key, &value);
                (key, value)
            },
        },
        GateCase {
            name: "edge_out_of_range_weight",
            container: QuarantineContainer::Edges,
            expected_reason: "InvalidEdgeWeight",
            setup: |vault, doc| {
                let src = EntityId::now();
                let tgt = EntityId::now();
                vault
                    .put_entity(&src, ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, b"s")
                    .unwrap();
                vault
                    .put_entity(&tgt, ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, b"t")
                    .unwrap();
                let key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
                // Finite but outside the contract range [0, 1]: decodes,
                // then the write gate rejects it (contracts.ts edgeKinds
                // weight pin, "enforced on every write path").
                let value = semantic_edge_value(1.5);
                insert_bytes(&doc.get_map("edges"), &key, &value);
                (key, value)
            },
        },
        GateCase {
            name: "tombstone_invalid_hex_id",
            container: QuarantineContainer::Tombstones,
            expected_reason: "InvalidKey",
            setup: |_vault, doc| {
                insert_bytes(&doc.get_map("tombstones"), "zzz-not-hex", b"1");
                ("zzz-not-hex".to_string(), b"1".to_vec())
            },
        },
    ];

    for case in cases {
        let (_dir, vault) = test_vault_with_dir();
        let doc = LoroDoc::new();
        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

        let (crdt_key, payload) = (case.setup)(&vault, &doc);
        doc.commit();

        let records = quarantined_records(&vault).unwrap();
        assert_eq!(
            records.len(),
            1,
            "case {}: exactly one x: record expected",
            case.name
        );
        let (seq, rec) = &records[0];
        assert_eq!(*seq, 1, "case {}", case.name);
        assert_eq!(rec.window_key, WINDOW, "case {}", case.name);
        assert_eq!(rec.container, case.container, "case {}", case.name);
        assert_eq!(
            rec.crdt_key_hash,
            xxh3_64(crdt_key.as_bytes()),
            "case {}: crdt key hash",
            case.name
        );
        assert_eq!(
            rec.crdt_key_len,
            u32::try_from(crdt_key.len()).unwrap(),
            "case {}: crdt key length",
            case.name
        );
        assert_eq!(
            rec.reason_code, case.expected_reason,
            "case {}: reason code literal",
            case.name
        );
        assert_eq!(
            rec.payload_hash,
            xxh3_64(&payload),
            "case {}: payload hash",
            case.name
        );
        assert!(rec.quarantined_at > 0, "case {}", case.name);
    }
}

/// ONE-1124 AC2 — one quarantined op never aborts the batch: the good
/// entity in the same delta still materializes.
#[test]
fn poisoned_entity_op_does_not_abort_the_batch() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

    let bad_id = EntityId::now();
    let good_id = EntityId::now();
    let entities = doc.get_map("entities");
    insert_bytes(
        &entities,
        &bad_id.to_hex(),
        &entity_blob(200, valid_time_range(), LEARNED_AT, b"bad"),
    );
    insert_bytes(
        &entities,
        &good_id.to_hex(),
        &entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, b"good"),
    );
    doc.commit();

    assert_eq!(
        vault.get(&good_id).unwrap().as_deref(),
        Some(b"good".as_slice()),
        "good op must land despite the poisoned sibling"
    );
    assert!(vault.get(&bad_id).unwrap().is_none());
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1.reason_code, "InvalidEntityType");
}

/// ONE-1124 AC2 — a poisoned edge op never aborts the edge batch.
#[test]
fn poisoned_edge_op_does_not_abort_the_batch() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();
    for (id, data) in [(&a, b"a"), (&b, b"b"), (&c, b"c")] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                valid_time_range(),
                LEARNED_AT,
                data.as_slice(),
            )
            .unwrap();
    }

    let edges = doc.get_map("edges");
    insert_bytes(
        &edges,
        &format_edge_key(&a, EdgeKind::Mentions, &b),
        &semantic_edge_value(1.5),
    );
    insert_bytes(
        &edges,
        &format_edge_key(&c, EdgeKind::Mentions, &a),
        &semantic_edge_value(0.6),
    );
    doc.commit();

    assert!(
        vault.edge_exists(&c, EdgeKind::Mentions, &a).unwrap(),
        "good edge must land despite the poisoned sibling"
    );
    assert!(!vault.edge_exists(&a, EdgeKind::Mentions, &b).unwrap());
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1.reason_code, "InvalidEdgeWeight");
    assert_eq!(
        records[0].1.crdt_key_hash,
        xxh3_64(format_edge_key(&a, EdgeKind::Mentions, &b).as_bytes())
    );
}

/// ONE-1124 fix (PR #105 blocker) — forward remat decodes the edge value
/// BEFORE the endpoint-existence check, mirroring Observer B's ordering: a
/// valid-key MALFORMED edge whose endpoints are absent is quarantined (x:
/// Edges row), never silently deferred. A WELL-FORMED edge with absent
/// endpoints in the same doc stays a deferral — no x: row.
#[test]
fn forward_remat_quarantines_malformed_edge_value_before_endpoint_deferral() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    // None of these endpoints exist in LMDB.
    let src = EntityId::from_hex("11111111111111111111111111111111").unwrap();
    let tgt = EntityId::from_hex("22222222222222222222222222222222").unwrap();
    let other = EntityId::from_hex("33333333333333333333333333333333").unwrap();
    let edges = doc.get_map("edges");

    let malformed_key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    let malformed_value = vec![1u8, 2, 3];
    insert_bytes(&edges, &malformed_key, &malformed_value);

    let deferred_key = format_edge_key(&src, EdgeKind::Mentions, &other);
    insert_bytes(
        &edges,
        &deferred_key,
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, 10, None, None).unwrap(),
    );
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 0);

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(
        records.len(),
        1,
        "malformed edge must be quarantined; well-formed deferral adds no x: row"
    );
    let (_, rec) = &records[0];
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.container, QuarantineContainer::Edges);
    assert_eq!(rec.crdt_key_hash, xxh3_64(malformed_key.as_bytes()));
    assert_eq!(rec.reason_code, "CorruptedIndex");
    assert_eq!(rec.payload_hash, xxh3_64(&malformed_value));
}

/// ONE-1124 fix (#96 family) — a tombstone REMOVAL delta is a protocol
/// violation (no engine version ever emits one; tombstones are permanent):
/// it persists an x: row (hash+metadata only, empty payload hashed — no
/// content captured) and never reverts the applied purge or panics.
#[test]
fn tombstone_removal_delta_is_quarantined_as_protocol_violation() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            b"victim",
        )
        .unwrap();
    insert_bytes(&doc.get_map("tombstones"), &id.to_hex(), b"1");
    doc.commit();
    assert!(
        vault.get(&id).unwrap().is_none(),
        "precondition: tombstone purge applied"
    );
    assert!(quarantined_records(&vault).unwrap().is_empty());

    // Synthetic removal delta — a crafted op no engine version produces.
    doc.get_map("tombstones").delete(&id.to_hex()).unwrap();
    doc.commit();

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1, "removal delta must persist an x: row");
    let (_, rec) = &records[0];
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.container, QuarantineContainer::Tombstones);
    assert_eq!(rec.crdt_key_hash, xxh3_64(id.to_hex().as_bytes()));
    assert_eq!(rec.reason_code, "SyncProtocolError");
    assert_eq!(
        rec.payload_hash,
        xxh3_64(&[]),
        "hash of the empty payload — a removal carries no bytes"
    );
    // The materialization outcome is unaffected: the purge stays applied.
    assert!(vault.get(&id).unwrap().is_none());
}

/// ONE-1124 rider — an UNDECODABLE endpoint blob in the CRDT entities map
/// is REMOTE garbage: the edge referencing it is quarantined and the batch
/// continues (the good sibling edge lands), instead of the error being
/// classified local and aborting the whole edge transaction.
#[test]
fn undecodable_endpoint_blob_quarantines_edge_and_batch_continues() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

    let a = EntityId::now();
    let b = EntityId::now();
    for (id, data) in [(&a, b"a"), (&b, b"b")] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                valid_time_range(),
                LEARNED_AT,
                data.as_slice(),
            )
            .unwrap();
    }
    let bad = EntityId::now();

    // The bad endpoint's entities-map blob is undecodable; its edge and a
    // good sibling edge arrive in the same commit.
    insert_bytes(&doc.get_map("entities"), &bad.to_hex(), b"short");
    let edges = doc.get_map("edges");
    let bad_edge_key = format_edge_key(&bad, EdgeKind::Mentions, &a);
    insert_bytes(
        &edges,
        &bad_edge_key,
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, 10, None, None).unwrap(),
    );
    insert_bytes(
        &edges,
        &format_edge_key(&a, EdgeKind::Mentions, &b),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, 11, None, None).unwrap(),
    );
    doc.commit();

    assert!(
        vault.edge_exists(&a, EdgeKind::Mentions, &b).unwrap(),
        "good sibling edge must land — the batch is not aborted"
    );
    assert!(!vault.edge_exists(&bad, EdgeKind::Mentions, &a).unwrap());

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 2, "entity blob + edge each quarantined");
    let edge_rec = records
        .iter()
        .find(|(_, r)| r.container == QuarantineContainer::Edges)
        .expect("edge x: row");
    assert_eq!(edge_rec.1.crdt_key_hash, xxh3_64(bad_edge_key.as_bytes()));
    assert_eq!(edge_rec.1.reason_code, "CorruptedIndex");
    let entity_rec = records
        .iter()
        .find(|(_, r)| r.container == QuarantineContainer::Entities)
        .expect("entity x: row");
    assert_eq!(entity_rec.1.crdt_key_hash, xxh3_64(bad.to_hex().as_bytes()));
    assert_eq!(entity_rec.1.reason_code, "CorruptedIndex");
}

/// ONE-1124 rider — a remote ChildOf single-parent violation is a
/// quarantine-and-continue rejection (typed `ChildOfCardinality`), never a
/// whole-batch abort; and within the rejected component only the op that
/// individually fails the gate is quarantined — the deterministic-first
/// sibling lands and is never falsely recorded as rejected.
#[test]
fn child_of_cardinality_violation_quarantines_only_failing_op() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

    // Fixed ids pin the deterministic per-op order (sorted by encoded edge
    // key: same src/kind, so parent_a's tgt bytes sort first).
    let child = EntityId::from_hex("11111111111111111111111111111111").unwrap();
    let parent_a = EntityId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let parent_b = EntityId::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    for (id, data) in [(&child, b"c"), (&parent_a, b"p"), (&parent_b, b"q")] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                valid_time_range(),
                LEARNED_AT,
                data.as_slice(),
            )
            .unwrap();
    }

    let edges = doc.get_map("edges");
    let key_a = format_edge_key(&child, EdgeKind::ChildOf, &parent_a);
    let key_b = format_edge_key(&child, EdgeKind::ChildOf, &parent_b);
    let child_of_value =
        encode_edge_value_for_crdt(EdgeKind::ChildOf, 1.0, 10, None, None).unwrap();
    insert_bytes(&edges, &key_a, &child_of_value);
    insert_bytes(&edges, &key_b, &child_of_value);
    // Good non-ChildOf sibling proves the batch is not aborted.
    let mentions_key = format_edge_key(&parent_a, EdgeKind::Mentions, &parent_b);
    insert_bytes(
        &edges,
        &mentions_key,
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, 11, None, None).unwrap(),
    );
    doc.commit();

    assert!(
        vault
            .edge_exists(&parent_a, EdgeKind::Mentions, &parent_b)
            .unwrap(),
        "non-ChildOf sibling must land — the batch is not aborted"
    );
    assert!(
        vault
            .edge_exists(&child, EdgeKind::ChildOf, &parent_a)
            .unwrap(),
        "deterministic-first ChildOf op must land"
    );
    assert!(
        !vault
            .edge_exists(&child, EdgeKind::ChildOf, &parent_b)
            .unwrap()
    );

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(
        records.len(),
        1,
        "only the individually-failing op is quarantined"
    );
    let (_, rec) = &records[0];
    assert_eq!(rec.container, QuarantineContainer::Edges);
    assert_eq!(rec.crdt_key_hash, xxh3_64(key_b.as_bytes()));
    assert_eq!(rec.reason_code, "ChildOfCardinality");
}

/// ONE-1124 fix wave 2 (item 4) — the forward tombstone pass runs through
/// the tombstone-aware iterator: a STRING-valued (non-Binary) tombstone is
/// visited and treated as HARD delete input (the entity purges; pre-fix the
/// Binary-only iterator skipped it and the body stayed live), and the
/// invalid-key quarantine bookkeeping still fires for non-Binary rows
/// (hashing the empty slice — no content captured).
#[test]
fn string_valued_tombstone_purges_entity_and_invalid_key_still_quarantined() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            b"victim",
        )
        .unwrap();

    let tombstones = doc.get_map("tombstones");
    tombstones
        .insert(&id.to_hex(), "not-binary-tombstone")
        .unwrap();
    tombstones.insert("zzz-not-hex", "also-not-binary").unwrap();
    doc.commit();

    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();

    assert!(
        vault.get(&id).unwrap().is_none(),
        "string-valued tombstone must purge — non-Binary is HARD input (fail closed)"
    );
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1, "invalid-key row still quarantined");
    let (_, rec) = &records[0];
    assert_eq!(rec.container, QuarantineContainer::Tombstones);
    assert_eq!(rec.crdt_key_hash, xxh3_64(b"zzz-not-hex"));
    assert_eq!(rec.reason_code, "InvalidKey");
    assert_eq!(
        rec.payload_hash,
        xxh3_64(&[]),
        "non-Binary value hashes as the empty slice — no content captured"
    );
    // Every validated tombstone purged cleanly: no rm: retry markers.
    assert!(
        oneiron::sync::pending_remat_windows(&vault)
            .unwrap()
            .is_empty()
    );
}
