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
use oneiron::edge::EdgeKind;
use oneiron::habit::TaskRole;
use oneiron::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK,
};
use oneiron::sync::WindowKey;
use oneiron::sync::bridge::{
    Materializer, encode_edge_value_for_crdt, format_edge_key, register_observer_b,
};
use oneiron::sync::quarantine::{QuarantineContainer, quarantined_records};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::forward_rematerialize;
use oneiron::temporal::TimeRange;
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

fn task_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(
        &mut bytes,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from(TaskRole::Task.role_byte()),
        )]),
    )
    .expect("writing MessagePack TASK body to Vec cannot fail");
    bytes
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

/// Hand-crafted `edge.provenance` value record carrying exactly the three
/// REQUIRED pinned snake_case keys (contracts.ts `edgeProvenanceClaim.fields`:
/// `actor_entity_ref` 16-byte binary, `confidence` in [0, 1],
/// `supersession_status` u8) — encoded independently of the engine's own
/// encoder so the ONE-1159 door tests pin the wire literals.
fn edge_provenance_value_record() -> rmpv::Value {
    rmpv::Value::Map(vec![
        (
            rmpv::Value::from("actor_entity_ref"),
            rmpv::Value::Binary(vec![0x42; 16]),
        ),
        (rmpv::Value::from("confidence"), rmpv::Value::F32(0.75)),
        (
            rmpv::Value::from("supersession_status"),
            rmpv::Value::from(1u8),
        ),
    ])
}

/// The engine-owned persisted actor-class evidence map `{"actor_class": u8}`
/// carried on the wrapping Claim's `evid` field (0 = human).
fn actor_class_evidence() -> rmpv::Value {
    rmpv::Value::Map(vec![(
        rmpv::Value::from("actor_class"),
        rmpv::Value::from(0u8),
    )])
}

/// Confidence carried by [`edge_provenance_value_record`]. The ONE-1159 door
/// now enforces wrapper↔value-record mirror equality, so a SURFACEABLE
/// wrapper's `conf` MUST equal this; the prior helper hardcoded `conf = 0.9`
/// (≠ the record's `0.75`), which the new mirror check correctly rejects —
/// the helper, not the assertions, was self-inconsistent.
const PROVENANCE_VALUE_CONFIDENCE: f32 = 0.75;

/// Hand-crafted D18-VALID type-0 CLAIM body with `pred = "edge.provenance"`
/// and a 33-byte EdgeRef `subj`, with full control over the WRAPPER axes the
/// ONE-1159 door gates — surfaceability (`appr`, `stale`) and the
/// value-record mirror fields (`conf`, `from`, `to`). Every D18 rule passes,
/// so the ONLY thing standing between a broken wrapper/value-record and the
/// entities table is the ONE-1159 structural branch at the replay door.
#[allow(clippy::too_many_arguments)]
fn edge_provenance_claim_body_with(
    val: rmpv::Value,
    evid: Option<rmpv::Value>,
    conf: f32,
    appr: &str,
    stale: Option<bool>,
    valid_from: Option<u64>,
    valid_to: Option<u64>,
) -> Vec<u8> {
    let mut edge_ref = Vec::with_capacity(33);
    edge_ref.extend_from_slice(&[0x11; 16]);
    edge_ref.push(EdgeKind::Mentions as u8);
    edge_ref.extend_from_slice(&[0x22; 16]);
    let mut entries = vec![
        (
            rmpv::Value::from("pred"),
            rmpv::Value::from("edge.provenance"),
        ),
        (rmpv::Value::from("val"), val),
        (rmpv::Value::from("conf"), rmpv::Value::F32(conf)),
    ];
    if let Some(evid) = evid {
        entries.push((rmpv::Value::from("evid"), evid));
    }
    if let Some(from) = valid_from {
        entries.push((rmpv::Value::from("from"), rmpv::Value::from(from)));
    }
    if let Some(to) = valid_to {
        entries.push((rmpv::Value::from("to"), rmpv::Value::from(to)));
    }
    entries.push((rmpv::Value::from("subj"), rmpv::Value::Binary(edge_ref)));
    entries.push((rmpv::Value::from("appr"), rmpv::Value::from(appr)));
    entries.push((rmpv::Value::from("life"), rmpv::Value::from("active")));
    if let Some(stale) = stale {
        entries.push((rmpv::Value::from("stale"), rmpv::Value::Boolean(stale)));
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries)).unwrap();
    out
}

/// Surfaceable wrapper (`appr = auto`, no `stale`, no valid-time) whose `conf`
/// mirrors the default value record's `confidence` ([`PROVENANCE_VALUE_CONFIDENCE`])
/// — the shape the existing positive controls and the broken-value-record
/// cases share. A broken `val`/`evid` is rejected on the value-record /
/// actor-class axis before the mirror check is reached.
fn edge_provenance_claim_body(val: rmpv::Value, evid: Option<rmpv::Value>) -> Vec<u8> {
    edge_provenance_claim_body_with(
        val,
        evid,
        PROVENANCE_VALUE_CONFIDENCE,
        "auto",
        None,
        None,
        None,
    )
}

fn valid_time_range() -> TimeRange {
    TimeRange { start: 1, end: 2 }
}

fn insert_bytes(map: &loro::LoroMap, key: &str, value: &[u8]) {
    map.insert(key, value).unwrap();
}

fn malformed_federation_grant_blob() -> Vec<u8> {
    entity_blob(
        ENTITY_TYPE_FEDERATION_GRANT,
        valid_time_range(),
        LEARNED_AT,
        b"not a federation grant body",
    )
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
                let blob = entity_blob(
                    ENTITY_TYPE_TASK,
                    valid_time_range(),
                    LEARNED_AT,
                    &task_body(),
                );
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
                    &task_body(),
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
                    .put_entity(
                        &id,
                        ENTITY_TYPE_TASK,
                        valid_time_range(),
                        LEARNED_AT,
                        &task_body(),
                    )
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
            name: "entity_malformed_federation_grant_body",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidFederationGrantBody",
            setup: |_vault, doc| {
                let id = EntityId::now();
                let blob = malformed_federation_grant_blob();
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        // ── ONE-1159: edge.provenance structural validation at the door.
        // Each forged wrapper is D18-VALID; the wrongness is a junk SHAPE
        // (never a key-count assumption), so every case stays invalid under
        // any grown value-record vocabulary.
        GateCase {
            name: "provenance_claim_non_map_value_record",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidProvenanceBody",
            setup: |_vault, doc| {
                let id = EntityId::now();
                let blob = entity_blob(
                    ENTITY_TYPE_CLAIM,
                    valid_time_range(),
                    LEARNED_AT,
                    &edge_provenance_claim_body(
                        rmpv::Value::from("junk-not-a-record"),
                        Some(actor_class_evidence()),
                    ),
                );
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        GateCase {
            name: "provenance_claim_missing_required_actor_entity_ref",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidProvenanceBody",
            setup: |_vault, doc| {
                let rmpv::Value::Map(mut entries) = edge_provenance_value_record() else {
                    unreachable!("helper emits a map");
                };
                entries.retain(|(key, _)| key.as_str() != Some("actor_entity_ref"));
                let id = EntityId::now();
                let blob = entity_blob(
                    ENTITY_TYPE_CLAIM,
                    valid_time_range(),
                    LEARNED_AT,
                    &edge_provenance_claim_body(
                        rmpv::Value::Map(entries),
                        Some(actor_class_evidence()),
                    ),
                );
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        GateCase {
            name: "provenance_claim_unknown_value_record_key",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidProvenanceBody",
            setup: |_vault, doc| {
                let rmpv::Value::Map(mut entries) = edge_provenance_value_record() else {
                    unreachable!("helper emits a map");
                };
                entries.push((rmpv::Value::from("zzz"), rmpv::Value::from(1u8)));
                let id = EntityId::now();
                let blob = entity_blob(
                    ENTITY_TYPE_CLAIM,
                    valid_time_range(),
                    LEARNED_AT,
                    &edge_provenance_claim_body(
                        rmpv::Value::Map(entries),
                        Some(actor_class_evidence()),
                    ),
                );
                insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
                (id.to_hex(), blob)
            },
        },
        GateCase {
            name: "provenance_claim_missing_actor_class_evidence",
            container: QuarantineContainer::Entities,
            expected_reason: "InvalidProvenanceBody",
            setup: |_vault, doc| {
                let id = EntityId::now();
                let blob = entity_blob(
                    ENTITY_TYPE_CLAIM,
                    valid_time_range(),
                    LEARNED_AT,
                    &edge_provenance_claim_body(edge_provenance_value_record(), None),
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
                    .put_entity(
                        &src,
                        ENTITY_TYPE_TASK,
                        valid_time_range(),
                        LEARNED_AT,
                        &task_body(),
                    )
                    .unwrap();
                vault
                    .put_entity(
                        &tgt,
                        ENTITY_TYPE_TASK,
                        valid_time_range(),
                        LEARNED_AT,
                        &task_body(),
                    )
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

/// ONE-1159 — the replay door validates `edge.provenance` Claims
/// STRUCTURALLY (pinned value record + persisted actor-class evidence), not
/// just D18-grammatically: forged D18-valid wrappers around broken
/// provenance records are typed-rejected at the door and never reach the
/// entities table, while a fully-valid Claim (legacy evid shape) in the SAME
/// batch replicates byte-identical — per-op isolation, hash-only x: rows.
///
/// FAILS against pre-fix code: every forged Claim materialized into LMDB
/// (D18 treats `val`/`evid` as opaque) and only failed closed later, at the
/// provenance ops that interpret it.
#[test]
fn replay_door_keeps_structurally_invalid_provenance_claims_out_of_entities() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let entities = doc.get_map("entities");

    let missing_actor = rmpv::Value::Map(vec![
        (rmpv::Value::from("confidence"), rmpv::Value::F32(0.75)),
        (
            rmpv::Value::from("supersession_status"),
            rmpv::Value::from(1u8),
        ),
    ]);
    let unknown_key = {
        let rmpv::Value::Map(mut entries) = edge_provenance_value_record() else {
            unreachable!("helper emits a map");
        };
        entries.push((rmpv::Value::from("zzz"), rmpv::Value::from(1u8)));
        rmpv::Value::Map(entries)
    };
    let forged_bodies: [(&str, Vec<u8>); 4] = [
        (
            "non-map value record",
            edge_provenance_claim_body(
                rmpv::Value::from("junk-not-a-record"),
                Some(actor_class_evidence()),
            ),
        ),
        (
            "missing required actor_entity_ref",
            edge_provenance_claim_body(missing_actor, Some(actor_class_evidence())),
        ),
        (
            "unknown value-record key zzz",
            edge_provenance_claim_body(unknown_key, Some(actor_class_evidence())),
        ),
        (
            "missing actor_class evidence",
            edge_provenance_claim_body(edge_provenance_value_record(), None),
        ),
    ];

    let mut forged = Vec::new();
    for (name, body) in forged_bodies {
        let id = EntityId::now();
        let blob = entity_blob(ENTITY_TYPE_CLAIM, valid_time_range(), LEARNED_AT, &body);
        insert_bytes(&entities, &id.to_hex(), &blob);
        forged.push((name, id, blob));
    }
    let valid_id = EntityId::now();
    let valid_blob = entity_blob(
        ENTITY_TYPE_CLAIM,
        valid_time_range(),
        LEARNED_AT,
        &edge_provenance_claim_body(edge_provenance_value_record(), Some(actor_class_evidence())),
    );
    insert_bytes(&entities, &valid_id.to_hex(), &valid_blob);
    doc.commit();

    // Positive control: the fully-valid Claim replicated byte-identical
    // despite the four poisoned siblings (per-op isolation).
    assert_eq!(
        vault.get_raw(&valid_id).unwrap().as_deref(),
        Some(valid_blob.as_slice()),
        "fully-valid edge.provenance claim must still replicate byte-identical"
    );
    // Every forged Claim was rejected AT THE DOOR: absent from entities…
    for (name, id, _) in &forged {
        assert!(
            vault.get_raw(id).unwrap().is_none(),
            "{name}: structurally invalid provenance claim must never reach entities"
        );
    }
    // …and quarantined typed + hash-only (`x:` rows, ONE-1124 discipline).
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(
        records.len(),
        forged.len(),
        "exactly one x: row per forged claim"
    );
    for (_, rec) in &records {
        assert_eq!(
            rec.reason_code, "InvalidProvenanceBody",
            "typed rejection reason literal"
        );
        assert_eq!(rec.container, QuarantineContainer::Entities);
    }
    let mut quarantined_hashes: Vec<u64> =
        records.iter().map(|(_, rec)| rec.payload_hash).collect();
    quarantined_hashes.sort_unstable();
    let mut expected_hashes: Vec<u64> = forged.iter().map(|(_, _, blob)| xxh3_64(blob)).collect();
    expected_hashes.sort_unstable();
    assert_eq!(
        quarantined_hashes, expected_hashes,
        "x: rows carry the xxh3_64 of each rejected blob (hash-only, GDPR-inert)"
    );
}

/// ONE-1159 fix-wave — the replay door also gates the WRAPPER axes D18 leaves
/// opaque. A Claim that is structurally well-formed (valid value record +
/// actor-class evidence) but NON-SURFACEABLE (`appr = rejected`, `stale =
/// true`), or whose wrapper `conf`/`from`/`to` does NOT mirror the value
/// record, is typed-rejected at the door and never reaches the entities
/// table; a surfaceable, mirror-consistent Claim in the SAME batch replicates
/// byte-identical (per-op isolation, hash-only x: rows).
///
/// FAILS against pre-fix code: the door validated only the value record +
/// actor-class evidence, so a `rejected`/`stale` wrapper or a `conf`-lying
/// wrapper materialized and could later steer edge-flag refresh.
#[test]
fn replay_door_rejects_non_surfaceable_and_mirror_mismatched_provenance_wrappers() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let entities = doc.get_map("entities");

    // Value record carrying optional valid-time: the record asserts a window
    // the wrapper then fails to mirror (wrapper from/to absent).
    let value_record_with_times = {
        let rmpv::Value::Map(mut entries) = edge_provenance_value_record() else {
            unreachable!("helper emits a map");
        };
        entries.push((rmpv::Value::from("valid_from"), rmpv::Value::from(10u64)));
        entries.push((rmpv::Value::from("valid_to"), rmpv::Value::from(20u64)));
        rmpv::Value::Map(entries)
    };

    let forged_bodies: [(&str, Vec<u8>); 4] = [
        // appr=rejected: value record + actor-class + mirrored conf all valid;
        // ONLY the surfaceability approval axis is wrong.
        (
            "non-surfaceable appr=rejected",
            edge_provenance_claim_body_with(
                edge_provenance_value_record(),
                Some(actor_class_evidence()),
                PROVENANCE_VALUE_CONFIDENCE,
                "rejected",
                None,
                None,
                None,
            ),
        ),
        // stale=true: everything else valid + mirrored.
        (
            "non-surfaceable stale=true",
            edge_provenance_claim_body_with(
                edge_provenance_value_record(),
                Some(actor_class_evidence()),
                PROVENANCE_VALUE_CONFIDENCE,
                "auto",
                Some(true),
                None,
                None,
            ),
        ),
        // conf mismatch: value-record confidence=0.75, wrapper conf=0.40.
        (
            "wrapper conf does not mirror value-record confidence",
            edge_provenance_claim_body_with(
                edge_provenance_value_record(),
                Some(actor_class_evidence()),
                0.40,
                "auto",
                None,
                None,
                None,
            ),
        ),
        // from/to mismatch: record carries valid_from=10/valid_to=20 but the
        // wrapper omits from/to entirely (Option inequality, not just conf).
        (
            "wrapper from/to do not mirror valid_from/valid_to",
            edge_provenance_claim_body_with(
                value_record_with_times,
                Some(actor_class_evidence()),
                PROVENANCE_VALUE_CONFIDENCE,
                "auto",
                None,
                None,
                None,
            ),
        ),
    ];

    let mut forged = Vec::new();
    for (name, body) in forged_bodies {
        let id = EntityId::now();
        let blob = entity_blob(ENTITY_TYPE_CLAIM, valid_time_range(), LEARNED_AT, &body);
        insert_bytes(&entities, &id.to_hex(), &blob);
        forged.push((name, id, blob));
    }

    // Positive control: SURFACEABLE (appr=auto, not stale), `conf` EXACTLY
    // mirrors the value-record confidence (0.75), from/to absent on both
    // sides — the door must NOT over-reject a genuinely-valid mirrored Claim.
    let valid_id = EntityId::now();
    let valid_blob = entity_blob(
        ENTITY_TYPE_CLAIM,
        valid_time_range(),
        LEARNED_AT,
        &edge_provenance_claim_body(edge_provenance_value_record(), Some(actor_class_evidence())),
    );
    insert_bytes(&entities, &valid_id.to_hex(), &valid_blob);
    doc.commit();

    assert_eq!(
        vault.get_raw(&valid_id).unwrap().as_deref(),
        Some(valid_blob.as_slice()),
        "surfaceable mirror-consistent edge.provenance claim must replicate byte-identical"
    );
    for (name, id, _) in &forged {
        assert!(
            vault.get_raw(id).unwrap().is_none(),
            "{name}: non-surfaceable / mirror-mismatched wrapper must never reach entities"
        );
    }
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(
        records.len(),
        forged.len(),
        "exactly one x: row per forged wrapper"
    );
    for (_, rec) in &records {
        assert_eq!(
            rec.reason_code, "InvalidProvenanceBody",
            "typed rejection reason literal"
        );
        assert_eq!(rec.container, QuarantineContainer::Entities);
    }
    let mut quarantined_hashes: Vec<u64> =
        records.iter().map(|(_, rec)| rec.payload_hash).collect();
    quarantined_hashes.sort_unstable();
    let mut expected_hashes: Vec<u64> = forged.iter().map(|(_, _, blob)| xxh3_64(blob)).collect();
    expected_hashes.sort_unstable();
    assert_eq!(
        quarantined_hashes, expected_hashes,
        "x: rows carry the xxh3_64 of each rejected blob (hash-only, GDPR-inert)"
    );
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
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    );
    doc.commit();

    assert_eq!(
        vault.get(&good_id).unwrap().as_deref(),
        Some(task_body().as_slice()),
        "good op must land despite the poisoned sibling"
    );
    assert!(vault.get(&bad_id).unwrap().is_none());
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1.reason_code, "InvalidEntityType");
}

/// FED-001: a malformed remote FEDERATION_GRANT body is a remote rejection,
/// not a local replay failure. Observer B quarantines the bad op and keeps
/// applying the valid sibling from the same CRDT commit.
#[test]
fn observer_b_quarantines_malformed_federation_grant_and_continues() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

    let bad_id = EntityId::now();
    let good_id = EntityId::now();
    let bad_blob = malformed_federation_grant_blob();
    let entities = doc.get_map("entities");
    insert_bytes(&entities, &bad_id.to_hex(), &bad_blob);
    insert_bytes(
        &entities,
        &good_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    );
    doc.commit();

    assert!(
        vault.get(&bad_id).unwrap().is_none(),
        "malformed federation grant must not materialize"
    );
    assert_eq!(
        vault.get(&good_id).unwrap().as_deref(),
        Some(task_body().as_slice()),
        "valid sibling must land after quarantining the malformed grant"
    );

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let (_, rec) = &records[0];
    assert_eq!(rec.container, QuarantineContainer::Entities);
    assert_eq!(rec.reason_code, "InvalidFederationGrantBody");
    assert_eq!(rec.crdt_key_hash, xxh3_64(bad_id.to_hex().as_bytes()));
    assert_eq!(rec.payload_hash, xxh3_64(&bad_blob));
}

/// FED-001 forward-remat parity: a malformed remote FEDERATION_GRANT body
/// must quarantine and continue instead of wedging rematerialization.
#[test]
fn forward_remat_quarantines_malformed_federation_grant_and_continues() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    let bad_id = EntityId::now();
    let good_id = EntityId::now();
    let bad_blob = malformed_federation_grant_blob();
    let entities = doc.get_map("entities");
    insert_bytes(&entities, &bad_id.to_hex(), &bad_blob);
    insert_bytes(
        &entities,
        &good_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    );
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 1, "only the valid sibling materializes");
    assert!(
        vault.get(&bad_id).unwrap().is_none(),
        "malformed federation grant must not materialize"
    );
    assert_eq!(
        vault.get(&good_id).unwrap().as_deref(),
        Some(task_body().as_slice())
    );

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let (_, rec) = &records[0];
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.container, QuarantineContainer::Entities);
    assert_eq!(rec.reason_code, "InvalidFederationGrantBody");
    assert_eq!(rec.crdt_key_hash, xxh3_64(bad_id.to_hex().as_bytes()));
    assert_eq!(rec.payload_hash, xxh3_64(&bad_blob));
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
    for id in [&a, &b, &c] {
        let body = task_body();
        vault
            .put_entity(id, ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, &body)
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
            &task_body(),
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
    for id in [&a, &b] {
        let body = task_body();
        vault
            .put_entity(id, ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, &body)
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
    for id in [&child, &parent_a, &parent_b] {
        let body = task_body();
        vault
            .put_entity(id, ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, &body)
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
            &task_body(),
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

/// ONE-1157 — the forward-remat ENTITY pass visits EVERY entities-map key:
/// a non-Binary (string) value where an entity blob belongs persists exactly
/// one `x:` row (container `entities`, typed reason literal `InvalidKey`,
/// key hash + length — never the key itself — and the EMPTY slice's payload
/// hash: a non-Binary value carries no bytes), nothing materializes for that
/// key, and the pass continues — the good sibling entity still lands.
/// Pre-fix the Binary-only iterator skipped the op invisibly: no x: row.
#[test]
fn forward_remat_quarantines_non_binary_entity_value_and_continues() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    let bad_id = EntityId::from_hex("0123456789abcdef0123456789abcdef").unwrap();
    let good_id = EntityId::now();
    let entities = doc.get_map("entities");
    entities
        .insert(&bad_id.to_hex(), "not-binary-entity")
        .unwrap();
    insert_bytes(
        &entities,
        &good_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    );
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 1, "only the good sibling materializes");
    assert!(
        vault.get(&bad_id).unwrap().is_none(),
        "a non-Binary op must never materialize"
    );
    assert_eq!(
        vault.get(&good_id).unwrap().as_deref(),
        Some(task_body().as_slice()),
        "the pass must continue past the quarantined op"
    );

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1, "exactly one x: row for the non-Binary op");
    let (_, rec) = &records[0];
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.container, QuarantineContainer::Entities);
    assert_eq!(rec.crdt_key_hash, xxh3_64(bad_id.to_hex().as_bytes()));
    assert_eq!(rec.crdt_key_len, 32);
    assert_eq!(rec.reason_code, "InvalidKey");
    assert_eq!(
        rec.payload_hash,
        xxh3_64(&[]),
        "non-Binary value hashes as the empty slice — no content captured"
    );
}

/// ONE-1157 (edge-pass parity — same gap, same trivial fix shape): a
/// non-Binary value under a well-formed edges-map key persists one `x:` row
/// (container `edges`, reason literal `InvalidKey`, empty-slice payload
/// hash), the edge never reaches LMDB, and the good sibling edge still
/// lands.
#[test]
fn forward_remat_quarantines_non_binary_edge_value_and_continues() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();
    for id in [&a, &b, &c] {
        let body = task_body();
        vault
            .put_entity(id, ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, &body)
            .unwrap();
    }

    let edges = doc.get_map("edges");
    let bad_key = format_edge_key(&a, EdgeKind::Mentions, &b);
    edges.insert(&bad_key, "not-binary-edge").unwrap();
    insert_bytes(
        &edges,
        &format_edge_key(&c, EdgeKind::Mentions, &a),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, 11, None, None).unwrap(),
    );
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 1, "only the good sibling edge materializes");
    assert!(
        !vault.edge_exists(&a, EdgeKind::Mentions, &b).unwrap(),
        "a non-Binary edge op must never materialize"
    );
    assert!(
        vault.edge_exists(&c, EdgeKind::Mentions, &a).unwrap(),
        "the pass must continue past the quarantined op"
    );

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1, "exactly one x: row for the non-Binary op");
    let (_, rec) = &records[0];
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.container, QuarantineContainer::Edges);
    assert_eq!(rec.crdt_key_hash, xxh3_64(bad_key.as_bytes()));
    assert_eq!(
        rec.crdt_key_len,
        u32::try_from(bad_key.len()).unwrap(),
        "key metadata is hash + length, never the key"
    );
    assert_eq!(rec.reason_code, "InvalidKey");
    assert_eq!(rec.payload_hash, xxh3_64(&[]));
}

/// ONE-1158 — an UPPERCASE (non-canonical) entities-map alias key delivered
/// through Observer B is a protocol violation: quarantined (`x:` row,
/// container `entities`, reason literal `InvalidKey`, hash of the ALIAS key
/// bytes + the blob's payload hash), and the body must NOT materialize in
/// LMDB under the parsed canonical id — pre-fix it materialized while the
/// alias KEY persisted in the live map, invisible to canonical-lowercase
/// tombstone-commit removal (suppressed byte residue). Canonical lowercase
/// delivery in the same commit still works (positive control: the batch is
/// not aborted).
#[test]
fn observer_b_quarantines_uppercase_alias_entity_key() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

    let alias_id = EntityId::from_hex("0123456789abcdef0123456789abcdef").unwrap();
    let alias_key = alias_id.to_hex().to_uppercase();
    assert_ne!(alias_key, alias_id.to_hex(), "case-shift must be real");
    let good_id = EntityId::now();
    let alias_blob = entity_blob(
        ENTITY_TYPE_TASK,
        valid_time_range(),
        LEARNED_AT,
        &task_body(),
    );
    let entities = doc.get_map("entities");
    insert_bytes(&entities, &alias_key, &alias_blob);
    insert_bytes(
        &entities,
        &good_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    );
    doc.commit();

    assert!(
        vault.get(&alias_id).unwrap().is_none(),
        "an alias key must never enter LMDB materialization"
    );
    assert_eq!(
        vault.get(&good_id).unwrap().as_deref(),
        Some(task_body().as_slice()),
        "canonical lowercase delivery still works — the batch is not aborted"
    );

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1, "exactly one x: row for the alias op");
    let (_, rec) = &records[0];
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.container, QuarantineContainer::Entities);
    assert_eq!(
        rec.crdt_key_hash,
        xxh3_64(alias_key.as_bytes()),
        "the x: row hashes the ALIAS key as delivered, never stores it"
    );
    assert_eq!(rec.crdt_key_len, 32);
    assert_eq!(rec.reason_code, "InvalidKey");
    assert_eq!(rec.payload_hash, xxh3_64(&alias_blob));
}

/// ONE-1158 (forward-remat parity): the forward-remat ENTITY pass applies
/// the same alias gate as Observer B — an uppercase-alias-keyed body in the
/// entities map quarantines (`x:` row with the alias-key hash and the blob's
/// payload hash) instead of materializing, while the canonical-keyed sibling
/// still lands.
#[test]
fn forward_remat_quarantines_uppercase_alias_entity_key() {
    let (_dir, vault) = test_vault_with_dir();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);

    let alias_id = EntityId::from_hex("0123456789abcdef0123456789abcdef").unwrap();
    let alias_key = alias_id.to_hex().to_uppercase();
    let good_id = EntityId::now();
    let alias_blob = entity_blob(
        ENTITY_TYPE_TASK,
        valid_time_range(),
        LEARNED_AT,
        &task_body(),
    );
    let entities = doc.get_map("entities");
    insert_bytes(&entities, &alias_key, &alias_blob);
    insert_bytes(
        &entities,
        &good_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        ),
    );
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 1, "only the canonical sibling materializes");
    assert!(
        vault.get(&alias_id).unwrap().is_none(),
        "an alias key must never enter LMDB materialization"
    );
    assert_eq!(
        vault.get(&good_id).unwrap().as_deref(),
        Some(task_body().as_slice())
    );

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1, "exactly one x: row for the alias op");
    let (_, rec) = &records[0];
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.container, QuarantineContainer::Entities);
    assert_eq!(rec.crdt_key_hash, xxh3_64(alias_key.as_bytes()));
    assert_eq!(rec.reason_code, "InvalidKey");
    assert_eq!(rec.payload_hash, xxh3_64(&alias_blob));
}
