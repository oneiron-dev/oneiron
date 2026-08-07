use super::*;
use crate::claim::validate_predicate;
use crate::error::ErrorKind;
use core::assert_matches;

use crate::test_util::entity;

#[test]
fn predicate_constant_pins_contract_literal() {
    assert_eq!(PREDICATE_EDGE_PROVENANCE, "edge.provenance");
    // Reserved on every public path; writable only through the door.
    assert_matches!(
        validate_predicate(PREDICATE_EDGE_PROVENANCE, false),
        Err(Error::ReservedPredicate { .. })
    );
    validate_predicate(PREDICATE_EDGE_PROVENANCE, true)
        .expect("the provenance door must admit the pinned predicate");
}

#[test]
fn body_keys_pin_ten_snake_case_literals() {
    // ONE-1138 vocabulary bump: the original seven + substrate_ref +
    // reasoning_effort + actor_class, in canonical order. The decoder is
    // fail-closed on unknown keys, so this array IS the wire vocabulary.
    assert_eq!(
        EDGE_PROVENANCE_BODY_KEYS,
        [
            "actor_entity_ref",
            "source_revision_ref",
            "body_snapshot_ref",
            "confidence",
            "supersession_status",
            "valid_from",
            "valid_to",
            "substrate_ref",
            "reasoning_effort",
            "actor_class",
        ]
    );
}

#[test]
fn edge_ref_codec_pins_byte_offsets_and_aligns_with_edge_key() {
    let source = entity(0x60);
    let target = entity(0x22);
    let edge_ref = EdgeRef::new(source, EdgeKind::Mentions, target);

    let encoded = edge_ref.encode();
    assert_eq!(encoded.len(), 33);
    assert_eq!(EDGE_REF_LEN, 33);
    // Pinned offsets: source @ 0..16, kind u8 @ 16, target @ 17..33.
    assert_eq!(&encoded[..16], source.as_bytes());
    assert_eq!(encoded[16], 9, "Mentions discriminant must be 9");
    assert_eq!(&encoded[17..33], target.as_bytes());
    // Byte-identical to the LMDB edge key layout.
    assert_eq!(
        encoded,
        Store::encode_edge_key(&source, EdgeKind::Mentions, &target)
    );

    assert_eq!(EdgeRef::decode(&encoded).expect("round trip"), edge_ref);

    // Wrong lengths.
    for len in [0_usize, 16, 32, 34] {
        assert_matches!(
            EdgeRef::decode(&vec![0x11_u8; len]),
            Err(Error::InvalidProvenanceBody(_))
        );
    }
    // Unregistered kind byte.
    let mut bad_kind = encoded;
    bad_kind[16] = 200;
    assert_matches!(
        EdgeRef::decode(&bad_kind),
        Err(Error::InvalidProvenanceBody(_))
    );
    // Reserved entity-id bytes (all zero source).
    let mut reserved = encoded;
    reserved[..16].copy_from_slice(&[0x00; 16]);
    assert_matches!(
        EdgeRef::decode(&reserved),
        Err(Error::InvalidProvenanceBody(_))
    );
}

#[test]
fn encode_emits_canonical_snake_case_keys_and_decode_round_trips() {
    let mut body = EdgeProvenanceClaimBody::new(entity(0x31), 0.75, SupersessionStatus::Confirmed);
    body.source_revision_ref = Some([0x41; 16]);
    body.body_snapshot_ref = Some([0x42; 16]);
    body.valid_from = Some(100);
    body.valid_to = Some(200);
    body.substrate_ref = Some(entity(0x43));
    // 32 bytes exactly: the REASONING_EFFORT_MAX_BYTES boundary is valid.
    body.reasoning_effort = Some("x".repeat(32));
    body.actor_class = Some(EdgeActorClass::Agent);

    let value = encode_edge_provenance_value(&body);
    let Value::Map(entries) = &value else {
        panic!("encoded value must be a map");
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|(k, _)| k.as_str().expect("string key"))
        .collect();
    // Full body carries EXACTLY the ten pinned keys in canonical order
    // (ONE-1138 bump: + substrate_ref + reasoning_effort + actor_class).
    assert_eq!(
        keys,
        [
            "actor_entity_ref",
            "source_revision_ref",
            "body_snapshot_ref",
            "confidence",
            "supersession_status",
            "valid_from",
            "valid_to",
            "substrate_ref",
            "reasoning_effort",
            "actor_class",
        ]
    );
    // supersession_status is stored as the integer u8, not a string.
    assert_eq!(entries[4].1.as_u64(), Some(1));
    // substrate_ref is 16-byte Binary (an EntityRef, same wire shape as
    // actor_entity_ref) — never a hex string, never inline name/version.
    let Value::Binary(substrate_bytes) = &entries[7].1 else {
        panic!("substrate_ref must encode as Binary");
    };
    assert_eq!(substrate_bytes.as_slice(), entity(0x43).as_bytes());
    // reasoning_effort is an inline string scalar; actor_class is the
    // integer u8 (agent = 1), byte-identical to the legacy evid value.
    assert_eq!(entries[8].1.as_str(), Some("x".repeat(32).as_str()));
    assert_eq!(entries[9].1.as_u64(), Some(1));
    let decoded = decode_edge_provenance_body(&value).expect("decode");
    assert_eq!(decoded, body);
    assert_eq!(decoded.substrate_ref, Some(entity(0x43)));
    assert_eq!(
        decoded.reasoning_effort.as_deref(),
        Some("x".repeat(32).as_str())
    );
    assert_eq!(decoded.actor_class, Some(EdgeActorClass::Agent));

    // Minimal body: only the three required keys.
    let minimal = EdgeProvenanceClaimBody::new(entity(0x32), 1.0, SupersessionStatus::Proposed);
    let value = encode_edge_provenance_value(&minimal);
    let Value::Map(entries) = &value else {
        panic!("encoded value must be a map");
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|(k, _)| k.as_str().expect("string key"))
        .collect();
    assert_eq!(
        keys,
        ["actor_entity_ref", "confidence", "supersession_status"]
    );
    let decoded = decode_edge_provenance_body(&value).expect("decode minimal");
    assert_eq!(decoded, minimal);
    assert_eq!(decoded.source_revision_ref, None);
    assert_eq!(decoded.valid_to, None);
    // Elide-the-default: the three ONE-1138 keys are absent, not nulled,
    // and absent = unrecorded-and-valid.
    assert_eq!(decoded.substrate_ref, None);
    assert_eq!(decoded.reasoning_effort, None);
    assert_eq!(decoded.actor_class, None);
}

#[test]
fn decode_negative_matrix_fail_closed() {
    let actor = entity(0x33);
    let base = || -> Vec<(Value, Value)> {
        vec![
            (
                Value::from("actor_entity_ref"),
                Value::Binary(actor.as_bytes().to_vec()),
            ),
            (Value::from("confidence"), Value::F32(0.5)),
            (Value::from("supersession_status"), Value::from(0_u8)),
        ]
    };
    let without = |key: &str| -> Value {
        Value::Map(
            base()
                .into_iter()
                .filter(|(k, _)| k.as_str() != Some(key))
                .collect(),
        )
    };
    let replacing = |key: &str, replacement: Value| -> Value {
        Value::Map(
            base()
                .into_iter()
                .map(|(k, v)| {
                    if k.as_str() == Some(key) {
                        (k, replacement.clone())
                    } else {
                        (k, v)
                    }
                })
                .collect(),
        )
    };
    let with_extra = |key: &str, value: Value| -> Value {
        let mut entries = base();
        entries.push((Value::from(key), value));
        Value::Map(entries)
    };

    let cases: Vec<(&str, Value)> = vec![
        ("non-map value", Value::from("not a map")),
        (
            "unknown camelCase key",
            with_extra("actorEntityRef", Value::Binary(vec![0x33; 16])),
        ),
        ("missing actor_entity_ref", without("actor_entity_ref")),
        ("missing confidence", without("confidence")),
        (
            "missing supersession_status",
            without("supersession_status"),
        ),
        (
            "confidence NaN",
            replacing("confidence", Value::F32(f32::NAN)),
        ),
        ("confidence -0.1", replacing("confidence", Value::F64(-0.1))),
        ("confidence 1.1", replacing("confidence", Value::F64(1.1))),
        (
            "supersession_status 4",
            replacing("supersession_status", Value::from(4_u8)),
        ),
        (
            "supersession_status 255",
            replacing("supersession_status", Value::from(255_u8)),
        ),
        (
            "supersession_status negative",
            replacing("supersession_status", Value::from(-1_i64)),
        ),
        (
            "supersession_status as string",
            replacing("supersession_status", Value::from("proposed")),
        ),
        (
            "actor ref 15 bytes",
            replacing("actor_entity_ref", Value::Binary(vec![0x33; 15])),
        ),
        (
            "actor ref 17 bytes",
            replacing("actor_entity_ref", Value::Binary(vec![0x33; 17])),
        ),
        (
            "actor ref not binary",
            replacing("actor_entity_ref", Value::from("stringy")),
        ),
        (
            "actor ref reserved all-zero id",
            replacing("actor_entity_ref", Value::Binary(vec![0x00; 16])),
        ),
        (
            "source_revision_ref 17 bytes",
            with_extra("source_revision_ref", Value::Binary(vec![0x41; 17])),
        ),
        (
            "body_snapshot_ref 15 bytes",
            with_extra("body_snapshot_ref", Value::Binary(vec![0x42; 15])),
        ),
        (
            "valid_from negative",
            with_extra("valid_from", Value::from(-5_i64)),
        ),
        (
            "valid_to not an integer",
            with_extra("valid_to", Value::from("soon")),
        ),
        ("duplicate key", {
            let mut entries = base();
            entries.push((Value::from("confidence"), Value::F32(0.9)));
            Value::Map(entries)
        }),
        ("valid_from exceeds valid_to", {
            let mut entries = base();
            entries.push((Value::from("valid_from"), Value::from(200_u64)));
            entries.push((Value::from("valid_to"), Value::from(100_u64)));
            Value::Map(entries)
        }),
        // ── ONE-1138 vocabulary bump: substrate_ref ──
        (
            "substrate_ref 15 bytes",
            with_extra("substrate_ref", Value::Binary(vec![0x43; 15])),
        ),
        (
            "substrate_ref 17 bytes",
            with_extra("substrate_ref", Value::Binary(vec![0x43; 17])),
        ),
        (
            "substrate_ref not binary",
            with_extra("substrate_ref", Value::from("mo1")),
        ),
        (
            "substrate_ref reserved all-zero id",
            with_extra("substrate_ref", Value::Binary(vec![0x00; 16])),
        ),
        ("substrate_ref duplicate", {
            let mut entries = base();
            entries.push((Value::from("substrate_ref"), Value::Binary(vec![0x43; 16])));
            entries.push((Value::from("substrate_ref"), Value::Binary(vec![0x44; 16])));
            Value::Map(entries)
        }),
        (
            "unknown camelCase substrateRef still rejected post-bump",
            with_extra("substrateRef", Value::Binary(vec![0x43; 16])),
        ),
        // ── ONE-1138 vocabulary bump: reasoning_effort ──
        (
            "reasoning_effort not a string",
            with_extra("reasoning_effort", Value::from(2_u8)),
        ),
        (
            "reasoning_effort empty string",
            with_extra("reasoning_effort", Value::from("")),
        ),
        (
            "reasoning_effort 33 bytes (over the 32-byte cap)",
            with_extra("reasoning_effort", Value::from("x".repeat(33).as_str())),
        ),
        // ── ONE-1138 vocabulary bump: actor_class body key ──
        (
            "actor_class 3 (above system=2)",
            with_extra("actor_class", Value::from(3_u8)),
        ),
        (
            "actor_class 255",
            with_extra("actor_class", Value::from(255_u8)),
        ),
        (
            "actor_class negative",
            with_extra("actor_class", Value::from(-1_i64)),
        ),
        (
            "actor_class as string",
            with_extra("actor_class", Value::from("human")),
        ),
    ];

    for (name, value) in cases {
        let err = decode_edge_provenance_body(&value)
            .expect_err(&format!("case {name}: decode must be rejected"));
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidProvenanceBody,
            "case {name}: got {err:?}"
        );
    }

    // The valid base decodes — proving the matrix rejects for the stated
    // reason, not because the scaffold is broken.
    decode_edge_provenance_body(&Value::Map(base())).expect("base case must decode");
}

#[test]
fn validate_edge_provenance_value_rejects_invalid_records() {
    let invalid = Value::Map(vec![
        (Value::from("confidence"), Value::F32(0.5)),
        (Value::from("supersession_status"), Value::from(0_u8)),
    ]);
    let err = validate_edge_provenance_value(&invalid)
        .expect_err("validator wrapper must reject malformed value records");
    assert_eq!(err.kind(), ErrorKind::InvalidProvenanceBody);
}

#[test]
fn derive_confirmation_status_is_identity_mirror() {
    // The pinned {0,1,2,3} identity mirror (contracts.ts
    // derivesEdgeFlags[0]) — both the variant mapping and the numeric
    // values are asserted so a permuted mapping fails.
    let cases = [
        (
            SupersessionStatus::Proposed,
            EdgeConfirmationStatus::Proposed,
            0_u8,
        ),
        (
            SupersessionStatus::Confirmed,
            EdgeConfirmationStatus::Confirmed,
            1,
        ),
        (
            SupersessionStatus::Disputed,
            EdgeConfirmationStatus::Disputed,
            2,
        ),
        (
            SupersessionStatus::Retracted,
            EdgeConfirmationStatus::Retracted,
            3,
        ),
    ];
    for (status, expected_flag, byte) in cases {
        assert_eq!(status as u8, byte);
        let derived = derive_confirmation_status(status);
        assert_eq!(derived, expected_flag);
        assert_eq!(derived as u8, byte);
    }
}

#[test]
fn validate_actor_class_pins_d13_matrix() {
    // PERSON (type byte 4) → {human=0, agent=1}.
    validate_actor_class(4, EdgeActorClass::Human).expect("PERSON+human");
    validate_actor_class(4, EdgeActorClass::Agent).expect("PERSON+agent");
    // MACHINE (type byte 82) → {system=2}.
    validate_actor_class(82, EdgeActorClass::System).expect("MACHINE+system");

    let rejected = [
        (4_u8, EdgeActorClass::System, 2_u8),
        (82, EdgeActorClass::Human, 0),
        (82, EdgeActorClass::Agent, 1),
        // Non-actor kinds never derive a class — typed error, no default.
        (0, EdgeActorClass::Human, 0),    // CLAIM
        (1, EdgeActorClass::System, 2),   // TURN
        (12, EdgeActorClass::Agent, 1),   // ORG
        (120, EdgeActorClass::System, 2), // REDACTION_AUDIT
        (200, EdgeActorClass::System, 2), // unregistered byte
    ];
    for (actor_type, class, class_byte) in rejected {
        let err = validate_actor_class(actor_type, class)
            .expect_err("mismatched actor class must be rejected");
        let Error::ActorClassMismatch {
            actor_entity_type,
            actor_class,
        } = err
        else {
            panic!("expected ActorClassMismatch, got {err:?}");
        };
        assert_eq!(actor_entity_type, actor_type);
        assert_eq!(actor_class, class_byte);
    }
}

#[test]
fn winner_ordering_pins_d14_precedence() {
    let precedence = |learned_at, confidence, id_byte: u8| ProvenancePrecedence {
        learned_at,
        confidence,
        claim_id: entity(id_byte),
    };

    // Empty slate → no winner.
    assert_eq!(winner_index(&[]), None);

    // learned_at DOMINATES confidence: t=2000/conf 0.1 beats
    // t=1000/conf 0.9 — a confidence-first implementation fails here.
    let by_learned = [precedence(1000, 0.9, 0x01), precedence(2000, 0.1, 0x02)];
    assert_eq!(winner_index(&by_learned), Some(1));

    // Confidence breaks learned_at ties.
    let by_confidence = [
        precedence(2000, 0.4, 0x01),
        precedence(2000, 0.6, 0x02),
        precedence(2000, 0.5, 0x03),
    ];
    assert_eq!(winner_index(&by_confidence), Some(1));

    // Full (learned_at, confidence) tie → greatest claim-id bytes win
    // (engine-defined determinism; order-of-input must not matter).
    let by_id = [precedence(2000, 0.5, 0x09), precedence(2000, 0.5, 0x04)];
    assert_eq!(winner_index(&by_id), Some(0));
    let by_id_reversed = [precedence(2000, 0.5, 0x04), precedence(2000, 0.5, 0x09)];
    assert_eq!(winner_index(&by_id_reversed), Some(1));
}

#[test]
fn close_and_retract_record_transforms_pin_window_rules() {
    let open = EdgeProvenanceClaimBody::new(entity(0x31), 0.7, SupersessionStatus::Confirmed);

    // SUPERSEDE close: absent valid_to → set to close_at; status untouched.
    let closed = close_record_for_supersession(&open, 2000).expect("close open record");
    assert_eq!(closed.valid_to, Some(2000));
    assert_eq!(closed.supersession_status, SupersessionStatus::Confirmed);

    // SUPERSEDE close: an explicit valid_to is PRESERVED, never extended.
    let mut bounded = open.clone();
    bounded.valid_from = Some(100);
    bounded.valid_to = Some(200);
    let closed = close_record_for_supersession(&bounded, 5000).expect("close bounded record");
    assert_eq!(closed.valid_to, Some(200), "explicit window must survive");

    // SUPERSEDE close: future-dated valid_from inverts the window → typed.
    let mut future = open;
    future.valid_from = Some(9000);
    assert_matches!(
        close_record_for_supersession(&future, 2000),
        Err(Error::InvalidProvenanceBody(_))
    );

    // RETRACT: status = retracted AND valid_to = now, OVERWRITING an
    // explicit valid_to (deliberate withdrawal at `now`).
    let retracted = retract_record(&bounded, 3000).expect("retract bounded record");
    assert_eq!(retracted.supersession_status, SupersessionStatus::Retracted);
    assert_eq!(retracted.valid_to, Some(3000));
    assert_eq!(retracted.valid_from, Some(100), "valid_from untouched");

    // RETRACT before valid_from → typed, never reordered.
    assert_matches!(
        retract_record(&future, 2000),
        Err(Error::InvalidProvenanceBody(_))
    );
}

#[test]
fn actor_class_evidence_codec_fail_closed() {
    for (class, byte) in [
        (EdgeActorClass::Human, 0_u8),
        (EdgeActorClass::Agent, 1),
        (EdgeActorClass::System, 2),
    ] {
        let evidence = encode_actor_class_evidence(class);
        // Pinned shape: exactly {"actor_class": <u8>}.
        let Value::Map(entries) = &evidence else {
            panic!("evidence must be a map");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.as_str(), Some("actor_class"));
        assert_eq!(entries[0].1.as_u64(), Some(u64::from(byte)));
        assert_eq!(
            decode_actor_class_evidence(Some(&evidence)).expect("round trip"),
            class
        );
    }

    // Fail-closed: missing, wrong shape, out-of-range byte, unknown key,
    // duplicate key — each a typed InvalidProvenanceBody, never a default.
    let cases: Vec<Option<Value>> = vec![
        None,
        Some(Value::from(0_u8)),
        Some(Value::Map(vec![])),
        Some(Value::Map(vec![(
            Value::from("actor_class"),
            Value::from(3_u8),
        )])),
        Some(Value::Map(vec![(
            Value::from("actor_class"),
            Value::from("human"),
        )])),
        Some(Value::Map(vec![(
            Value::from("actorClass"),
            Value::from(0_u8),
        )])),
        Some(Value::Map(vec![
            (Value::from("actor_class"), Value::from(0_u8)),
            (Value::from("actor_class"), Value::from(1_u8)),
        ])),
    ];
    for case in &cases {
        assert!(
            matches!(
                decode_actor_class_evidence(case.as_ref()),
                Err(Error::InvalidProvenanceBody(_))
            ),
            "case {case:?} must be rejected"
        );
    }
}

#[test]
fn resolve_persisted_actor_class_pins_transition_matrix() {
    // ONE-1138 transition semantics, pinned: body-only (new shape) wins;
    // evid-only (legacy pre-bump shape) still decodes — old claims are
    // never invalidated; BOTH → ambiguous, fail closed; NEITHER → fail
    // closed (the old shape required the class on every claim, so a
    // new-shape claim without it is invalid — never defaulted, D13).
    let mut new_shape =
        EdgeProvenanceClaimBody::new(entity(0x31), 0.5, SupersessionStatus::Proposed);
    new_shape.actor_class = Some(EdgeActorClass::Agent);
    let legacy_shape =
        EdgeProvenanceClaimBody::new(entity(0x31), 0.5, SupersessionStatus::Proposed);
    let legacy_evidence = encode_actor_class_evidence(EdgeActorClass::System);

    // New shape: the body key is authoritative.
    assert_eq!(
        resolve_persisted_actor_class(&new_shape, None).expect("new shape resolves"),
        EdgeActorClass::Agent
    );
    // Legacy shape: the evid map is decoded with unchanged validation.
    assert_eq!(
        resolve_persisted_actor_class(&legacy_shape, Some(&legacy_evidence))
            .expect("legacy shape resolves"),
        EdgeActorClass::System
    );
    // Both places → ambiguity, typed reject — even when the two values
    // AGREE (two sources of truth are never reconciled silently).
    let agreeing_evidence = encode_actor_class_evidence(EdgeActorClass::Agent);
    for evidence in [&legacy_evidence, &agreeing_evidence] {
        assert_matches!(
            resolve_persisted_actor_class(&new_shape, Some(evidence)),
            Err(Error::InvalidProvenanceBody(_))
        );
    }
    // Neither place → typed reject, never a defaulted class.
    assert_matches!(
        resolve_persisted_actor_class(&legacy_shape, None),
        Err(Error::InvalidProvenanceBody(_))
    );
}

// ── ONE-1936: stale-attest guard on edge-provenance wrappers ─────────────
//
// Provenance wrappers are not chained by `Supersedes`; their current head is
// the D14 cohort winner. These rows pin that the guard reports THAT head, and
// that a fully-closed cohort names the target itself rather than inventing a
// successor.

fn provenance_guard_fixture() -> (tempfile::TempDir, Vault, EdgeRef, EntityId) {
    let (temp, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let actor = entity(0x5A);
    let source = entity(0x5B);
    let target = entity(0x5C);
    for id in [actor, source, target] {
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"provenance fixture",
            )
            .expect("seed entity");
    }
    vault
        .put_edge(&source, EdgeKind::Mentions, &target, 0.5)
        .expect("seed semantic edge");
    (
        temp,
        vault,
        EdgeRef::new(source, EdgeKind::Mentions, target),
        actor,
    )
}

#[test]
fn stale_attest_target_reports_the_active_cohort_winner() -> Result<()> {
    let (_temp, vault, subject, actor) = provenance_guard_fixture();
    let prior = entity(0x5D);
    let winner = entity(0x5E);

    vault.put_edge_provenance(
        &prior,
        &subject,
        &EdgeProvenanceClaimBody::new(actor, 0.5, SupersessionStatus::Proposed),
        EdgeActorClass::Human,
        100,
    )?;
    // A live target passes straight through — no side lookup, no version field.
    vault.require_named_provenance_target_active(&prior)?;

    // The D14 winner closes the prior wrapper.
    vault.supersede_edge_provenance(
        &prior,
        &winner,
        &subject,
        &EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        200,
    )?;

    let err = vault
        .require_named_provenance_target_active(&prior)
        .expect_err("the named wrapper is no longer the cohort head");
    assert_eq!(err.kind(), ErrorKind::WriteVerbTargetStale);
    let Error::WriteVerbTargetStale {
        target,
        lifecycle,
        successor_short_id,
    } = err
    else {
        panic!("expected a typed stale-target refusal");
    };
    assert_eq!(target, prior);
    assert_eq!(lifecycle, ClaimLifecycleStatus::Superseded);
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        successor_short_id,
        vault.claim_short_ref_in(&rtxn, &winner)?,
        "the reported head is the live D14 cohort winner"
    );
    drop(rtxn);
    Ok(())
}

#[test]
fn stale_attest_with_fully_closed_cohort_names_the_target_itself() -> Result<()> {
    let (_temp, vault, subject, actor) = provenance_guard_fixture();
    let only = entity(0x5F);

    vault.put_edge_provenance(
        &only,
        &subject,
        &EdgeProvenanceClaimBody::new(actor, 0.5, SupersessionStatus::Proposed),
        EdgeActorClass::Human,
        100,
    )?;
    vault.retract_edge_provenance(&only, 200)?;

    let err = vault
        .require_named_provenance_target_active(&only)
        .expect_err("a retracted wrapper is stale");
    let Error::WriteVerbTargetStale {
        target,
        lifecycle,
        successor_short_id,
    } = err
    else {
        panic!("expected a typed stale-target refusal");
    };
    assert_eq!(target, only);
    assert_eq!(lifecycle, ClaimLifecycleStatus::Retracted);
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        successor_short_id,
        vault.claim_short_ref_in(&rtxn, &only)?,
        "no live wrapper remains, so the target is its own terminal head"
    );
    Ok(())
}

#[test]
fn stale_attest_with_closed_cohort_reports_the_newest_closed_wrapper() -> Result<()> {
    let (_temp, vault, subject, actor) = provenance_guard_fixture();
    let prior = entity(0x61);
    let winner = entity(0x62);

    vault.put_edge_provenance(
        &prior,
        &subject,
        &EdgeProvenanceClaimBody::new(actor, 0.5, SupersessionStatus::Proposed),
        EdgeActorClass::Human,
        100,
    )?;
    vault.supersede_edge_provenance(
        &prior,
        &winner,
        &subject,
        &EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        200,
    )?;
    // The wrapper that replaced `prior` is itself withdrawn. No LIVE member is
    // left, but "no live winner" is not "no newer wrapper": `winner` is still
    // the newest wrapper and still the stamp the edge carries.
    vault.retract_edge_provenance(&winner, 300)?;

    let err = vault
        .require_named_provenance_target_active(&prior)
        .expect_err("the named wrapper is still stale");
    let Error::WriteVerbTargetStale {
        lifecycle,
        successor_short_id,
        ..
    } = err
    else {
        panic!("expected a typed stale-target refusal");
    };
    assert_eq!(lifecycle, ClaimLifecycleStatus::Superseded);
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        successor_short_id,
        vault.claim_short_ref_in(&rtxn, &winner)?,
        "a superseded target names the newest wrapper, never itself"
    );
    assert_ne!(successor_short_id, vault.claim_short_ref_in(&rtxn, &prior)?);
    Ok(())
}

#[test]
fn active_cohort_winner_short_ref_is_none_for_a_closed_cohort() -> Result<()> {
    let (_temp, vault, subject, actor) = provenance_guard_fixture();
    let only = entity(0x59);

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        active_cohort_winner_short_ref_in(&vault, &rtxn, &subject)?,
        None,
        "an edge with no provenance wrapper at all has no head"
    );
    drop(rtxn);

    vault.put_edge_provenance(
        &only,
        &subject,
        &EdgeProvenanceClaimBody::new(actor, 0.5, SupersessionStatus::Proposed),
        EdgeActorClass::Human,
        100,
    )?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        active_cohort_winner_short_ref_in(&vault, &rtxn, &subject)?,
        Some(vault.claim_short_ref_in(&rtxn, &only)?)
    );
    drop(rtxn);

    vault.retract_edge_provenance(&only, 200)?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        active_cohort_winner_short_ref_in(&vault, &rtxn, &subject)?,
        None,
        "a fully closed cohort is a legitimate end state, not corruption"
    );
    Ok(())
}
