use super::*;
use crate::Vault;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::{WriteActor, WriteEnvelope};
use core::assert_matches;
use rmpv::Value;

#[test]
fn psych_mirror_selection_affect_trigger_contributes_affect_salience() -> Result<()> {
    let affected_person = EntityId::from_bytes([0x44; 16]).expect("valid id");
    let trigger_ref = EntityId::from_bytes([0x45; 16]).expect("valid id");
    let value = crate::affect::AffectTriggerValue::new(
        affected_person,
        trigger_ref,
        crate::affect::VadDelta::new(-1.0, 0.5, -0.5)?,
        0.8,
        2,
        4,
    )?;
    let mut body = ClaimBody::new(
        crate::affect::AFFECT_TRIGGER_PREDICATE,
        ClaimSubject::Entity(affected_person),
        crate::affect::affect_trigger_value(&value),
        value.confidence(),
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.salience = Some(0.3);

    let affect_salience = psych_mirror_claim_affect_salience(&body)?;

    assert!((affect_salience - 0.4).abs() < 1e-6);
    Ok(())
}

#[test]
fn psych_mirror_selection_affect_trigger_decode_errors_propagate() {
    let affected_person = EntityId::from_bytes([0x46; 16]).expect("valid id");
    let body = ClaimBody::new(
        crate::affect::AFFECT_TRIGGER_PREDICATE,
        ClaimSubject::Entity(affected_person),
        Value::from("malformed affect trigger"),
        0.8,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );

    assert!(psych_mirror_claim_affect_salience(&body).is_err());
}

#[test]
fn predicate_grammar_accepts_well_formed_unknown_predicates() {
    for predicate in [
        "hobby.collects",
        "profile.lives_in",
        "goal.learning_v2",
        "a.b.c",
    ] {
        validate_predicate(predicate, false).expect("well-formed predicate must pass");
    }
}

#[test]
fn registered_predicates_carry_layer_prefix() {
    assert_eq!(
        PREDICATE_LAYER_NAMESPACES,
        [
            PREDICATE_NAMESPACE_CORE,
            PREDICATE_NAMESPACE_COMPANION,
            PREDICATE_NAMESPACE_EIRI,
            PREDICATE_NAMESPACE_COMMITMENT
        ]
    );

    for predicate in CLAIM_PREDICATE_REGISTRY {
        validate_predicate(predicate, false).expect("registered predicate must be valid");
        let layer = predicate
            .split('.')
            .next()
            .expect("valid predicate must have a first segment");
        assert!(
            PREDICATE_LAYER_NAMESPACES.contains(&layer),
            "{predicate} must start with core.*, companion.*, eiri.*, or commitment.*"
        );
    }
}

#[test]
fn predicate_grammar_rejects_violations_typed() {
    // Single segment.
    assert_matches!(
        validate_predicate("profile", false),
        Err(Error::InvalidPredicate { .. })
    );
    // Uppercase.
    assert_matches!(
        validate_predicate("Edge.Provenance", false),
        Err(Error::InvalidPredicate { .. })
    );
    // Empty segment.
    assert_matches!(
        validate_predicate("profile.", false),
        Err(Error::InvalidPredicate { .. })
    );
    // Segment starting with digit / underscore.
    assert_matches!(
        validate_predicate("profile.9lives", false),
        Err(Error::InvalidPredicate { .. })
    );
    assert_matches!(
        validate_predicate("profile._hidden", false),
        Err(Error::InvalidPredicate { .. })
    );
    // Non-ASCII.
    assert_matches!(
        validate_predicate("profilé.name", false),
        Err(Error::InvalidPredicate { .. })
    );
}

#[test]
fn predicate_length_gate_is_128_bytes_inclusive() {
    // 2 segments: "a." + 126 'b's = exactly 128 bytes — accepted.
    let at_limit = format!("a.{}", "b".repeat(126));
    assert_eq!(at_limit.len(), 128);
    validate_predicate(&at_limit, false).expect("128-byte predicate must pass");

    let over_limit = format!("a.{}", "b".repeat(127));
    assert_eq!(over_limit.len(), 129);
    assert_matches!(
        validate_predicate(&over_limit, false),
        Err(Error::InvalidPredicate { .. })
    );
}

#[test]
fn claim_source_parse_accepts_inferred_and_imported_wire_values() {
    for (wire, source) in [
        ("inferred", ClaimSource::Inferred),
        ("imported", ClaimSource::Imported),
    ] {
        assert_eq!(ClaimSource::parse(wire), Some(source), "{wire}");
        assert_eq!(source.as_str(), wire, "{wire} round-trip literal");
    }
}

#[test]
fn lexical_query_hint_cap_ignores_oversize_tail_entries() -> Result<()> {
    let overlong = "x".repeat(MAX_LEXICAL_QUERY_HINT_BYTES + 1);
    let hints = vec![
        "hint zero",
        "hint one",
        "hint two",
        "hint three",
        "hint four",
        "hint five",
        "hint six",
        "hint seven",
        overlong.as_str(),
    ];

    let normalized = normalize_lexical_query_hints(&hints)?;
    assert_eq!(normalized.len(), MAX_LEXICAL_QUERY_HINTS_PER_CLAIM);
    assert!(!normalized.iter().any(|hint| hint == &overlong));
    Ok(())
}

#[test]
fn write_door_validates_lexical_query_hint_claim_structure() -> Result<()> {
    let target = EntityId::from_bytes([0x60; 16]).expect("valid id");
    let other = EntityId::from_bytes([0x22; 16]).expect("valid id");
    let encode = |subject: EntityId, value: Value| -> Result<Vec<u8>> {
        let body = ClaimBody::new(
            PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(subject),
            value,
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        encode_claim_body(&body)
    };

    validate_claim_body_bytes(
        &encode(
            target,
            encode_lexical_query_hint_value(&target, "future migration question"),
        )?,
        false,
    )?;

    assert_matches!(
        validate_claim_body_bytes(&encode(target, Value::from("not a hint map"))?, false),
        Err(Error::InvalidClaimBody(_))
    );
    assert_matches!(
        validate_claim_body_bytes(
            &encode(
                other,
                encode_lexical_query_hint_value(&target, "future migration question"),
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody(_))
    );
    Ok(())
}

#[test]
fn write_door_validates_companion_expression_claim_values() -> Result<()> {
    let subject = EntityId::from_bytes([0x33; 16]).expect("valid id");
    let encode = |value: Value| -> Result<Vec<u8>> {
        let body = ClaimBody::new(
            PREDICATE_COMPANION_EXPRESSION,
            ClaimSubject::Entity(subject),
            value,
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        encode_claim_body(&body)
    };

    for expression in [
        COMPANION_EXPRESSION_PROFESSIONAL,
        COMPANION_EXPRESSION_WARM,
        COMPANION_EXPRESSION_UNRESTRICTED,
    ] {
        validate_claim_body_bytes(&encode(Value::from(expression))?, false)?;
    }

    assert_matches!(
        validate_claim_body_bytes(&encode(Value::from("future_closed"))?, false),
        Err(Error::InvalidClaimBody(
            "expression must be professional|warm|unrestricted"
        ))
    );
    assert_matches!(
        validate_claim_body_bytes(&encode(Value::Map(Vec::new()))?, false),
        Err(Error::InvalidClaimBody(
            "companion.expression value must be a string"
        ))
    );
    Ok(())
}

#[test]
fn affect_trigger_write_door_validates_value_shape() -> Result<()> {
    let affected_person = EntityId::from_bytes([0x44; 16]).expect("valid id");
    let trigger_ref = EntityId::from_bytes([0x45; 16]).expect("valid id");
    let value = crate::affect::AffectTriggerValue::new(
        affected_person,
        trigger_ref,
        crate::affect::VadDelta::new(-0.4, 0.2, -0.1)?,
        0.82,
        3,
        12,
    )?;
    let encode_with_confidence =
        |subject: ClaimSubject, value: Value, confidence: f32| -> Result<Vec<u8>> {
            let body = ClaimBody::new(
                crate::affect::AFFECT_TRIGGER_PREDICATE,
                subject,
                value,
                confidence,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            );
            encode_claim_body(&body)
        };
    let encode = |subject: ClaimSubject, value: Value| -> Result<Vec<u8>> {
        encode_with_confidence(subject, value, 0.82)
    };
    let duplicate_top_level_value = || {
        let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
            panic!("affect.trigger value is a map");
        };
        entries.push((Value::from("confidence"), Value::F32(value.confidence())));
        Value::Map(entries)
    };
    let duplicate_vad_delta_value = || {
        let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
            panic!("affect.trigger value is a map");
        };
        let Some((_, vad_delta)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("vadDelta"))
        else {
            panic!("affect.trigger value has vadDelta");
        };
        let Value::Map(vad_entries) = vad_delta else {
            panic!("vadDelta value is a map");
        };
        vad_entries.push((Value::from("arousal"), Value::F32(0.2)));
        Value::Map(entries)
    };
    let f64_arousal_rounded_into_range_value = || {
        let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
            panic!("affect.trigger value is a map");
        };
        let Some((_, vad_delta)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("vadDelta"))
        else {
            panic!("affect.trigger value has vadDelta");
        };
        let Value::Map(vad_entries) = vad_delta else {
            panic!("vadDelta value is a map");
        };
        let Some((_, arousal)) = vad_entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("arousal"))
        else {
            panic!("vadDelta value has arousal");
        };
        *arousal = Value::F64(1.0_f64 + f64::EPSILON);
        Value::Map(entries)
    };
    let impossible_trigger_count_value = || {
        let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
            panic!("affect.trigger value is a map");
        };
        let Some((_, k)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("k"))
        else {
            panic!("affect.trigger value has k");
        };
        *k = Value::from(13_u64);
        Value::Map(entries)
    };
    let integer_vad_delta_value = || {
        let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
            panic!("affect.trigger value is a map");
        };
        let Some((_, vad_delta)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("vadDelta"))
        else {
            panic!("affect.trigger value has vadDelta");
        };
        let Value::Map(vad_entries) = vad_delta else {
            panic!("vadDelta value is a map");
        };
        for (_, component) in vad_entries {
            *component = Value::from(0_i64);
        }
        Value::Map(entries)
    };

    validate_claim_body_bytes(
        &encode(
            ClaimSubject::Entity(affected_person),
            crate::affect::affect_trigger_value(&value),
        )?,
        false,
    )?;
    for (k, observed_n) in [(0, 1), (1, 1), (12, 12)] {
        let boundary_value = crate::affect::AffectTriggerValue::new(
            affected_person,
            trigger_ref,
            crate::affect::VadDelta::new(-0.4, 0.2, -0.1)?,
            0.82,
            k,
            observed_n,
        )?;
        validate_claim_body_bytes(
            &encode(
                ClaimSubject::Entity(affected_person),
                crate::affect::affect_trigger_value(&boundary_value),
            )?,
            false,
        )?;
    }

    assert_matches!(
        validate_claim_body_bytes(
            &encode(
                ClaimSubject::Entity(trigger_ref),
                crate::affect::affect_trigger_value(&value),
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody(
            "affect.trigger affectedPerson must match subject"
        ))
    );
    assert_matches!(
        validate_claim_body_bytes(
            &encode(
                ClaimSubject::Entity(affected_person),
                Value::Map(Vec::new())
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody(_))
    );
    assert_matches!(
        validate_claim_body_bytes(
            &encode(
                ClaimSubject::Entity(affected_person),
                impossible_trigger_count_value()
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody("k must not exceed observedN"))
    );
    let legacy_impossible_count_value = impossible_trigger_count_value();
    let legacy_trigger =
        crate::affect::decode_affect_trigger_value(&legacy_impossible_count_value)?;
    assert_eq!(legacy_trigger.k(), 13);
    assert_eq!(legacy_trigger.observed_n(), 12);
    let legacy_body = ClaimBody::new(
        crate::affect::AFFECT_TRIGGER_PREDICATE,
        ClaimSubject::Entity(affected_person),
        legacy_impossible_count_value,
        0.82,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let legacy_salience = psych_mirror_claim_affect_salience(&legacy_body)?;
    assert!(legacy_salience.is_finite());
    validate_claim_body_bytes(
        &encode(
            ClaimSubject::Entity(affected_person),
            integer_vad_delta_value(),
        )?,
        false,
    )?;
    assert_matches!(
        validate_claim_body_bytes(
            &encode_with_confidence(
                ClaimSubject::Entity(affected_person),
                crate::affect::affect_trigger_value(&value),
                0.81
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody(
            "affect.trigger wrapper confidence must mirror value confidence"
        ))
    );
    assert_matches!(
        validate_claim_body_bytes(
            &encode(
                ClaimSubject::Entity(affected_person),
                duplicate_top_level_value()
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody(
            "duplicate affect.trigger value key"
        ))
    );
    assert_matches!(
        validate_claim_body_bytes(
            &encode(
                ClaimSubject::Entity(affected_person),
                duplicate_vad_delta_value()
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody("duplicate vadDelta value key"))
    );
    assert_matches!(
        validate_claim_body_bytes(
            &encode(
                ClaimSubject::Entity(affected_person),
                f64_arousal_rounded_into_range_value()
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody(
            "vadDelta arousal must be finite in [-1, 1]"
        ))
    );
    Ok(())
}

#[test]
fn conflict_predicates_validate_as_ordinary_claims() -> Result<()> {
    let subject = EntityId::from_bytes([0x46; 16]).expect("valid id");
    let encode = |predicate: &str, subject: ClaimSubject, value: Value| -> Result<Vec<u8>> {
        let body = ClaimBody::new(
            predicate,
            subject,
            value,
            0.7,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Superseded,
        );
        encode_claim_body(&body)
    };

    validate_claim_body_bytes(
        &encode(
            PREDICATE_CONFLICT_OPEN,
            ClaimSubject::Entity(subject),
            Value::from("two active interpretations disagree"),
        )?,
        false,
    )?;
    validate_claim_body_bytes(
        &encode(
            PREDICATE_CONFLICT_RESOLVED,
            ClaimSubject::Entity(subject),
            Value::from("resolved by newer observation"),
        )?,
        false,
    )?;

    assert_matches!(
        validate_claim_body_bytes(
            &encode(
                PREDICATE_CONFLICT_OPEN,
                ClaimSubject::Entity(subject),
                Value::Nil,
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody(
            "conflict claim value must not be nil"
        ))
    );
    assert_matches!(
        validate_claim_body_bytes(
            &encode(
                PREDICATE_CONFLICT_RESOLVED,
                ClaimSubject::Edge {
                    source: EntityId::from_bytes([0x67; 16]).expect("valid id"),
                    kind: EdgeKind::Mentions,
                    target: EntityId::from_bytes([0x48; 16]).expect("valid id"),
                },
                Value::from("edge-scoped conflict"),
            )?,
            false,
        ),
        Err(Error::InvalidClaimBody(
            "conflict claim subject must be an entity"
        ))
    );
    Ok(())
}

#[test]
fn reserved_namespace_rejected_public_allowed_internal() {
    assert_matches!(
        validate_predicate("edge.provenance", false),
        Err(Error::ReservedPredicate { .. })
    );
    assert_matches!(
        validate_predicate("edge.anything_else", false),
        Err(Error::ReservedPredicate { .. })
    );
    assert_matches!(
        validate_predicate("skill.scan_verdict", false),
        Err(Error::ReservedPredicate { .. })
    );
    // The internal door allows the reserved namespace…
    validate_predicate("edge.provenance", true).expect("door must allow edge.*");
    validate_predicate("skill.scan_verdict", true).expect("door must allow skill.*");
    // …but grammar still applies through the door.
    assert_matches!(
        validate_predicate("Edge.Provenance", true),
        Err(Error::InvalidPredicate { .. })
    );
    // "edgework.x" is NOT in the reserved namespace (prefix is segment-exact).
    validate_predicate("edgework.tools", false).expect("edgework.* is not reserved");
}

#[test]
fn public_skill_claim_lifecycle_is_reserved_and_edge_stays_provenance_owned() -> Result<()> {
    let temp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(temp.path(), crate::VaultConfig::default())?;
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"subject",
    )?;

    let mut skill_body = ClaimBody::new(
        crate::skill_hub::PREDICATE_SKILL_SCAN_VERDICT,
        ClaimSubject::Entity(subject),
        Value::from("door-owned"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    skill_body.source = Some(ClaimSource::Observed);
    assert_matches!(
        vault.put_claim(
            &EntityId::now(),
            &skill_body,
            TimeRange { start: 2, end: 2 },
            2,
        ),
        Err(Error::ReservedPredicate { .. })
    );

    let old_skill_id = EntityId::now();
    let new_skill_id = EntityId::now();
    let mut wtxn = vault.store.env.write_txn()?;
    vault.put_reserved_claim_in_txn(
        &mut wtxn,
        &old_skill_id,
        &skill_body,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    vault.put_reserved_claim_in_txn(
        &mut wtxn,
        &new_skill_id,
        &skill_body,
        TimeRange { start: 3, end: 3 },
        3,
    )?;
    wtxn.commit()?;

    assert_matches!(
        vault.supersede_claim(&new_skill_id, &old_skill_id, 4),
        Err(Error::ProvenanceClaimLifecycle { .. })
    );
    assert_matches!(
        vault.retract_claim(&old_skill_id, 4),
        Err(Error::ProvenanceClaimLifecycle { .. })
    );

    let mut edge_body = ClaimBody::new(
        "edge.internal_record",
        ClaimSubject::Entity(subject),
        Value::from("provenance-owned"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    edge_body.source = Some(ClaimSource::Observed);
    let old_edge_id = EntityId::now();
    let new_edge_id = EntityId::now();
    let mut wtxn = vault.store.env.write_txn()?;
    vault.put_reserved_claim_in_txn(
        &mut wtxn,
        &old_edge_id,
        &edge_body,
        TimeRange { start: 5, end: 5 },
        5,
    )?;
    vault.put_reserved_claim_in_txn(
        &mut wtxn,
        &new_edge_id,
        &edge_body,
        TimeRange { start: 6, end: 6 },
        6,
    )?;
    assert_matches!(
        vault.supersede_reserved_claim_in_txn(&mut wtxn, &new_edge_id, &old_edge_id, 7),
        Err(Error::ProvenanceClaimLifecycle { .. })
    );
    Ok(())
}

/// ONE-1159 — the write-door chokepoint ([`validate_claim_body_bytes`],
/// shared by `put_reserved_claim` AND both `put_replicated` builders via
/// `apply_put`) runs FULL structural validation on `edge.provenance`
/// Claims: pinned value-record shape + persisted actor-class evidence,
/// typed `InvalidProvenanceBody` rejections. Forged cases are junk
/// SHAPES (never key-count assumptions), so each stays invalid under any
/// grown value-record vocabulary.
#[test]
fn write_door_validates_edge_provenance_claim_structure() {
    use crate::edge::EdgeActorClass;
    use crate::provenance::{
        EVIDENCE_KEY_ACTOR_CLASS, EdgeProvenanceClaimBody, SupersessionStatus,
        encode_actor_class_evidence, encode_edge_provenance_value,
    };

    let actor = EntityId::from_bytes([0x62; 16]).expect("valid id");
    // ONE-1159 fix-wave: a surfaceable wrapper's `conf` MUST mirror the
    // value-record `confidence`. The prior control hardcoded `0.9` ≠ the
    // record's `0.75` — a self-inconsistent "valid" wrapper the new mirror
    // check correctly rejects. Mirror both to one literal (fix the
    // control, not the assertion). The negative cases below all reject on
    // an EARLIER axis (value-record decode / actor-class), so the shared
    // `conf` value never weakens them.
    let confidence = 0.75_f32;
    let valid_value = || {
        encode_edge_provenance_value(&EdgeProvenanceClaimBody::new(
            actor,
            confidence,
            SupersessionStatus::Confirmed,
        ))
    };
    let evid = encode_actor_class_evidence(EdgeActorClass::Human);
    let subject = ClaimSubject::Edge {
        source: EntityId::from_bytes([0x60; 16]).expect("valid id"),
        kind: EdgeKind::Mentions,
        target: EntityId::from_bytes([0x22; 16]).expect("valid id"),
    };
    let encode = |predicate: &str, value: Value, evidence: Option<Value>| {
        let mut body = ClaimBody::new(
            predicate,
            subject,
            value,
            confidence,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = evidence;
        encode_claim_body(&body).expect("encode")
    };

    // Fully-valid legacy shape (value record + engine-owned evid map):
    // accepted through the reserved door.
    validate_claim_body_bytes(
        &encode("edge.provenance", valid_value(), Some(evid.clone())),
        true,
    )
    .expect("valid edge.provenance claim must pass the write door");

    let missing_actor = {
        let Value::Map(mut entries) = valid_value() else {
            unreachable!("encoder emits a map");
        };
        entries.retain(|(key, _)| key.as_str() != Some("actor_entity_ref"));
        Value::Map(entries)
    };
    let garbage_key = {
        let Value::Map(mut entries) = valid_value() else {
            unreachable!("encoder emits a map");
        };
        entries.push((Value::from("zzz"), Value::from(1_u8)));
        Value::Map(entries)
    };
    let class_in_value_record = {
        let Value::Map(mut entries) = valid_value() else {
            unreachable!("encoder emits a map");
        };
        entries.push((Value::from(EVIDENCE_KEY_ACTOR_CLASS), Value::from(0_u8)));
        Value::Map(entries)
    };

    let rejected: [(&str, Vec<u8>); 6] = [
        (
            "non-map value record",
            encode("edge.provenance", Value::from("junk"), Some(evid.clone())),
        ),
        (
            "value record missing required actor_entity_ref",
            encode("edge.provenance", missing_actor, Some(evid.clone())),
        ),
        (
            "unknown key zzz in value record",
            encode("edge.provenance", garbage_key, Some(evid.clone())),
        ),
        (
            "missing actor_class evidence entirely",
            encode("edge.provenance", valid_value(), None),
        ),
        (
            "malformed actor_class evidence (non-map evid)",
            encode("edge.provenance", valid_value(), Some(Value::from(7_u8))),
        ),
        // Rejected under BOTH vocabularies: today `actor_class` is not a
        // value-record key (unknown-key reject); once the vocabulary
        // carries it, body-key + evid together are the ambiguous
        // two-sources-of-truth shape (both-present reject).
        (
            "actor_class in both the value record and evid",
            encode("edge.provenance", class_in_value_record, Some(evid)),
        ),
    ];
    for (name, data) in rejected {
        assert!(
            matches!(
                validate_claim_body_bytes(&data, true),
                Err(Error::InvalidProvenanceBody(_))
            ),
            "{name}: must reject typed (InvalidProvenanceBody) at the write door"
        );
    }

    // Predicate-scoped: the structural branch fires on the pinned
    // edge.provenance literal only. Other reserved-namespace claims and
    // public claims keep their opaque D18 `val`.
    validate_claim_body_bytes(
        &encode("edge.other_records", Value::from("opaque"), None),
        true,
    )
    .expect("non-provenance reserved claim keeps opaque val");
    validate_claim_body_bytes(
        &encode("hobby.collects", Value::from("opaque"), None),
        false,
    )
    .expect("public claim keeps opaque val");
}

#[test]
fn claim_subject_decode_pins_both_encodings() {
    let id = EntityId::from_bytes([0x60; 16]).expect("valid id");
    assert_eq!(
        ClaimSubject::decode(id.as_bytes()).expect("16-byte subj"),
        ClaimSubject::Entity(id)
    );

    let source = EntityId::from_bytes([0x22; 16]).expect("valid id");
    let target = EntityId::from_bytes([0x33; 16]).expect("valid id");
    let mut edge_ref = Vec::new();
    edge_ref.extend_from_slice(source.as_bytes());
    edge_ref.push(9); // Mentions
    edge_ref.extend_from_slice(target.as_bytes());
    assert_eq!(
        ClaimSubject::decode(&edge_ref).expect("33-byte subj"),
        ClaimSubject::Edge {
            source,
            kind: EdgeKind::Mentions,
            target,
        }
    );

    // 17 bytes — neither encoding.
    assert_matches!(
        ClaimSubject::decode(&[0x44; 17]),
        Err(Error::InvalidClaimBody(_))
    );
    // 33 bytes with an unregistered kind byte.
    let mut bad_kind = edge_ref.clone();
    bad_kind[16] = 200;
    assert_matches!(
        ClaimSubject::decode(&bad_kind),
        Err(Error::InvalidClaimBody(_))
    );
    // Reserved entity-id bytes (all zero) rejected.
    assert_matches!(
        ClaimSubject::decode(&[0x00; 16]),
        Err(Error::InvalidClaimBody(_))
    );
}

/// ARCH-0004 / ARCH-0022 world write-validation, exercised on the claim
/// body chokepoint with hand-built MessagePack so a wrong impl that stores
/// arbitrary `world` bytes FAILS: a present `world` must be exactly 16
/// binary bytes (→ an `EntityId`), an absent key is base reality (`None`),
/// and a 15-byte blob or a string is a typed `InvalidClaimBody`.
#[test]
fn world_value_must_be_16_byte_binary() {
    let subj = EntityId::from_bytes([0x60; 16]).expect("valid subject id");
    let body_with_world = |world: Option<Value>| -> Vec<u8> {
        let mut entries = vec![
            (Value::from("pred"), Value::from("profile.name")),
            (Value::from("val"), Value::from("x")),
            (Value::from("conf"), Value::F32(1.0)),
        ];
        if let Some(world) = world {
            entries.push((Value::from("world"), world));
        }
        entries.push((Value::from("subj"), Value::Binary(subj.as_bytes().to_vec())));
        entries.push((Value::from("appr"), Value::from("auto")));
        entries.push((Value::from("life"), Value::from("active")));
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode body");
        out
    };

    // Exactly 16 binary bytes → an EntityId.
    let world_id = EntityId::from_bytes([0x5A; 16]).expect("valid world id");
    let good = body_with_world(Some(Value::Binary(world_id.as_bytes().to_vec())));
    assert_eq!(
        decode_claim_body(&good, false)
            .expect("16-byte world passes")
            .world,
        Some(world_id)
    );

    // Absent key = base reality (None), the elide-the-default pattern.
    let base = body_with_world(None);
    assert_eq!(
        decode_claim_body(&base, false)
            .expect("absent world passes")
            .world,
        None
    );

    // 15-byte blob rejected fail-closed.
    assert_matches!(
        decode_claim_body(&body_with_world(Some(Value::Binary(vec![0x5A; 15]))), false),
        Err(Error::InvalidClaimBody(_))
    );

    // String rejected fail-closed (the pre-fix opaque-bytes behavior).
    assert_matches!(
        decode_claim_body(&body_with_world(Some(Value::from("w0"))), false),
        Err(Error::InvalidClaimBody(_))
    );
}

#[test]
fn psych_profile_keeps_legacy_profile_claim_body_backward_compatible() {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x60; 16]).expect("valid id"));
    let mut legacy = ClaimBody::new(
        "profile.preference",
        subject,
        Value::from("prefers concise explanations"),
        0.72,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    legacy.source = Some(ClaimSource::Observed);
    legacy.stale = false;

    let encoded = encode_claim_body(&legacy).expect("legacy profile claim encodes");
    let decoded = decode_claim_body(&encoded, false).expect("legacy profile claim decodes");

    assert_eq!(decoded.predicate, "profile.preference");
    assert_eq!(decoded.value, Value::from("prefers concise explanations"));
    assert_eq!(decoded.source, Some(ClaimSource::Observed));
    assert!(!decoded.stale);
    assert_eq!(
        CLAIM_BODY_KEYS,
        [
            "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "rel", "subj",
            "scope", "appr", "life", "stale", "sess",
        ],
        "PsychProfile snapshots must preserve the pinned Claim body ABI"
    );
}

#[test]
fn claim_field_profile_slices_are_prefixes_of_the_pinned_keys() {
    assert_eq!(CLAIM_FIELDS_MINIMAL, &CLAIM_BODY_KEYS[..2]);
    assert_eq!(CLAIM_FIELDS_STANDARD, &CLAIM_BODY_KEYS[..5]);
    assert_eq!(CLAIM_FIELDS_FULL, &CLAIM_BODY_KEYS[..12]);
}

/// D19 literal truth table: `appr ∈ {auto, approved}` ∧ `life = active`
/// ∧ `stale = false` — every other combination is excluded (ARCH-0003;
/// ARCH-0004 §H items 1/2/4).
#[test]
fn claim_surfaceable_pins_the_full_status_truth_table() {
    use ClaimApprovalStatus as A;
    use ClaimLifecycleStatus as L;

    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x60; 16]).expect("valid id"));
    let body = |appr: ClaimApprovalStatus, life: ClaimLifecycleStatus, stale: bool| {
        let mut body = ClaimBody::new("test.pred", subject, Value::from("v"), 0.5, appr, life);
        body.stale = stale;
        body
    };

    // The ONLY surfaceable combinations.
    assert!(claim_surfaceable(&body(A::Auto, L::Active, false)));
    assert!(claim_surfaceable(&body(A::Approved, L::Active, false)));

    // Approval axis excludes independently of lifecycle (AC 3).
    assert!(!claim_surfaceable(&body(A::Proposed, L::Active, false)));
    assert!(!claim_surfaceable(&body(A::Rejected, L::Active, false)));

    // Lifecycle axis excludes independently of approval.
    assert!(!claim_surfaceable(&body(A::Auto, L::Superseded, false)));
    assert!(!claim_surfaceable(&body(A::Auto, L::Retracted, false)));
    assert!(!claim_surfaceable(&body(A::Approved, L::Superseded, false)));
    assert!(!claim_surfaceable(&body(A::Approved, L::Retracted, false)));

    // Staleness excludes even when both status axes pass (AC 1).
    assert!(!claim_surfaceable(&body(A::Auto, L::Active, true)));
    assert!(!claim_surfaceable(&body(A::Approved, L::Active, true)));

    // `ClaimBody::new` leaves `stale` at the decode default (absent =
    // false) — absence alone must not exclude (AC 4).
    assert!(claim_surfaceable(&ClaimBody::new(
        "test.pred",
        subject,
        Value::from("v"),
        0.5,
        A::Auto,
        L::Active,
    )));
}

#[test]
fn claim_consolidatable_excludes_auto_generated_until_vetted() {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x12; 16]).expect("valid id"));
    let mut body = ClaimBody::new(
        "test.pred",
        subject,
        Value::from("v"),
        0.5,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );

    body.source = Some(ClaimSource::Generated);
    assert!(
        claim_surfaceable(&body),
        "Auto/Generated claims still surface for read/review"
    );
    assert!(
        !claim_consolidatable(&body),
        "Auto/Generated claims are not authority-admissible"
    );

    body.approval = ClaimApprovalStatus::Approved;
    assert!(
        claim_consolidatable(&body),
        "vetted Generated claims are consolidatable"
    );

    body.approval = ClaimApprovalStatus::Auto;
    body.source = Some(ClaimSource::Inferred);
    assert!(
        claim_consolidatable(&body),
        "non-Generated surfaceable claims keep existing admission"
    );

    body.source = Some(ClaimSource::Imported);
    body.scope = Some(Value::Map(vec![(
        Value::from(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
        Value::from(ClaimSource::Generated.as_str()),
    )]));
    assert!(
        !claim_consolidatable(&body),
        "federated Generated origin remains authority-inadmissible after import restamp"
    );

    body.stale = true;
    assert!(
        !claim_consolidatable(&body),
        "consolidation preserves surfaceability's stale exclusion"
    );
}

#[test]
fn self_unconfirmed_not_consolidatable() -> Result<()> {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x18; 16]).expect("valid id"));
    let mut body = ClaimBody::new(
        "profile.preference",
        subject,
        Value::from("night owl"),
        0.8,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Generated);
    body.session_tag = Some("agent:alpha/session:42".to_owned());

    let encoded = encode_claim_body(&body)?;
    let decoded = decode_claim_body(&encoded, false)?;

    assert_eq!(
        decoded.session_tag.as_deref(),
        Some("agent:alpha/session:42")
    );
    assert!(
        !claim_consolidatable(&decoded),
        "an agent's own unconfirmed session proposal must stay outside consolidation"
    );
    Ok(())
}

#[test]
fn session_claim_producer_uses_envelope_actor_evidence_fail_closed() -> Result<()> {
    let producer = EntityId::from_bytes([0x19; 16]).expect("valid producer id");
    let envelope = WriteEnvelope::new(
        crate::write_envelope::WriteActor::new(producer, crate::edge::EdgeActorClass::Human),
        ClaimSource::Generated,
        crate::write_envelope::WriteProvenance::new(Value::from("session-producer-test"))?,
        ClaimApprovalStatus::Proposed,
    );
    let mut body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(EntityId::from_bytes([0x1A; 16]).expect("valid subject id")),
        Value::from("concise"),
        0.8,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.evidence = Some(crate::write_envelope::write_envelope_evidence(
        &envelope, None,
    ));

    assert_eq!(session_claim_producer(&body), Some(producer));

    body.evidence = Some(Value::Map(vec![
        (
            Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::Binary(producer.as_bytes().to_vec()),
        ),
        (
            Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::Binary(producer.as_bytes().to_vec()),
        ),
    ]));
    assert_eq!(
        session_claim_producer(&body),
        None,
        "duplicate producer stamps must not match a session bundle"
    );

    body.evidence = Some(Value::Map(vec![(
        Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
        Value::Binary(vec![0x19; 15]),
    )]));
    assert_eq!(
        session_claim_producer(&body),
        None,
        "malformed producer stamps must not match a session bundle"
    );
    Ok(())
}

/// GATE-11 (ONE-1391): generated origin is evidence-inadmissible regardless
/// of approval status; every non-generated source stays admissible.
#[test]
fn generated_not_evidence() {
    use ClaimApprovalStatus as A;

    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x14; 16]).expect("valid id"));
    let body = |source: Option<ClaimSource>, appr: ClaimApprovalStatus| {
        let mut body = ClaimBody::new(
            "test.pred",
            subject,
            Value::from("v"),
            0.5,
            appr,
            ClaimLifecycleStatus::Active,
        );
        body.source = source;
        body
    };

    // Declared Generated fails for EVERY approval status, including Approved.
    for appr in [A::Auto, A::Proposed, A::Approved, A::Rejected] {
        assert!(
            !claim_evidence_admissible(&body(Some(ClaimSource::Generated), appr)),
            "Generated claim with approval {appr:?} must not be evidence"
        );
    }

    // Imported restamp preserving a generated pre-restamp origin fails too.
    let mut restamped = body(Some(ClaimSource::Imported), A::Approved);
    restamped.scope = Some(Value::Map(vec![(
        Value::from(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
        Value::from(ClaimSource::Generated.as_str()),
    )]));
    assert!(
        !claim_evidence_admissible(&restamped),
        "federated Generated origin stays evidence-inadmissible after import restamp"
    );

    // Every non-generated source passes (Imported here = non-restamped).
    for source in [
        ClaimSource::UserStated,
        ClaimSource::Observed,
        ClaimSource::Inferred,
        ClaimSource::ToolOutput,
        ClaimSource::Imported,
    ] {
        assert!(
            claim_evidence_admissible(&body(Some(source), A::Auto)),
            "{source:?} claim must remain evidence-admissible"
        );
    }
}

/// GATE-11 (ONE-1391): corroboration counting over a mixed evidence set —
/// a Generated claim contributes ZERO boost even when Approved. Models the
/// ONE-1290 consumption contract: turn refs count; claim refs count iff
/// `claim_evidence_admissible`.
#[test]
fn no_self_corroboration() {
    enum EvidenceRef {
        Turn,
        Claim(Box<ClaimBody>),
    }
    let corroboration = |refs: &[EvidenceRef]| {
        refs.iter()
            .filter(|entry| match entry {
                EvidenceRef::Turn => true,
                EvidenceRef::Claim(body) => claim_evidence_admissible(body),
            })
            .count()
    };

    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x15; 16]).expect("valid id"));
    let mut generated = ClaimBody::new(
        "test.pred",
        subject,
        Value::from("v"),
        0.5,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    generated.source = Some(ClaimSource::Generated);
    assert!(
        claim_consolidatable(&generated),
        "fixture claim must be the Approved-Generated divergence case"
    );

    let without_generated = [EvidenceRef::Turn, EvidenceRef::Turn];
    let with_generated = [
        EvidenceRef::Turn,
        EvidenceRef::Turn,
        EvidenceRef::Claim(Box::new(generated)),
    ];
    assert_eq!(
        corroboration(&with_generated),
        corroboration(&without_generated),
        "an Approved Generated claim must add zero corroboration"
    );
}

/// GATE-11 (ONE-1391) distinctness pin: an `Approved` Generated claim IS
/// consolidatable (merge-eligible) but NOT evidence-admissible — the two
/// predicates diverge exactly there.
#[test]
fn approved_generated_consolidatable_but_not_evidence() {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x16; 16]).expect("valid id"));
    let mut body = ClaimBody::new(
        "test.pred",
        subject,
        Value::from("v"),
        0.5,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Generated);

    assert!(
        claim_consolidatable(&body),
        "Approved Generated claims are merge-eligible"
    );
    assert!(
        !claim_evidence_admissible(&body),
        "Approved Generated claims still are not evidence"
    );
}

/// ONE-1159 fix-wave — the WRITE door's surfaceability guard reuses the
/// `claim_surfaceable` approval set: `Approved` is accepted (not only
/// `Auto`), and `Proposed` is a typed reject. Pins the {auto, approved}
/// boundary directly on the door function, independent of the read gate.
#[test]
fn provenance_door_accepts_approved_and_rejects_proposed_wrappers() {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x60; 16]).expect("valid id"));
    // Valid value record (3 required keys), conf mirrors the wrapper, no
    // valid-time on either side, actor-class on the wrapper `evid`.
    let value_record = Value::Map(vec![
        (
            Value::from("actor_entity_ref"),
            Value::Binary(vec![0x62; 16]),
        ),
        (Value::from("confidence"), Value::F32(0.75)),
        (Value::from("supersession_status"), Value::from(1u8)),
    ]);
    let actor_class_evid = Value::Map(vec![(Value::from("actor_class"), Value::from(0u8))]);
    let wrapper = |appr: ClaimApprovalStatus| {
        let mut body = ClaimBody::new(
            crate::provenance::PREDICATE_EDGE_PROVENANCE,
            subject,
            value_record.clone(),
            0.75,
            appr,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(actor_class_evid.clone());
        body
    };

    // `Approved` is in the surfaceable set → the door passes it.
    validate_edge_provenance_claim_structure(&wrapper(ClaimApprovalStatus::Approved))
        .expect("approved provenance wrapper must pass the door");
    // `Proposed` is outside {auto, approved} → typed reject.
    assert_matches!(
        validate_edge_provenance_claim_structure(&wrapper(ClaimApprovalStatus::Proposed)),
        Err(Error::InvalidProvenanceBody(_))
    );
}

#[test]
fn six_value_src_roundtrip() {
    for source in [
        ClaimSource::UserStated,
        ClaimSource::Observed,
        ClaimSource::Inferred,
        ClaimSource::Imported,
        ClaimSource::ToolOutput,
        ClaimSource::Generated,
    ] {
        assert_eq!(ClaimSource::parse(source.as_str()), Some(source));
    }
}

#[test]
fn claim_source_explicit_auto_permit_set_includes_generated() {
    for source in [
        ClaimSource::Imported,
        ClaimSource::ToolOutput,
        ClaimSource::Generated,
    ] {
        assert!(
            source.requires_explicit_auto_permit(),
            "{} must require explicit auto permit",
            source.as_str()
        );
    }

    for source in [
        ClaimSource::UserStated,
        ClaimSource::Observed,
        ClaimSource::Inferred,
    ] {
        assert!(
            !source.requires_explicit_auto_permit(),
            "{} must not require explicit auto permit",
            source.as_str()
        );
    }
}

/// DESIGN-PIN A0 table (ONE-1289): drop-the-leaf grouping across the docs
/// pack, crate-layer, chain, and arbitrary wild namespaces — total, never
/// panics, no registry lookup.
#[test]
fn predicate_root_table() {
    let table = [
        // docs pack (ARCH-0003) — families stay together
        ("profile.name", "profile"),
        ("profile.lives_in", "profile"),
        ("companion.nickname", "companion"),
        ("companion.inside_joke", "companion"),
        // crate layer
        ("core.conflict.open", "core.conflict"),
        ("core.conflict.resolved", "core.conflict"),
        ("core.lexical.query_hint", "core.lexical"),
        ("companion.expression", "companion"),
        // this chain (D13)
        ("dreamer.step", "dreamer"),
        // affect module
        ("affect.mood", "affect"),
        // reserved
        ("edge.provenance", "edge"),
        // arbitrary namespaces already in the wild
        ("oneiron.custom_thing", "oneiron"),
        ("user.some.deep.namespace.leaf", "user.some.deep.namespace"),
    ];
    for (predicate, expected_root) in table {
        assert_eq!(predicate_root(predicate), expected_root, "{predicate}");
    }

    // Totality: never panics on inputs outside the grammar.
    assert_eq!(predicate_root("single_segment"), "single_segment");
    assert_eq!(predicate_root(""), "");
    assert_eq!(predicate_root(".leading_dot"), ".leading_dot");
    assert_eq!(predicate_root("trailing_dot."), "trailing_dot");
}

// ─── ONE-1645 unstamped sensitivity floor ───────────────────────────────────

fn band_probe_body(scope: Option<Value>) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.hobby",
        ClaimSubject::Entity(EntityId::from_bytes([0x51; 16]).expect("valid id")),
        Value::from("value"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.scope = scope;
    body
}

/// A claim with no recorded provenance reads the floor band, not band 0.
/// Both shapes of "missing" collapse to the same answer: no scope map at all,
/// and a scope map that simply carries no `sensitivity` key.
#[test]
fn unstamped_claim_sensitivity_reads_floor_band() {
    let table: [(&str, Option<Value>); 3] = [
        ("no scope map", None),
        ("empty scope map", Some(Value::Map(vec![]))),
        (
            "scope map without a sensitivity key",
            Some(Value::Map(vec![(
                Value::from("federated_original_source"),
                Value::from("imported"),
            )])),
        ),
    ];
    for (label, scope) in table {
        assert_eq!(
            claim_sensitivity_band(&band_probe_body(scope)),
            Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND),
            "{label} must read the unstamped floor"
        );
    }
    // The floor is the disclosure-closing band, below the persona clamp.
    assert_eq!(UNSTAMPED_CLAIM_SENSITIVITY_BAND, 2);
}

/// Positive evidence still wins: an explicit public stamp reads band 0 in
/// both its string and integer encodings. The floor narrows absence only.
#[test]
fn stamped_public_claim_reads_band_zero() {
    let table: [(&str, Value); 2] = [
        ("string encoding", Value::from("public")),
        ("integer encoding", Value::from(0_u64)),
    ];
    for (label, stamp) in table {
        let scope = Value::Map(vec![(Value::from("sensitivity"), stamp)]);
        assert_eq!(
            claim_sensitivity_band(&band_probe_body(Some(scope))),
            Some(0),
            "{label} of an explicit public stamp must read band 0"
        );
    }
}

/// Ambiguous is not missing: a duplicated key stays unreadable (`None`), so
/// consumers that clamp harder on `None` than on the floor keep doing so.
#[test]
fn duplicate_sensitivity_still_ambiguous() {
    let scope = Value::Map(vec![
        (Value::from("sensitivity"), Value::from("public")),
        (Value::from("sensitivity"), Value::from("restricted")),
    ]);
    assert_eq!(claim_sensitivity_band(&band_probe_body(Some(scope))), None);
}

/// The `calendar.*` family reaches the same central local-write validator that
/// sync replay reaches, so a malformed calendar claim is rejected at the write
/// door rather than at a calendar-specific read. Value-shape coverage lives in
/// `calendar::claims`; this pins the chokepoint wiring.
#[test]
fn write_door_validates_calendar_claim_structure() -> Result<()> {
    let (_temp, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_EVENT,
        TimeRange { start: 1, end: 1 },
        1,
        b"event",
    )?;

    let calendar_body = |value: Value| {
        ClaimBody::new(
            crate::calendar::claims::PREDICATE_CALENDAR_STATUS,
            ClaimSubject::Entity(subject),
            value,
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
    };
    let status_value = |status: &str| {
        Value::Map(vec![
            (Value::from("status"), Value::from(status)),
            (Value::from("basis"), Value::from("owner")),
            (Value::from("recorded_at"), Value::from(1_754_400_000_u64)),
        ])
    };

    // The canonical shape stores through the public claim door.
    vault.put_claim(
        &EntityId::now(),
        &calendar_body(status_value("confirmed")),
        TimeRange { start: 2, end: 2 },
        2,
    )?;

    // An invalid closed-set token is rejected at that same door.
    assert_matches!(
        vault.put_claim(
            &EntityId::now(),
            &calendar_body(status_value("tentative")),
            TimeRange { start: 3, end: 3 },
            3,
        ),
        Err(Error::InvalidClaimBody(_))
    );

    // So is a wholly wrong value type, proving the branch is not shape-blind.
    assert_matches!(
        vault.put_claim(
            &EntityId::now(),
            &calendar_body(Value::from("cancelled")),
            TimeRange { start: 4, end: 4 },
            4,
        ),
        Err(Error::InvalidClaimBody(_))
    );

    // An unknown `calendar.*` predicate is NOT interpreted as a family member:
    // the matcher is exact-table membership, so it stores as an ordinary claim.
    let unknown = ClaimBody::new(
        "calendar.unknown",
        ClaimSubject::Entity(subject),
        Value::from("free-form"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(
        &EntityId::now(),
        &unknown,
        TimeRange { start: 5, end: 5 },
        5,
    )?;
    Ok(())
}

// ── ONE-1936: write-verb validity guard ──────────────────────────────────
//
// The claim id a verb NAMES is its version token. These rows pin what a
// caller who named a replaced head gets back: a typed refusal carrying the
// public ref of the CURRENT head, with nothing written and nothing retargeted.

/// A vault plus one PERSON subject the fixture claims hang off.
fn guard_fixture() -> (tempfile::TempDir, Vault, EntityId) {
    let (temp, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .expect("seed subject");
    (temp, vault, subject)
}

fn guard_claim(vault: &Vault, subject: &EntityId, value: &str, learned_at: u64) -> EntityId {
    let id = EntityId::now();
    let body = ClaimBody::new(
        "profile.lives_in",
        ClaimSubject::Entity(*subject),
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(
            &id,
            &body,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        )
        .expect("seed active claim");
    id
}

fn guard_short_ref(vault: &Vault, id: &EntityId) -> String {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault.claim_short_ref_in(&rtxn, id).expect("short ref")
}

/// Writes a raw inbound `Supersedes` row (`new ─Supersedes→ old`) WITHOUT the
/// lifecycle transition. The public verb refuses to build a branch or a cycle —
/// which is the point: these shapes are corruption, and the walk must fail
/// closed on them rather than pick a head.
fn seed_raw_supersedes_edge(vault: &Vault, new_claim: &EntityId, old_claim: &EntityId) {
    vault
        .with_write_txn(|wtxn| {
            let key =
                crate::store::Store::encode_edge_key(old_claim, EdgeKind::Supersedes, new_claim);
            vault.store.edges_in.put(wtxn, &key, &[0_u8; 12])?;
            Ok(())
        })
        .expect("seed raw supersedes edge");
}

#[test]
fn stale_supersede_returns_successor_short_id() -> Result<()> {
    let (_temp, vault, subject) = guard_fixture();
    let old = guard_claim(&vault, &subject, "osaka", 2);
    let replacement = guard_claim(&vault, &subject, "tokyo", 3);
    let latecomer = guard_claim(&vault, &subject, "kyoto", 4);

    vault.supersede_claim(&replacement, &old, 100)?;

    let err = vault
        .supersede_claim(&latecomer, &old, 200)
        .expect_err("the named target is no longer the head");
    assert_eq!(err.kind(), ErrorKind::WriteVerbTargetStale);
    let Error::WriteVerbTargetStale {
        target,
        lifecycle,
        successor_short_id,
    } = err
    else {
        panic!("expected a typed stale-target refusal");
    };
    assert_eq!(target, old);
    assert_eq!(lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(successor_short_id, guard_short_ref(&vault, &replacement));
    // The ref is a resolvable public short ref, never a hex fallback.
    assert!(successor_short_id.starts_with("cl"));
    assert_ne!(successor_short_id, replacement.to_hex());

    // Loud failure: the verb was NOT applied to the successor, and the first
    // close timestamp survives.
    assert_eq!(
        vault
            .get_claim(&replacement)?
            .expect("replacement")
            .lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault.get_claim(&latecomer)?.expect("latecomer").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(vault.get_claim(&old)?.expect("old").valid_to, Some(100));
    assert!(
        vault
            .sources(&old, EdgeKind::Supersedes, None)?
            .iter()
            .all(|source| *source == replacement),
        "a refused supersede must write no supersedes edge"
    );
    Ok(())
}

#[test]
fn supersession_chain_head_returned() -> Result<()> {
    let (_temp, vault, subject) = guard_fixture();
    let first = guard_claim(&vault, &subject, "osaka", 2);
    let second = guard_claim(&vault, &subject, "tokyo", 3);
    let third = guard_claim(&vault, &subject, "kyoto", 4);
    let latecomer = guard_claim(&vault, &subject, "nara", 5);

    // Two hops: first ← second ← third.
    vault.supersede_claim(&second, &first, 100)?;
    vault.supersede_claim(&third, &second, 200)?;

    let err = vault
        .supersede_claim(&latecomer, &first, 300)
        .expect_err("the two-hop chain head is reported");
    let Error::WriteVerbTargetStale {
        successor_short_id, ..
    } = err
    else {
        panic!("expected a typed stale-target refusal");
    };
    // The TERMINAL head, not the immediate successor.
    assert_eq!(successor_short_id, guard_short_ref(&vault, &third));
    assert_ne!(successor_short_id, guard_short_ref(&vault, &second));
    Ok(())
}

#[test]
fn stale_retract_never_retargets_successor() -> Result<()> {
    let (_temp, vault, subject) = guard_fixture();
    let old = guard_claim(&vault, &subject, "osaka", 2);
    let replacement = guard_claim(&vault, &subject, "tokyo", 3);
    vault.supersede_claim(&replacement, &old, 100)?;

    let err = vault
        .retract_claim(&old, 200)
        .expect_err("retracting a replaced head is stale, not a retarget");
    assert_eq!(err.kind(), ErrorKind::WriteVerbTargetStale);
    let Error::WriteVerbTargetStale {
        target,
        lifecycle,
        successor_short_id,
    } = err
    else {
        panic!("expected a typed stale-target refusal");
    };
    assert_eq!(target, old);
    assert_eq!(lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(successor_short_id, guard_short_ref(&vault, &replacement));

    // The successor is untouched: naming a stale target never withdraws the
    // claim that replaced it.
    let successor_body = vault.get_claim(&replacement)?.expect("replacement");
    assert_eq!(successor_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(successor_body.valid_to, None);
    // …and the stale target keeps its own first-close state.
    let old_body = vault.get_claim(&old)?.expect("old");
    assert_eq!(old_body.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_body.valid_to, Some(100));

    // A DIRECTLY retracted target has no newer entity: its terminal head is
    // itself, reported with its own public ref and `Retracted`.
    let solo = guard_claim(&vault, &subject, "nara", 4);
    vault.retract_claim(&solo, 300)?;
    let err = vault
        .retract_claim(&solo, 400)
        .expect_err("a retracted target is its own head");
    let Error::WriteVerbTargetStale {
        target,
        lifecycle,
        successor_short_id,
    } = err
    else {
        panic!("expected a typed stale-target refusal");
    };
    assert_eq!(target, solo);
    assert_eq!(lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(successor_short_id, guard_short_ref(&vault, &solo));
    assert_eq!(vault.get_claim(&solo)?.expect("solo").valid_to, Some(300));
    Ok(())
}

#[test]
fn superseded_target_whose_successor_was_deleted_fails_closed() -> Result<()> {
    let (_temp, vault, subject) = guard_fixture();
    let old = guard_claim(&vault, &subject, "osaka", 2);
    let replacement = guard_claim(&vault, &subject, "tokyo", 3);
    let latecomer = guard_claim(&vault, &subject, "kyoto", 4);
    vault.supersede_claim(&replacement, &old, 100)?;

    // Deleting the successor through the ordinary delete door takes both
    // incident `Supersedes` rows with it: `old` stays closed with nothing
    // newer left to name.
    vault.batch().delete(&replacement).commit()?;
    assert_eq!(
        vault.get_claim(&old)?.expect("old").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert!(vault.sources(&old, EdgeKind::Supersedes, None)?.is_empty());

    // Naming its own ref is exclusive to a RETRACTED head. A superseded claim
    // whose successor row is gone has no head to report, so the walk fails
    // closed rather than handing the caller back the stale token it already
    // holds.
    for err in [
        vault
            .retract_claim(&old, 200)
            .expect_err("a missing successor row must fail closed"),
        vault
            .supersede_claim(&latecomer, &old, 300)
            .expect_err("a missing successor row must fail closed"),
    ] {
        assert_eq!(err.kind(), ErrorKind::InvariantViolation);
    }

    // Loud failure: neither verb was applied.
    let old_body = vault.get_claim(&old)?.expect("old");
    assert_eq!(old_body.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_body.valid_to, Some(100));
    assert_eq!(
        vault.get_claim(&latecomer)?.expect("latecomer").lifecycle,
        ClaimLifecycleStatus::Active
    );
    Ok(())
}

#[test]
fn branching_supersession_graph_fails_closed_without_picking_a_head() -> Result<()> {
    let (_temp, vault, subject) = guard_fixture();
    let old = guard_claim(&vault, &subject, "osaka", 2);
    let replacement = guard_claim(&vault, &subject, "tokyo", 3);
    let rival = guard_claim(&vault, &subject, "kyoto", 4);
    let latecomer = guard_claim(&vault, &subject, "nara", 5);

    vault.supersede_claim(&replacement, &old, 100)?;
    // A second, illegitimate successor for the same target: two terminal heads.
    seed_raw_supersedes_edge(&vault, &rival, &old);

    let err = vault
        .supersede_claim(&latecomer, &old, 200)
        .expect_err("a branch must not resolve to a head");
    assert_eq!(err.kind(), ErrorKind::InvariantViolation);
    Ok(())
}

#[test]
fn cyclic_supersession_graph_fails_closed() -> Result<()> {
    let (_temp, vault, subject) = guard_fixture();
    let old = guard_claim(&vault, &subject, "osaka", 2);
    let replacement = guard_claim(&vault, &subject, "tokyo", 3);
    let latecomer = guard_claim(&vault, &subject, "kyoto", 4);

    vault.supersede_claim(&replacement, &old, 100)?;
    // Close the loop: the successor is itself superseded by the target.
    seed_raw_supersedes_edge(&vault, &old, &replacement);

    let err = vault
        .supersede_claim(&latecomer, &old, 200)
        .expect_err("a cycle must not spin or resolve");
    assert_eq!(err.kind(), ErrorKind::CycleDetected);
    Ok(())
}

#[test]
fn supersession_chain_node_that_is_not_a_claim_fails_closed() -> Result<()> {
    let (_temp, vault, subject) = guard_fixture();
    let old = guard_claim(&vault, &subject, "osaka", 2);
    let latecomer = guard_claim(&vault, &subject, "tokyo", 3);
    vault.retract_claim(&old, 100)?;

    // A non-CLAIM node wired into the chain is corruption, not a successor.
    seed_raw_supersedes_edge(&vault, &subject, &old);

    let err = vault
        .supersede_claim(&latecomer, &old, 200)
        .expect_err("a non-CLAIM chain node must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    Ok(())
}

#[test]
fn active_target_follows_the_verb_path_with_no_side_lookup() -> Result<()> {
    let (_temp, vault, subject) = guard_fixture();
    let old = guard_claim(&vault, &subject, "osaka", 2);
    let replacement = guard_claim(&vault, &subject, "tokyo", 3);

    // The guard is transparent for a live head: the existing transition runs.
    vault.supersede_claim(&replacement, &old, 100)?;
    assert_eq!(
        vault.get_claim(&old)?.expect("old").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault.sources(&old, EdgeKind::Supersedes, None)?,
        vec![replacement]
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-vault coreference claim predicates (FED-07, ONE-1414)
// ---------------------------------------------------------------------------

const COREFERENCE_LINK_SOURCE: u8 = 0x51;
const COREFERENCE_LINK_TARGET: u8 = 0x52;

fn coreference_edge_subject() -> ClaimSubject {
    ClaimSubject::Edge {
        source: crate::test_util::entity(COREFERENCE_LINK_SOURCE),
        kind: EdgeKind::SameAs,
        target: crate::test_util::entity(COREFERENCE_LINK_TARGET),
    }
}

fn coreference_body(predicate: &str, value: Value, approval: ClaimApprovalStatus) -> ClaimBody {
    ClaimBody::new(
        predicate,
        coreference_edge_subject(),
        value,
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )
}

fn consent_value(pact_hex: &str) -> Value {
    Value::Map(vec![(
        Value::from(COREFERENCE_SHARE_CONSENT_PACT_KEY),
        Value::from(pact_hex),
    )])
}

fn valid_pact_hex() -> String {
    "63".repeat(32)
}

/// Runs a body through the REAL write-door chokepoint (encode → validate),
/// so these tests exercise the same path every `put_claim` takes rather than
/// calling the private validators directly.
fn coreference_validation(body: &ClaimBody) -> Result<()> {
    validate_claim_body_bytes(&encode_claim_body(body)?, false)
}

/// ONE-1414 done-means 11 — REGISTRY APPEND LAW.
///
/// The two coreference rows are APPENDED: every predicate registered before
/// this ticket keeps its seat, and the length is asserted as `landed + 2`
/// rather than as a magic number, so a concurrent lane adding its own row
/// fails here loudly instead of being silently dropped by a rebase.
#[test]
fn coreference_predicates_append_to_the_registry_without_dropping_a_row() {
    let pre_existing = [
        PREDICATE_LEXICAL_QUERY_HINT,
        PREDICATE_COMPANION_EXPRESSION,
        PREDICATE_CONFLICT_OPEN,
        PREDICATE_CONFLICT_RESOLVED,
    ];
    for predicate in pre_existing {
        assert!(
            CLAIM_PREDICATE_REGISTRY.contains(&predicate),
            "{predicate} was dropped from the registry"
        );
    }
    assert!(CLAIM_PREDICATE_REGISTRY.contains(&PREDICATE_COREFERENCE_STATUS));
    assert!(CLAIM_PREDICATE_REGISTRY.contains(&PREDICATE_COREFERENCE_SHARE_CONSENT));
    let named_rows = pre_existing.len() + 2;
    assert!(CLAIM_PREDICATE_REGISTRY.len() >= named_rows);
    let unique: std::collections::BTreeSet<_> = CLAIM_PREDICATE_REGISTRY.iter().copied().collect();
    assert_eq!(unique.len(), CLAIM_PREDICATE_REGISTRY.len());

    // Both predicates sit under the shared namespace prefix the export filter
    // excludes wholesale, so neither can be withheld by name alone.
    for predicate in [
        PREDICATE_COREFERENCE_STATUS,
        PREDICATE_COREFERENCE_SHARE_CONSENT,
    ] {
        assert!(predicate.starts_with(PREDICATE_COREFERENCE_PREFIX));
    }
}

/// Both validators are WIRED at the dispatch, not merely defined: a body that
/// only these branches reject must fail through the ordinary write door.
#[test]
fn both_coreference_validators_are_wired_into_the_write_door() {
    // Rejected only by the status validator (value outside the closed set).
    assert_matches!(
        coreference_validation(&coreference_body(
            PREDICATE_COREFERENCE_STATUS,
            Value::from("merged"),
            ClaimApprovalStatus::Approved,
        )),
        Err(Error::InvalidClaimBody(_))
    );
    // Rejected only by the share-consent validator (value is not the pinned map).
    assert_matches!(
        coreference_validation(&coreference_body(
            PREDICATE_COREFERENCE_SHARE_CONSENT,
            Value::from(valid_pact_hex()),
            ClaimApprovalStatus::Approved,
        )),
        Err(Error::InvalidClaimBody(_))
    );
}

/// ONE-1414 done-means 2 — the status/approval pairing is ONE gate.
///
/// `confirmed` is settled identity and needs an owner `Approved`; `proposed`
/// is an open assertion and admits `Auto`/`Proposed` only. The cross pairings
/// are the interesting half: a `confirmed` row wearing `Auto` would be an
/// unreviewed identity merge with a reviewed label.
#[test]
fn coreference_status_pins_value_to_approval() {
    let cases: [(&str, ClaimApprovalStatus, bool); 8] = [
        ("confirmed", ClaimApprovalStatus::Approved, true),
        ("confirmed", ClaimApprovalStatus::Auto, false),
        ("confirmed", ClaimApprovalStatus::Proposed, false),
        ("confirmed", ClaimApprovalStatus::Rejected, false),
        ("proposed", ClaimApprovalStatus::Auto, true),
        ("proposed", ClaimApprovalStatus::Proposed, true),
        ("proposed", ClaimApprovalStatus::Approved, false),
        ("proposed", ClaimApprovalStatus::Rejected, false),
    ];
    for (status, approval, admitted) in cases {
        let result = coreference_validation(&coreference_body(
            PREDICATE_COREFERENCE_STATUS,
            Value::from(status),
            approval,
        ));
        assert_eq!(
            result.is_ok(),
            admitted,
            "status {status} at approval {approval:?} decided wrong: {result:?}"
        );
    }
}

/// Values outside `proposed|confirmed` fail regardless of approval, and a
/// non-string value fails before the closed-set check.
#[test]
fn coreference_status_rejects_values_outside_the_closed_set() {
    for value in [
        Value::from("Confirmed"),
        Value::from("same"),
        Value::from(""),
        Value::from(1_u64),
        Value::Nil,
    ] {
        assert_matches!(
            coreference_validation(&coreference_body(
                PREDICATE_COREFERENCE_STATUS,
                value,
                ClaimApprovalStatus::Approved,
            )),
            Err(Error::InvalidClaimBody(_))
        );
    }
}

/// ONE-1414 done-means 6 — a malformed pact id fails STRUCTURAL decode.
///
/// Odd length, uppercase, and non-hex bytes are each sufficient alone. So is a
/// second map key: this value is read by the export filter to decide what
/// crosses a grant, so a map with room for unread keys is a place to hide a
/// second, unhonored scope.
#[test]
fn coreference_share_consent_rejects_malformed_pact_ids_and_extra_keys() {
    let malformed_values = [
        consent_value(&"6".repeat(63)),
        consent_value(&"6".repeat(65)),
        consent_value(&"63".repeat(31)),
        // Uppercase must be spelled with hex LETTERS: `"63"` has no case, so
        // upper-casing it would silently test nothing.
        consent_value(&"ab".repeat(32).to_uppercase()),
        consent_value(&format!("{}Ab", "ab".repeat(31))),
        consent_value(&format!("{}zz", "63".repeat(31))),
        consent_value(""),
        Value::Map(vec![(Value::from("pact"), Value::from(valid_pact_hex()))]),
        Value::Map(vec![
            (
                Value::from(COREFERENCE_SHARE_CONSENT_PACT_KEY),
                Value::from(valid_pact_hex()),
            ),
            (Value::from("also"), Value::from("everything")),
        ]),
        Value::Map(Vec::new()),
        Value::Map(vec![(
            Value::from(COREFERENCE_SHARE_CONSENT_PACT_KEY),
            Value::from(0x63_u64),
        )]),
    ];
    for (index, value) in malformed_values.into_iter().enumerate() {
        let result = coreference_validation(&coreference_body(
            PREDICATE_COREFERENCE_SHARE_CONSENT,
            value,
            ClaimApprovalStatus::Approved,
        ));
        assert!(
            matches!(result, Err(Error::InvalidClaimBody(_))),
            "malformed consent case {index} was admitted: {result:?}"
        );
    }
}

/// A well-formed consent claim admits at `Approved` and NOWHERE else: widening
/// disclosure is an owner decision, so there is no `Auto` path to it.
#[test]
fn coreference_share_consent_requires_approved() {
    coreference_validation(&coreference_body(
        PREDICATE_COREFERENCE_SHARE_CONSENT,
        consent_value(&valid_pact_hex()),
        ClaimApprovalStatus::Approved,
    ))
    .expect("a well-formed approved consent claim must admit");

    for approval in [
        ClaimApprovalStatus::Auto,
        ClaimApprovalStatus::Proposed,
        ClaimApprovalStatus::Rejected,
    ] {
        assert_matches!(
            coreference_validation(&coreference_body(
                PREDICATE_COREFERENCE_SHARE_CONSENT,
                consent_value(&valid_pact_hex()),
                approval,
            )),
            Err(Error::InvalidClaimBody(_))
        );
    }
}

/// ONE-1414 done-means 7 — the byte-20 EdgeRef subject round-trips through
/// encode/decode, and EVERY other subject shape fails BOTH validators.
///
/// The foreign-EdgeKind cases are the load-bearing ones: the subject check is
/// exact-kind, not "some structural edge", so a consent claim cannot vouch for
/// a link it never described.
#[test]
fn coreference_claims_admit_only_a_same_as_edge_ref_subject() -> Result<()> {
    let approved = coreference_body(
        PREDICATE_COREFERENCE_STATUS,
        Value::from("confirmed"),
        ClaimApprovalStatus::Approved,
    );
    let decoded = decode_claim_body(&encode_claim_body(&approved)?, false)?;
    assert_eq!(decoded.subject, coreference_edge_subject());

    let source = crate::test_util::entity(COREFERENCE_LINK_SOURCE);
    let target = crate::test_util::entity(COREFERENCE_LINK_TARGET);
    let wrong_subjects = [
        ClaimSubject::Entity(source),
        ClaimSubject::Edge {
            source,
            kind: EdgeKind::MergedInto,
            target,
        },
        ClaimSubject::Edge {
            source,
            kind: EdgeKind::BelongsTo,
            target,
        },
    ];
    for subject in wrong_subjects {
        let mut status = approved.clone();
        status.subject = subject;
        assert_matches!(
            coreference_validation(&status),
            Err(Error::InvalidClaimBody(_))
        );

        let mut consent = coreference_body(
            PREDICATE_COREFERENCE_SHARE_CONSENT,
            consent_value(&valid_pact_hex()),
            ClaimApprovalStatus::Approved,
        );
        consent.subject = subject;
        assert_matches!(
            coreference_validation(&consent),
            Err(Error::InvalidClaimBody(_))
        );
    }
    Ok(())
}

#[test]
fn expression_preference_registry_is_name_complete_and_unique() {
    let expected = [
        PREDICATE_COMPANION_EXPRESSION_LANGUAGE,
        PREDICATE_COMPANION_EXPRESSION_REGISTER,
        PREDICATE_COMPANION_EXPRESSION_KEIGO,
        PREDICATE_COMPANION_EXPRESSION_STYLE,
    ];
    let unique: std::collections::BTreeSet<_> = CLAIM_PREDICATE_REGISTRY.iter().copied().collect();
    assert_eq!(unique.len(), CLAIM_PREDICATE_REGISTRY.len());
    for predicate in expected {
        assert_eq!(
            CLAIM_PREDICATE_REGISTRY
                .iter()
                .filter(|item| **item == predicate)
                .count(),
            1
        );
        assert!(is_expression_preference_predicate(predicate));
    }
}

#[test]
fn expression_preference_validators_pin_vocabularies() -> Result<()> {
    fn body(predicate: &str, value: Value) -> ClaimBody {
        ClaimBody::new(
            predicate,
            ClaimSubject::Entity(EntityId::from_bytes([0x71; 16]).unwrap()),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
    }
    for tag in ["ja", "en-US", "zh-Hant"] {
        validate_expression_preference_claim_structure(&body(
            PREDICATE_COMPANION_EXPRESSION_LANGUAGE,
            Value::from(tag),
        ))?;
    }
    for tag in ["EN-us", "en--US", "en-", "ja-", "ja--JP", "日本語", ""] {
        assert_matches!(
            validate_expression_preference_claim_structure(&body(
                PREDICATE_COMPANION_EXPRESSION_LANGUAGE,
                Value::from(tag)
            )),
            Err(Error::InvalidClaimBody(_))
        );
    }
    for value in ["casual", "neutral", "formal"] {
        validate_expression_preference_claim_structure(&body(
            PREDICATE_COMPANION_EXPRESSION_REGISTER,
            Value::from(value),
        ))?;
    }
    for value in ["none", "teineigo", "sonkeigo", "kenjogo", "adaptive"] {
        validate_expression_preference_claim_structure(&body(
            PREDICATE_COMPANION_EXPRESSION_KEIGO,
            Value::from(value),
        ))?;
    }
    validate_expression_preference_claim_structure(&body(
        PREDICATE_COMPANION_EXPRESSION_STYLE,
        Value::from("compact-neutral"),
    ))?;
    for (predicate, value) in [
        (PREDICATE_COMPANION_EXPRESSION_REGISTER, "warm"),
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "honorific"),
        (PREDICATE_COMPANION_EXPRESSION_STYLE, ""),
        (PREDICATE_COMPANION_EXPRESSION_STYLE, "9bad"),
        (PREDICATE_COMPANION_EXPRESSION_STYLE, "Bad"),
        (PREDICATE_COMPANION_EXPRESSION_STYLE, "bad value"),
        (PREDICATE_COMPANION_EXPRESSION_STYLE, &"a".repeat(65)),
    ] {
        assert_matches!(
            validate_expression_preference_claim_structure(&body(predicate, Value::from(value))),
            Err(Error::InvalidClaimBody(_))
        );
    }
    Ok(())
}

/// Keep expression-preference coverage on the ordinary write/dispatch door,
/// rather than only exercising its private structural validator.
fn expression_preference_validation(body: &ClaimBody) -> Result<()> {
    validate_claim_body_bytes(&encode_claim_body(body)?, false)
}

fn expression_preference_body(predicate: &str, subject: ClaimSubject, value: Value) -> ClaimBody {
    ClaimBody::new(
        predicate,
        subject,
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
}

#[test]
fn expression_preference_write_door_rejects_non_entity_subjects() {
    let subject = ClaimSubject::Edge {
        source: crate::test_util::entity(0x73),
        kind: EdgeKind::SameAs,
        target: crate::test_util::entity(0x74),
    };
    assert_matches!(
        expression_preference_validation(&expression_preference_body(
            PREDICATE_COMPANION_EXPRESSION_LANGUAGE,
            subject,
            Value::from("en-US"),
        )),
        Err(Error::InvalidClaimBody(_))
    );
}

#[test]
fn expression_preference_write_door_rejects_non_string_values() {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x75; 16]).unwrap());
    for predicate in [
        PREDICATE_COMPANION_EXPRESSION_LANGUAGE,
        PREDICATE_COMPANION_EXPRESSION_REGISTER,
        PREDICATE_COMPANION_EXPRESSION_KEIGO,
        PREDICATE_COMPANION_EXPRESSION_STYLE,
    ] {
        assert_matches!(
            expression_preference_validation(&expression_preference_body(
                predicate,
                subject,
                Value::from(7_u64),
            )),
            Err(Error::InvalidClaimBody(_))
        );
    }
}

#[test]
fn expression_preference_write_door_rejects_malformed_vocabularies() {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x76; 16]).unwrap());
    for (predicate, value) in [
        (PREDICATE_COMPANION_EXPRESSION_LANGUAGE, "EN-us"),
        (PREDICATE_COMPANION_EXPRESSION_REGISTER, "warm"),
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "honorific"),
        (PREDICATE_COMPANION_EXPRESSION_STYLE, "Bad"),
    ] {
        assert_matches!(
            expression_preference_validation(&expression_preference_body(
                predicate,
                subject,
                Value::from(value),
            )),
            Err(Error::InvalidClaimBody(_))
        );
    }
}

#[test]
fn expression_preference_malformed_body_is_rejected_by_vault_put_claim() -> Result<()> {
    let (_temp, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let subject = EntityId::from_bytes([0x77; 16]).unwrap();
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"subject",
    )?;
    let claim_id = EntityId::from_bytes([0x78; 16]).unwrap();
    let body = expression_preference_body(
        PREDICATE_COMPANION_EXPRESSION_REGISTER,
        ClaimSubject::Entity(subject),
        Value::from("unknown-register"),
    );
    assert_matches!(
        vault.put_claim(&claim_id, &body, TimeRange { start: 2, end: 2 }, 2),
        Err(Error::InvalidClaimBody(_))
    );
    assert!(vault.get_claim(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn expression_preference_legacy_bare_predicate_remains_compatible() -> Result<()> {
    for value in [
        COMPANION_EXPRESSION_PROFESSIONAL,
        COMPANION_EXPRESSION_WARM,
        COMPANION_EXPRESSION_UNRESTRICTED,
    ] {
        let body = ClaimBody::new(
            PREDICATE_COMPANION_EXPRESSION,
            ClaimSubject::Entity(EntityId::from_bytes([0x72; 16]).unwrap()),
            Value::from(value),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        validate_companion_expression_claim_structure(&body)?;
    }
    Ok(())
}

fn expression_preference_fixture() -> (tempfile::TempDir, Vault, EntityId, WriteActor, WriteActor) {
    let (temp, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (
            Value::from("pack_id"),
            Value::from("one-1421-expression-preference"),
        ),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (
            Value::from("rules"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("prefix"), Value::from("companion.expression.")),
                (
                    Value::from("axes"),
                    Value::Map(vec![
                        (Value::from("criticality"), Value::from("normal")),
                        (Value::from("sensitivity"), Value::from("normal")),
                    ]),
                ),
            ])]),
        ),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::from("actor_class"), Value::from("agent")),
                    (Value::from("ceiling"), Value::from("auto")),
                ]),
                Value::Map(vec![
                    (Value::from("actor_class"), Value::from("human")),
                    (Value::from("ceiling"), Value::from("auto")),
                ]),
                // supersede/retract lifecycle Puts use envelope-less first_party actor
                Value::Map(vec![
                    (Value::from("actor_class"), Value::from("first_party")),
                    (Value::from("ceiling"), Value::from("auto")),
                ]),
            ]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("encode manifest");
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        EntityId::from_bytes([0xE1; 16]).expect("id"),
        &data,
    )
    .expect("install auto-band manifest");
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .expect("seed expression preference subject");
    let human = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let agent = WriteActor::new(EntityId::now(), EdgeActorClass::Agent);
    for actor in [&human, &agent] {
        vault
            .put_entity(
                &actor.entity_ref(),
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"actor",
            )
            .expect("seed write actor");
    }
    (temp, vault, subject, human, agent)
}

#[test]
fn expression_preference_agent_explicit_user_rejected() {
    let (_temp, vault, subject, _human, agent) = expression_preference_fixture();
    let result = vault.set_expression_preference(
        &agent,
        EntityId::now(),
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("en-US".to_owned()),
            origin: ExpressionPreferenceOrigin::ExplicitUser,
            valid_from: 1,
        },
        TimeRange { start: 1, end: 1 },
        1,
    );
    assert_matches!(result, Err(Error::InvalidClaimBody(_)));
}

#[test]
fn expression_preference_auto_agent_inferred_write_and_gate_receipt() -> Result<()> {
    let (_temp, vault, subject, _human, agent) = expression_preference_fixture();
    let claim_id = EntityId::now();
    let result = vault.set_expression_preference(
        &agent,
        claim_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("en-US".to_owned()),
            origin: ExpressionPreferenceOrigin::Inferred,
            valid_from: 1,
        },
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    assert_eq!(result.approval, ClaimApprovalStatus::Auto);
    let stored = vault.get_claim(&claim_id)?.expect("stored claim");
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    let records = vault.gate_decisions(128)?;
    assert!(
        records.iter().any(|record| {
            record.claim_id.as_ref() == Some(claim_id.as_bytes()) && record.outcome == "allow"
        }),
        "expected ordinary allow GateDecisionRecord for claim; got {records:?}"
    );
    Ok(())
}

#[test]
fn expression_preference_user_over_inferred_precedence() -> Result<()> {
    let (_temp, vault, subject, human, agent) = expression_preference_fixture();
    let inferred_id = EntityId::now();
    vault.set_expression_preference(
        &agent,
        inferred_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("ja".to_owned()),
            origin: ExpressionPreferenceOrigin::Inferred,
            valid_from: 100,
        },
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let user_id = EntityId::now();
    vault.set_expression_preference(
        &human,
        user_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("en-US".to_owned()),
            origin: ExpressionPreferenceOrigin::ExplicitUser,
            valid_from: 1,
        },
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    assert_eq!(
        vault
            .expression_preferences(&subject, 200)?
            .language
            .as_deref(),
        Some("en-US")
    );
    let later_inferred_id = EntityId::now();
    let later = vault.set_expression_preference(
        &agent,
        later_inferred_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("zh-Hant".to_owned()),
            origin: ExpressionPreferenceOrigin::Inferred,
            valid_from: 300,
        },
        TimeRange {
            start: 300,
            end: 300,
        },
        300,
    )?;
    assert!(later.superseded_claim_ids.is_empty());
    assert_eq!(
        vault.get_claim(&user_id)?.expect("user head").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault
            .expression_preferences(&subject, 400)?
            .language
            .as_deref(),
        Some("en-US")
    );
    Ok(())
}

#[test]
fn expression_preference_same_source_replacement_supersedes() -> Result<()> {
    let (_temp, vault, subject, _human, agent) = expression_preference_fixture();
    let old_id = EntityId::now();
    vault.set_expression_preference(
        &agent,
        old_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("ja".to_owned()),
            origin: ExpressionPreferenceOrigin::Inferred,
            valid_from: 1,
        },
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let new_id = EntityId::now();
    let result = vault.set_expression_preference(
        &agent,
        new_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("en-US".to_owned()),
            origin: ExpressionPreferenceOrigin::Inferred,
            valid_from: 2,
        },
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    assert!(result.superseded_claim_ids.contains(&old_id));
    assert_eq!(
        vault.get_claim(&old_id)?.expect("old claim").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault
            .expression_preferences(&subject, 3)?
            .language
            .as_deref(),
        Some("en-US")
    );
    Ok(())
}

#[test]
fn expression_preference_retract_reveals_previous() -> Result<()> {
    let (_temp, vault, subject, _human, agent) = expression_preference_fixture();
    let old_id = EntityId::now();
    vault.set_expression_preference(
        &agent,
        old_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("ja".to_owned()),
            origin: ExpressionPreferenceOrigin::Inferred,
            valid_from: 1,
        },
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let new_id = EntityId::now();
    vault.set_expression_preference(
        &agent,
        new_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("en-US".to_owned()),
            origin: ExpressionPreferenceOrigin::Inferred,
            valid_from: 2,
        },
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    vault.retract_expression_preference(&agent, &new_id, 3)?;
    assert_eq!(
        vault
            .expression_preferences(&subject, 3)?
            .language
            .as_deref(),
        Some("ja")
    );
    Ok(())
}

/// Seeds one inferred agent-written preference and returns its claim id.
fn seed_agent_expression_preference(
    vault: &Vault,
    agent: &WriteActor,
    subject: EntityId,
) -> Result<EntityId> {
    let claim_id = EntityId::now();
    vault.set_expression_preference(
        agent,
        claim_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language("ja".to_owned()),
            origin: ExpressionPreferenceOrigin::Inferred,
            valid_from: 1,
        },
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    Ok(claim_id)
}

#[test]
fn expression_preference_retract_refuses_unbound_actor() -> Result<()> {
    let (_temp, vault, subject, _human, agent) = expression_preference_fixture();
    let claim_id = seed_agent_expression_preference(&vault, &agent, subject)?;
    // Never seeded as an entity: an actor key asserts identity, the store
    // decides whether it holds.
    let stranger = WriteActor::new(EntityId::now(), EdgeActorClass::Agent);
    assert_matches!(
        vault.retract_expression_preference(&stranger, &claim_id, 3),
        Err(Error::InvalidClaimBody(_))
    );
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    Ok(())
}

#[test]
fn expression_preference_retract_refuses_non_author_agent() -> Result<()> {
    let (_temp, vault, subject, _human, agent) = expression_preference_fixture();
    let claim_id = seed_agent_expression_preference(&vault, &agent, subject)?;
    let other = WriteActor::new(EntityId::now(), EdgeActorClass::Agent);
    vault.put_entity(
        &other.entity_ref(),
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    assert_matches!(
        vault.retract_expression_preference(&other, &claim_id, 3),
        Err(Error::InvalidClaimBody(_))
    );
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    Ok(())
}

#[test]
fn expression_preference_retract_admits_human_owner_actor() -> Result<()> {
    let (_temp, vault, subject, human, agent) = expression_preference_fixture();
    let claim_id = seed_agent_expression_preference(&vault, &agent, subject)?;
    // No authority root is folded in this vault, so owner verbs keep the
    // store-truth check only.
    vault.retract_expression_preference(&human, &claim_id, 3)?;
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    Ok(())
}

/// Seeds one agent-inferred language preference at a chosen instant, so a
/// second one supersedes the first and the chain has a predecessor to restore.
fn seed_agent_language_preference(
    vault: &Vault,
    agent: &WriteActor,
    subject: EntityId,
    language: &str,
    at: u64,
) -> Result<EntityId> {
    let claim_id = EntityId::now();
    vault.set_expression_preference(
        agent,
        claim_id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language(language.to_owned()),
            origin: ExpressionPreferenceOrigin::Inferred,
            valid_from: at,
        },
        TimeRange { start: at, end: at },
        at,
    )?;
    Ok(claim_id)
}

/// The generic retract door does not own `companion.expression.*`. Closing one
/// of these heads means restoring its direct predecessor, and the generic door
/// performs only the closing half — which would leave the chain headless. So
/// the family is refused here, and nothing is written.
#[test]
fn generic_retract_refuses_an_expression_preference() -> Result<()> {
    let (_temp, vault, subject, _human, agent) = expression_preference_fixture();
    let first = seed_agent_language_preference(&vault, &agent, subject, "ja", 1)?;
    let head = seed_agent_language_preference(&vault, &agent, subject, "en-US", 2)?;
    let before = vault.get_raw(&head)?.expect("head stored");

    assert_matches!(
        vault.retract_claim(&head, 3),
        Err(Error::InvalidClaimBody(
            "expression preference lifecycle is owned by retract_expression_preference"
        ))
    );

    assert_eq!(
        vault.get_raw(&head)?.expect("head stored"),
        before,
        "a refused retraction writes nothing"
    );
    assert_eq!(
        vault.get_claim(&head)?.expect("head").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault.get_claim(&first)?.expect("predecessor").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    Ok(())
}

/// The typed door is unchanged and still performs BOTH halves: it closes the
/// head and restores the predecessor the head had superseded.
#[test]
fn typed_retract_restores_the_superseded_predecessor() -> Result<()> {
    let (_temp, vault, subject, _human, agent) = expression_preference_fixture();
    let first = seed_agent_language_preference(&vault, &agent, subject, "ja", 1)?;
    let head = seed_agent_language_preference(&vault, &agent, subject, "en-US", 2)?;
    assert_eq!(
        vault.get_claim(&first)?.expect("predecessor").lifecycle,
        ClaimLifecycleStatus::Superseded
    );

    vault.retract_expression_preference(&agent, &head, 3)?;

    assert_eq!(
        vault.get_claim(&head)?.expect("head").lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    let restored = vault.get_claim(&first)?.expect("predecessor");
    assert_eq!(restored.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(restored.valid_to, None);
    Ok(())
}

// ── ONE-1710 · central lineage-forgery guard ────────────────────────────

/// A body stamped with `source` and an engine-owned `evidence_taint` of
/// `taint` — the exact shape the forger needs to produce to launder a
/// tool-output lineage into a first-person label.
fn lineage_body(predicate: &str, source: ClaimSource, taint: Option<ClaimSource>) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(EntityId::from_bytes([0x51; 16]).expect("valid id")),
        Value::from("value"),
        0.7,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(source);
    if let Some(taint) = taint {
        body.scope = Some(Value::Map(vec![(
            Value::from(CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
            Value::from(taint.as_str()),
        )]));
    }
    body
}

/// Round-trips the body through the WRITE chokepoint, which is where the
/// guard sits — never through a direct call only.
fn validate_through_write_chokepoint(body: &ClaimBody) -> Result<()> {
    let data = encode_claim_body(body)?;
    validate_claim_body_bytes(&data, false)
}

#[test]
fn lineage_guard_rejects_every_upward_move_from_tool_output() {
    for forged in [
        ClaimSource::Generated,
        ClaimSource::Inferred,
        ClaimSource::Observed,
        ClaimSource::UserStated,
    ] {
        let body = lineage_body("profile.name", forged, Some(ClaimSource::ToolOutput));
        let error = validate_through_write_chokepoint(&body)
            .expect_err("a tool-output lineage may not be restamped upward");
        assert_matches!(
            error,
            Error::InvalidClaimBody("claim source widens beyond evidence lineage")
        );
    }

    // Imported is the lattice bottom: EVERY higher class is a widening.
    for forged in [
        ClaimSource::ToolOutput,
        ClaimSource::Generated,
        ClaimSource::Inferred,
        ClaimSource::Observed,
        ClaimSource::UserStated,
    ] {
        let body = lineage_body("profile.name", forged, Some(ClaimSource::Imported));
        assert!(
            validate_through_write_chokepoint(&body).is_err(),
            "imported lineage cannot be relabelled as {}",
            forged.as_str()
        );
    }
}

#[test]
fn lineage_guard_admits_equal_more_restrictive_and_unstamped_bodies() -> Result<()> {
    // Equal labels are the ordinary consolidation shape.
    validate_through_write_chokepoint(&lineage_body(
        "profile.name",
        ClaimSource::ToolOutput,
        Some(ClaimSource::ToolOutput),
    ))?;
    // A MORE restrictive label than the lineage is never a forgery.
    validate_through_write_chokepoint(&lineage_body(
        "profile.name",
        ClaimSource::Imported,
        Some(ClaimSource::Generated),
    ))?;
    // A sourceless legacy/sync-replay body cannot widen anything.
    let mut sourceless = lineage_body(
        "profile.name",
        ClaimSource::Generated,
        Some(ClaimSource::ToolOutput),
    );
    sourceless.source = None;
    validate_through_write_chokepoint(&sourceless)?;
    // No taint stamp at all: nothing to compare against.
    validate_through_write_chokepoint(&lineage_body(
        "profile.name",
        ClaimSource::UserStated,
        None,
    ))?;
    Ok(())
}

#[test]
fn lineage_guard_fails_closed_on_malformed_taint() {
    // Unparseable taint decodes as Imported (the bottom), so a Generated
    // label over it is a widening and is refused rather than admitted.
    let mut body = lineage_body("profile.name", ClaimSource::Generated, None);
    body.scope = Some(Value::Map(vec![(
        Value::from(CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
        Value::from("not-a-source"),
    )]));
    assert!(validate_through_write_chokepoint(&body).is_err());

    // A DUPLICATED taint key is ambiguous and likewise fails closed.
    let mut duplicated = lineage_body("profile.name", ClaimSource::Generated, None);
    duplicated.scope = Some(Value::Map(vec![
        (
            Value::from(CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
            Value::from(ClaimSource::Generated.as_str()),
        ),
        (
            Value::from(CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
            Value::from(ClaimSource::Generated.as_str()),
        ),
    ]));
    assert!(validate_through_write_chokepoint(&duplicated).is_err());
}

#[test]
fn lineage_guard_exempts_engine_reserved_predicates() -> Result<()> {
    // ONE-1314's two-axis actor claims record WHO observed a fact beside the
    // trust class of the chain they observed. The namespaces are unreachable
    // from the generic public Claim API, so the shape is not a laundering
    // path — and rejecting it would break the attribution projector and sync
    // convergence for already-replicated rows.
    for predicate in [PREDICATE_ACTOR_EDIT_COST, PREDICATE_SKILL_EDIT_COST] {
        let body = lineage_body(
            predicate,
            ClaimSource::Observed,
            Some(ClaimSource::ToolOutput),
        );
        assert!(
            validate_claim_source_lineage(&body).is_ok(),
            "{predicate} is engine-reserved and keeps its two independent axes"
        );
    }
    // The exemption is keyed on the PREDICATE, not on the reserved-door
    // flag: an agent-reachable predicate is still refused when the reserved
    // door is open.
    let body = lineage_body(
        "profile.name",
        ClaimSource::Observed,
        Some(ClaimSource::ToolOutput),
    );
    let data = encode_claim_body(&body)?;
    assert!(validate_claim_body_bytes(&data, true).is_err());
    Ok(())
}

#[test]
fn lineage_guard_rank_never_lets_a_stored_source_outrank_its_meet() {
    // Property floor: over every (source, meet) pair the guard admits, the
    // stored rank is never greater than the meet rank.
    let sources = [
        ClaimSource::Imported,
        ClaimSource::ToolOutput,
        ClaimSource::Inferred,
        ClaimSource::Generated,
        ClaimSource::Observed,
        ClaimSource::UserStated,
    ];
    for source in sources {
        for meet in sources {
            let admitted =
                validate_claim_source_lineage(&lineage_body("profile.name", source, Some(meet)))
                    .is_ok();
            assert_eq!(
                admitted,
                !claim_source_widens_beyond(source, meet),
                "{} over {} must be admitted iff it does not widen",
                source.as_str(),
                meet.as_str()
            );
        }
    }
}

#[test]
fn claim_demotion_rung_is_fail_closed_and_ordered() -> Result<()> {
    let subject = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Ada"),
        0.8,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    assert_eq!(claim_demotion_rung(&body)?, None);
    body.scope = Some(Value::Map(vec![(
        Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
        Value::from("decayed"),
    )]));
    assert_eq!(
        claim_demotion_rung(&body)?,
        Some(ClaimDemotionRung::Decayed)
    );
    body.scope = Some(Value::Map(vec![
        (
            Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
            Value::from("decayed"),
        ),
        (
            Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
            Value::from("stale"),
        ),
    ]));
    assert!(claim_demotion_rung(&body).is_err());
    Ok(())
}

/// Every arm of the write-door validator chain must carry a DISTINCT guard.
///
/// The chain is one `else if` ladder, so a second arm repeating an earlier
/// arm's predicate test can never run: the family reaching it was already
/// consumed above. A repeat therefore reads as a validator that is installed
/// when it is not, and the two copies drift apart on the next edit to one of
/// them.
///
/// The scanned source is read at test time rather than `include_str!`d so the
/// guard tracks the file wherever the module split moves it; a floor on the arm
/// count keeps a mislocated scan from passing vacuously.
#[test]
fn claim_validator_chain_has_no_repeated_predicate_guard() {
    use std::collections::BTreeSet;

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/claim/core_types.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {} must succeed: {err}", path.display()));
    let start = src
        .find("pub(crate) fn validate_claim_body_and_decode(")
        .expect("the validator chain must be findable by its function signature");
    let end = start
        + src[start..]
            .find("\n}\n")
            .expect("the validator chain function must terminate");

    // The chain wraps long conditions across lines, so compare on a
    // comment-stripped, whitespace-collapsed rendering of the body.
    let normalized = src[start..end]
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut seen = BTreeSet::new();
    let mut repeated = Vec::new();
    let mut arms = 0_usize;
    for chunk in normalized.split("if ").skip(1) {
        let Some((condition, _)) = chunk.split_once(" {") else {
            continue;
        };
        arms += 1;
        if !seen.insert(condition.trim().to_owned()) {
            repeated.push(condition.trim().to_owned());
        }
    }

    assert!(
        arms >= 20,
        "the validator-chain scan found only {arms} arms in {} — the scan is mislocated",
        path.display(),
    );
    assert!(
        repeated.is_empty(),
        "unreachable duplicate arms in validate_claim_body_and_decode: {repeated:?}",
    );
}

// ── ONE-1728 · scoped read composes the session's out-edges ─────────────

/// Seeds three PERSON entities and one base out-edge `a -> b`, then returns
/// `(a, b, c)` plus the raw base edge row so a caller can stage a sibling row
/// for `c` into an overlay without re-implementing the edge record codec.
fn scoped_read_session_edge_fixture(
    vault: &Vault,
) -> Result<(EntityId, EntityId, EntityId, Vec<u8>)> {
    let ids = [EntityId::now(), EntityId::now(), EntityId::now()];
    for id in &ids {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"node",
        )?;
    }
    let [a, b, c] = ids;
    vault
        .batch()
        .edge(&a, EdgeKind::Mentions, &b, 1.0)
        .commit()?;
    let rtxn = vault.store.env.read_txn()?;
    let mut key = crate::vault::edge_kind_prefix(&a, EdgeKind::Mentions).to_vec();
    key.extend_from_slice(b.as_bytes());
    let value = vault
        .store
        .edges_out
        .get(&rtxn, &key)?
        .expect("base edge row")
        .to_vec();
    drop(rtxn);
    Ok((a, b, c, value))
}

#[test]
fn scoped_read_in_session_sees_session_staged_out_edges() -> Result<()> {
    let (_temp, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let (a, b, c, edge_value) = scoped_read_session_edge_fixture(&vault)?;

    let overlay = crate::session_overlay::SessionOverlay::new(64 * 1024);
    let segment = overlay.install_txn_segment()?;
    let mut staged_key = crate::vault::edge_kind_prefix(&a, EdgeKind::Mentions).to_vec();
    staged_key.extend_from_slice(c.as_bytes());
    overlay.put(
        crate::session_overlay::OverlayKeyspace::EdgesOut,
        &staged_key,
        &edge_value,
    )?;
    segment.commit()?;

    let actor_key = ScopedReadActorKey::new("agent:reader").expect("actor key");
    let base_targets: Vec<EntityId> = vault
        .scoped_read(actor_key.clone())
        .edges_out(&a)?
        .expect("readable")
        .into_iter()
        .map(|edge| edge.target)
        .collect();
    assert_eq!(base_targets, vec![b]);

    let view = vault.store.session_view(overlay)?;
    let mut session_targets: Vec<EntityId> = vault
        .scoped_read_in_session(actor_key, &view)
        .edges_out(&a)?
        .expect("readable")
        .into_iter()
        .map(|edge| edge.target)
        .collect();
    session_targets.sort_unstable();
    let mut expected = vec![b, c];
    expected.sort_unstable();
    assert_eq!(session_targets, expected);
    Ok(())
}
