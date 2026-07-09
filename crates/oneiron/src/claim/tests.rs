use super::*;
use core::assert_matches;

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
            PREDICATE_NAMESPACE_EIRI
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
            "{predicate} must start with core.*, companion.*, or eiri.*"
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
    let target = EntityId::from_bytes([0x11; 16]).expect("valid id");
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
                    source: EntityId::from_bytes([0x47; 16]).expect("valid id"),
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
    // The internal door allows the reserved namespace…
    validate_predicate("edge.provenance", true).expect("door must allow edge.*");
    // …but grammar still applies through the door.
    assert_matches!(
        validate_predicate("Edge.Provenance", true),
        Err(Error::InvalidPredicate { .. })
    );
    // "edgework.x" is NOT in the reserved namespace (prefix is segment-exact).
    validate_predicate("edgework.tools", false).expect("edgework.* is not reserved");
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

    let actor = EntityId::from_bytes([0x42; 16]).expect("valid id");
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
        source: EntityId::from_bytes([0x11; 16]).expect("valid id"),
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
    let id = EntityId::from_bytes([0x11; 16]).expect("valid id");
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
    let subj = EntityId::from_bytes([0x11; 16]).expect("valid subject id");
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
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x11; 16]).expect("valid id"));
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
            "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "subj", "scope",
            "appr", "life", "stale",
        ],
        "PsychProfile snapshots must not extend the pinned Claim body ABI"
    );
}

#[test]
fn claim_field_profile_slices_are_prefixes_of_the_pinned_keys() {
    assert_eq!(CLAIM_FIELDS_MINIMAL, &CLAIM_BODY_KEYS[..2]);
    assert_eq!(CLAIM_FIELDS_STANDARD, &CLAIM_BODY_KEYS[..5]);
    assert_eq!(CLAIM_FIELDS_FULL, &CLAIM_BODY_KEYS[..11]);
}

/// D19 literal truth table: `appr ∈ {auto, approved}` ∧ `life = active`
/// ∧ `stale = false` — every other combination is excluded (ARCH-0003;
/// ARCH-0004 §H items 1/2/4).
#[test]
fn claim_surfaceable_pins_the_full_status_truth_table() {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x11; 16]).expect("valid id"));
    let body = |appr: ClaimApprovalStatus, life: ClaimLifecycleStatus, stale: bool| {
        let mut body = ClaimBody::new("test.pred", subject, Value::from("v"), 0.5, appr, life);
        body.stale = stale;
        body
    };

    use ClaimApprovalStatus as A;
    use ClaimLifecycleStatus as L;

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

/// ONE-1159 fix-wave — the WRITE door's surfaceability guard reuses the
/// `claim_surfaceable` approval set: `Approved` is accepted (not only
/// `Auto`), and `Proposed` is a typed reject. Pins the {auto, approved}
/// boundary directly on the door function, independent of the read gate.
#[test]
fn provenance_door_accepts_approved_and_rejects_proposed_wrappers() {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x11; 16]).expect("valid id"));
    // Valid value record (3 required keys), conf mirrors the wrapper, no
    // valid-time on either side, actor-class on the wrapper `evid`.
    let value_record = Value::Map(vec![
        (
            Value::from("actor_entity_ref"),
            Value::Binary(vec![0x42; 16]),
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
