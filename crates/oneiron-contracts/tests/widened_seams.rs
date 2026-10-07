//! Direct calls into the items `oneiron-contracts` made `pub` so `oneiron` can reach them
//! across the crate split. Called from outside the engine, the guards still refuse bad
//! input exactly as they did when they were crate-private.

use oneiron_contracts::affect::{Vad, VadComponent};
use oneiron_contracts::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ReadScope, ScopedReadReceipt,
};
use oneiron_contracts::entity_id::{EntityId, derived_domains, parse_entity_id, serde_hex};
use oneiron_contracts::error::{Error, RegistryError};
use oneiron_contracts::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_NOTE,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_RECEIPT_RECORD,
    ENTITY_TYPE_SKILL_CONTENT_ANCHOR, TYPE_BYTE_FAMILIES, TypeByteFamily,
    VAULT_ID_NAMESPACE_PREFIX, is_delete_protected_engine_record, short_id_prefix,
    static_short_id_prefix_collision, validate_entity_type, validate_entity_type_for_mode,
    validate_public_entity_type,
};
use oneiron_contracts::retrieval_telemetry::{
    RetrievalBlendWeights, validate_retrieval_blend_weights,
};

#[test]
fn derive_refuses_an_empty_or_non_utf8_domain() {
    for domain in [&b""[..], &[0xFF, 0xFE][..]] {
        let refused = EntityId::derive(domain, &[b"part"]);
        assert!(
            matches!(refused, Err(Error::InvariantViolation(_))),
            "{refused:?}"
        );
    }
    let id = EntityId::derive(derived_domains::KEY_VALUE, &[b"part"]).unwrap();
    assert_eq!(id.as_bytes()[6] >> 4, 8, "derived ids carry version eight");
}

#[test]
fn parse_entity_id_refuses_short_rows_and_sentinels() {
    let short = parse_entity_id(&[0x11; 15], "probe");
    assert!(
        matches!(short, Err(Error::CorruptedIndex("probe"))),
        "{short:?}"
    );
    for sentinel in [[0x00; 16], [0xFF; 16]] {
        let refused = parse_entity_id(&sentinel, "probe");
        assert!(matches!(refused, Err(Error::InvalidKey)), "{refused:?}");
    }
}

#[test]
fn entity_type_validators_refuse_reserved_and_engine_only_bytes() {
    for dev in [false, true] {
        assert!(validate_entity_type_for_mode(255, dev).is_err(), "sentinel");
        assert!(
            validate_entity_type_for_mode(130, dev).is_err(),
            "pack handle"
        );
    }
    assert!(
        validate_entity_type_for_mode(126, false).is_err(),
        "experimental zone outside dev"
    );
    let engine_only = validate_public_entity_type(ENTITY_TYPE_AUTHORITY_LOG);
    assert!(
        matches!(
            engine_only,
            Err(Error::Registry(RegistryError::MaintenanceKindNotWritable(
                _
            )))
        ),
        "{engine_only:?}"
    );
    assert!(validate_public_entity_type(ENTITY_TYPE_PERSON).is_ok());
}

#[test]
fn record_axes_derives_axes_without_widening_a_receipt() {
    let scope = |band| ReadScope {
        entity_types: None,
        max_sensitivity_band: band,
        include_stale: false,
        min_confidence: 0.0,
        min_salience: 0.0,
        deny_all: false,
    };
    let mut receipt = ScopedReadReceipt {
        requested: scope(3),
        actor_ceiling: scope(1),
        applied: scope(1),
        narrowed_axes: Vec::new(),
        suppressed_count: 0,
        replan_hint: Vec::new(),
    };
    let before = receipt.clone();
    receipt.record_axes();
    assert_eq!(receipt.requested, before.requested);
    assert_eq!(receipt.actor_ceiling, before.actor_ceiling);
    assert_eq!(receipt.applied, before.applied);
    assert_eq!(receipt.narrowed_axes, ["max_sensitivity_band"]);
    assert_eq!(receipt.replan_hint, receipt.narrowed_axes);
}

#[test]
fn claim_status_parsers_refuse_unknown_and_case_shifted_names() {
    for value in ["", "Approved", "approved ", "pending"] {
        assert_eq!(ClaimApprovalStatus::parse(value), None, "{value:?}");
    }
    assert_eq!(
        ClaimApprovalStatus::parse("approved"),
        Some(ClaimApprovalStatus::Approved)
    );
    for value in ["", "Active", "deleted"] {
        assert_eq!(ClaimLifecycleStatus::parse(value), None, "{value:?}");
    }
    assert_eq!(
        ClaimLifecycleStatus::parse("retracted"),
        Some(ClaimLifecycleStatus::Retracted)
    );
    for value in ["", "User_Stated", "hearsay"] {
        assert_eq!(ClaimSource::parse(value), None, "{value:?}");
    }
    assert_eq!(
        ClaimSource::parse("tool_output"),
        Some(ClaimSource::ToolOutput)
    );
}

#[test]
fn delete_protection_covers_every_engine_record_and_no_public_kind() {
    for kind in [
        ENTITY_TYPE_POLICY_MANIFEST,
        ENTITY_TYPE_AUTHORITY_LOG,
        ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
        ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        ENTITY_TYPE_RECEIPT_RECORD,
    ] {
        assert!(is_delete_protected_engine_record(kind), "{kind}");
    }
    for kind in [ENTITY_TYPE_PERSON, ENTITY_TYPE_NOTE, 0, 255] {
        assert!(!is_delete_protected_engine_record(kind), "{kind}");
    }
}

#[test]
fn family_codes_refuse_zero_and_codes_past_the_table() {
    let past = u8::try_from(TYPE_BYTE_FAMILIES.len() + 1).unwrap();
    for code in [0, past, u8::MAX] {
        assert_eq!(TypeByteFamily::from_code(code), None, "{code}");
    }
    for entry in TYPE_BYTE_FAMILIES {
        assert_eq!(
            TypeByteFamily::from_code(entry.family.code()),
            Some(entry.family)
        );
    }
}

#[test]
fn entity_id_hex_codec_refuses_malformed_and_sentinel_ids() {
    let zeros = format!("\"{}\"", "0".repeat(32));
    for text in ["\"\"", "\"zz\"", "\"0011\"", zeros.as_str()] {
        let mut de = serde_json::Deserializer::from_str(text);
        assert!(serde_hex::deserialize(&mut de).is_err(), "{text}");
        let mut de = serde_json::Deserializer::from_str(text);
        assert!(serde_hex::optional::deserialize(&mut de).is_err(), "{text}");
    }
    let id = EntityId::from_bytes([0x11; 16]).unwrap();
    let text = format!("\"{}\"", id.to_hex());
    let mut de = serde_json::Deserializer::from_str(&text);
    assert_eq!(serde_hex::deserialize(&mut de).unwrap(), id);
}

#[test]
fn only_imported_tool_and_generated_sources_need_an_explicit_auto_permit() {
    for source in [
        ClaimSource::Imported,
        ClaimSource::ToolOutput,
        ClaimSource::Generated,
    ] {
        assert!(source.requires_explicit_auto_permit(), "{source:?}");
    }
    for source in [
        ClaimSource::UserStated,
        ClaimSource::Observed,
        ClaimSource::Inferred,
    ] {
        assert!(!source.requires_explicit_auto_permit(), "{source:?}");
    }
}

#[test]
fn vad_and_vector_checks_refuse_non_finite_and_out_of_range_components() {
    let component = |valence, arousal, dominance| {
        Vad {
            valence,
            arousal,
            dominance,
        }
        .invalid_component()
        .map(|(component, _)| component)
    };
    assert_eq!(component(f32::NAN, 0.5, 0.5), Some(VadComponent::Valence));
    assert_eq!(
        component(0.0, f32::INFINITY, 0.5),
        Some(VadComponent::Arousal)
    );
    assert_eq!(component(-1.5, 0.5, 0.5), Some(VadComponent::Valence));
    assert_eq!(component(0.0, -0.1, 0.5), Some(VadComponent::Arousal));
    assert_eq!(component(0.0, 0.5, 1.5), Some(VadComponent::Dominance));
    assert_eq!(component(-1.0, 0.0, 1.0), None);

    let refused = Error::invalid_vector_component(&[0.5, f32::NAN, 1.0]);
    assert!(
        matches!(refused, Some(Error::InvalidVector { index: 1, .. })),
        "{refused:?}"
    );
    assert!(Error::invalid_vector_component(&[0.5, -2.0]).is_none());
}

#[test]
fn the_entity_type_wrapper_and_prefix_check_refuse_reserved_and_taken_names() {
    for kind in [255, 130] {
        assert!(validate_entity_type(kind).is_err(), "{kind}");
    }
    assert!(validate_entity_type(ENTITY_TYPE_PERSON).is_ok());

    let person = short_id_prefix(ENTITY_TYPE_PERSON).unwrap();
    assert!(static_short_id_prefix_collision(person));
    assert!(static_short_id_prefix_collision(VAULT_ID_NAMESPACE_PREFIX));
    assert!(!static_short_id_prefix_collision("unregistered-prefix"));
}

#[test]
fn blend_weights_refuse_non_finite_negative_and_massless_tables() {
    for weights in [
        RetrievalBlendWeights::new(f32::NAN, 0.3, 0.2, 0.1),
        RetrievalBlendWeights::new(0.4, f32::INFINITY, 0.2, 0.1),
        RetrievalBlendWeights::new(0.4, 0.3, -0.2, 0.1),
        RetrievalBlendWeights::new(0.0, 0.0, 0.0, 0.0),
    ] {
        assert!(
            validate_retrieval_blend_weights(weights).is_err(),
            "{weights:?}"
        );
        let refused = weights.normalized();
        assert!(
            matches!(refused, Err(Error::InvalidConfig(_))),
            "{refused:?}"
        );
    }
    let normalized = RetrievalBlendWeights::new(2.0, 1.0, 1.0, 0.0)
        .normalized()
        .unwrap();
    assert_eq!(normalized, RetrievalBlendWeights::new(0.5, 0.25, 0.25, 0.0));
}
