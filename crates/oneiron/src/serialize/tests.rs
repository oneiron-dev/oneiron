use std::collections::HashMap;

use crate::context_pack::ContextEntity;
use crate::context_pack::ContextPack;
use crate::context_pack::FieldProfile;
use crate::context_pack::PackFormat;
use crate::context_pack::PackStats;
use crate::context_pack::TokenAllocation;
use crate::entity_id::EntityId;
use crate::pipeline::Signal;

use serde_json::{Number, Value};

use super::pack_entry::*;
use crate::registry::ENTITY_TYPE_MACHINE;

fn sample_pack() -> ContextPack {
    let mut claim_fields = HashMap::new();
    claim_fields.insert("pred".to_owned(), Value::String("goal.learning".to_owned()));
    claim_fields.insert(
        "val".to_owned(),
        Value::String("Learn Japanese by June".to_owned()),
    );
    claim_fields.insert(
        "evid".to_owned(),
        Value::Array(vec![
            Value::String("tn17:a1".to_owned()),
            Value::String("tn23:c4".to_owned()),
        ]),
    );

    let mut turn_fields = HashMap::new();
    turn_fields.insert(
        "txt".to_owned(),
        Value::String("I really want to learn Japanese".to_owned()),
    );
    turn_fields.insert("spkr".to_owned(), Value::String("user".to_owned()));
    turn_fields.insert(
        "at".to_owned(),
        Value::Number(Number::from(
            crate::unix_seconds_now().saturating_sub(3 * 86_400),
        )),
    );

    ContextPack {
        capabilities: Vec::new(),
        l2_base: None,
        retrieval_quality: Default::default(),
        results: vec![
            ContextEntity {
                source_revision_ref: None,
                critical: false,
                id: EntityId::from_bytes_unchecked([1; 16]),
                short_id: "cl88".to_owned(),
                content_hash: 0xf2,
                entity_type: 0,
                score: 0.42,
                fields: Some(claim_fields),
                edges: None,
                vector: None,
            },
            ContextEntity {
                source_revision_ref: None,
                critical: false,
                id: EntityId::from_bytes_unchecked([2; 16]),
                short_id: "tn17".to_owned(),
                content_hash: 0xa1,
                entity_type: 1,
                score: 0.39,
                fields: Some(turn_fields),
                edges: None,
                vector: None,
            },
        ],
        neighbors: vec![ContextEntity {
            source_revision_ref: None,
            critical: false,
            id: EntityId::from_bytes_unchecked([3; 16]),
            short_id: "pr05".to_owned(),
            content_hash: 0xb3,
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            score: 0.0,
            fields: Some(HashMap::from([(
                "name".to_owned(),
                Value::String("Alice".to_owned()),
            )])),
            edges: None,
            vector: None,
        }],
        stats: PackStats {
            critical_over_budget: false,
            critical_count: 0,
            candidates_considered: 45,
            signals_used: vec![Signal::Vector, Signal::Text, Signal::Temporal],
            query_time_us: 2_100,
            entities_hydrated: 2,
            neighbors_hydrated: 1,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokens: crate::context_pack::PackTokenStats::default(),
            items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
            items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
        },
        empty: None,
    }
}

fn config(format: PackFormat) -> SerializeConfig {
    SerializeConfig {
        format,
        profile: FieldProfile::Standard,
        budget: 4000,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: 500,
        max_item_tokens: 0,
    }
}

fn savings_config(format: PackFormat, profile: FieldProfile) -> SerializeConfig {
    SerializeConfig {
        format,
        profile,
        budget: 0,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: 500,
        max_item_tokens: 0,
    }
}

#[test]
fn yaml_quotes_scalar_control_characters() {
    let pack = ContextPack {
            capabilities: Vec::new(),
        l2_base: None,
            retrieval_quality: Default::default(),
            results: vec![ContextEntity {
                source_revision_ref: None,
                critical: false,
                id: EntityId::from_bytes_unchecked([0x93; 16]),
                short_id: "mc02".to_owned(),
                content_hash: 0x02,
                entity_type: ENTITY_TYPE_MACHINE,
                score: 0.5,
                fields: Some(HashMap::from([(
                    "text".to_owned(),
                    Value::String(
                        "nul\0bel\x07backspace\x08vertical\x0Bform\x0Cesc\x1Bunit\x1Fdel\x7Fnextline\u{0085}"
                            .to_owned(),
                    ),
                )])),
                edges: None,
                vector: None,
            }],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };

    let text = String::from_utf8(serialize_pack(&pack, &config(PackFormat::Yaml))).expect("utf8");
    assert!(
            text.contains(
                "text: \"nul\\0bel\\abackspace\\bvertical\\vform\\fesc\\eunit\\x1Fdel\\x7Fnextline\\x85\""
            ),
            "{text}"
        );
}

// ── TaskList and Task productivity-band tests ──────────────────

fn empty_stats() -> PackStats {
    PackStats {
        critical_over_budget: false,
        critical_count: 0,
        candidates_considered: 0,
        signals_used: vec![],
        query_time_us: 0,
        entities_hydrated: 0,
        neighbors_hydrated: 0,
        cosine_ghosts_dampened: 0,
        claims_suppressed: 0,
        tokens: crate::context_pack::PackTokenStats::default(),
        items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
        items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
    }
}

#[test]
fn whole_vault_export_nulls_retired_companion_identity_carriers() {
    let person = EntityId::from_bytes_unchecked([0x71; 16]);
    let body = crate::companion::tests::support::retired_persona_facet_body(person);
    for kind in [
        crate::registry::ENTITY_TYPE_FACET,
        crate::companion::ENTITY_TYPE_COMPANION_REGISTER,
    ] {
        assert!(matches!(
            super::ExportBody::from_bytes(&body, kind),
            super::ExportBody::Nulled
        ));
    }
}

#[test]
fn provider_read_formats_have_wire_envelopes_and_null_secrets_before_truncation() {
    for (format, source, field) in [
        (PackFormat::OpenaiCompat, "openai-compat", "messages"),
        (
            PackFormat::AnthropicMessages,
            "anthropic-messages",
            "messages",
        ),
        (PackFormat::Gemini, "gemini-api", "contents"),
    ] {
        let mut pack = sample_pack();
        pack.results[1].fields.as_mut().unwrap().insert(
            "txt".into(),
            serde_json::json!("ghp_0123456789abcdefghijklmnopqrstuvwxyz"),
        );
        let fields = pack.results[1].fields.as_mut().unwrap();
        for key in [
            "apiKey",
            "accessToken",
            "refreshToken",
            "privateKey",
            "ssh_key",
            "API-KEY",
            "bearerToken",
            "authToken",
            "apiToken",
            "passphrase",
        ] {
            fields.insert(key.into(), serde_json::json!("must-not-export"));
        }
        fields.insert(
            "nested".into(),
            serde_json::json!([
                {"private_key": "must-not-export"},
                {"note": "-----BEGIN RSA PRIVATE KEY-----\nbody\n-----END RSA PRIVATE KEY-----"}
            ]),
        );
        let wire = serialize_pack(&pack, &config(format));
        let text = String::from_utf8(wire).unwrap();
        assert!(!text.contains("ghp_"));
        assert!(!text.contains("must-not-export"));
        assert!(!text.contains("BEGIN RSA PRIVATE KEY"));
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["secrets_nulled"], serde_json::json!(true));
        assert!(value[field].as_array().is_some_and(|v| !v.is_empty()));
        for message in value[field].as_array().unwrap() {
            assert!(message["role"].as_str().is_some());
            match format {
                PackFormat::OpenaiCompat => assert!(message["content"].is_string()),
                PackFormat::AnthropicMessages => {
                    for block in message["content"].as_array().unwrap() {
                        assert_eq!(block["type"], "text");
                        assert!(block["text"].is_string());
                    }
                }
                PackFormat::Gemini => {
                    for part in message["parts"].as_array().unwrap() {
                        assert!(part["text"].is_string());
                    }
                }
                _ => unreachable!(),
            }
        }
        let normalized = crate::ingest::INGEST_SOURCE_REGISTRY
            .normalize(source, &text)
            .unwrap();
        assert!(!normalized.records.is_empty());
        let mut small = config(format);
        small.max_field_chars = 10;
        assert!(
            !String::from_utf8(serialize_pack(&pack, &small))
                .unwrap()
                .contains("ghp_")
        );
    }
}

#[test]
fn credentials_are_null_in_every_format_without_an_opt_out() {
    let secret = format!("ghp_{}", "a".repeat(36));
    let mut pack = sample_pack();
    let fields = pack.results[0].fields.as_mut().unwrap();
    fields.insert(
        "val".into(),
        serde_json::json!({
            "api_key": "opaque-key",
            "nested": [{"accessToken": "opaque-token", "password": "opaque-password"}],
            "content": secret,
            "ordinary": "retained"
        }),
    );
    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
    ] {
        let mut cfg = savings_config(format, FieldProfile::Full);
        cfg.max_field_chars = 0;
        let output = String::from_utf8(serialize_pack(&pack, &cfg)).unwrap();
        for forbidden in ["opaque-key", "opaque-token", "opaque-password", &secret] {
            assert!(
                !output.contains(forbidden),
                "{format:?} leaked a credential"
            );
        }
        assert!(output.contains("retained"));
        assert!(output.contains("null"));
    }
    let output: Value = serde_json::from_slice(&serialize_pack(
        &pack,
        &savings_config(PackFormat::Json, FieldProfile::Full),
    ))
    .unwrap();
    assert!(output["claims"][0]["val"]["api_key"].is_null());
    assert!(output["claims"][0]["val"]["nested"][0]["accessToken"].is_null());
}

#[test]
fn whole_vault_provenance_references_are_preserved_only_in_the_typed_value() {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::provenance::{EdgeProvenanceClaimBody, SupersessionStatus};
    let mut provenance =
        EdgeProvenanceClaimBody::new(EntityId::now(), 0.75, SupersessionStatus::Proposed);
    provenance.actor_class = Some(crate::edge::EdgeActorClass::Human);
    provenance.substrate_ref = Some(EntityId::now());
    provenance.source_revision_ref = Some([128; 16]);
    provenance.body_snapshot_ref = Some([129; 16]);
    let mut claim = ClaimBody::new(
        crate::provenance::PREDICATE_EDGE_PROVENANCE,
        ClaimSubject::Edge {
            source: EntityId::now(),
            kind: crate::edge::EdgeKind::DerivedFrom,
            target: EntityId::now(),
        },
        crate::provenance::encode_edge_provenance_value(&provenance),
        0.75,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    claim.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("substrate_ref"),
        rmpv::Value::Binary(vec![128; 16]),
    )]));
    let bytes = crate::claim::encode_claim_body(&claim).unwrap();
    let exported = super::ExportBody::from_bytes(&bytes, crate::registry::ENTITY_TYPE_CLAIM);
    exported
        .validate(crate::registry::ENTITY_TYPE_CLAIM)
        .unwrap();
    let imported = crate::claim::decode_claim_body(&exported.to_bytes().unwrap(), true).unwrap();
    assert_eq!(imported.value, claim.value);
    assert_eq!(
        imported.scope,
        Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("substrate_ref"),
            rmpv::Value::Nil
        )]))
    );
    claim.predicate = "preference.example".into();
    let exported = super::ExportBody::from_bytes(
        &crate::claim::encode_claim_body(&claim).unwrap(),
        crate::registry::ENTITY_TYPE_CLAIM,
    );
    let imported = crate::claim::decode_claim_body(&exported.to_bytes().unwrap(), false).unwrap();
    assert!(crate::provenance::decode_edge_provenance_body(&imported.value).is_err());
}
