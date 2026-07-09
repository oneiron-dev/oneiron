use std::collections::BTreeSet;

use oneiron::companion::ENTITY_TYPE_COMPANION_REGISTER;
use oneiron::registry::ENTITY_TYPE_REGISTRY;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, CompanionExportClassification, CompanionProvenance,
    CompanionRecord, CompanionScope, EdgeActorClass, companion_value_from_json,
    encode_companion_record_body,
};

use super::*;

#[test]
fn view_deserializes_contract_literals() {
    assert_eq!(
        serde_json::from_str::<View>("\"summary\"").unwrap(),
        View::Summary
    );
    assert_eq!(
        serde_json::from_str::<View>("\"standard\"").unwrap(),
        View::Standard
    );
    assert_eq!(
        serde_json::from_str::<View>("\"full\"").unwrap(),
        View::Full
    );
    assert!(serde_json::from_str::<View>("\"tiny\"").is_err());
}

#[test]
fn entity_projection_field_sets_are_subsets_of_full() {
    for entry in ENTITY_TYPE_REGISTRY {
        let full: BTreeSet<_> = entity_projection_keys(entry.type_byte, View::Full)
            .into_iter()
            .collect();
        for summary_key in entity_projection_keys(entry.type_byte, View::Summary) {
            assert!(
                full.contains(summary_key),
                "{} summary key {summary_key} missing from full",
                entry.kind
            );
        }
        for standard_key in entity_projection_keys(entry.type_byte, View::Standard) {
            assert!(
                full.contains(standard_key),
                "{} standard key {standard_key} missing from full",
                entry.kind
            );
        }
    }
}

#[test]
fn summary_projection_has_exact_contract_keys() {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({
        "title": "Ship projection",
        "body": "heavy body",
        "metadata": {"large": true}
    }))
    .unwrap();
    let value = project_entity_parts(&id, ENTITY_TYPE_TASK, 1_777_000_000, &body, View::Summary);
    let keys: BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, BTreeSet::from(["id", "kind", "label", "updatedAt"]));
    assert!(!value.as_object().unwrap().contains_key("body"));
    assert!(!value.as_object().unwrap().contains_key("metadata"));
}

#[test]
fn full_projection_preserves_recognized_entity_body_and_custom_fields() {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({
        "title": "Ship projection",
        "role": "agent",
        "status": "open",
        "priority": 2,
        "dueDate": 1_777_100_000_u64,
        "body": "full body text",
        "custom": {"nested": true}
    }))
    .unwrap();
    let standard =
        project_entity_parts(&id, ENTITY_TYPE_TASK, 1_777_000_000, &body, View::Standard);
    let full = project_entity_parts(&id, ENTITY_TYPE_TASK, 1_777_000_000, &body, View::Full);
    let standard_object = standard.as_object().unwrap();
    let full_object = full.as_object().unwrap();

    for key in standard_object.keys() {
        assert_eq!(
            full_object.get(key),
            standard_object.get(key),
            "full must preserve standard field {key}"
        );
    }
    assert_eq!(full["body"], "full body text");
    assert_eq!(full["custom"], json!({"nested": true}));
    assert_eq!(full["id"], id.to_hex());
    assert_eq!(full["kind"], "TASK");
    assert_eq!(full["label"], "Ship projection");
    assert_eq!(full["updatedAt"], 1_777_000_000_u64);
}

#[test]
fn skill_full_projection_exposes_reliability_metadata() {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({
        "skillId": "oneiron.skill.full",
        "desc": "Full SKILL projection",
        "version": "1.0.0",
        "approvalStatus": "approved",
        "lifecycleStatus": "active",
        "source": "user_stated",
        "confidence": 1.0,
        "generated": false,
        "humanAuthored": true,
        "dependencies": [{"skillId": "oneiron.skill.base", "minVersion": "1.0.0"}],
        "provenance": {"source": "fixture"}
    }))
    .unwrap();

    let full = project_entity_parts(&id, ENTITY_TYPE_SKILL, 1_777_000_000, &body, View::Full);
    let full_object = full.as_object().unwrap();
    for key in SKILL_RECORD_BODY_KEYS {
        assert!(
            full_object.contains_key(key),
            "full SKILL projection must include {key}"
        );
    }
    assert_eq!(full["generated"], false);
    assert_eq!(full["humanAuthored"], true);
    assert_eq!(full["dependencies"][0]["skillId"], "oneiron.skill.base");
    assert_eq!(full["provenance"]["source"], "fixture");
}

#[test]
fn companion_register_api_projection_redacts_private_values() {
    let id = EntityId::from_bytes([0x51; 16]).unwrap();
    let actor = EntityId::from_bytes([0x52; 16]).unwrap();
    let record = CompanionRecord::persona(
        CompanionScope::neutral(),
        id,
        companion_value_from_json(&json!({
            "note": "private companion projection note",
        }))
        .unwrap(),
        CompanionProvenance::new(
            actor,
            EdgeActorClass::Agent,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            companion_value_from_json(&json!({
                "note": "private companion provenance note",
            }))
            .unwrap(),
        ),
        CompanionExportClassification::Portable,
    );
    let body = encode_companion_record_body(&record.created_at(1_777_000_000).unwrap()).unwrap();

    for view in [View::Standard, View::Full] {
        let value = project_entity_parts(
            &id,
            ENTITY_TYPE_COMPANION_REGISTER,
            1_777_000_000,
            &body,
            view,
        );
        let rendered = serde_json::to_string(&value).unwrap();
        assert!(!rendered.contains("private companion projection note"));
        assert!(!rendered.contains("private companion provenance note"));
        assert!(
            value
                .as_object()
                .unwrap()
                .get("provenance")
                .and_then(Value::as_object)
                .is_some_and(|provenance| !provenance.contains_key("value")),
            "projection provenance must omit opaque provenance.value"
        );
        assert_eq!(
            value.get("lifecycle_events"),
            Some(&json!([{ "kind": "created", "at": 1_777_000_000_u64 }]))
        );
    }
}

#[test]
fn companion_register_api_projection_redacts_malformed_body_bytes() {
    let id = EntityId::from_bytes([0x53; 16]).unwrap();
    let value = project_entity_parts(
        &id,
        ENTITY_TYPE_COMPANION_REGISTER,
        1_777_000_000,
        b"private malformed companion bytes",
        View::Full,
    );

    let rendered = serde_json::to_string(&value).unwrap();
    assert_eq!(value["redacted"], "invalid_companion_register_body");
    assert!(!rendered.contains("private malformed companion bytes"));
    assert!(!value.as_object().unwrap().contains_key("bodyBytes"));
}
