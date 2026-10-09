use oneiron::registry::ENTITY_TYPE_FACET;

use super::*;

#[test]
fn retired_companion_facet_projection_never_exposes_private_body() {
    let id = EntityId::from_bytes([0x51; 16]).expect("fixture id");
    let body = rmp_serde::to_vec_named(&json!({
        "kind": "persona",
        "value": {"private_note": "never reveal this identity note"},
        "provenance": {"value": "never reveal this source"}
    }))
    .expect("legacy-shaped FACET");
    for view in [View::Standard, View::Full] {
        let value = project_entity_parts(&id, ENTITY_TYPE_FACET, 5, &body, view);
        let rendered = serde_json::to_string(&value).expect("projection");
        assert!(!rendered.contains("never reveal"));
        if view == View::Full {
            assert_eq!(value["redacted"], "retired_companion_facet_body");
        }
    }
}

#[test]
fn malformed_facet_projection_redacts_body_bytes() {
    let id = EntityId::from_bytes([0x53; 16]).unwrap();
    let value = project_entity_parts(
        &id,
        ENTITY_TYPE_FACET,
        1_777_000_000,
        b"private malformed companion bytes",
        View::Full,
    );

    let rendered = serde_json::to_string(&value).unwrap();
    assert_eq!(value["redacted"], "invalid_facet_body");
    assert!(!rendered.contains("private malformed companion bytes"));
    assert!(!value.as_object().unwrap().contains_key("bodyBytes"));
}
