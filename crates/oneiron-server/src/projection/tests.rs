use oneiron::registry::ENTITY_TYPE_FACET;

use super::*;

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("fresh vault");
    (dir, vault)
}

#[test]
fn retired_companion_facet_projection_never_exposes_private_body() {
    let id = EntityId::from_bytes([0x51; 16]).expect("fixture id");
    let body = rmp_serde::to_vec_named(&json!({
        "kind": "persona",
        "value": {"private_note": "never reveal this identity note"},
        "provenance": {"value": "never reveal this source"}
    }))
    .expect("legacy-shaped FACET");
    let (_dir, vault) = fresh_vault();
    for view in [View::Standard, View::Full] {
        let value = project_entity_parts(&vault, &id, ENTITY_TYPE_FACET, 5, &body, view);
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
    let (_dir, vault) = fresh_vault();
    let value = project_entity_parts(
        &vault,
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
