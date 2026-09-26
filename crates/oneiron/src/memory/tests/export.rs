//! The public export verb renders the full vault and hydratable short refs.
use super::*;

#[test]
fn export_five_formats_and_rehydrate_each_emitted_short_ref() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 31);
    let other = put_person(&vault, 32);
    let memory = facade_for(&vault, actor);
    let actor_ref = memory
        .get_entity(&actor.to_hex())
        .unwrap()
        .unwrap()
        .short_ref
        .unwrap();
    let other_ref = memory
        .get_entity(&other.to_hex())
        .unwrap()
        .unwrap()
        .short_ref
        .unwrap();
    let json = memory
        .export(&ExportOptions {
            format: Some("json".into()),
        })
        .unwrap();
    let document: serde_json::Value = serde_json::from_str(&json.rendered).unwrap();
    assert!(document["manifest"]["secrets_nulled"].as_bool().unwrap());
    let entities = document["evidence_ledger"]["entities"].as_array().unwrap();
    for (id, reference) in [(actor, &actor_ref), (other, &other_ref)] {
        assert!(
            entities
                .iter()
                .any(|row| row["id"] == id.to_hex() && row["short_ref"] == *reference)
        );
    }
    for row in entities
        .iter()
        .chain(document["claims"].as_array().unwrap())
    {
        if let Some(reference) = row["short_ref"].as_str() {
            let (short, hash) = crate::entity_id::parse_short_ref_syntax(reference).unwrap();
            let hydrated = vault.hydrate_short_id(short, hash).unwrap().unwrap();
            assert_eq!(hydrated.id.to_hex(), row["id"].as_str().unwrap());
        }
    }
    let hydrated = memory
        .hydrate(&[actor_ref.clone(), other_ref.clone()])
        .unwrap();
    assert_eq!(
        hydrated.iter().map(|view| &view.id_hex).collect::<Vec<_>>(),
        vec![&actor.to_hex(), &other.to_hex()]
    );
    for format in ["toon", "md", "json", "yaml", "txt"] {
        let export = memory
            .export(&ExportOptions {
                format: Some(format.into()),
            })
            .unwrap();
        assert_eq!(export.format, format);
        assert!(
            export.rendered.contains(&actor_ref),
            "missing actor in {format}"
        );
        assert!(
            export.rendered.contains(&other_ref),
            "missing other in {format}"
        );
        assert!(
            export.rendered.contains("evidence_ledger"),
            "missing full vault in {format}"
        );
    }
    assert_eq!(
        memory.export(&ExportOptions::default()).unwrap().format,
        "toon"
    );
    assert_eq!(
        memory
            .export(&ExportOptions {
                format: Some("gemini".into())
            })
            .unwrap_err()
            .code,
        MEMORY_CODE_BAD_REQUEST
    );
}
