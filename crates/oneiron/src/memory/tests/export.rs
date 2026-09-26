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

#[test]
fn export_uses_current_note_document_in_all_formats_without_rewriting_birth() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 33);
    let memory = facade_for(&vault, actor);
    let receipt = memory
        .author_take(TakeTarget::Subject(actor), "old-only-string")
        .unwrap();
    let note = EntityId::from_hex(&receipt.id_hex).unwrap();
    let birth = vault.get_raw(&note).unwrap().unwrap();
    let initial = vault.note_document(note).unwrap().frontier;
    memory
        .apply_note_ops(
            note,
            &initial,
            &[crate::note::NoteEdit {
                start: 0,
                delete: "old-only-string".chars().count(),
                insert: "new-only-string".into(),
            }],
        )
        .unwrap();
    assert_eq!(vault.get_raw(&note).unwrap().unwrap(), birth);
    for format in ["toon", "md", "json", "yaml", "txt"] {
        let rendered = memory
            .export(&ExportOptions {
                format: Some(format.into()),
            })
            .unwrap()
            .rendered;
        assert!(
            rendered.contains("new-only-string"),
            "stale NOTE in {format}"
        );
        assert!(
            !rendered.contains("old-only-string"),
            "birth NOTE in {format}"
        );
        if format == "json" {
            let raw: serde_json::Value = serde_json::from_str(&rendered).unwrap();
            let entries = raw["evidence_ledger"]["entities"].as_array().unwrap();
            let note_raw = entries
                .iter()
                .find(|row| row["id"] == note.to_hex())
                .unwrap();
            let exported: crate::serialize::ExportBody =
                serde_json::from_value(note_raw["body"].clone()).unwrap();
            let roundtrip = crate::serialize::ExportBody::from_bytes(
                &exported.to_bytes().unwrap(),
                ENTITY_TYPE_NOTE,
            );
            assert_eq!(exported, roundtrip, "NOTE archive body roundtrip");
            let archive = vault.read_whole_vault_json(rendered.as_bytes()).unwrap();
            let row = archive
                .evidence_ledger
                .entities
                .iter()
                .find(|row| row.id == note.to_hex())
                .unwrap();
            let crate::serialize::ExportBody::MessagePack(body) = &row.body else {
                panic!("NOTE must retain a typed MessagePack body");
            };
            let mut encoded = Vec::new();
            rmpv::encode::write_value(&mut encoded, &body.to_msgpack().unwrap()).unwrap();
            assert_eq!(
                crate::note::decode_note_body(&encoded).unwrap().markdown,
                "new-only-string"
            );
        }
    }
    assert_eq!(vault.get_raw(&note).unwrap().unwrap(), birth);
}
