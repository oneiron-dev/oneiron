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

#[cfg(feature = "sync")]
#[test]
fn export_streamed_message_uses_committed_document_not_pointer_or_partial() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 34);
    let memory = facade_for(&vault, actor);
    let message = EntityId::now();
    let turn = WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        occurred_at: 10,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "dialogue".into(),
            content: String::new(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    };
    let first = memory
        .begin_message_stream(&turn, Some(MessageWriteMode::Atomic))
        .unwrap();
    memory
        .append_to_stream(first, "export-stream-base")
        .unwrap();
    memory.finalize_stream(first).unwrap();
    let continuation = memory
        .begin_message_stream(&turn, Some(MessageWriteMode::Atomic))
        .unwrap();
    memory.append_to_stream(continuation, "-committed").unwrap();
    memory.finalize_stream(continuation).unwrap();
    let raw = vault.get_raw(&message).unwrap().unwrap();
    let raw_body: serde_json::Value =
        rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..]).unwrap();
    assert_eq!(raw_body["entity_doc_ref"], message.to_hex());
    assert!(raw_body.get("content").is_none());
    let partial = memory
        .begin_message_stream(&turn, Some(MessageWriteMode::Atomic))
        .unwrap();
    memory
        .append_to_stream(partial, "-uncommitted-tail")
        .unwrap();
    let expected = "export-stream-base-committed";
    for format in ["toon", "md", "json", "yaml", "txt"] {
        let export = memory
            .export(&ExportOptions {
                format: Some(format.into()),
            })
            .unwrap();
        assert!(
            export.rendered.contains(expected),
            "missing committed MESSAGE in {format}"
        );
        assert!(
            !export.rendered.contains("-uncommitted-tail"),
            "partial leaked in {format}"
        );
        if format == "json" {
            let archive = vault
                .read_whole_vault_json(export.rendered.as_bytes())
                .unwrap();
            let row = archive
                .evidence_ledger
                .entities
                .iter()
                .find(|row| row.id == message.to_hex())
                .unwrap();
            let body: serde_json::Value =
                rmp_serde::from_slice(&row.body.to_bytes().unwrap()).unwrap();
            assert_eq!(body["content"], expected);
            assert!(body.get("entity_doc_ref").is_none());
        }
    }
    assert_eq!(vault.get_raw(&message).unwrap().unwrap(), raw);
}

#[cfg(feature = "sync")]
#[test]
fn export_migrated_note_and_asset_text_uses_committed_document() {
    use crate::consent::AuthenticatedOwner;
    use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
    use crate::write_envelope::WriteActor;

    fn append(
        vault: &crate::Vault,
        id: EntityId,
        actor: WriteActor,
        owner: &AuthenticatedOwner,
        suffix: &str,
    ) {
        let length = vault.entity_text(&id).unwrap().chars().count();
        let anchor = vault.entity_text_anchor(&id, length, length).unwrap();
        vault
            .edit_entity_text(
                &id,
                &[AnchoredEdit {
                    actor: Some(actor),
                    verb: EditVerb::AppendToSection {
                        section: anchor,
                        text: suffix.into(),
                    },
                }],
                &DocAuthorization::Owner(owner),
                20,
            )
            .unwrap();
    }

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 35);
    let memory = facade_for(&vault, actor);
    let writer = WriteActor::new(actor, EdgeActorClass::Human);
    let owner = vault
        .authenticate_owner(
            actor,
            "principal:export-document-test",
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let asset = EntityId::now();
    vault
        .put_entity(
            &asset,
            ENTITY_TYPE_ASSET,
            test_time(1),
            1,
            b"asset-document-base",
        )
        .unwrap();
    vault
        .migrate_entity_text(
            &asset,
            &TextField::Utf8Body,
            writer,
            &DocAuthorization::Owner(&owner),
        )
        .unwrap();
    let note = memory
        .author_take(TakeTarget::Subject(actor), "note-document-base")
        .unwrap();
    let note = EntityId::from_hex(&note.id_hex).unwrap();
    vault
        .migrate_entity_text(
            &note,
            &TextField::MapField("markdown".into()),
            writer,
            &DocAuthorization::Owner(&owner),
        )
        .unwrap();
    append(&vault, asset, writer, &owner, "-current");
    append(&vault, note, writer, &owner, "-current");
    let asset_pointer = vault.get_raw(&asset).unwrap().unwrap();
    let note_pointer = vault.get_raw(&note).unwrap().unwrap();
    assert!(
        !asset_pointer
            .windows(b"asset-document-base".len())
            .any(|slice| slice == b"asset-document-base")
    );
    assert!(
        !note_pointer
            .windows(b"note-document-base".len())
            .any(|slice| slice == b"note-document-base")
    );
    for format in ["toon", "md", "json", "yaml", "txt"] {
        let export = memory
            .export(&ExportOptions {
                format: Some(format.into()),
            })
            .unwrap();
        for expected in ["asset-document-base-current", "note-document-base-current"] {
            assert!(
                export.rendered.contains(expected),
                "missing {expected} in {format}"
            );
        }
        if format == "json" {
            let archive = vault
                .read_whole_vault_json(export.rendered.as_bytes())
                .unwrap();
            let asset_row = archive
                .evidence_ledger
                .entities
                .iter()
                .find(|row| row.id == asset.to_hex())
                .unwrap();
            assert_eq!(
                asset_row.body.to_bytes().unwrap(),
                b"asset-document-base-current"
            );
            let note_row = archive
                .evidence_ledger
                .entities
                .iter()
                .find(|row| row.id == note.to_hex())
                .unwrap();
            assert_eq!(
                crate::note::decode_note_body(&note_row.body.to_bytes().unwrap())
                    .unwrap()
                    .markdown,
                "note-document-base-current"
            );
        }
    }
    assert_eq!(vault.get_raw(&asset).unwrap().unwrap(), asset_pointer);
    assert_eq!(vault.get_raw(&note).unwrap().unwrap(), note_pointer);
}
