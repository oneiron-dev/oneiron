//! The public export verb renders the full vault and hydratable short refs.
use super::*;

fn owner_vault() -> (tempfile::TempDir, crate::Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open_owned(dir.path(), VaultConfig::default()).unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    (dir, vault, owner)
}

#[test]
fn export_five_formats_and_rehydrate_each_emitted_short_ref() {
    let (_dir, vault, actor) = owner_vault();
    let other = put_person(&vault, 32);
    let memory = facade_for(&vault, actor);
    let actor_ref = memory
        .get_entity(&actor.to_hex())
        .unwrap()
        .value
        .unwrap()
        .short_ref
        .unwrap();
    let other_ref = memory
        .get_entity(&other.to_hex())
        .unwrap()
        .value
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
    let (_dir, vault, actor) = owner_vault();
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
    let (_dir, vault, actor) = owner_vault();
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
    let conversation = EntityId::from_hex(&turn.conversation_ref).unwrap();
    assert_eq!(
        vault
            .conversation_last_message_snippet(&conversation)
            .unwrap()
            .as_deref(),
        Some(expected),
        "only committed stream text may appear inline"
    );
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
fn preview_migrated_edited_message_reads_committed_document() {
    use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
    use crate::write_envelope::WriteActor;

    let (_dir, vault, actor) = owner_vault();
    let memory = facade_for(&vault, actor);
    let conversation = EntityId::now();
    let message = EntityId::now();
    memory
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            occurred_at: 10,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: "migrated base".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    let writer = WriteActor::new(actor, EdgeActorClass::Human);
    let owner = vault
        .authenticate_owner(
            actor,
            "principal:preview-document-test",
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    vault
        .migrate_entity_text(
            &message,
            &TextField::MapField("content".into()),
            writer,
            &DocAuthorization::Owner(&owner),
        )
        .unwrap();
    let raw = vault.get_raw(&message).unwrap().unwrap();
    let body: serde_json::Value =
        rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..]).unwrap();
    assert!(body.get("content").is_none());
    let end = vault.entity_text(&message).unwrap().chars().count();
    let anchor = vault.entity_text_anchor(&message, end, end).unwrap();
    vault
        .edit_entity_text(
            &message,
            &[AnchoredEdit {
                actor: Some(writer),
                verb: EditVerb::AppendToSection {
                    section: anchor,
                    text: " and current".into(),
                },
            }],
            &DocAuthorization::Owner(&owner),
            20,
        )
        .unwrap();
    assert_eq!(
        vault
            .conversation_last_message_snippet(&conversation)
            .unwrap()
            .as_deref(),
        Some("migrated base and current")
    );
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

    let (_dir, vault, actor) = owner_vault();
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

#[test]
fn export_refuses_other_people_and_unleased_owner_handles() {
    let (_dir, vault, owner) = owner_vault();
    let other = put_person(&vault, 36);
    assert_eq!(
        facade_for(&vault, other)
            .export(&ExportOptions::default())
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    assert!(
        facade_for(&vault, owner)
            .export(&ExportOptions::default())
            .is_ok()
    );
    let (_unleased_dir, unleased) = open_vault();
    let owner = unleased.ensure_embedded_owner_actor().unwrap();
    assert_eq!(
        facade_for(&unleased, owner)
            .export(&ExportOptions::default())
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
}

/// engine-prs-13: a live full slip is not the Owner role. Its holder exports
/// the whole vault only while it is an owner of this vault.
#[test]
fn a_live_full_slip_without_the_owner_role_does_not_export_the_vault() {
    use crate::authority::HostSlipIssuer;
    let (_dir, vault, _owner) = owner_vault();
    let other = put_person(&vault, 41);
    let issuer = HostSlipIssuer::from_secret(b"fixture-export-non-owner-root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(b"full-vault-export-non-owner").as_bytes();
    claims.parent_id = None;
    claims.holder_ref = other.to_hex();
    claims.actor_class = Some("human".into());
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let proof = vault
        .verify_capability_slip(
            &issuer.public_key(),
            &slip,
            b"export-non-owner-test",
            &issuer
                .binding_proof(&slip, b"export-non-owner-test")
                .unwrap(),
        )
        .unwrap();
    assert!(proof.is_full_vault_owner_grade());
    assert_eq!(
        facade_for(&vault, other)
            .export_with_verified_owner(&ExportOptions::default(), &proof)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    assert!(vault.export_receipts().unwrap().is_empty());
}

/// A deleted owner exports nothing with the slip it still holds (Sol review
/// 2). A plain delete keeps the PERSON shell and its Active lifecycle, so the
/// live-owner check reads the deletion tombstone too.
#[test]
fn a_deleted_owner_does_not_export_the_vault_with_a_live_slip() {
    use crate::authority::HostSlipIssuer;
    let (_dir, vault, actor) = owner_vault();
    let issuer = HostSlipIssuer::from_secret(b"fixture-export-deleted-owner-root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(b"full-vault-export-deleted-owner").as_bytes();
    claims.parent_id = None;
    claims.holder_ref = actor.to_hex();
    claims.actor_class = Some("human".into());
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let proof = vault
        .verify_capability_slip(
            &issuer.public_key(),
            &slip,
            b"export-deleted-owner-test",
            &issuer
                .binding_proof(&slip, b"export-deleted-owner-test")
                .unwrap(),
        )
        .unwrap();
    let memory = facade_for(&vault, actor);
    assert!(
        memory
            .export_with_verified_owner(&ExportOptions::default(), &proof)
            .is_ok()
    );
    assert!(vault.delete_entity(&actor).unwrap());
    assert_eq!(
        memory
            .export_with_verified_owner(&ExportOptions::default(), &proof)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
}

#[test]
fn verified_owner_export_rechecks_read_only_and_revoked_slips() {
    use crate::authority::HostSlipIssuer;
    use crate::federation::ScopeAxis;
    let (_dir, vault, actor) = owner_vault();
    let issuer = HostSlipIssuer::from_secret(b"fixture-export-owner-root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(b"full-vault-export-identified-owner").as_bytes();
    claims.parent_id = None;
    claims.holder_ref = actor.to_hex();
    claims.actor_class = Some("human".into());
    let slip = vault.mint_capability_slip(&issuer, claims.clone()).unwrap();
    let proof = vault
        .verify_capability_slip(
            &issuer.public_key(),
            &slip,
            b"export-owner-test",
            &issuer.binding_proof(&slip, b"export-owner-test").unwrap(),
        )
        .unwrap();
    let memory = facade_for(&vault, actor);
    assert!(
        memory
            .export_with_verified_owner(&ExportOptions::default(), &proof)
            .is_ok()
    );

    claims.slip_id = *blake3::hash(b"full-vault-export-read-only").as_bytes();
    claims.scope.verbs = ScopeAxis::Some(std::collections::BTreeSet::from(["read".into()]));
    let read_only = vault.mint_capability_slip(&issuer, claims).unwrap();
    let narrow = vault
        .verify_capability_slip(
            &issuer.public_key(),
            &read_only,
            b"export-read-only-test",
            &issuer
                .binding_proof(&read_only, b"export-read-only-test")
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        memory
            .export_with_verified_owner(&ExportOptions::default(), &narrow)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    vault
        .revoke_capability_slip(&issuer, slip.claims.slip_id)
        .unwrap();
    assert_eq!(
        memory
            .export_with_verified_owner(&ExportOptions::default(), &proof)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
}

#[test]
fn conflicting_authority_roots_suspend_embedded_export() {
    let (_dir, vault, actor) = owner_vault();
    let (a, _) = authority_root(0x76);
    let (b, _) = authority_root(0x77);
    vault
        .put_authority_log_entries(&[(a, test_time(1), 1), (b, test_time(2), 2)])
        .unwrap();
    assert!(vault.authority_fold().unwrap().vault_root_is_conflicted());
    assert_eq!(
        facade_for(&vault, actor)
            .export(&ExportOptions::default())
            .unwrap_err()
            .code,
        MEMORY_CODE_INVALID_STATE
    );
}

#[test]
fn every_export_lands_a_receipt_and_a_refused_one_lands_none() {
    let (_dir, vault, owner) = owner_vault();
    let other = put_person(&vault, 38);
    assert!(
        facade_for(&vault, other)
            .export(&ExportOptions::default())
            .is_err()
    );
    assert!(vault.export_receipts().unwrap().is_empty());
    let export = facade_for(&vault, owner)
        .export(&ExportOptions {
            format: Some("md".into()),
        })
        .unwrap();
    let receipts = vault.export_receipts().unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].format, "md");
    assert_eq!(receipts[0].bytes, export.rendered.len() as u64);
    assert_eq!(
        receipts[0].digest,
        blake3::hash(export.rendered.as_bytes())
            .to_hex()
            .to_string()
    );
    assert_eq!(receipts[0].by, owner.to_hex());
    facade_for(&vault, owner)
        .export(&ExportOptions::default())
        .unwrap();
    assert_eq!(vault.export_receipts().unwrap().len(), 2);
}

/// The public BIP39 test vector, as a recovery phrase's words.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// The phrase a word per 64-bit number, with two floats between its halves
/// whose widths no JSON number keeps: read at either width alone, each float
/// puts a non-list word into the run.
fn phrase_in_numbers() -> Vec<Value> {
    let mut items: Vec<Value> = PHRASE
        .split(' ')
        .map(|word| {
            let mut padded = [b' '; 8];
            padded[..word.len()].copy_from_slice(word.as_bytes());
            Value::from(u64::from_be_bytes(padded))
        })
        .collect();
    items.insert(6, Value::F32(f32::from_bits(0x4000_0208)));
    items.insert(7, Value::F64(f64::from_bits(0x4088_0000_0000_0000)));
    items
}

/// An owner vault whose write scan is off, as an owner may switch it.
fn scan_off_vault() -> (tempfile::TempDir, crate::Vault, EntityId) {
    let (dir, vault, owner) = owner_vault();
    let id = crate::vault::embedded_owner_actor_id().unwrap();
    let authenticated = vault
        .authenticate_owner(id, &id.to_hex(), true, crate::store::GateDecisionId::now())
        .unwrap();
    vault
        .set_secret_scan_mode(
            &authenticated,
            crate::batch::secret_scan::SecretScanMode::Off,
            10,
        )
        .unwrap();
    (dir, vault, owner)
}

/// `value` stored as an ASSET body and as a claim's value, served back by
/// `get_entity` and `claim_list`.
fn served_both_ways(
    vault: &crate::Vault,
    owner: EntityId,
    value: Value,
    seed: u8,
) -> [serde_json::Value; 2] {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &value).unwrap();
    let asset = EntityId::now();
    vault
        .batch()
        .put(&asset, ENTITY_TYPE_ASSET, test_time(5), 5, &body)
        .commit()
        .unwrap();
    let subject = put_person(vault, seed);
    let mut claim = crate::claim::ClaimBody::new(
        "profile.note",
        crate::claim::ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    claim.source = Some(crate::claim::ClaimSource::UserStated);
    vault
        .put_claim(&EntityId::now(), &claim, test_time(6), 6)
        .unwrap();

    let memory = facade_for(vault, owner);
    let asset = memory.get_entity(&asset.to_hex()).unwrap().value.unwrap();
    let claims = memory
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: None,
            lifecycle: None,
            limit: 10,
        })
        .unwrap()
        .value;
    assert_eq!(claims.len(), 1);
    [asset.body.unwrap_or_default(), claims[0].value.clone()]
}

#[test]
fn memory_reads_read_messagepack_before_projecting_it() {
    let (_dir, vault, owner) = scan_off_vault();
    let value = Value::Array(phrase_in_numbers());
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &value).unwrap();
    assert!(crate::batch::secret_scan::scan_write_payload(&body).is_err());
    for served in served_both_ways(&vault, owner, value, 0x6b) {
        // Read back through MessagePack, as the projection was read from it.
        let mut bytes = Vec::new();
        rmpv::encode::write_value(
            &mut bytes,
            &serde_json::from_value::<Value>(served.clone()).unwrap(),
        )
        .unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains("sausage"),
            "{served}"
        );
    }
}

#[test]
fn memory_reads_read_the_projection_they_serve() {
    let (_dir, vault, owner) = scan_off_vault();
    // Sol R8: a safe binary keeps the numbers' words apart until the
    // projection nulls it; a line break, then the phrase whole under a
    // credential name.
    let mut items = phrase_in_numbers();
    items.insert(6, Value::Binary(b"PROSE".to_vec()));
    let value = Value::Array(vec![
        Value::Array(items),
        Value::from("\n"),
        Value::Map(vec![(Value::from("password"), Value::from(PHRASE))]),
    ]);
    let sausage = u64::from_be_bytes(*b"sausage ").to_string();
    for served in served_both_ways(&vault, owner, value, 0x6c) {
        assert!(!served.to_string().contains(&sausage), "{served}");
    }
    // A body the write door accepts serves all but its credential field.
    let accepted = Value::Map(vec![
        (Value::from("title"), Value::from("kept words")),
        (Value::from("password"), Value::from("changeme")),
    ]);
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &accepted).unwrap();
    assert!(crate::batch::secret_scan::scan_write_payload(&body).is_ok());
    for served in served_both_ways(&vault, owner, accepted, 0x6d) {
        assert_eq!(
            served,
            serde_json::json!({"title": "kept words", "password": "[redacted]"})
        );
    }
}

#[test]
fn a_write_accepted_body_of_wide_floats_serves_its_numbers() {
    // Sol R11: each word's first four letters as the bits of a float a single
    // width holds exactly, stored wide, the rest of the word in byte-sized
    // integers after it. Only the narrow width the floats never had spells
    // the phrase.
    let mut items = Vec::new();
    for word in PHRASE.split(' ') {
        let (head, rest) = word.as_bytes().split_at(4);
        let bits = u32::from_be_bytes(head.try_into().unwrap());
        items.push(Value::F64(f64::from(f32::from_bits(bits))));
        items.extend(rest.iter().copied().map(Value::from));
    }
    let value = Value::Array(items);
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &value).unwrap();
    assert!(crate::batch::secret_scan::scan_write_payload(&body).is_ok());
    let (_dir, vault, owner) = owner_vault();
    let numbers = crate::companion::companion_value_to_json(&value);
    for served in served_both_ways(&vault, owner, value, 0x6e) {
        assert_eq!(served, numbers);
    }
    assert_eq!(crate::batch::export::redacted_memory_body(&body), numbers);
    let asset = EntityId::now();
    vault
        .batch()
        .put(&asset, ENTITY_TYPE_ASSET, test_time(7), 7, &body)
        .commit()
        .unwrap();
    let bundle: serde_json::Value =
        serde_json::from_slice(&vault.export_entity_bundle_json(&[asset]).unwrap()).unwrap();
    assert_eq!(bundle["entities"][0]["body"], numbers);
    assert_eq!(bundle["manifest"]["secrets_nulled"]["payloads"], false);
}

/// `value` stored as an ASSET body.
fn put_asset(vault: &crate::Vault, body: &[u8], at: u64) -> EntityId {
    let asset = EntityId::now();
    vault
        .batch()
        .put(&asset, ENTITY_TYPE_ASSET, test_time(at), at, body)
        .commit()
        .unwrap();
    asset
}

fn encoded(value: &Value) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, value).unwrap();
    body
}

#[test]
fn the_chat_document_pack_withholds_a_body_the_write_door_refuses() {
    let (_dir, vault, owner) = scan_off_vault();
    // Sol R9: a word per field behind keys the Markdown and Plaintext rows
    // leave out, and the phrase whole under a credential name, which a memory
    // read redacts alone.
    let mut fields: Vec<(Value, Value)> = PHRASE
        .split(' ')
        .enumerate()
        .map(|(at, word)| {
            (
                Value::from(format!("PROSE{:02}", at + 1)),
                Value::from(word),
            )
        })
        .collect();
    fields.push((Value::from("password"), Value::from(PHRASE)));
    let refused = encoded(&Value::Map(fields));
    let accepted = encoded(&Value::Map(vec![
        (Value::from("title"), Value::from("kept asset words")),
        (Value::from("password"), Value::from("changeme")),
    ]));
    assert!(crate::batch::secret_scan::scan_write_payload(&refused).is_err());
    assert!(crate::batch::secret_scan::scan_write_payload(&accepted).is_ok());
    let refused = put_asset(&vault, &refused, 8);
    let accepted = put_asset(&vault, &accepted, 9);
    let memory = facade_for(&vault, owner);
    // A memory read stays surgical.
    let surgical = memory.hydrate(&[refused.to_hex()]).unwrap().value;
    assert_eq!(surgical[0].body.as_ref().unwrap()["PROSE06"], "sausage");
    let chat = |document: EntityId, format: Option<&str>| {
        memory
            .chat(
                "what does it say?",
                ChatDepth::Light,
                ChatOptions {
                    scope: ChatScope::Documents {
                        source_short_ids: vec![document.to_hex()],
                    },
                    limit: 10,
                    format,
                    lease: None,
                    composer: None,
                },
            )
            .unwrap()
    };
    for format in [Some("md"), Some("txt"), None] {
        // The extractive answer is the rendered pack, or the item's text.
        match chat(refused, format) {
            ChatResponse::Answered {
                answer, retrieval, ..
            } => {
                assert!(format.is_some(), "an item with no text answers nothing");
                assert!(!answer.contains("sausage"), "{format:?}: {answer}");
                assert!(!format!("{retrieval:?}").contains("sausage"), "{format:?}");
            }
            ChatResponse::Abstained { reason, .. } => {
                assert_eq!(reason, ChatAbstentionReason::InsufficientEvidence);
            }
        }
        let ChatResponse::Answered { answer, .. } = chat(accepted, format) else {
            panic!("{format:?}: the accepted document answers");
        };
        assert!(answer.contains("kept asset words"), "{format:?}: {answer}");
        assert!(!answer.contains("changeme"), "{format:?}: {answer}");
    }
}

#[test]
fn a_claim_predicate_is_read_as_the_text_it_is_served_as() {
    // Slot test 2026-10-14: the public vector dotted is a valid predicate,
    // and a reader that nulled it before the joint read served it whole.
    let predicate = format!("profile.{}", PHRASE.replace(' ', "."));
    let (_dir, vault, owner) = scan_off_vault();
    let subject = put_person(&vault, 0x6f);
    let memory = facade_for(&vault, owner);
    let upsert = |predicate: &str, value: &str| {
        memory.claim_upsert(&claim_input(
            predicate,
            &subject,
            "user_stated",
            serde_json::json!(value),
        ))
    };
    let secret = upsert(&predicate, "lantern festival tickets").unwrap();
    upsert("profile.city", "lantern harbour town").unwrap();
    let listed = memory
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: None,
            lifecycle: None,
            limit: 10,
        })
        .unwrap()
        .value;
    let history = memory.claim_history(&secret.claim_short_id).unwrap().value;
    // Recall finds a claim through the text its host indexes for it.
    for view in &listed {
        let id = EntityId::from_hex(&view.claim_ref).unwrap();
        vault
            .batch()
            .text(&id, &[("body", "lantern")])
            .commit()
            .unwrap();
    }
    let recalled = memory
        .recall(
            "lantern",
            Effort::Light,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .unwrap();
    let recalled: Vec<_> = recalled
        .items
        .iter()
        .filter(|item| item.kind == "CLAIM")
        .map(|item| (item.predicate.clone().unwrap(), item.value_text.clone()))
        .collect();
    let served: Vec<_> = listed
        .iter()
        .chain(&history)
        .map(|view| (view.predicate.clone(), view.value.to_string()))
        .chain(recalled.iter().cloned())
        .collect();
    let predicates: std::collections::BTreeSet<_> = served
        .iter()
        .map(|(predicate, _)| predicate.as_str())
        .collect();
    assert_eq!(
        predicates.into_iter().collect::<Vec<_>>(),
        ["[redacted]", "profile.city"],
        "{served:?}"
    );
    assert_eq!(listed.len(), 2);
    assert_eq!(recalled.len(), 2, "{recalled:?}");
    assert!(!history.is_empty());
    assert!(!format!("{served:?}").contains("sausage"), "{served:?}");
    // A claim the write door accepts serves its value.
    assert!(format!("{served:?}").contains("lantern harbour town"));

    // With the scan on, the write door refuses the predicate.
    let (_dir, vault, owner) = owner_vault();
    let subject = put_person(&vault, 0x70);
    let memory = facade_for(&vault, owner);
    let refused = memory.claim_upsert(&claim_input(
        &predicate,
        &subject,
        "user_stated",
        serde_json::json!("lantern festival tickets"),
    ));
    assert!(
        !matches!(&refused, Ok(receipt) if receipt.approval != "rejected"),
        "{refused:?}"
    );
    let stored = memory
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: None,
            lifecycle: None,
            limit: 10,
        })
        .unwrap()
        .value;
    assert!(stored.is_empty(), "{stored:?}");
}

#[test]
fn a_write_accepted_body_of_wide_integers_serves_its_numbers() {
    // The phrase's letters after a string and a line break, each a
    // byte-sized integer stored after a one-byte header: no run of stored
    // bytes spells the phrase, and only a re-encoding at the narrowest width
    // would. Stored at that width, it is a body the write door refuses.
    let letters: Vec<u8> = std::iter::once(b'\n').chain(PHRASE.bytes()).collect();
    let body = |header: &[u8]| {
        let mut body = vec![0xdc];
        body.extend(u16::try_from(letters.len() + 1).unwrap().to_be_bytes());
        body.push(0xa5);
        body.extend_from_slice(b"notes");
        for letter in &letters {
            body.extend_from_slice(header);
            body.push(*letter);
        }
        body
    };
    let (wide, narrow) = (body(&[0xcc]), body(&[]));
    assert!(crate::batch::secret_scan::scan_write_payload(&wide).is_ok());
    assert!(crate::batch::secret_scan::scan_write_payload(&narrow).is_err());
    let numbers = crate::companion::companion_value_to_json(
        &rmpv::decode::read_value(&mut &wide[..]).unwrap(),
    );
    let (_dir, vault, owner) = scan_off_vault();
    let memory = facade_for(&vault, owner);
    let bundle = |asset: EntityId| -> serde_json::Value {
        serde_json::from_slice(&vault.export_entity_bundle_json(&[asset]).unwrap()).unwrap()
    };

    let kept = put_asset(&vault, &wide, 10);
    let view = memory.get_entity(&kept.to_hex()).unwrap().value.unwrap();
    assert_eq!(view.body.unwrap(), numbers);
    assert_eq!(crate::batch::export::redacted_memory_body(&wide), numbers);
    assert_eq!(
        crate::batch::export::redacted_memory_payload(wide.clone()).unwrap(),
        wide
    );
    let exported = bundle(kept);
    assert_eq!(exported["entities"][0]["body"], numbers);
    assert_eq!(exported["manifest"]["secrets_nulled"]["payloads"], false);

    // The same letters at the width the write door refuses stay withheld.
    let withheld = put_asset(&vault, &narrow, 11);
    let view = memory
        .get_entity(&withheld.to_hex())
        .unwrap()
        .value
        .unwrap();
    assert_eq!(view.body.unwrap(), "[redacted]");
    assert_eq!(
        crate::batch::export::redacted_memory_body(&narrow),
        "[redacted]"
    );
    assert_eq!(
        crate::batch::export::redacted_memory_payload(narrow).unwrap(),
        b"\xaa[redacted]"
    );
    let exported = bundle(withheld);
    assert_eq!(exported["entities"][0]["body"], serde_json::Value::Null);
}
