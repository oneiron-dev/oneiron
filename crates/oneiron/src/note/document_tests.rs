//! Concurrent editor operations, stable provenance and blessed brief acceptance.

use super::document::NoteDocument;
use super::*;
use crate::{EdgeActorClass, TimeRange, Vault, VaultConfig, WriteActor};
use std::ops::ControlFlow;

fn person(vault: &Vault, byte: u8) -> EntityId {
    let id = EntityId::from_bytes([byte; 16]).unwrap();
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    id
}

#[test]
fn concurrent_note_batches_converge_with_durable_actor_stamps_and_cursors() {
    let a = EntityId::from_bytes([0x71; 16]).unwrap();
    let b = EntityId::from_bytes([0x72; 16]).unwrap();
    let id = EntityId::from_bytes([0x73; 16]).unwrap();
    let claim = EntityId::from_bytes([0x74; 16]).unwrap();
    let actor_a = WriteActor::new(a, EdgeActorClass::Human);
    let actor_b = WriteActor::new(b, EdgeActorClass::Human);
    let first = NoteDocument::birth(id, "before quoted after", &actor_a).unwrap();
    let pin = first.pin(claim, 7, 13).unwrap();
    first.add_pin(&pin, &actor_a).unwrap();
    let base = first.view().unwrap().frontier;
    let second = NoteDocument::load(id, &first.snapshot().unwrap()).unwrap();
    assert!(
        first
            .edit(
                &base,
                &[NoteEdit {
                    start: 0,
                    delete: 0,
                    insert: "A ".into()
                }],
                &actor_a,
                &[]
            )
            .unwrap()
    );
    assert!(
        second
            .edit(
                &base,
                &[NoteEdit {
                    start: 19,
                    delete: 0,
                    insert: " B".into()
                }],
                &actor_b,
                &[]
            )
            .unwrap()
    );
    let a_updates = first.snapshot().unwrap();
    let b_updates = second.snapshot().unwrap();
    first.doc.import(&b_updates).unwrap();
    second.doc.import(&a_updates).unwrap();
    let first = NoteDocument::load(id, &first.snapshot().unwrap()).unwrap();
    let second = NoteDocument::load(id, &second.snapshot().unwrap()).unwrap();
    assert_eq!(first.view().unwrap(), second.view().unwrap());
    assert_eq!(first.resolve(&pin).unwrap(), second.resolve(&pin).unwrap());
    assert!(
        matches!(first.resolve(&pin).unwrap(), NoteSpanResolution::Mapped { claim: found, ref quote, .. } if found == claim && quote == "quoted")
    );
    let mut actors = std::collections::BTreeSet::new();
    first
        .doc
        .travel_change_ancestors(
            &first.doc.oplog_frontiers().iter().collect::<Vec<_>>(),
            &mut |change| {
                actors.insert(change.message.unwrap().to_string());
                ControlFlow::Continue(())
            },
        )
        .unwrap();
    assert_eq!(
        actors,
        std::collections::BTreeSet::from([
            format!("oneiron.note/v1 actor={}", a.to_hex()),
            format!("oneiron.note/v1 actor={}", b.to_hex())
        ])
    );
    // Drift retains the quote, not an incorrectly remapped span.
    let drift = NoteDocument::birth(id, "unrelated", &actor_a).unwrap();
    assert!(
        matches!(drift.resolve(&pin).unwrap(), NoteSpanResolution::Drifted { quote, .. } if quote == "quoted")
    );
}

#[test]
fn brief_kind_round_trip_is_person_stamped_and_fail_closed() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let actor = person(&vault, 0x61);
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let contract = memory.bless_brief_kind().unwrap();
    assert_eq!(contract.person(), actor);
    assert_eq!(
        BriefKindContract::decode(&contract.encode().unwrap()).unwrap(),
        contract
    );
    let mut value: serde_json::Value = serde_json::from_slice(&contract.encode().unwrap()).unwrap();
    value["extraction"] = serde_json::json!("allowed");
    assert!(BriefKindContract::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    for tag in ["brief", "unknown.pack"] {
        let body = NoteBody {
            kind: NoteKind::Plugin(tag.into()),
            author_ref: actor,
            markdown: "authored".into(),
        };
        assert_eq!(
            decode_note_body(&encode_note_body(&body).unwrap()).unwrap(),
            body
        );
    }
    assert_eq!(NOTE_BODY_KEYS, ["kind", "author_ref", "markdown"]);
}

fn claim_input(id: EntityId, subject: EntityId, value: &str) -> crate::memory::ClaimInput {
    crate::memory::ClaimInput {
        id: Some(id.to_hex()),
        predicate: "profile.name".into(),
        subject_ref: subject.to_hex(),
        value: serde_json::json!(value),
        confidence: 0.9,
        source: "user_stated".into(),
        world_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

#[test]
fn brief_pins_editor_proposals_purge_and_fresh_views() {
    use crate::claim::ScopedReadActorKey;
    use crate::lens::{LensPrincipalBinding, LensRenderFrame, LensRenderId};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let author = person(&vault, 0x41);
    let subject = person(&vault, 0x42);
    let first_claim = EntityId::from_bytes([0x43; 16]).unwrap();
    let second_claim = EntityId::from_bytes([0x44; 16]).unwrap();
    let memory = vault.memory(author, EdgeActorClass::Human);
    memory
        .claim_upsert(&claim_input(first_claim, subject, "Ada"))
        .unwrap();
    memory
        .claim_upsert(&claim_input(second_claim, author, "Bo"))
        .unwrap();
    memory.bless_brief_kind().unwrap();
    let source = memory
        .author_take(TakeTarget::Subject(subject), "first quote / second quote")
        .unwrap();
    let source = EntityId::from_hex(&source.id_hex).unwrap();
    let pin_a = vault.pin_note_span(source, first_claim, 0, 11).unwrap();
    let pin_b = vault.pin_note_span(source, second_claim, 14, 26).unwrap();
    let brief = memory
        .author_brief(
            "# Overview\nAuthored text <script>",
            &[pin_a.clone(), pin_b.clone()],
        )
        .unwrap();
    let brief = EntityId::from_hex(&brief.id_hex).unwrap();
    assert_eq!(vault.note_document(brief).unwrap().pins.len(), 2);
    let read_key = ScopedReadActorKey::with_actor_class(author.to_hex(), "human").unwrap();
    let frame = LensRenderFrame::new(
        LensRenderId::new("brief-view").unwrap(),
        LensPrincipalBinding::human_view(author.to_hex(), read_key.clone(), vec![read_key.clone()])
            .unwrap(),
    );
    let read_lane = vault.scoped_read(read_key.clone());
    let first = vault
        .render_brief(brief, &frame, &read_lane)
        .unwrap()
        .unwrap();
    assert!(
        first
            .citations
            .iter()
            .all(|pin| !pin.redacted && !pin.stale)
    );
    assert!(!first.instrument.html.contains("<script>"));
    assert!(first.instrument.html.contains("&lt;script&gt;"));
    drop(read_lane);
    // A citation in another document protects its source span without a
    // self-pin or an extra editor registration call.
    let base = vault.note_document(source).unwrap().frontier;
    let proposed = memory
        .apply_note_ops(
            source,
            &base,
            &[NoteEdit {
                start: 3,
                delete: 2,
                insert: "replacement".into(),
            }],
        )
        .unwrap();
    let NoteEditOutcome::Proposed(receipt) = proposed else {
        panic!("reviewed proposal")
    };
    assert_eq!(receipt.approval, "proposed");
    assert!(receipt.receipt_ref.starts_with("gate:"));
    assert_eq!(
        vault.note_document(source).unwrap().markdown,
        "first quote / second quote"
    );
    let direct = memory
        .apply_note_ops(
            source,
            &base,
            &[NoteEdit {
                start: 26,
                delete: 0,
                insert: " appendix".into(),
            }],
        )
        .unwrap();
    let NoteEditOutcome::Applied(direct) = direct else {
        panic!("free prose")
    };
    assert!(direct.markdown.ends_with(" appendix"));
    assert!(memory.purge_note_history(source, &direct.frontier).is_err());
    let next = EntityId::from_bytes([0x45; 16]).unwrap();
    memory
        .claim_upsert(&claim_input(next, subject, "Ada updated"))
        .unwrap();
    let read_lane = vault.scoped_read(read_key);
    let after = vault
        .render_brief(brief, &frame, &read_lane)
        .unwrap()
        .unwrap();
    let old = after
        .citations
        .iter()
        .find(|citation| citation.claim == first_claim)
        .unwrap();
    assert!(old.redacted && !old.stale && !old.drifted);
    assert!(
        after
            .citations
            .iter()
            .any(|citation| citation.claim == second_claim && citation.stale && !citation.redacted)
    );
    assert!(old.quote.is_none() && old.confidence.is_none());
    assert_eq!(first.instrument.html, after.instrument.html); // flags, not regeneration
    drop(read_lane);
    let before_reopen = vault.note_document(source).unwrap();
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    assert_eq!(before_reopen, reopened.note_document(source).unwrap());
    assert!(
        matches!(reopened.resolve_note_pin(&pin_a).unwrap(), NoteSpanResolution::Mapped { quote, .. } if quote == "first quote")
    );
    assert!(reopened.delete_entity(&source).unwrap());
    let read_key = ScopedReadActorKey::with_actor_class(author.to_hex(), "human").unwrap();
    let read = reopened.scoped_read(read_key);
    let erased = reopened
        .render_brief(brief, &frame, &read)
        .unwrap()
        .unwrap();
    assert!(erased.citations.iter().all(|citation| citation.redacted
        && citation.quote.is_none()
        && !citation.stale
        && !citation.drifted));
}
