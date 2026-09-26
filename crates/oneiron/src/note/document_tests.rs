//! Concurrent editor operations, stable provenance and blessed brief acceptance.

use super::document::NoteDocument;
use super::*;
use crate::{EdgeActorClass, TimeRange, Vault, VaultConfig, WriteActor};
use std::ops::ControlFlow;

fn person(vault: &Vault, byte: u8) -> EntityId {
    let id = EntityId::from_bytes([byte; 16]).expect("valid fixture person id");
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("store fixture person");
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

fn claim_input(id: EntityId, subject: EntityId, value: &str) -> crate::memory::ClaimInput {
    crate::memory::ClaimInput {
        id: Some(id.to_hex()),
        predicate: "profile.name".into(),
        subject_ref: subject.to_hex(),
        value: serde_json::json!(value),
        confidence: 0.9,
        source: "user_stated".into(),
        world_ref: None,
        relationship_ref: None,
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
    vault
        .install_read_permit_for_test(WriteActor::new(author, EdgeActorClass::Human))
        .unwrap();
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
    let markdown = "# Overview\nAuthored text <script>";
    let brief = memory
        .author_brief(markdown, &[pin_a.clone(), pin_b])
        .unwrap();
    let brief = EntityId::from_hex(&brief.id_hex).unwrap();
    let stored_document = vault.note_document(brief).unwrap();
    assert_eq!(stored_document.pins.len(), 2);
    assert_eq!(stored_document.markdown, markdown);
    let document_key = format!("d:e:{}", brief.to_hex());
    let stored_bytes = vault.sync_state_get(&document_key).unwrap().unwrap();
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
        .value
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
    memory.claim_retract(&first_claim.to_hex()).unwrap();
    let read_lane = vault.scoped_read(read_key);
    let after = vault
        .render_brief(brief, &frame, &read_lane)
        .unwrap()
        .value
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
    // Rendering is read-only: neither HTML nor escaped markdown replaces the
    // authored body or is appended to its persisted document between views.
    assert_eq!(vault.note_document(brief).unwrap(), stored_document);
    assert_eq!(
        vault.sync_state_get(&document_key).unwrap().unwrap(),
        stored_bytes
    );
    assert_eq!(
        decode_note_body(&vault.get(&brief).unwrap().unwrap())
            .unwrap()
            .markdown,
        markdown
    );
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
        .value
        .unwrap();
    assert!(erased.citations.iter().all(|citation| citation.redacted
        && citation.quote.is_none()
        && !citation.stale
        && !citation.drifted));
}

#[test]
fn quoted_character_endpoints_survive_boundary_edits_and_state_only_reopen() {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    // Include a one-character span, interior and end-of-body spans, and
    // non-BMP text. All offsets and the exclusive end remain scalar indices.
    for (start, end) in [(0, 1), (1, 3), (0, 4), (3, 4)] {
        let id = EntityId::now();
        let claim = EntityId::now();
        let doc = NoteDocument::birth(id, "α🦀bç", &actor).unwrap();
        let pin = doc.pin(claim, start, end).unwrap();
        doc.add_pin(&pin, &actor).unwrap();
        let before = doc.view().unwrap();
        assert!(
            doc.edit(
                &before.frontier,
                &[
                    NoteEdit {
                        start: end,
                        delete: 0,
                        insert: " suffix".into(),
                    },
                    NoteEdit {
                        start,
                        delete: 0,
                        insert: "prefix ".into(),
                    },
                ],
                &actor,
                &[],
            )
            .unwrap()
        );
        let mut expected: Vec<_> = "α🦀bç".chars().collect();
        expected.splice(end..end, " suffix".chars());
        expected.splice(start..start, "prefix ".chars());
        let after = doc.view().unwrap();
        assert_eq!(after.markdown, expected.into_iter().collect::<String>());
        assert_eq!(after.pins, before.pins);
        assert_eq!(after.authorship, before.authorship);
        for bytes in [
            doc.snapshot().unwrap(),
            crate::sync::documents::storage::state_copy(&doc.doc).unwrap(),
        ] {
            let reopened = NoteDocument::load(id, &bytes).unwrap();
            assert_eq!(reopened.view().unwrap(), after);
            assert_eq!(
                reopened.resolve(&pin).unwrap(),
                NoteSpanResolution::Mapped {
                    start: start + 7,
                    end: end + 7,
                    claim,
                    quote: pin.quote_text.clone(),
                }
            );
            assert!(
                !reopened
                    .edit(
                        &after.frontier,
                        &[NoteEdit {
                            start: start + 7,
                            delete: 1,
                            insert: "replacement".into(),
                        }],
                        &actor,
                        &[],
                    )
                    .unwrap()
            );
            assert_eq!(reopened.view().unwrap(), after);
        }
    }
}

#[test]
fn deleted_quote_anchor_drifts_instead_of_remapping_identical_neighbor() {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let id = EntityId::now();
    let claim = EntityId::now();
    let doc = NoteDocument::birth(id, "aaa", &actor).unwrap();
    let pin = doc.pin(claim, 1, 2).unwrap();
    doc.add_pin(&pin, &actor).unwrap();
    // Model out-of-band source drift. The normal edit door rejects this touch.
    doc.doc.get_text("body").delete(1, 1).unwrap();
    doc.doc.commit();
    for bytes in [
        doc.snapshot().unwrap(),
        crate::sync::documents::storage::state_copy(&doc.doc).unwrap(),
    ] {
        let reopened = NoteDocument::load(id, &bytes).unwrap();
        assert_eq!(reopened.view().unwrap().pins, vec![pin.clone()]);
        assert_eq!(
            reopened.resolve(&pin).unwrap(),
            NoteSpanResolution::Drifted {
                claim,
                quote: "a".into(),
            }
        );
    }
}

#[test]
fn shallow_note_admits_only_available_edit_and_citation_frontiers() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let author = person(&vault, 0x51);
    let claim = EntityId::now();
    let memory = vault.memory(author, EdgeActorClass::Human);
    memory
        .claim_upsert(&claim_input(claim, author, "Ada"))
        .unwrap();
    let note = EntityId::from_hex(
        &memory
            .author_take(TakeTarget::Subject(author), "quote")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let old_pin = vault.pin_note_span(note, claim, 0, 5).unwrap();
    let old_base = vault.note_document(note).unwrap().frontier;
    let NoteEditOutcome::Applied(before) = memory
        .apply_note_ops(
            note,
            &old_base,
            &[NoteEdit {
                start: 0,
                delete: 0,
                insert: "prefix ".into(),
            }],
        )
        .unwrap()
    else {
        panic!("uncited prose")
    };
    // Use the same carrier compaction as citation erasure, without fabricating
    // erased dependencies. Old and current offsets now name different text.
    vault
        .with_write_txn(|txn| {
            let doc = crate::sync::documents::storage::load(&vault, txn, note)?;
            crate::sync::documents::storage::snapshot(&vault, txn, note, &doc, true)
        })
        .unwrap();
    assert_eq!(vault.note_document(note).unwrap(), before);
    assert!(
        memory
            .apply_note_ops(
                note,
                &old_base,
                &[NoteEdit {
                    start: 0,
                    delete: 1,
                    insert: "wrong base".into(),
                }],
            )
            .is_err()
    );
    // A quote still resolving now cannot prove its discarded source frontier.
    assert!(matches!(
        vault.resolve_note_pin(&old_pin).unwrap(),
        NoteSpanResolution::Mapped { .. }
    ));
    assert!(memory.cite_note_span(note, &old_pin).is_err());
    assert_eq!(vault.note_document(note).unwrap(), before);
    let pin = vault.pin_note_span(note, claim, 7, 12).unwrap();
    memory.cite_note_span(note, &pin).unwrap();
    let cited = vault.note_document(note).unwrap();
    let NoteEditOutcome::Applied(after) = memory
        .apply_note_ops(
            note,
            &cited.frontier,
            &[NoteEdit {
                start: 12,
                delete: 0,
                insert: " suffix".into(),
            }],
        )
        .unwrap()
    else {
        panic!("free prose after compaction")
    };
    assert_eq!(after.markdown, "prefix quote suffix");
    assert_eq!(after.pins, vec![pin.clone()]);
    assert_eq!(after.authorship.len(), cited.authorship.len() + 1);
    assert!(
        cited
            .authorship
            .iter()
            .all(|record| after.authorship.contains(record))
    );
    assert!(matches!(
        memory
            .apply_note_ops(
                note,
                &after.frontier,
                &[NoteEdit {
                    start: 7,
                    delete: 1,
                    insert: "Q".into(),
                }],
            )
            .unwrap(),
        NoteEditOutcome::Proposed(_)
    ));
    assert_eq!(vault.note_document(note).unwrap(), after);
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    assert_eq!(reopened.note_document(note).unwrap(), after);
    assert_eq!(
        reopened.resolve_note_pin(&pin).unwrap(),
        NoteSpanResolution::Mapped {
            start: 7,
            end: 12,
            claim,
            quote: "quote".into(),
        }
    );
}
