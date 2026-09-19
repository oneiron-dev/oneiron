//! Exact citation erasure, carrier fences, and authority replay regressions.

use super::*;
use crate::{EdgeActorClass, TimeRange, Vault, VaultConfig};

fn actor(vault: &Vault) -> EntityId {
    let id = EntityId::now();
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

// Read the stored row through the feature-independent store. The production
// sync convenience methods deliberately do not exist in the featureless crate.
fn document_carrier(vault: &Vault, note: EntityId) -> Option<Vec<u8>> {
    let txn = vault.store.env.read_txn().unwrap();
    vault
        .store
        .sync_state
        .get(&txn, &format!("d:e:{}", note.to_hex()))
        .unwrap()
        .map(|bytes| bytes.to_vec())
}

// This law runs featureless too: lacking a Loro decoder is not permission to
// discard the document or silently project its older birth markdown.
#[test]
fn pending_citation_erasure_fences_reads_without_deleting_document() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let person = actor(&vault);
    let note = EntityId::from_hex(
        &vault
            .memory(person, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(person), "birth prose")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let source = EntityId::now();
    let claim = EntityId::now();
    let opaque = b"opaque sync-edited document carrier";
    let value = serde_json::to_vec(
        &serde_json::json!({"document": source.to_hex(), "claim": claim.to_hex()}),
    )
    .unwrap();
    let hash = blake3::hash(&value).to_hex().to_string();
    let index = format!(
        "note.pin/source/{}:{}:{hash}",
        source.to_hex(),
        note.to_hex()
    );
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .sync_state
                .put(txn, &format!("d:e:{}", note.to_hex()), opaque)?;
            vault.store.vault_meta.put(txn, index.as_bytes(), &value)?;
            let found = citation_erase::fence_dependents(&vault.store, txn, source)?;
            assert_eq!(found, vec![note]);
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        vault.get(&note),
        Err(crate::Error::Record(
            crate::error::RecordError::InvalidNoteBody(_)
        ))
    ));
    assert_eq!(
        document_carrier(&vault, note).as_deref(),
        Some(opaque.as_slice())
    );
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    assert!(matches!(
        vault.get(&note),
        Err(crate::Error::Record(
            crate::error::RecordError::InvalidNoteBody(_)
        ))
    ));
    assert_eq!(
        document_carrier(&vault, note).as_deref(),
        Some(opaque.as_slice())
    );
    #[cfg(not(feature = "sync"))]
    {
        // The copied citation is local delete scope even with no source row.
        vault.delete_entity(&source).unwrap();
        let sweep = crate::sweep::run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(sweep.jobs_processed, 0);
        assert!(sweep.jobs_deferred > 0);
        assert_eq!(
            document_carrier(&vault, note).as_deref(),
            Some(opaque.as_slice())
        );
    }
}

#[cfg(feature = "sync")]
fn claim(vault: &Vault, person: EntityId) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(person, EdgeActorClass::Human)
        .claim_upsert(&crate::memory::ClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.name".into(),
            subject_ref: person.to_hex(),
            value: serde_json::json!(id.to_hex()),
            confidence: 0.9,
            source: "user_stated".into(),
            world_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .unwrap();
    id
}

#[cfg(feature = "sync")]
#[test]
fn source_and_claim_erasure_keep_other_pin_prose_authorship_and_refuse_replay() {
    use crate::sync::transport::document_sub_tags;
    for erase_claim in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        let person = actor(&vault);
        let first_claim = claim(&vault, person);
        let other_person = actor(&vault);
        let second_claim = claim(&vault, other_person);
        let memory = vault.memory(person, EdgeActorClass::Human);
        memory.bless_brief_kind().unwrap();
        let source = EntityId::from_hex(
            &memory
                .author_take(TakeTarget::Subject(person), "erased quote")
                .unwrap()
                .id_hex,
        )
        .unwrap();
        let other = EntityId::from_hex(
            &memory
                .author_take(TakeTarget::Subject(other_person), "retained quote")
                .unwrap()
                .id_hex,
        )
        .unwrap();
        let removed_pin = vault.pin_note_span(source, first_claim, 0, 12).unwrap();
        let retained_pin = vault.pin_note_span(other, second_claim, 0, 14).unwrap();
        let brief = EntityId::from_hex(
            &memory
                .author_brief(
                    "unrelated authored prose",
                    &[removed_pin.clone(), retained_pin.clone()],
                )
                .unwrap()
                .id_hex,
        )
        .unwrap();
        let base = vault.note_document(brief).unwrap().frontier;
        memory
            .apply_note_ops(
                brief,
                &base,
                &[NoteEdit {
                    start: 0,
                    delete: 0,
                    insert: "edited ".into(),
                }],
            )
            .unwrap();
        let before = vault.note_document(brief).unwrap();
        let raw = vault
            .sync_state_get(&format!("d:e:{}", brief.to_hex()))
            .unwrap()
            .unwrap();
        let source_raw = vault.get_raw(&source).unwrap().unwrap();
        vault
            .delete_entity(&if erase_claim { first_claim } else { source })
            .unwrap();
        let after = vault.note_document(brief).unwrap();
        assert_eq!(after.markdown, before.markdown);
        assert_eq!(after.authorship, before.authorship);
        assert_eq!(after.pins, vec![retained_pin.clone()]);
        assert!(vault.resolve_note_pin(&removed_pin).is_err());
        assert!(
            matches!(vault.resolve_note_pin(&retained_pin).unwrap(), NoteSpanResolution::Mapped { quote, .. } if quote == "retained quote")
        );
        let clean = vault
            .sync_state_get(&format!("d:e:{}", brief.to_hex()))
            .unwrap()
            .unwrap();
        let doc = document::NoteDocument::load(brief, &clean).unwrap();
        // No obsolete state can be recovered by asking the stored carrier for
        // the old frontier. This tests the history, not a compressed byte scan.
        assert!(
            doc.doc
                .fork_at(&document::frontier(&before.frontier).unwrap())
                .is_err()
        );
        assert_eq!(doc.view().unwrap().pins, vec![retained_pin.clone()]);
        memory
            .apply_note_ops(
                brief,
                &after.frontier,
                &[NoteEdit {
                    start: 0,
                    delete: 0,
                    insert: "after erase ".into(),
                }],
            )
            .unwrap();
        // The unrelated source remains purge-pinned after the index rebuild.
        let other_base = vault.note_document(other).unwrap().frontier;
        let NoteEditOutcome::Applied(other_edit) = memory
            .apply_note_ops(
                other,
                &other_base,
                &[NoteEdit {
                    start: 14,
                    delete: 0,
                    insert: " suffix".into(),
                }],
            )
            .unwrap()
        else {
            panic!("free prose")
        };
        assert!(
            memory
                .purge_note_history(other, &other_edit.frontier)
                .is_err()
        );
        assert!(memory.cite_note_span(brief, &removed_pin).is_err());
        let durable = vault.note_document(brief).unwrap();
        drop(vault);
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        assert_eq!(vault.note_document(brief).unwrap(), durable);
        vault
            .sync_state_put(&format!("ds:e:{}", brief.to_hex()), b"desired subscription")
            .unwrap();
        assert!(import_note_from_authority(&vault, brief, document_sub_tags::STATE, &raw).is_err());
        assert_eq!(vault.note_document(brief).unwrap(), durable);
        // A newer authority snapshot must not reintroduce the erased pin either.
        let replay = document::NoteDocument::load(
            brief,
            &vault
                .sync_state_get(&format!("d:e:{}", brief.to_hex()))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        replay
            .add_pin(
                &removed_pin,
                &crate::WriteActor::new(person, EdgeActorClass::Human),
            )
            .unwrap();
        let poisoned_frontier = replay.view().unwrap().frontier;
        assert!(
            import_note_from_authority(
                &vault,
                brief,
                document_sub_tags::STATE,
                &replay.snapshot().unwrap()
            )
            .is_err()
        );
        let value = serde_json::to_string(&removed_pin).unwrap();
        replay
            .doc
            .get_map("pins")
            .delete(&blake3::hash(value.as_bytes()).to_hex().to_string())
            .unwrap();
        replay.doc.commit();
        // Its live state is now lawful, but its full history still carries the
        // copied quote. Accept the authority state only after normalization.
        import_note_from_authority(
            &vault,
            brief,
            document_sub_tags::STATE,
            &replay.snapshot().unwrap(),
        )
        .unwrap();
        let accepted = vault.note_document(brief).unwrap();
        assert_eq!(accepted.markdown, durable.markdown);
        assert_eq!(accepted.pins, durable.pins);
        assert_eq!(accepted.authorship, durable.authorship);
        let stored = document::NoteDocument::load(
            brief,
            &vault
                .sync_state_get(&format!("d:e:{}", brief.to_hex()))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(
            stored
                .doc
                .fork_at(&document::frontier(&poisoned_frontier).unwrap())
                .is_err()
        );
        if !erase_claim {
            let key = crate::sync::WindowKey::from_timestamp(
                crate::batch::EntityMetadataHeader::parse(&source_raw)
                    .unwrap()
                    .learned_at,
            );
            let stale = crate::sync::schema::create_window_doc("stale-source", &key);
            crate::sync::loro_support::map_insert_bytes(
                &stale.get_map("entities"),
                &source.to_hex(),
                &source_raw,
            )
            .unwrap();
            stale.commit();
            crate::sync::window::forward_rematerialize(
                &vault,
                &stale,
                &crate::sync::bridge::Materializer::new(),
                &key,
            )
            .unwrap();
            assert!(vault.get_raw(&source).unwrap().is_none());
            assert_eq!(vault.note_document(brief).unwrap(), accepted);
        }
    }
}

#[cfg(feature = "sync")]
#[test]
fn pending_scrub_replays_committed_updates_and_preserves_unrelated_edits() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let person = actor(&vault);
    let claim = claim(&vault, person);
    let memory = vault.memory(person, EdgeActorClass::Human);
    memory.bless_brief_kind().unwrap();
    let source = EntityId::from_hex(
        &memory
            .author_take(TakeTarget::Subject(person), "quote")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let pin = vault.pin_note_span(source, claim, 0, 5).unwrap();
    let brief = EntityId::from_hex(
        &memory
            .author_brief("prose", std::slice::from_ref(&pin))
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let before = vault.note_document(brief).unwrap();
    let cite_request = NoteOperation {
        request_id: EntityId::now(),
        change: NoteChange::Cite { pin: pin.clone() },
    };
    let edit_request = NoteOperation {
        request_id: EntityId::now(),
        change: NoteChange::Edit {
            base: before.frontier.clone(),
            edits: vec![],
        },
    };
    vault
        .with_write_txn(|txn| {
            let doc = crate::sync::documents::storage::load(&vault, txn, brief)?;
            let vv = doc.oplog_vv();
            doc.get_text("body")
                .insert(5, " pending unrelated edit")
                .unwrap();
            doc.commit();
            let updates = doc.export(loro::ExportMode::updates(&vv)).unwrap();
            crate::sync::documents::storage::append(&vault, txn, brief, &updates)?;
            for op in [&cite_request, &edit_request] {
                let frame = crate::sync::transport::encode_document(
                    brief,
                    crate::sync::transport::document_sub_tags::NOTE_OPS,
                    &op.encode()?,
                )
                .into_result()
                .unwrap();
                vault.store.sync_state.put(
                    txn,
                    &format!("qn:e:{}:{}", brief.to_hex(), op.request_id.to_hex()),
                    &frame,
                )?;
            }
            pin_index::track_citation_request(
                &vault.store,
                txn,
                brief,
                cite_request.request_id,
                &pin,
            )?;
            citation_erase::fence_dependents(&vault.store, txn, source)?;
            Ok(())
        })
        .unwrap();
    assert!(vault.note_document(brief).is_err());
    crate::sweep::run_hard_erase_sweep(&vault).unwrap();
    let after = vault.note_document(brief).unwrap();
    assert_eq!(after.markdown, "prose pending unrelated edit");
    assert_eq!(after.authorship, before.authorship);
    assert!(after.pins.is_empty());
    assert!(
        vault
            .sync_state_get(&format!(
                "qn:e:{}:{}",
                brief.to_hex(),
                cite_request.request_id.to_hex()
            ))
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .sync_state_get(&format!(
                "qn:e:{}:{}",
                brief.to_hex(),
                edit_request.request_id.to_hex()
            ))
            .unwrap()
            .is_some()
    );
    assert!(memory.cite_note_span(brief, &pin).is_err());
    assert!(matches!(
        memory
            .apply_note_ops(
                brief,
                &after.frontier,
                &[NoteEdit {
                    start: 0,
                    delete: 0,
                    insert: "new ".into()
                }]
            )
            .unwrap(),
        NoteEditOutcome::Applied(_)
    ));
}
