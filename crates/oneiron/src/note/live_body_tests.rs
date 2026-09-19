//! Live read projections share a document frontier and keep raw birth bytes intact.

use super::{NoteEdit, NoteEditOutcome, TakeTarget, decode_note_body};
use crate::claim::ScopedReadActorKey;
use crate::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

#[test]
fn note_live_reads_survive_reopen_without_mirroring_projection_into_birth() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let actor = EntityId::from_bytes([0x51; 16]).unwrap();
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let receipt = memory
        .author_take(TakeTarget::Subject(actor), "birthneedle text")
        .unwrap();
    let note = EntityId::from_hex(&receipt.id_hex).unwrap();
    let raw_birth = vault.get_raw(&note).unwrap().unwrap();
    vault
        .batch()
        .text(&note, &[("body", "birthneedle text")])
        .commit()
        .unwrap();
    let base = vault.note_document(note).unwrap().frontier;
    let outcome = memory
        .apply_note_ops(
            note,
            &base,
            &[NoteEdit {
                start: 0,
                delete: 0,
                insert: "live ".into(),
            }],
        )
        .unwrap();
    let NoteEditOutcome::Applied(applied) = outcome else {
        panic!("uncited prose should apply");
    };
    let expected = "live birthneedle text";
    assert_eq!(applied.markdown, expected);
    assert_eq!(vault.get_raw(&note).unwrap().unwrap(), raw_birth);
    assert_eq!(
        decode_note_body(&vault.get(&note).unwrap().unwrap())
            .unwrap()
            .markdown,
        expected
    );
    let view = memory.get_entity(&receipt.id_hex).unwrap().unwrap();
    assert_eq!(view.body.as_ref().unwrap()["markdown"], expected);
    assert_eq!(
        memory
            .hydrate(std::slice::from_ref(&receipt.id_hex))
            .unwrap()[0],
        view
    );
    let read_key = ScopedReadActorKey::with_actor_class(actor.to_hex(), "human").unwrap();
    let read = vault.scoped_read(read_key);
    assert_eq!(
        decode_note_body(&read.get(&note).unwrap().unwrap())
            .unwrap()
            .markdown,
        expected
    );
    let short_ref = view.short_ref.unwrap();
    let (short_id, hash) = short_ref.split_once(':').unwrap();
    let hash = u8::from_str_radix(hash, 16).unwrap();
    assert_eq!(
        decode_note_body(
            &read
                .hydrate_short_id(short_id, hash)
                .unwrap()
                .unwrap()
                .body
                .unwrap()
        )
        .unwrap()
        .markdown,
        expected
    );
    let latest = vault
        .latest_entity_bodies_by_type(crate::registry::ENTITY_TYPE_NOTE, 1, 16)
        .unwrap();
    assert_eq!(latest[0].0, note);
    assert_eq!(decode_note_body(&latest[0].2).unwrap().markdown, expected);
    // Candidate selection uses the indexed frontier, but hydration is live.
    let pack = vault
        .context_pack()
        .search_text("birthneedle", 4)
        .run()
        .unwrap();
    let hydrated = pack
        .results
        .iter()
        .find(|entity| entity.id == note)
        .unwrap();
    assert_eq!(hydrated.fields.as_ref().unwrap()["markdown"], expected);
    drop(read);
    assert!(
        memory
            .apply_note_ops(
                note,
                &applied.frontier,
                &[NoteEdit {
                    start: 0,
                    delete: expected.chars().count(),
                    insert: String::new()
                }],
            )
            .is_err()
    );
    assert_eq!(vault.note_document(note).unwrap(), applied);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    assert_eq!(vault.note_document(note).unwrap(), applied);
    assert_eq!(
        decode_note_body(&vault.get(&note).unwrap().unwrap())
            .unwrap()
            .markdown,
        expected
    );
    assert_eq!(vault.get_raw(&note).unwrap().unwrap(), raw_birth);
    // A corrupt live document is an error, never an invitation to serve birth text.
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .sync_state
                .put(txn, &super::document_store::key(note), b"invalid")?;
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        vault.get(&note),
        Err(crate::Error::Record(
            crate::error::RecordError::InvalidNoteBody(_)
        ))
    ));
}
