//! An edit through the scalar NOTE doors lands by the Grant's answer for the
//! writer and the NOTE, never by the writer's authorship (DEC-0006 #10,
//! ARCH-0032 #forks-proposals: "An agent lands only under an automatic grant,
//! and otherwise it proposes"; FIX [NOTE-SCALAR-DOOR-AUTHOR-LANDS]). The NOTE
//! socket asks the same gate. A writer the Grant does not land is refused
//! there, with no fork opened, and proposes its edit through the program door
//! (RULING NOTE-SCALAR-NO-GRANT = A). The owner's scalar edit lands.
//!
//! `cargo test --locked -p oneiron --all-features --test note_scalar_edit_lands_by_grant`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_OWNER_BINDING_REQUIRED};
use oneiron::note::{NoteScalarEdit, NoteScalarEditOutcome};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

const BASE: &str = "The lighthouse keeper logs the tide at dawn.";

/// The reason code of a scalar or socket NOTE edit the Grant does not land.
const NOTE_EDIT_NEEDS_GRANT: &str = "note.edit.needs_grant";

fn person(vault: &Vault, class: EdgeActorClass) -> WriteActor {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"writer",
        )
        .expect("writer PERSON");
    WriteActor::new(id, class)
}

fn open(dir: &tempfile::TempDir) -> (Vault, WriteActor, WriteActor) {
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let agent = person(&vault, EdgeActorClass::Agent);
    (vault, WriteActor::new(owner, EdgeActorClass::Human), agent)
}

fn prepend(
    vault: &Vault,
    writer: WriteActor,
    note: EntityId,
    words: &str,
) -> oneiron::memory::MemoryResult<NoteScalarEditOutcome> {
    let frontier = vault.note_document(note).expect("NOTE document").frontier;
    vault
        .memory(writer.entity_ref(), writer.actor_class())
        .apply_note_ops(
            note,
            &frontier,
            &[NoteScalarEdit {
                start: 0,
                delete: 0,
                insert: words.to_owned(),
            }],
        )
}

fn text(vault: &Vault, note: EntityId) -> String {
    vault
        .note_program_document(note)
        .expect("read document")
        .expect("NOTE document")
        .text()
}

#[test]
fn an_agents_scalar_edit_of_its_own_note_with_no_grant_does_not_land() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, _owner, agent) = open(&dir);
    let note = vault
        .create_note("research", BASE, agent)
        .expect("the agent writes a NOTE");
    let refused = prepend(&vault, agent, note, "Agent words. ").expect_err(
        "an agent's scalar edit with no grant is refused, its authorship notwithstanding",
    );
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    assert_eq!(
        refused.reason_codes,
        vec![NOTE_EDIT_NEEDS_GRANT.to_owned()],
        "{refused:?}"
    );
    assert_eq!(text(&vault, note), BASE, "the NOTE's text stays as it was");
}

#[test]
fn an_agents_title_change_of_its_own_note_with_no_grant_does_not_land() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, _owner, agent) = open(&dir);
    let note = vault
        .create_note("research", BASE, agent)
        .expect("the agent writes a NOTE");
    let before = vault.note_document(note).expect("NOTE document").title;
    let refused = vault
        .memory(agent.entity_ref(), EdgeActorClass::Agent)
        .set_note_title(note, "Tide log")
        .expect_err(
            "an agent's title change with no grant is refused, its authorship notwithstanding",
        );
    assert_eq!(
        refused.reason_codes,
        vec![NOTE_EDIT_NEEDS_GRANT.to_owned()],
        "{refused:?}"
    );
    assert_eq!(
        vault.note_document(note).expect("NOTE document").title,
        before,
        "the NOTE's title stays as it was"
    );
}

#[test]
fn a_persons_scalar_edit_of_its_own_note_with_no_grant_does_not_land() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, _owner, _agent) = open(&dir);
    let writer = person(&vault, EdgeActorClass::Human);
    let note = vault
        .create_note("research", BASE, writer)
        .expect("a person who is not the owner writes a NOTE");
    let refused = prepend(&vault, writer, note, "Person words. ").expect_err(
        "a person's scalar edit with no grant is refused, its authorship notwithstanding",
    );
    assert_eq!(
        refused.code, MEMORY_CODE_OWNER_BINDING_REQUIRED,
        "{refused:?}"
    );
    assert_eq!(
        refused.reason_codes,
        vec![NOTE_EDIT_NEEDS_GRANT.to_owned()],
        "{refused:?}"
    );
    assert_eq!(text(&vault, note), BASE, "the NOTE's text stays as it was");
}

#[test]
fn the_owners_scalar_edit_of_an_agents_note_applies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, agent) = open(&dir);
    let note = vault
        .create_note("research", BASE, agent)
        .expect("the agent writes a NOTE");
    let outcome = prepend(&vault, owner, note, "Owner words. ").expect("the owner's edit is taken");
    assert!(
        matches!(outcome, NoteScalarEditOutcome::Applied(_)),
        "the owner lands everywhere in the owner's own vault: {outcome:?}"
    );
    assert_eq!(text(&vault, note), format!("Owner words. {BASE}"));
}
