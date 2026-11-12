//! Whether a NOTE edit lands or waits is the Grant's answer for the actor
//! and the NOTE, never the writer's authorship (DEC-0006 #10, ARCH-0032
//! #forks-proposals: "An agent lands only under an automatic grant, and
//! otherwise it proposes"; FIX [DRIFT-CONSENT-2]). An agent's edit of a NOTE
//! it wrote, with no grant, opens a fork and leaves the text alone. The
//! owner's edit lands. Two planes stay the writer's own by a proof the door
//! holds: an agent's append to its live session pad, and a changed file of a
//! folder the owner attached.
//!
//! `cargo test --locked -p oneiron --all-features --test note_edit_lands_by_grant`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use oneiron::note::{
    FolderFile, FolderRescan, ImportedNote, NoteProgramEdit, NoteProgramEditOutcome,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

const BASE: &str = "The lighthouse keeper logs the tide at dawn.";

fn open(dir: &tempfile::TempDir) -> (Vault, WriteActor, WriteActor) {
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let agent = EntityId::now();
    vault
        .put_entity(
            &agent,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .expect("agent PERSON");
    (
        vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        WriteActor::new(agent, EdgeActorClass::Agent),
    )
}

fn text(vault: &Vault, note: EntityId) -> String {
    vault
        .note_program_document(note)
        .expect("read document")
        .expect("NOTE document")
        .text()
}

fn append(vault: &Vault, note: EntityId, words: &str) -> NoteProgramEdit {
    let doc = vault
        .note_program_document(note)
        .expect("read document")
        .expect("NOTE document");
    NoteProgramEdit::InsertAfter {
        anchor: doc.anchor(doc.text().chars().count()).expect("end anchor"),
        text: words.to_owned(),
    }
}

#[test]
fn an_agents_edit_of_its_own_note_with_no_grant_opens_a_fork() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, _owner, agent) = open(&dir);
    let note = vault
        .create_note("research", BASE, agent)
        .expect("the agent writes a NOTE");
    let outcome = vault
        .edit_note(note, &append(&vault, note, " Agent words."), agent)
        .expect("the edit is taken");
    assert!(
        matches!(outcome, NoteProgramEditOutcome::ProposedFork { .. }),
        "an agent's edit with no grant proposes, its authorship notwithstanding: {outcome:?}"
    );
    assert_eq!(text(&vault, note), BASE, "the NOTE's text stays as it was");
}

#[test]
fn the_owners_edit_of_an_agents_note_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, agent) = open(&dir);
    let note = vault
        .create_note("research", BASE, agent)
        .expect("the agent writes a NOTE");
    let outcome = vault
        .edit_note(note, &append(&vault, note, " Owner words."), owner)
        .expect("the edit is taken");
    assert!(
        matches!(outcome, NoteProgramEditOutcome::Edited { .. }),
        "the owner lands everywhere in his own vault: {outcome:?}"
    );
    assert_eq!(text(&vault, note), format!("{BASE} Owner words."));
}

#[test]
fn an_agents_append_to_its_live_session_pad_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, _owner, agent) = open(&dir);
    let memory = vault.memory(agent.entity_ref(), EdgeActorClass::Agent);
    let first = memory
        .scratchpad_append("session-1", "the first line of the run", None, false)
        .expect("the first line opens the pad");
    assert!(first.opened);
    let second = memory
        .scratchpad_append("session-1", "the second line of the run", None, false)
        .expect("the second line lands on the live pad");
    assert_eq!(second.pad, first.pad, "the same live pad");
    assert!(!second.opened);
    let pad = text(&vault, first.pad);
    assert!(
        pad.contains("the second line of the run"),
        "the pad holds the appended line: {pad:?}"
    );
}

#[test]
fn a_changed_file_of_an_owner_attached_folder_supersedes_its_note() {
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault");
    let folder_path = temp.path().join("notes");
    std::fs::create_dir(&folder_path).expect("notes directory");
    let first = "# Tide\n\nThe tide was low.\n";
    let changed = "# Tide\n\nThe tide was high.\n";
    std::fs::write(folder_path.join("tide.md"), first).expect("Markdown file");
    let folder = std::fs::canonicalize(&folder_path)
        .expect("canonical folder")
        .to_str()
        .expect("UTF-8 folder")
        .to_owned();
    let vault = Vault::open_owned(&vault_path, VaultConfig::device()).expect("open vault");
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let source = vault
        .attach_folder_source(&owner, &folder, Vec::new(), "observation")
        .expect("attach folder");
    let rescan = |new: Vec<ImportedNote>, present: Vec<FolderFile>| FolderRescan {
        folder: source.folder.clone(),
        new,
        links: Vec::new(),
        present,
        name_only: Vec::new(),
        missing: Vec::new(),
        raw_hashes: HashMap::new(),
        facts: HashMap::new(),
        whole: true,
    };
    let landed = vault
        .rescan_folder_source(
            &owner,
            rescan(
                vec![ImportedNote {
                    path: "tide.md".to_owned(),
                    kind: source.kind.clone(),
                    title: Some("Tide".to_owned()),
                    written_at: 1,
                    markdown: first.to_owned(),
                    original: None,
                }],
                Vec::new(),
            ),
        )
        .expect("first rescan");
    assert_eq!(landed.landed, 1, "the file lands: {landed:?}");
    let report = vault
        .rescan_folder_source(
            &owner,
            rescan(
                Vec::new(),
                vec![FolderFile {
                    path: "tide.md".to_owned(),
                    markdown: changed.to_owned(),
                    links: Some(Vec::new()),
                }],
            ),
        )
        .expect("second rescan");
    assert_eq!(
        (report.superseded, report.proposed, report.failed),
        (1, 0, 0),
        "the changed file supersedes its note: {report:?}"
    );
    let id = Vault::imported_note_id(&source.namespace(), "tide.md").expect("NOTE id");
    assert_eq!(
        vault
            .read_note(&id)
            .expect("read NOTE")
            .expect("NOTE")
            .markdown,
        changed
    );
}
