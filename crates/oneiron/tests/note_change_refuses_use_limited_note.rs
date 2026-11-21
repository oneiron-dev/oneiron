//! A NOTE kept from use takes no named change (FIX PUT-OVER-USE-LIMITED-RECORD-LANDS; OF-470 C6;
//! BIZ-LEGAL-0004 Art. 18 "storage only, no changes"). The base put and the entity text edit
//! already refuse a record a customer hold kept from its privacy erasure; a NOTE's document
//! writers asked nothing.
//!
//! Public doors only; neutral fixtures; vaults in tempdirs. Each test opens a hosted vault, where
//! a customer hold refuses a NOTE's privacy erase and so keeps the NOTE stored and use-limited.
//!
//! * `an_edit_of_a_use_limited_note_answers_not_found_and_keeps_its_text`: the owner's edit of
//!   the held NOTE answers not found and its text stays; the same edit of a second NOTE lands.
//! * `a_title_seal_or_fork_of_a_use_limited_note_answers_not_found`: a title, a seal and a new
//!   fork of the held NOTE each answer not found.
//! * `a_fork_opened_before_the_use_limit_does_not_land_after_it`: a rewrite fork the owner
//!   opened before the hold does not switch in after it, and a fork made before the hold is not
//!   opened after it; the NOTE's text stays.
//! * `a_facet_fork_of_a_use_limited_note_answers_not_found`: a fork of the held NOTE to another
//!   facet, with or without superseding it, answers not found and copies nothing; the same fork
//!   of a second NOTE lands.
//!
//! All four run red at main 864ee0cf3cd, whose NOTE writers ask no use limit, and green at the
//! fix.
//! `cargo test --locked -p oneiron --all-features --test note_change_refuses_use_limited_note`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason, MEMORY_CODE_NOT_FOUND, MemoryError};
use oneiron::note::{NoteProgramEdit, NoteProgramEditOutcome, NoteVerdict};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::store::GateDecisionId;
use oneiron::{
    EdgeActorClass, EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig, WriteActor,
};

const TEXT: &str = "The lighthouse keeper logs the tide at dawn.";

/// A hosted vault with a device keystore, so a held privacy erase keeps its record
/// use-limited.
fn open_hosted_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the hosted vault");
    let mut config = VaultConfig::default();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open_owned(dir.path(), config).expect("open the hosted vault");
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    (dir, vault)
}

fn owner(vault: &Vault) -> EntityId {
    vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor")
}

fn owner_writer(vault: &Vault) -> WriteActor {
    WriteActor::new(owner(vault), EdgeActorClass::Human)
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = owner(vault);
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: owner proof")
}

/// Places a customer hold on `record` and runs its privacy erase, which the hold refuses: the
/// record stays stored and use-limited.
fn use_limit(vault: &Vault, record: EntityId) {
    let hold = vault
        .place_legal_hold(
            &owner_proof(vault),
            vec![LegalHoldTarget::Record(record)],
            Some("matter-note-content".to_owned()),
        )
        .expect("FIXTURE: place the customer hold");
    assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
    let memory = vault.memory(owner(vault), EdgeActorClass::Human);
    let preview = memory
        .preview_entity_delete(&record)
        .expect("FIXTURE: preview the privacy erase");
    let outcome = memory
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
        .expect("FIXTURE: the privacy erase runs");
    assert_eq!(
        outcome.first.reason.as_str(),
        "privacy_erase_kept",
        "FIXTURE: the held privacy erase is kept: {outcome:?}"
    );
    assert!(
        vault
            .legal_hold_use_limit(&record)
            .expect("FIXTURE: read the use limit")
            .is_some(),
        "FIXTURE: the kept erase use-limits the record"
    );
}

fn write_note(vault: &Vault) -> EntityId {
    vault
        .create_note("research", TEXT, owner_writer(vault))
        .expect("FIXTURE: the owner writes the NOTE")
}

/// An append at the end of `note`'s text, built while the NOTE still reads.
fn append(vault: &Vault, note: EntityId, words: &str) -> NoteProgramEdit {
    let doc = vault
        .note_program_document(note)
        .expect("FIXTURE: read the NOTE document")
        .expect("FIXTURE: the NOTE has a document");
    NoteProgramEdit::InsertAfter {
        anchor: doc
            .anchor(doc.text().chars().count())
            .expect("FIXTURE: the end anchor"),
        text: words.to_owned(),
    }
}

fn text(vault: &Vault, note: EntityId) -> String {
    vault
        .note_text(note)
        .expect("the stored NOTE text reads at the host")
}

fn assert_not_found<T: std::fmt::Debug>(result: Result<T, MemoryError>, door: &str) {
    let refused = match result {
        Ok(answer) => panic!("{door} of a use-limited NOTE is refused, not answered: {answer:?}"),
        Err(refused) => refused,
    };
    assert_eq!(
        refused.code, MEMORY_CODE_NOT_FOUND,
        "{door} answers the base put's absence: {refused:?}"
    );
}

#[test]
fn an_edit_of_a_use_limited_note_answers_not_found_and_keeps_its_text() {
    let (_dir, vault) = open_hosted_vault();
    let held = write_note(&vault);
    let control = write_note(&vault);
    let held_edit = append(&vault, held, " Later words.");
    let control_edit = append(&vault, control, " Later words.");
    use_limit(&vault, held);

    assert_not_found(
        vault.edit_note(held, &held_edit, owner_writer(&vault)),
        "the owner's edit",
    );
    assert_eq!(
        text(&vault, held),
        TEXT,
        "the use-limited NOTE keeps its text"
    );
    assert!(
        vault
            .legal_hold_use_limit(&held)
            .expect("read the use limit")
            .is_some(),
        "the NOTE stays use-limited"
    );

    let landed = vault
        .edit_note(control, &control_edit, owner_writer(&vault))
        .expect("the same edit of a NOTE no hold keeps is taken");
    assert!(
        matches!(landed, NoteProgramEditOutcome::Edited { .. }),
        "the owner's edit of a NOTE no hold keeps lands: {landed:?}"
    );
    assert_eq!(text(&vault, control), format!("{TEXT} Later words."));
}

#[test]
fn a_title_seal_or_fork_of_a_use_limited_note_answers_not_found() {
    let (_dir, vault) = open_hosted_vault();
    let held = write_note(&vault);
    use_limit(&vault, held);
    let memory = vault.memory(owner(&vault), EdgeActorClass::Human);

    assert_not_found(memory.set_note_title(held, "Tide log"), "a title");
    assert_not_found(vault.seal_note(held, owner_writer(&vault)), "a seal");
    assert_not_found(
        vault.fork_note(
            held,
            &NoteProgramEdit::Rewrite {
                text: format!("{TEXT} Rewritten."),
            },
            owner_writer(&vault),
        ),
        "a new fork",
    );
    assert_eq!(
        text(&vault, held),
        TEXT,
        "the use-limited NOTE keeps its text"
    );
}

#[test]
fn a_fork_opened_before_the_use_limit_does_not_land_after_it() {
    let (_dir, vault) = open_hosted_vault();
    let held = write_note(&vault);
    let rewrite = |words: &str| NoteProgramEdit::Rewrite {
        text: format!("{TEXT} {words}"),
    };
    let opened = vault
        .fork_note(held, &rewrite("Switched."), owner_writer(&vault))
        .expect("FIXTURE: the owner forks the NOTE");
    let bundle = vault
        .open_note_proposal(&[opened], "revise the log", owner_writer(&vault))
        .expect("FIXTURE: the owner opens the proposal");
    assert!(
        bundle.landed.is_empty(),
        "FIXTURE: a declared rewrite waits for a switch"
    );
    let unopened = vault
        .fork_note(held, &rewrite("Merged."), owner_writer(&vault))
        .expect("FIXTURE: the owner forks the NOTE again");
    use_limit(&vault, held);

    assert_not_found(
        vault.review_note_proposal(bundle.id, NoteVerdict::Switch, owner_writer(&vault)),
        "a switch of a fork opened before the hold",
    );
    assert_not_found(
        vault.open_note_proposal(&[unopened], "revise the log", owner_writer(&vault)),
        "opening a fork made before the hold",
    );
    assert_eq!(
        text(&vault, held),
        TEXT,
        "the use-limited NOTE keeps its text"
    );
}

#[test]
fn a_facet_fork_of_a_use_limited_note_answers_not_found() {
    let (_dir, vault) = open_hosted_vault();
    let held = write_note(&vault);
    let control = write_note(&vault);
    let facet = EntityId::from_bytes([0x53; 16]).expect("facet id");
    vault
        .put_entity(
            &facet,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .expect("FIXTURE: a facet to fork into");
    use_limit(&vault, held);
    let held_edges = vault
        .edges_in(&held)
        .expect("read the edges into the held NOTE")
        .len();

    for supersede in [false, true] {
        assert_not_found(
            vault.fork_to_facet(held, facet, supersede, owner_writer(&vault)),
            "a facet fork",
        );
    }
    assert_eq!(
        text(&vault, held),
        TEXT,
        "the use-limited NOTE keeps its text"
    );
    assert_eq!(
        vault
            .edges_in(&held)
            .expect("read the edges into the held NOTE")
            .len(),
        held_edges,
        "no fork links to or supersedes the use-limited NOTE"
    );

    let fork = vault
        .fork_to_facet(control, facet, true, owner_writer(&vault))
        .expect("the same fork of a NOTE no hold keeps is taken");
    assert_eq!(
        text(&vault, fork),
        TEXT,
        "the fork of a NOTE no hold keeps carries its text"
    );
}
