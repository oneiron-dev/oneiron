//! A shared-vault member's NOTE edit inside its content-write grant lands,
//! on the program door and on the scalar NOTE door (FIX
//! [NOTE-EDIT-FEDERATION-GRANT]). Whether an edit lands or waits is the
//! Grant's answer for this actor and this NOTE (DEC-0006 #10, ARCH-0032
//! #forks-proposals); a Member works "exactly as its scopes allow" (ARCH-0043
//! #shared-vault-authority; RULING MEMBER-SYNC-WRITES = A), whatever its
//! class (RULING MEMBER-GRANT-AGENT-LANDS = A). The same grant decides the
//! Member's own fork, and no other writer's: another Member's fork still
//! waits for the owner. A Viewer's edit is still refused, and a personal
//! vault, which has no roster, still answers by the owner binding and
//! automatic grants alone.
//!
//! Each founding member is invited and holds its grant once it accepts
//! (OF-531), so the roster accepts before anyone writes.
//!
//! `cargo test --locked -p oneiron --all-features --test shared_note_member_edit_lands`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::note::{
    NoteEdit, NoteEditOutcome, NoteProgramEdit, NoteProgramEditOutcome, NoteVerdict,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

const SHARED: u64 = 42;
const BASE: &str = "The lighthouse keeper logs the tide at dawn.";

fn person(vault: &Vault, label: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            label,
        )
        .expect("a live person");
    id
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `member` accepts its founding invitation at `role`, so it holds the grant.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("the member's invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// The roster of one shared vault: its embedded owner as Owner, two
/// Members and a Viewer, each having accepted its founding invitation.
struct Roster {
    a: EntityId,
    b: EntityId,
    viewer: EntityId,
}

fn shared(vault: &Vault) -> Roster {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let roster = Roster {
        a: person(vault, b"member a"),
        b: person(vault, b"member b"),
        viewer: person(vault, b"viewer"),
    };
    let member = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[
                member(owner, Role::Owner),
                member(roster.a, Role::Member),
                member(roster.b, Role::Member),
                member(roster.viewer, Role::Viewer),
            ],
            1,
        )
        .expect("a shared vault with two Members and a Viewer");
    accept(vault, roster.a, Role::Member);
    accept(vault, roster.b, Role::Member);
    accept(vault, roster.viewer, Role::Viewer);
    roster
}

/// A NOTE that `author` writes as a Human through its own memory door.
fn note_by(vault: &Vault, author: EntityId) -> EntityId {
    let receipt = vault
        .memory(author, EdgeActorClass::Human)
        .create_note("research", BASE)
        .expect("the member writes a NOTE");
    EntityId::from_hex(&receipt.id_hex).expect("NOTE id")
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

fn prefix(words: &str) -> [NoteEdit; 1] {
    [NoteEdit {
        start: 0,
        delete: 0,
        insert: words.to_owned(),
    }]
}

#[test]
fn a_members_program_edit_of_its_own_note_inside_its_grant_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let roster = shared(&vault);
    let note = note_by(&vault, roster.a);
    let outcome = vault
        .edit_note(
            note,
            &append(&vault, note, " Member words."),
            WriteActor::new(roster.a, EdgeActorClass::Human),
        )
        .expect("the edit is taken");
    assert!(
        matches!(outcome, NoteProgramEditOutcome::Edited { .. }),
        "a Member's edit inside its grant lands, not waits for the owner: {outcome:?}"
    );
    assert_eq!(text(&vault, note), format!("{BASE} Member words."));
}

#[test]
fn a_members_scalar_edit_of_another_members_note_inside_its_grant_applies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let roster = shared(&vault);
    let note = note_by(&vault, roster.a);
    let frontier = vault.note_document(note).expect("document").frontier;
    let outcome = vault
        .memory(roster.b, EdgeActorClass::Human)
        .apply_note_ops(note, &frontier, &prefix("Member B: "))
        .expect("a Member's scalar edit inside its grant is admitted");
    assert!(
        matches!(outcome, NoteEditOutcome::Applied(_)),
        "the edit applies: {outcome:?}"
    );
    assert_eq!(text(&vault, note), format!("Member B: {BASE}"));
}

#[test]
fn a_members_grant_decides_its_own_fork_and_no_other_writers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let roster = shared(&vault);
    let note = note_by(&vault, roster.a);
    let a = WriteActor::new(roster.a, EdgeActorClass::Human);
    let fork = vault
        .fork_note(
            note,
            &NoteProgramEdit::Rewrite {
                text: "A rewritten log.".to_owned(),
            },
            a,
        )
        .expect("the Member forks its own NOTE");
    let bundle = vault
        .open_note_proposal(&[fork], "Rewrite the log", a)
        .expect("the Member opens its proposal");
    assert_eq!(bundle.waiting.len(), 1, "a rewrite waits for its switch");
    let other = vault.review_note_proposal(
        bundle.id,
        NoteVerdict::Reject,
        WriteActor::new(roster.b, EdgeActorClass::Human),
    );
    assert!(
        other.is_err(),
        "another Member's grant decides no other writer's fork: {other:?}"
    );
    assert_eq!(text(&vault, note), BASE, "the rewrite still waits");
    let own = vault
        .review_note_proposal(bundle.id, NoteVerdict::Switch, a)
        .expect("the Member's grant decides its own fork");
    assert!(own.waiting.is_empty(), "the fork is decided: {own:?}");
    assert_eq!(text(&vault, note), "A rewritten log.");
}

#[test]
fn a_viewers_edit_is_still_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let roster = shared(&vault);
    let note = note_by(&vault, roster.a);
    let frontier = vault.note_document(note).expect("document").frontier;
    let scalar = vault
        .memory(roster.viewer, EdgeActorClass::Human)
        .apply_note_ops(note, &frontier, &prefix("Viewer: "));
    assert!(
        scalar.is_err(),
        "a Viewer's grant admits no write: {scalar:?}"
    );
    let program = vault.edit_note(
        note,
        &append(&vault, note, " Viewer words."),
        WriteActor::new(roster.viewer, EdgeActorClass::Human),
    );
    assert!(
        program.is_err(),
        "a Viewer's program edit is refused too: {program:?}"
    );
    assert_eq!(text(&vault, note), BASE, "the NOTE's text stays as it was");
}

#[test]
fn in_a_personal_vault_an_agents_edit_with_no_grant_still_forks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    let agent = WriteActor::new(person(&vault, b"agent"), EdgeActorClass::Agent);
    let other = person(&vault, b"other agent");
    let note = vault
        .create_note("research", BASE, agent)
        .expect("the agent writes a NOTE");
    let outcome = vault
        .edit_note(note, &append(&vault, note, " Agent words."), agent)
        .expect("the edit is taken");
    assert!(
        matches!(outcome, NoteProgramEditOutcome::ProposedFork { .. }),
        "with no roster and no automatic grant, an agent's edit proposes: {outcome:?}"
    );
    let frontier = vault.note_document(note).expect("document").frontier;
    let scalar = vault.memory(other, EdgeActorClass::Agent).apply_note_ops(
        note,
        &frontier,
        &prefix("Other: "),
    );
    assert!(
        scalar.is_err(),
        "another agent's scalar edit with no grant is refused: {scalar:?}"
    );
    assert_eq!(text(&vault, note), BASE, "the NOTE's text stays as it was");
}
