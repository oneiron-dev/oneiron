//! ROLES-CHECKIN P2.5, row 2k2b (ARCH-0082 #act-table "Erase (C)" and
//! #owner-own-acts; Engine ruling P25-SHAPE Q1 and Q4 = A, 14 Nov 13:39): a
//! NOTE's history purge in the 2j apply shape.
//!
//! - `vault.notes.history_purge`, whose door names the act class `erase`,
//!   takes `check_in_ref`. An Owner's own purge is never gated: its outcome
//!   records the Owner's own-proof decision.
//! - With `check_in_ref` the Owner applies another asker's approved check-in
//!   for that note's purge on their own proof: it is spent before the
//!   purge, the outcome names the asker as requester, and it applies once.
//!   A check-in for another note's history erases nothing and stays unspent.
//! - With two Owners the purge waits on its `erase` act, and the act records
//!   the decision.
//!
//! On the base (2k2a) this file does not build: the purge request has no
//! `check_in_ref`, its outcome no `check_in`, and
//! `text_history_erase_effect_digest` does not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_history_erase_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::check_in::{ActClass, text_history_erase_effect_digest};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::verbs::{
    NoteHistoryPurgeOutcome, NoteHistoryPurgeRequest, purge_note_history_as_owner,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange};
use owner_apply_fixture::{approved, owner_decision, proof, rooted, spent};

const SHARED: u64 = 44;
const HISTORY_PURGE: &str = "vault.notes.history_purge";

#[test]
fn the_owner_applies_an_approved_history_purge_once() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let note = || {
        let take = memory
            .author_take(TakeTarget::Subject(owner), "a take about the owner")
            .expect("the owner authors a NOTE");
        EntityId::from_hex(&take.id_hex).expect("a note id")
    };
    let purge = |note: EntityId, check_in_ref: Option<EntityId>| {
        purge_note_history_as_owner(
            &vault,
            &owner_proof,
            NoteHistoryPurgeRequest {
                note_ref: note.to_hex(),
                check_in_ref: check_in_ref.map(|id| id.to_hex()),
            },
        )
    };
    let decision = |outcome: NoteHistoryPurgeOutcome| match outcome {
        NoteHistoryPurgeOutcome::Erased { check_in, .. } => check_in,
        waiting @ NoteHistoryPurgeOutcome::Waiting { .. } => {
            panic!("one Owner: the purge erases at once: {waiting:?}")
        }
    };

    let own = purge(note(), None).expect("the owner purges on their own proof");
    assert_eq!(
        decision(own),
        Some(owner_decision(ActClass::Erase, None, None)),
        "the Owner's own purge records their own proof"
    );

    let target = note();
    let digest = text_history_erase_effect_digest(&target, None);
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        HISTORY_PURGE,
        ActClass::Erase,
        &digest,
    );
    let other_note = purge(note(), Some(asked));
    assert!(
        other_note.is_err(),
        "an ask for another note's history erases nothing: {other_note:?}"
    );
    assert!(!spent(&vault, &asked), "a refused apply spends nothing");

    let applied = purge(target, Some(asked)).expect("the owner applies the approved purge");
    assert_eq!(
        decision(applied),
        Some(owner_decision(ActClass::Erase, Some(asked), Some(asker))),
        "the outcome names the check-in it applied and its asker"
    );
    assert!(spent(&vault, &asked), "the purge spent the check-in");
    let again = purge(target, Some(asked));
    assert!(again.is_err(), "a spent check-in applies once: {again:?}");
}

#[test]
fn a_history_purge_held_by_the_veto_window_records_its_decision_on_its_act() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let second = EntityId::now();
    vault
        .put_entity(
            &second,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let member = |member_ref| InitialSharedMember {
        member_ref,
        role: Some(Role::Owner),
    };
    vault
        .initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[member(owner), member(second)],
            1,
        )
        .expect("a shared vault with two Owners");
    let second_proof = proof(&vault, second);
    let invitation = vault
        .shared_invitations(&second_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == Role::Owner)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&second_proof, SHARED, &invitation.id)
        .expect("the second Owner accepts");
    let note = EntityId::from_hex(
        &vault
            .memory(owner, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(owner), "a take about the owner")
            .expect("the owner authors a NOTE")
            .id_hex,
    )
    .expect("a note id");

    let outcome = purge_note_history_as_owner(
        &vault,
        &owner_proof,
        NoteHistoryPurgeRequest {
            note_ref: note.to_hex(),
            check_in_ref: None,
        },
    )
    .expect("the owner starts the purge");
    let (act_id, check_in) = match outcome {
        NoteHistoryPurgeOutcome::Waiting {
            act_id, check_in, ..
        } => (act_id, check_in),
        erased @ NoteHistoryPurgeOutcome::Erased { .. } => {
            panic!("two Owners: the purge waits on its act: {erased:?}")
        }
    };
    assert_eq!(check_in, Some(owner_decision(ActClass::Erase, None, None)));
    let act = vault
        .pending_authority_act(&act_id)
        .expect("read the act")
        .expect("the act is stored");
    assert_eq!(
        act.check_in, check_in,
        "the erase act records that the Owner went on their own proof"
    );
}
