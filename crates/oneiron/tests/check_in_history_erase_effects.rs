//! ROLES-CHECKIN P2.5, row 2k2b (ARCH-0082 #act-table "Erase (C)" and
//! #owner-own-acts; Engine ruling P25-SHAPE Q1 and Q4 = A, 14 Nov 13:39): a
//! NOTE's history purge in the 2j apply shape.
//!
//! - `vault.notes.history_purge`, whose door names the act class `erase`,
//!   takes `check_in_ref`. An Owner's own purge is never gated: its outcome
//!   records the Owner's own-proof decision.
//! - With `check_in_ref` the Owner applies another asker's approved check-in
//!   for that note's purge on their own proof: it is spent in the purge's
//!   own writer, the outcome names the asker as requester, and it applies
//!   once. A check-in for another note's history erases nothing and stays
//!   unspent, and so does one whose purge a legal hold refuses
//!   ([CHECK-IN-SPEND-BEFORE-ERASE]).
//! - With two Owners the purge waits on its `erase` act, and the act records
//!   the decision. The act's start spends an applied check-in in its own
//!   writer, so an erase whose act never starts leaves it unspent.
//! - With one Owner the purge erases at once, so it takes the owner's shared
//!   confirm (L8-49): the call passes back the confirm
//!   `vault.owner_confirm.preview` returned for it, and the preview names the
//!   same `check_in_ref`. The two-Owner start takes none (PURGE-START).
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
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::verbs::{
    NoteHistoryPurgeOutcome, NoteHistoryPurgeRequest, OwnerConfirmPreviewRequest,
    preview_owner_confirm, purge_note_history_as_owner,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
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
        let input = NoteHistoryPurgeRequest {
            note_ref: note.to_hex(),
            confirm: None,
            check_in_ref: check_in_ref.map(|id| id.to_hex()),
        };
        let confirm = preview_owner_confirm(
            &memory,
            &owner_proof,
            OwnerConfirmPreviewRequest {
                verb: HISTORY_PURGE.to_owned(),
                input: serde_json::to_value(&input).expect("the purge input encodes"),
            },
        )
        .expect("the owner previews the purge")
        .confirm;
        purge_note_history_as_owner(
            &vault,
            &owner_proof,
            NoteHistoryPurgeRequest {
                confirm: Some(confirm),
                ..input
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
    second_owner(&vault, owner, &owner_proof);
    let note = authored_note(&vault, owner);

    let outcome = purge_note_history_as_owner(
        &vault,
        &owner_proof,
        NoteHistoryPurgeRequest {
            note_ref: note.to_hex(),
            confirm: None,
            check_in_ref: None,
        },
    )
    .expect("the owner starts the purge with no confirm");
    let (act_id, check_in) = waiting(outcome);
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

/// [CHECK-IN-SPEND-BEFORE-ERASE], erase at once: a purge that a legal hold
/// refuses leaves the approved check-in it applied unspent, so the asker
/// need not ask again.
#[test]
fn a_purge_a_legal_hold_refuses_leaves_the_applied_check_in_unspent() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let note = authored_note(&vault, owner);
    let digest = text_history_erase_effect_digest(&note, None);
    let (asked, _asker) = approved(
        &vault,
        owner,
        &owner_proof,
        HISTORY_PURGE,
        ActClass::Erase,
        &digest,
    );
    vault
        .place_legal_hold(&owner_proof, vec![LegalHoldTarget::Record(note)], None)
        .expect("the owner holds the note");
    let input = NoteHistoryPurgeRequest {
        note_ref: note.to_hex(),
        confirm: None,
        check_in_ref: Some(asked.to_hex()),
    };
    let confirm = preview_owner_confirm(
        &vault.memory(owner, EdgeActorClass::Human),
        &owner_proof,
        OwnerConfirmPreviewRequest {
            verb: HISTORY_PURGE.to_owned(),
            input: serde_json::to_value(&input).expect("the purge input encodes"),
        },
    )
    .expect("the owner previews the purge")
    .confirm;
    let refused = purge_note_history_as_owner(
        &vault,
        &owner_proof,
        NoteHistoryPurgeRequest {
            confirm: Some(confirm),
            ..input
        },
    );
    assert!(
        refused.is_err(),
        "a held note keeps its history: {refused:?}"
    );
    assert!(
        !spent(&vault, &asked),
        "a purge the hold refuses leaves the approval unspent"
    );
}

/// [CHECK-IN-SPEND-BEFORE-ERASE], veto window: with two Owners the `erase`
/// act's start spends the applied check-in in its own writer. An erase whose
/// act never starts (an entity with no text history) leaves it unspent; a
/// NOTE's act that starts spends it and records it.
#[test]
fn a_veto_window_erase_spends_its_check_in_only_when_its_act_starts() {
    let (_dir, vault, owner, owner_proof) = rooted();
    second_owner(&vault, owner, &owner_proof);

    let bare = EntityId::now();
    let (bare_ask, _) = approved(
        &vault,
        owner,
        &owner_proof,
        HISTORY_PURGE,
        ActClass::Erase,
        &text_history_erase_effect_digest(&bare, None),
    );
    let refused = vault.start_text_history_erase_with_check_in(
        &owner_proof,
        &bare,
        None,
        Some(bare_ask),
        || Ok(None),
    );
    assert!(
        refused.is_err(),
        "an entity with no text history starts no erase act: {refused:?}"
    );
    assert!(
        !spent(&vault, &bare_ask),
        "an erase act that never starts leaves the approval unspent"
    );

    let note = authored_note(&vault, owner);
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        HISTORY_PURGE,
        ActClass::Erase,
        &text_history_erase_effect_digest(&note, None),
    );
    let outcome = purge_note_history_as_owner(
        &vault,
        &owner_proof,
        NoteHistoryPurgeRequest {
            note_ref: note.to_hex(),
            confirm: None,
            check_in_ref: Some(asked.to_hex()),
        },
    )
    .expect("the owner starts the purge applying the approved check-in");
    let (act_id, check_in) = waiting(outcome);
    assert_eq!(
        check_in,
        Some(owner_decision(ActClass::Erase, Some(asked), Some(asker))),
        "the outcome names the check-in it applied and its asker"
    );
    let act = vault
        .pending_authority_act(&act_id)
        .expect("read the act")
        .expect("the act is stored");
    assert_eq!(act.check_in, check_in, "the erase act records the decision");
    assert!(spent(&vault, &asked), "the act's start spent the check-in");
}

/// A NOTE the owner authors.
fn authored_note(vault: &Vault, owner: EntityId) -> EntityId {
    EntityId::from_hex(
        &vault
            .memory(owner, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(owner), "a take about the owner")
            .expect("the owner authors a NOTE")
            .id_hex,
    )
    .expect("a note id")
}

/// The act id and the decision of a purge that waits on its `erase` act.
fn waiting(
    outcome: NoteHistoryPurgeOutcome,
) -> (String, Option<oneiron::check_in::CheckInDecision>) {
    match outcome {
        NoteHistoryPurgeOutcome::Waiting {
            act_id, check_in, ..
        } => (act_id, check_in),
        erased @ NoteHistoryPurgeOutcome::Erased { .. } => {
            panic!("two Owners: the purge waits on its act: {erased:?}")
        }
    }
}

/// Makes the vault a shared one with a second live Owner beside `owner`, so
/// a history erase waits on the `erase` veto window.
fn second_owner(vault: &Vault, owner: EntityId, owner_proof: &AuthenticatedOwner) {
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
            owner_proof,
            SHARED,
            None,
            &[member(owner), member(second)],
            1,
        )
        .expect("a shared vault with two Owners");
    let second_proof = proof(vault, second);
    let invitation = vault
        .shared_invitations(&second_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == Role::Owner)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&second_proof, SHARED, &invitation.id)
        .expect("the second Owner accepts");
}
