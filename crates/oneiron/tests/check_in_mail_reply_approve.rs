//! ROLES-CHECKIN P2.5, row 2k9a (ARCH-0082 #act-table "Outbound send (C)" and
//! #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov 13:39):
//! `vault.mail.reply.approve` checks in, in the 2j apply shape.
//!
//! - The vault Owner's approval of their own mailbox's draft goes on their own
//!   proof and records an `outbound_send` decision. With `check_in_ref` the
//!   Owner applies an asker's approved check-in for exactly the revision's
//!   send, spent in the approve writer; the decision names the check-in and
//!   its asker. A refused spend refuses the whole writer and spends nothing.
//! - A retry names the same check-in or none; another check-in is refused.
//! - A member's approval of their own mailbox's draft records no decision; a
//!   `check_in_ref` from a member is refused before anything is written.
//!
//! The dispatch after the writer cannot reach a server here, so each approve
//! may answer Ok or `did not dispatch`; every assertion reads the stored
//! draft back instead of the answer.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_mail_reply_approve`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::check_in::{
    ActClass, CheckInMode, CheckInScope, HolderKind, OpenPendingCheckIn, Rung, RungHolder,
    RungMembers, WaitReason, mail_reply_approve_effect_digest,
};
use oneiron::mail_pack::{MailReplyApproveRequest, MailReplyDraftState};
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::check_in::{FixedChain, open};
use oneiron::test_doors::mail_reply::{hold_draft, read_draft, seed};
use oneiron::{EntityId, TimeRange, Vault};
use owner_apply_fixture::{approved, owner_decision, proof, rooted, spent};

const APPROVE: &str = "vault.mail.reply.approve";

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

/// An asker's ask for `verb`'s `act` over `digest`, opened and left
/// unanswered: its id and its asker.
fn opened(
    vault: &Vault,
    owner: EntityId,
    verb: &str,
    act: ActClass,
    digest: &[u8; 32],
) -> (EntityId, EntityId) {
    let asker = EntityId::now();
    let chain = FixedChain::default().with(
        Rung::Owner,
        RungMembers::Holders(vec![RungHolder {
            principal: owner,
            kind: HolderKind::Person,
        }]),
    );
    let ask = OpenPendingCheckIn {
        asker,
        grant_ref: "grant:deputy".to_owned(),
        verb: verb.to_owned(),
        act,
        scope: CheckInScope::default(),
        effect_digest: *digest,
        mode: CheckInMode::AlwaysAsk,
        reason: WaitReason::AlwaysAsk,
        asker_wait_secs: None,
        until: None,
        undo_plan: None,
        delay_window: None,
    };
    let id = open(vault, ask, &chain).expect("the agent asks").id;
    (id, asker)
}

fn approve_request(
    draft: EntityId,
    revision: u64,
    check_in: Option<EntityId>,
) -> MailReplyApproveRequest {
    MailReplyApproveRequest {
        draft_ref: draft.to_hex(),
        revision,
        check_in_ref: check_in.map(|id| id.to_hex()),
    }
}

/// An approve that reached its writer answers Ok or `did not dispatch`; any
/// other Err means the writer refused it.
fn assert_writer_outcome(
    outcome: &Result<oneiron::mail_pack::MailReplyDraftView, oneiron::memory::MemoryError>,
) {
    if let Err(error) = outcome {
        assert!(
            error.message.contains("did not dispatch"),
            "an approve that ran its writer only fails its dispatch: {error:?}"
        );
    }
}

/// The Owner's own approval records their own proof and leaves Proposed.
#[test]
fn an_owners_own_approval_records_own_proof() {
    let (_dir, vault, owen, owen_proof) = rooted();
    let (draft, revision, _plan) =
        seed(&vault, owen, "owen@example.com", "yuki@example.com").expect("a proposed reply");
    let outcome = vault.approve_mail_reply(&owen_proof, &approve_request(draft, revision, None));
    assert_writer_outcome(&outcome);
    let stored = read_draft(&vault, owen, draft).expect("the draft reads back");
    assert_ne!(
        stored.state,
        MailReplyDraftState::Proposed,
        "the approval ran: {stored:?}"
    );
    assert_eq!(
        stored.check_in,
        Some(owner_decision(ActClass::OutboundSend, None, None)),
        "the Owner's own approval records their own proof: {stored:?}"
    );
}

/// The Owner applies an asker's approved ask once. A retry of the approved
/// revision (left Approved, as a held dispatch leaves it) passes on the same
/// check-in and spends nothing again; another check-in is refused and stays
/// unspent.
#[test]
fn an_owner_applies_an_askers_approved_ask() {
    let (_dir, vault, owen, owen_proof) = rooted();
    let (draft, revision, plan) =
        seed(&vault, owen, "owen@example.com", "yuki@example.com").expect("a proposed reply");
    let digest = mail_reply_approve_effect_digest(&draft, revision, &plan);
    let (asked, asker) = approved(
        &vault,
        owen,
        &owen_proof,
        APPROVE,
        ActClass::OutboundSend,
        &digest,
    );
    let outcome =
        vault.approve_mail_reply(&owen_proof, &approve_request(draft, revision, Some(asked)));
    assert_writer_outcome(&outcome);
    let stored = read_draft(&vault, owen, draft).expect("the draft reads back");
    assert_ne!(
        stored.state,
        MailReplyDraftState::Proposed,
        "the applied approval ran: {stored:?}"
    );
    assert_eq!(
        stored.check_in,
        Some(owner_decision(
            ActClass::OutboundSend,
            Some(asked),
            Some(asker)
        )),
        "the decision names the check-in and its asker: {stored:?}"
    );
    assert!(spent(&vault, &asked), "the writer spent the check-in");

    // The dummy credential's send ends Unsettled, which a retry may not
    // press; a held dispatch leaves the revision Approved, and its retry
    // reaches the check-in guard.
    hold_draft(&vault, draft).expect("the draft held");
    let (another, _) = approved(
        &vault,
        owen,
        &owen_proof,
        APPROVE,
        ActClass::OutboundSend,
        &digest,
    );
    let swapped = vault.approve_mail_reply(
        &owen_proof,
        &approve_request(draft, revision, Some(another)),
    );
    let error = swapped.expect_err("a retry on another check-in is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{error:?}");
    assert!(
        error.message.contains("not on that check-in"),
        "the press names its check-in: {error:?}"
    );
    assert!(!spent(&vault, &another), "a refused retry spends nothing");

    let retry =
        vault.approve_mail_reply(&owen_proof, &approve_request(draft, revision, Some(asked)));
    if let Err(error) = &retry {
        assert!(
            !error.message.contains("not on that check-in"),
            "the same check-in is not refused: {error:?}"
        );
    }
    let again = read_draft(&vault, owen, draft).expect("the draft reads back");
    assert_eq!(
        again.check_in, stored.check_in,
        "a retry spends nothing again: {again:?}"
    );
}

/// An ask that does not apply is refused and left unspent: unanswered, or
/// approved over another digest.
#[test]
fn an_ask_that_does_not_apply_is_refused_and_left_unspent() {
    let (_dir, vault, owen, owen_proof) = rooted();
    let (draft, revision, plan) =
        seed(&vault, owen, "owen@example.com", "yuki@example.com").expect("a proposed reply");
    let digest = mail_reply_approve_effect_digest(&draft, revision, &plan);
    let (unanswered, _) = opened(&vault, owen, APPROVE, ActClass::OutboundSend, &digest);
    let refused = vault.approve_mail_reply(
        &owen_proof,
        &approve_request(draft, revision, Some(unanswered)),
    );
    assert!(
        refused.is_err(),
        "an unanswered ask approves nothing: {refused:?}"
    );
    let stored = read_draft(&vault, owen, draft).expect("the draft reads back");
    assert_eq!(
        (stored.state, stored.check_in.clone()),
        (MailReplyDraftState::Proposed, None),
        "a refused approve writes nothing: {stored:?}"
    );
    assert!(
        !spent(&vault, &unanswered),
        "a refused apply spends nothing"
    );

    let (_dir, vault, owen, owen_proof) = rooted();
    let (draft, revision, plan) =
        seed(&vault, owen, "owen@example.com", "yuki@example.com").expect("a proposed reply");
    let other = mail_reply_approve_effect_digest(&draft, revision + 1, &plan);
    let (asked, _) = approved(
        &vault,
        owen,
        &owen_proof,
        APPROVE,
        ActClass::OutboundSend,
        &other,
    );
    let refused =
        vault.approve_mail_reply(&owen_proof, &approve_request(draft, revision, Some(asked)));
    assert!(
        refused.is_err(),
        "an ask for another revision approves nothing: {refused:?}"
    );
    let stored = read_draft(&vault, owen, draft).expect("the draft reads back");
    assert_eq!(
        (stored.state, stored.check_in.clone()),
        (MailReplyDraftState::Proposed, None),
        "a refused approve writes nothing: {stored:?}"
    );
    assert!(!spent(&vault, &asked), "a refused apply spends nothing");
}

/// A member's `check_in_ref` is refused and their own approval records none.
#[test]
fn a_members_check_in_ref_is_refused_and_their_own_approval_records_none() {
    let (_dir, vault, owen, owen_proof) = rooted();
    let yuki = EntityId::now();
    person(&vault, yuki);
    let yuki_proof = proof(&vault, yuki);
    let (draft, revision, plan) =
        seed(&vault, yuki, "yuki@example.com", "owen@example.com").expect("a proposed reply");
    let digest = mail_reply_approve_effect_digest(&draft, revision, &plan);
    let (asked, _) = approved(
        &vault,
        owen,
        &owen_proof,
        APPROVE,
        ActClass::OutboundSend,
        &digest,
    );
    let refused =
        vault.approve_mail_reply(&yuki_proof, &approve_request(draft, revision, Some(asked)));
    let error = refused.expect_err("a member's check_in_ref is refused");
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "a member names no check-in: {error:?}"
    );
    let stored = read_draft(&vault, yuki, draft).expect("the draft reads back");
    assert_eq!(
        (stored.state, stored.check_in.clone()),
        (MailReplyDraftState::Proposed, None),
        "a refused approve writes nothing: {stored:?}"
    );
    assert!(!spent(&vault, &asked), "a refused apply spends nothing");

    let outcome = vault.approve_mail_reply(&yuki_proof, &approve_request(draft, revision, None));
    assert_writer_outcome(&outcome);
    let stored = read_draft(&vault, yuki, draft).expect("the draft reads back");
    assert_ne!(
        stored.state,
        MailReplyDraftState::Proposed,
        "the member's own approval ran: {stored:?}"
    );
    assert_eq!(
        stored.check_in, None,
        "a member's own approval records none: {stored:?}"
    );
}
