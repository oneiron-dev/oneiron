//! ROLES-CHECKIN P2.6a3, piece 2m (ARCH-0082 #agent-room-add; Engine
//! rulings P26-SHAPE Q2 to Q4 = A and P26-AGENT-GRANT = A, 15 Nov 02:04):
//! a room's Admission yes is the add of the join's subject, and check-in
//! judges it at `rooms.consent`; the owner's invitation records her own
//! decision.
//!
//! - An agent that leads the room's project, and so answers its admission,
//!   is refused while no Grant of its lists `rooms.consent`, nothing opened.
//!   Once a Grant lists it, its yes waits: the door opens the agent's own
//!   pending check-in and the join still holds. Once the Owner approves,
//!   the yes naming it lands the join and records the decision.
//! - Only an Admission yes spends a check-in: any other answer naming one,
//!   Membership included, is refused before anything is read.
//! - The owner's invitation goes at once, with her own decision. A filing
//!   already settled (here refused) records no yes and carries none.
//!
//! Fixture: `check_in/room_add_fixture.rs` (P2.6a).
//!
//! On the base (P2.6a2) this file does not build: the consent answer has no
//! `check_in_ref` and the join outcome no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_room_admission`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/room_add_fixture.rs"]
mod room_add_fixture;

use oneiron::check_in::{CheckInDecision, ROOM_ADD_NOT_GRANTED_REASON};
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN};
use oneiron::workspace_roster::{
    ConsentAnswer, ConsentNeed, ConsentPart, JoinDecision, JoinRequest, JoinSubject,
};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use room_add_fixture::{CONSENT, Org, approved, grant, pending_id};

/// Whether `decision` holds on the room's admission alone.
fn holds_on_admission(decision: &JoinDecision) -> bool {
    matches!(
        decision,
        JoinDecision::Hold { needs }
            if needs.iter().map(|need: &ConsentNeed| need.part).eq([ConsentPart::Admission])
    )
}

#[test]
fn an_agent_leaders_admission_yes_waits_and_lands_once_approved() {
    let org = Org::with_agent_led_room();
    let filed = org.file_seeker_join();
    assert!(
        holds_on_admission(&filed.decision.state),
        "the seeker's join holds on the room's admission: {filed:?}"
    );
    let agent = org.as_agent(org.agent);
    let ungranted = org
        .admit(&agent, &filed.join_ref, None)
        .expect_err("no Grant of the agent lists the verb");
    assert_eq!(ungranted.code, MEMORY_CODE_FORBIDDEN, "{ungranted:?}");
    assert!(
        ungranted.message.contains(ROOM_ADD_NOT_GRANTED_REASON)
            && ungranted.message.contains(CONSENT),
        "the refusal names the route and the verb: {ungranted:?}"
    );
    assert!(
        org.check_in_receipts().is_empty(),
        "the refusal opened no check-in"
    );
    grant(&org.vault, &org.owner_proof, org.agent, &[CONSENT]);
    let waits = org
        .admit(&agent, &filed.join_ref, None)
        .expect_err("the agent's yes waits");
    let id = pending_id(&waits);
    let again = org
        .admit(&agent, &filed.join_ref, None)
        .expect_err("the same yes still waits");
    assert_eq!(
        pending_id(&again),
        id,
        "the same add finds the same check-in"
    );
    assert!(
        holds_on_admission(&org.file_seeker_join().decision.state),
        "a yes that waits lands nothing: the join still holds"
    );
    org.owner_approves(&id);
    let landed = org
        .admit(&agent, &filed.join_ref, Some(&id))
        .expect("the yes naming the approved check-in lands");
    assert_eq!(landed.decision.state, JoinDecision::Ready, "{landed:?}");
    assert_eq!(
        landed.check_in,
        approved(&id),
        "the decision rides the outcome"
    );
    let receipts = org.check_in_receipts();
    assert!(
        receipts.iter().any(|outcome| outcome == "consumed"),
        "the landing yes spent the check-in: {receipts:?}"
    );
}

#[test]
fn only_an_admission_yes_takes_a_check_in_ref() {
    let org = Org::new();
    let owner = org.vault.memory(org.owner, EdgeActorClass::Human);
    for (part, grant) in [
        (ConsentPart::Subject, true),
        (ConsentPart::Membership, true),
        (ConsentPart::Spend, true),
        (ConsentPart::Admission, false),
    ] {
        let refused = owner
            .rooms_consent(&ConsentAnswer {
                join_ref: "ab".repeat(32),
                part,
                grant,
                spend_scope: None,
                check_in_ref: Some(EntityId::now().to_hex()),
            })
            .expect_err("an answer that adds no one spends no check-in");
        assert_eq!(
            refused.code, MEMORY_CODE_BAD_REQUEST,
            "{part:?}: {refused:?}"
        );
        assert!(
            refused.message.contains("check_in_ref"),
            "{part:?}: the refusal names the field: {refused:?}"
        );
    }
    assert!(
        org.check_in_receipts().is_empty(),
        "no refusal opened a check-in"
    );
}

#[test]
fn the_owners_invitation_records_her_own_decision() {
    let org = Org::new();
    let room = EntityId::now();
    org.vault
        .create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![org.owner],
                ..Default::default()
            },
            WriteActor::new(org.owner, EdgeActorClass::Human),
            org.vault.now_recorded_at(),
        )
        .expect("the owner's room");
    let owner = org.vault.memory(org.owner, EdgeActorClass::Human);
    let invitation = |person: EntityId, intent_key: &str| JoinRequest {
        room,
        branch: None,
        subject: JoinSubject::Person(person),
        paid: false,
        spend_scope: None,
        intent_key: intent_key.to_owned(),
    };
    let invited = owner
        .rooms_invite(&invitation(org.member, "invite-member"))
        .expect("the owner invites the person");
    assert_eq!(
        invited.check_in,
        Some(CheckInDecision {
            act_class: "room_add".to_owned(),
            role: "owner".to_owned(),
            mode: Some("auto".to_owned()),
            basis: "sure".to_owned(),
            check_in: None,
            requester: None,
        }),
        "her admission yes is her own add: {invited:?}"
    );
    // No PERSON has this id: the filing is refused at once, so no yes of
    // hers is recorded, on the first call or its replay.
    let nobody = invitation(EntityId::now(), "invite-nobody");
    for call in ["first", "replay"] {
        let refused = owner
            .rooms_invite(&nobody)
            .expect("a refused invitation answers its outcome");
        assert!(
            matches!(refused.decision.state, JoinDecision::Refuse(_)),
            "{call}: {refused:?}"
        );
        assert_eq!(
            refused.check_in, None,
            "{call}: a settled filing records no yes, so no decision: {refused:?}"
        );
    }
    assert!(
        org.check_in_receipts().is_empty(),
        "the owner's own add opens no check-in"
    );
}
