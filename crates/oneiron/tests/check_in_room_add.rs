//! ROLES-CHECKIN P2.6a, piece 2m (ARCH-0082 #agent-room-add; Engine rulings
//! P26-SHAPE Q2 to Q4 = A and P26-AGENT-GRANT = A, 15 Nov 02:04): an add of
//! someone else to a private thread is judged by check-in at its door.
//!
//! - An agent's add of a room member waits: the door opens the agent's own
//!   pending check-in, adds no one and answers `CHECK_IN_PENDING` naming
//!   it; a repeat names the same one. Once the Owner approves, the call
//!   naming it as `check_in_ref` lands the add from now on and its receipt
//!   records the decision. The spent check-in lands nothing again.
//! - An agent's add asking for the full history, and an add by an agent
//!   whose Grant does not list the verb, are refused, nothing opened.
//! - The Owner's own add goes at once on their own judgment (`sure`).
//!
//! Fixture: `check_in/room_add_fixture.rs`.
//!
//! On the base (1ffd62d8ab9) this file does not build: the add request has
//! no `check_in_ref` and its receipt no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_room_add`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/room_add_fixture.rs"]
mod room_add_fixture;

use oneiron::check_in::{CheckInDecision, ROOM_ADD_FROM_NOW_REASON, ROOM_ADD_NOT_GRANTED_REASON};
use oneiron::memory::{MEMORY_CODE_CHECK_IN_PENDING, MEMORY_CODE_FORBIDDEN};
use oneiron::workspace_roster::ThreadAudienceHistory;
use oneiron::{EdgeActorClass, EntityId};
use room_add_fixture::{ADD, Org, approved, pending_id};

#[test]
fn an_agents_add_waits_and_the_approved_recall_lands_from_now_once() {
    let org = Org::new();
    let agent = org.as_agent(org.agent);
    let waiting = org
        .add(&agent, org.member, ThreadAudienceHistory::FromNow, None)
        .expect_err("the agent's add waits");
    let id = pending_id(&waiting);
    let receipts = org.check_in_receipts();
    assert_eq!(
        receipts.first().map(String::as_str),
        Some("opened"),
        "the wait opened a check-in: {receipts:?}"
    );
    let again = org
        .add(&agent, org.member, ThreadAudienceHistory::FromNow, None)
        .expect_err("a repeat waits");
    assert_eq!(pending_id(&again), id, "a repeat names the same check-in");
    assert_eq!(org.check_in_receipts(), receipts, "a repeat writes nothing");
    let row = org
        .vault
        .pending_check_in(&EntityId::from_hex(&id).expect("a check-in id"))
        .expect("read the check-in")
        .expect("the check-in is stored");
    assert_eq!(
        (row.asker, row.verb.as_str()),
        (org.agent, ADD),
        "the agent's own ask for the add"
    );
    let early = org
        .add(
            &agent,
            org.member,
            ThreadAudienceHistory::FromNow,
            Some(&id),
        )
        .expect_err("an unanswered check-in lands nothing");
    assert_ne!(early.code, MEMORY_CODE_CHECK_IN_PENDING, "{early:?}");

    org.owner_approves(&id);
    let landed = org
        .add(
            &agent,
            org.member,
            ThreadAudienceHistory::FromNow,
            Some(&id),
        )
        .expect("the approved add lands");
    assert_eq!(landed.thread_ref, org.thread.to_hex());
    assert_eq!(
        landed.history,
        Some(ThreadAudienceHistory::FromNow),
        "the person reads from now on"
    );
    assert_eq!(
        landed.check_in,
        approved(&id),
        "the receipt records the decision"
    );
    assert!(
        org.add(
            &agent,
            org.member,
            ThreadAudienceHistory::FromNow,
            Some(&id)
        )
        .is_err(),
        "a spent check-in lands nothing again"
    );
}

#[test]
fn an_agents_full_history_add_and_an_ungranted_agents_add_open_nothing() {
    let org = Org::new();
    let full = org
        .add(
            &org.as_agent(org.agent),
            org.member,
            ThreadAudienceHistory::Full,
            None,
        )
        .expect_err("an agent's add is from now on");
    assert_eq!(full.code, MEMORY_CODE_FORBIDDEN, "{full:?}");
    assert!(full.message.contains(ROOM_ADD_FROM_NOW_REASON), "{full:?}");

    let ungranted = org
        .add(
            &org.as_agent(org.ungranted),
            org.member,
            ThreadAudienceHistory::FromNow,
            None,
        )
        .expect_err("an agent whose Grant does not list the verb is refused");
    assert_eq!(ungranted.code, MEMORY_CODE_FORBIDDEN, "{ungranted:?}");
    assert!(
        ungranted.message.contains(ROOM_ADD_NOT_GRANTED_REASON) && ungranted.message.contains(ADD),
        "the refusal names the route and the verb: {ungranted:?}"
    );
    assert!(
        org.check_in_receipts().is_empty(),
        "neither refusal opened a check-in"
    );
}

#[test]
fn the_owners_add_goes_at_once_on_their_own_judgment() {
    let org = Org::new();
    let owner = org.vault.memory(org.owner, EdgeActorClass::Human);
    let added = org
        .add(&owner, org.member, ThreadAudienceHistory::Full, None)
        .expect("the Owner adds at once");
    assert_eq!(added.history, Some(ThreadAudienceHistory::Full));
    assert_eq!(
        added.check_in,
        Some(CheckInDecision {
            act_class: "room_add".to_owned(),
            role: "owner".to_owned(),
            mode: Some("auto".to_owned()),
            basis: "sure".to_owned(),
            check_in: None,
            requester: None,
        }),
        "the Owner's add records their own judgment"
    );
    assert!(
        org.check_in_receipts().is_empty(),
        "a person's own add opens no check-in"
    );
}
