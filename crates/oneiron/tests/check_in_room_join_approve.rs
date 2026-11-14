//! ROLES-CHECKIN P2.6a2, piece 2m (ARCH-0082 #agent-room-add; Engine
//! rulings P26-SHAPE Q2 to Q4 = A and P26-AGENT-GRANT = A, 15 Nov 02:04):
//! approving a request to join a private thread adds the one who asked, and
//! check-in judges that add at the door.
//!
//! - An agent whose Grant does not list the verb is refused, nothing opened.
//! - An agent's approval waits: the door opens the agent's own pending
//!   check-in and settles nothing; a denial takes no `check_in_ref`. Once
//!   the Owner approves, the approval naming it lands and records the
//!   decision.
//!
//! Fixture: `check_in/room_add_fixture.rs` (P2.6a).
//!
//! On the base (P2.6a) this file does not build: the decision request has
//! no `check_in_ref` and the request view no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_room_join_approve`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/room_add_fixture.rs"]
mod room_add_fixture;

use oneiron::check_in::ROOM_ADD_NOT_GRANTED_REASON;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN};
use oneiron::workspace_roster::{
    ThreadJoinDecisionRequest, ThreadJoinRequest, ThreadJoinRequestState, ThreadJoinRequestsRequest,
};
use room_add_fixture::{APPROVE, Org, approved, pending_id};

#[test]
fn an_agents_approval_of_a_join_request_waits_and_lands_once_approved() {
    let org = Org::new();
    let asked = org
        .as_agent(org.seeker)
        .rooms_thread_join_request(&ThreadJoinRequest {
            thread_ref: org.thread.to_hex(),
        })
        .expect("the seeker asks to join");
    let decide = |check_in_ref: Option<&str>| ThreadJoinDecisionRequest {
        thread_ref: org.thread.to_hex(),
        request_ref: asked.request_ref.clone(),
        check_in_ref: check_in_ref.map(str::to_owned),
    };
    let ungranted = org
        .as_agent(org.ungranted)
        .rooms_thread_join_approve(&decide(None))
        .expect_err("an agent whose Grant does not list the verb is refused");
    assert_eq!(ungranted.code, MEMORY_CODE_FORBIDDEN, "{ungranted:?}");
    assert!(
        ungranted.message.contains(ROOM_ADD_NOT_GRANTED_REASON)
            && ungranted.message.contains(APPROVE),
        "the refusal names the route and the verb: {ungranted:?}"
    );
    assert!(
        org.check_in_receipts().is_empty(),
        "the refusal opened no check-in"
    );
    let agent = org.as_agent(org.agent);
    let waiting = agent
        .rooms_thread_join_approve(&decide(None))
        .expect_err("the agent's approval waits");
    let id = pending_id(&waiting);
    let pending = agent
        .rooms_thread_join_requests(&ThreadJoinRequestsRequest {
            thread_ref: org.thread.to_hex(),
        })
        .expect("the agent lists the requests");
    assert_eq!(
        pending
            .iter()
            .map(|request| (request.request_ref.as_str(), request.state))
            .collect::<Vec<_>>(),
        [(asked.request_ref.as_str(), ThreadJoinRequestState::Pending)],
        "a waiting approval settles nothing"
    );
    let deny = agent
        .rooms_thread_join_deny(&decide(Some(&id)))
        .expect_err("a denial takes no check-in");
    assert_eq!(deny.code, MEMORY_CODE_BAD_REQUEST, "{deny:?}");

    org.owner_approves(&id);
    let approved_view = agent
        .rooms_thread_join_approve(&decide(Some(&id)))
        .expect("the approved approval lands");
    assert_eq!(approved_view.state, ThreadJoinRequestState::Approved);
    assert_eq!(
        approved_view.check_in,
        approved(&id),
        "the approval records the decision"
    );
}
