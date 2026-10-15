//! Event classification, provenance minting and route_event admission tests.

use super::tests::k;
use super::*;

struct OwnFixture;

impl OwnTaskProvenanceSource for OwnFixture {
    fn routing_actor_for_own_task(
        &self,
        _: &StreamConnectionId,
        task: &str,
    ) -> Result<String, WakeMintError> {
        if task == "foreign" {
            Err(WakeMintError::NotOwnTask {
                task_ref: task.into(),
                actor_ref: "other".into(),
            })
        } else {
            Ok("actor".into())
        }
    }
}

#[test]
fn route_event_requires_both_subscription_and_authoritative_actor_for_wakes_and_carriers() {
    let owner = StreamConnectionId("owner".into());
    let consultee = StreamConnectionId("consultee".into());
    let parent = StreamConnectionId("parent".into());
    let unsubscribed_owner = StreamConnectionId("unsubscribed-owner".into());
    let wrong_owner = StreamConnectionId("wrong-owner".into());
    let unsubscribed_parent = StreamConnectionId("unsubscribed-parent".into());
    let wrong_parent = StreamConnectionId("wrong-parent".into());
    let unsubscribed_consultee = StreamConnectionId("unsubscribed-consultee".into());
    let mut r = BoardStreamRegistry::default();
    for (connection, actor, scopes) in [
        (
            &owner,
            "owner",
            BTreeSet::from([SubscriptionScope::MyTasks]),
        ),
        (
            &consultee,
            "consultee",
            BTreeSet::from([SubscriptionScope::ConsultsToMe]),
        ),
        (
            &parent,
            "parent",
            BTreeSet::from([SubscriptionScope::MyChildren]),
        ),
        (&unsubscribed_owner, "owner", BTreeSet::new()),
        (
            &wrong_owner,
            "wrong",
            BTreeSet::from([SubscriptionScope::MyTasks]),
        ),
        (&unsubscribed_parent, "parent", BTreeSet::new()),
        (
            &wrong_parent,
            "wrong",
            BTreeSet::from([SubscriptionScope::MyChildren]),
        ),
        (&unsubscribed_consultee, "consultee", BTreeSet::new()),
    ] {
        r.attach_connection(
            connection.clone(),
            BoardRenderMode::Resident,
            actor.into(),
            scopes,
            0,
        );
    }
    // Every carrier candidate starts with a held epoch; otherwise a broken
    // actor/subscription guard could pass merely because it cannot enqueue yet.
    for connection in [
        &owner,
        &parent,
        &unsubscribed_owner,
        &wrong_owner,
        &unsubscribed_parent,
        &wrong_parent,
    ] {
        assert_eq!(
            r.enqueue(connection, k(1)),
            FrameEnqueueOutcome::ReplacedWithKeyframe
        );
        assert!(r.next_carrier_payload(connection).is_some());
    }
    assert_eq!(r.next_carrier_payload(&consultee), None);
    assert_eq!(r.next_carrier_payload(&unsubscribed_consultee), None);
    let owner_event = VerifiedOwnTaskEvent {
        task_ref: "own".into(),
        actor_ref: "owner".into(),
        event_ref: "wake-owner".into(),
    };
    let consult_event = VerifiedOwnTaskEvent {
        task_ref: "consult".into(),
        actor_ref: "consultee".into(),
        event_ref: "wake-consult".into(),
    };
    let child_event = ChildEvent {
        child_ref: "child".into(),
        parent_actor_ref: "parent".into(),
        event_ref: "carrier-child".into(),
    };
    assert_eq!(
        r.route_event(BoardEvent::OwnTaskFailed {
            event: owner_event.clone(),
            line: "failed".into()
        })
        .wake_enqueued,
        1
    );
    assert_eq!(
        r.route_event(BoardEvent::ConsultArrived {
            event: consult_event,
            line: "consult".into()
        })
        .wake_enqueued,
        1
    );
    assert_eq!(
        r.route_event(BoardEvent::OwnTaskDone {
            event: owner_event,
            delta: DeltaRow {
                key: "owner".into(),
                line: "done".into()
            }
        })
        .carrier_enqueued,
        1
    );
    assert_eq!(
        r.route_event(BoardEvent::ChildDone {
            event: child_event,
            delta: DeltaRow {
                key: "child".into(),
                line: "done".into()
            }
        })
        .carrier_enqueued,
        1
    );
    // ONE-1703: `next_wake` is a non-draining peek, so a routed wake stays
    // queued and every repeated call observes the same envelope.
    assert!(r.next_wake(&owner).is_some());
    assert_eq!(r.next_wake(&owner), r.next_wake(&owner));
    assert_eq!(r.connection_state(&owner).unwrap().wakes.len(), 1);
    assert!(r.next_wake(&consultee).is_some());
    assert_eq!(r.next_wake(&consultee), r.next_wake(&consultee));
    assert!(r.next_carrier_payload(&owner).is_some());
    assert!(r.next_carrier_payload(&parent).is_some());
    for connection in [
        &unsubscribed_owner,
        &wrong_owner,
        &unsubscribed_parent,
        &wrong_parent,
        &unsubscribed_consultee,
    ] {
        assert!(r.next_wake(connection).is_none());
        assert!(r.next_carrier_payload(connection).is_none());
    }
}
