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

struct ChildFixture;

impl ChildProvenanceSource for ChildFixture {
    fn parent_actor_ref(&self, child: &str) -> Result<String, ChildMintError> {
        if child == "missing" {
            Err(ChildMintError::ChildMissing(child.into()))
        } else {
            Ok("actor".into())
        }
    }
}

#[test]
fn provenance_mints_reject_foreign_and_bind_parent() {
    let c = StreamConnectionId("c".into());
    assert!(matches!(
        mint_own_task_event(&OwnFixture, &c, "foreign", "e"),
        Err(WakeMintError::NotOwnTask { .. })
    ));
    let child = mint_child_event(&ChildFixture, "child", "e").unwrap();
    assert_eq!(child.parent_actor_ref(), "actor");
    assert!(mint_child_event(&ChildFixture, "missing", "e").is_err());
}

#[test]
fn own_task_done_routes_delta_after_pending_keyframe() {
    let connection = StreamConnectionId("own-task-route".into());
    let mut registry = BoardStreamRegistry::default();
    let allowed = BTreeSet::from([SubscriptionScope::MyTasks]);
    registry.attach_connection(
        connection.clone(),
        BoardRenderMode::Stream,
        "actor".into(),
        allowed.clone(),
        0,
    );
    registry
        .subscribe(&connection, &allowed)
        .expect("the own-task scope is allowed");
    assert_eq!(
        registry.enqueue(&connection, k(11)),
        FrameEnqueueOutcome::ReplacedWithKeyframe,
    );

    let event = mint_own_task_event(&OwnFixture, &connection, "own", "done")
        .expect("the producer minted a verified own-task event");
    assert_eq!(event.task_ref(), "own");
    assert_eq!(event.actor_ref(), "actor");
    assert_eq!(event.event_ref(), "done");
    let observation = registry.route_event(BoardEvent::OwnTaskDone {
        event,
        delta: DeltaRow {
            key: "task-1".into(),
            line: "settled".into(),
        },
    });
    assert_eq!(observation.carrier_enqueued, 1);

    assert_eq!(registry.next_carrier_payload(&connection), Some(k(11)));
    let delta = registry
        .next_carrier_payload(&connection)
        .expect("the same-epoch settlement delta follows the keyframe");
    assert_eq!(delta.epoch, 11);
    assert_eq!(
        delta.kind,
        FrameKind::Delta(vec![DeltaRow {
            key: super::super::one_line_token("task-1"),
            line: super::super::one_line_token("settled"),
        }])
    );
    assert!(registry.next_carrier_payload(&connection).is_none());
}

#[test]
fn on_demand_never_routes_in_any_mode() {
    for mode in [BoardRenderMode::Stream, BoardRenderMode::Resident] {
        let c = StreamConnectionId(format!("{mode:?}"));
        let mut r = BoardStreamRegistry::default();
        r.attach_connection(
            c.clone(),
            mode,
            "actor".into(),
            SubscriptionScope::ALL.into_iter().collect(),
            0,
        );
        let o = r.route_event(BoardEvent::MemoriesChanged {
            event_ref: "m".into(),
        });
        assert_eq!(o.wake_enqueued + o.carrier_enqueued, 0);
        // ONE-1703: a peek over an empty queue stays empty on every call.
        assert!(r.next_wake(&c).is_none());
        assert!(r.next_wake(&c).is_none());
        assert!(r.next_carrier_payload(&c).is_none());
    }
}

#[test]
fn event_variants_have_exact_class_and_scope() {
    let c = StreamConnectionId("c".into());
    let own = mint_own_task_event(&OwnFixture, &c, "own", "e").unwrap();
    let child = mint_child_event(&ChildFixture, "child", "e").unwrap();
    let cases = [
        (
            BoardEvent::ConsultArrived {
                event: own.clone(),
                line: "x".into(),
            },
            DeliveryClass::Wake,
            SubscriptionScope::ConsultsToMe,
        ),
        (
            BoardEvent::OwnTaskFailed {
                event: own.clone(),
                line: "x".into(),
            },
            DeliveryClass::Wake,
            SubscriptionScope::MyTasks,
        ),
        (
            BoardEvent::OwnTaskDone {
                event: own,
                delta: DeltaRow {
                    key: "x".into(),
                    line: "x".into(),
                },
            },
            DeliveryClass::Carrier,
            SubscriptionScope::MyTasks,
        ),
        (
            BoardEvent::ChildDone {
                event: child,
                delta: DeltaRow {
                    key: "x".into(),
                    line: "x".into(),
                },
            },
            DeliveryClass::Carrier,
            SubscriptionScope::MyChildren,
        ),
        (
            BoardEvent::MemoriesChanged {
                event_ref: "x".into(),
            },
            DeliveryClass::OnDemand,
            SubscriptionScope::Memories,
        ),
        (
            BoardEvent::PresenceChanged {
                event_ref: "x".into(),
            },
            DeliveryClass::OnDemand,
            SubscriptionScope::Presence,
        ),
        (
            BoardEvent::WorldsChanged {
                event_ref: "x".into(),
            },
            DeliveryClass::OnDemand,
            SubscriptionScope::Worlds,
        ),
        (
            BoardEvent::CountsChanged {
                event_ref: "x".into(),
            },
            DeliveryClass::OnDemand,
            SubscriptionScope::Counts,
        ),
    ];
    for (event, class, scope) in cases {
        assert_eq!(event.class(), class);
        assert_eq!(event.subscription_scope(), scope);
    }
}

#[test]
fn repeated_subscription_changes_are_local_and_reattach_resets_defaults() {
    let first = StreamConnectionId("first".into());
    let second = StreamConnectionId("second".into());
    let allowed = BTreeSet::from([SubscriptionScope::MyTasks, SubscriptionScope::MyChildren]);
    let mut r = BoardStreamRegistry::default();
    r.attach_connection(
        first.clone(),
        BoardRenderMode::Resident,
        "actor".into(),
        allowed.clone(),
        0,
    );
    r.attach_connection(
        second.clone(),
        BoardRenderMode::Resident,
        "other".into(),
        allowed.clone(),
        0,
    );
    let defaults = allowed.clone();
    let children = BTreeSet::from([SubscriptionScope::MyChildren]);
    assert_eq!(
        r.unsubscribe(&first, &children).unwrap().active,
        BTreeSet::from([SubscriptionScope::MyTasks])
    );
    let first_add = r.subscribe(&first, &children).unwrap();
    assert_eq!(first_add.active, defaults);
    let second_add = r.subscribe(&first, &children).unwrap();
    assert_eq!(second_add.active, defaults);
    assert_eq!(second_add.connection, first);
    assert_eq!(r.connection_state(&second).unwrap().subscribed, defaults);
    let first_remove = r.unsubscribe(&first, &children).unwrap();
    assert_eq!(
        first_remove.active,
        BTreeSet::from([SubscriptionScope::MyTasks])
    );
    let second_remove = r.unsubscribe(&first, &children).unwrap();
    assert_eq!(
        second_remove.active,
        BTreeSet::from([SubscriptionScope::MyTasks])
    );
    assert_eq!(second_remove.connection, first);
    assert_eq!(r.connection_state(&second).unwrap().subscribed, defaults);
    r.detach(&first);
    r.attach_connection(
        first.clone(),
        BoardRenderMode::Stream,
        "actor".into(),
        allowed,
        0,
    );
    assert_eq!(r.connection_state(&first).unwrap().subscribed, defaults);
}

#[test]
fn keyed_delta_property_preserves_last_value_each_key() {
    let updates = [("a", "0"), ("a", "1"), ("b", "0"), ("b", "1")];
    // Exhaust every sequence through length five, rather than checking one hand-picked trace.
    for length in 0..=5 {
        for encoded in 0..updates.len().pow(length) {
            let mut expected = BTreeMap::new();
            let mut buffer = CarrierCoalesceBuffer::default();
            buffer.push(k(1));
            let _ = buffer.drain();
            let mut trace = encoded;
            for _ in 0..length {
                let (key, line) = updates[trace % updates.len()];
                trace /= updates.len();
                expected.insert(key.to_owned(), line.to_owned());
                buffer.push(BoardStreamFrame {
                    epoch: 1,
                    kind: FrameKind::Delta(vec![DeltaRow {
                        key: key.into(),
                        line: line.into(),
                    }]),
                });
            }
            let rows = match buffer.drain() {
                Some(BoardStreamFrame {
                    kind: FrameKind::Delta(rows),
                    ..
                }) => rows,
                None if expected.is_empty() => Vec::new(),
                other => panic!("unexpected coalesced frame: {other:?}"),
            };
            assert_eq!(
                rows.len(),
                expected.len(),
                "encoded sequence {encoded}, length {length}: duplicate keys"
            );
            let actual = rows
                .iter()
                .map(|row| row.key.as_str())
                .collect::<BTreeSet<_>>();
            assert_eq!(actual.len(), rows.len(), "duplicate raw drained keys");
            let actual = rows
                .into_iter()
                .map(|row| (row.key, row.line))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(
                actual, expected,
                "encoded sequence {encoded}, length {length}"
            );
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
