//! Instance binding, dispatch fallback and delivery-report fencing tests.

use super::*;

fn wake_registry(connections: &[(&StreamConnectionId, &str)]) -> BoardStreamRegistry {
    let mut r = BoardStreamRegistry::default();
    for (connection, actor) in connections {
        r.attach_connection(
            (*connection).clone(),
            BoardRenderMode::Stream,
            (*actor).into(),
            BTreeSet::from([SubscriptionScope::MyTasks]),
            0,
        );
    }
    r
}

fn push_wake(r: &mut BoardStreamRegistry, actor: &str, event: &str) {
    r.route_event(BoardEvent::OwnTaskFailed {
        event: VerifiedOwnTaskEvent {
            task_ref: "task".into(),
            actor_ref: actor.into(),
            event_ref: event.into(),
        },
        line: "failed".into(),
    });
}

#[test]
fn candidate_order_is_total_and_matches_derived_ord() {
    let full = BTreeSet::from([
        WakeAdapterKind::BootPromptSpawn,
        WakeAdapterKind::TmuxSendKeys,
        WakeAdapterKind::CodexStopHook,
        WakeAdapterKind::ClaudeCodeMonitor,
    ]);
    let expected = vec![
        WakeAdapterKind::ClaudeCodeMonitor,
        WakeAdapterKind::CodexStopHook,
        WakeAdapterKind::TmuxSendKeys,
        WakeAdapterKind::BootPromptSpawn,
    ];
    assert_eq!(ordered_candidates(&full), expected);
    // The derived order and the (layer, same_layer_order) rank must never
    // drift into two silent sources of truth.
    assert_eq!(full.into_iter().collect::<Vec<_>>(), expected);
    assert_eq!(WakeAdapterKind::ClaudeCodeMonitor.layer(), 2);
    assert_eq!(WakeAdapterKind::CodexStopHook.layer(), 2);
    assert_eq!(WakeAdapterKind::TmuxSendKeys.layer(), 3);
    assert_eq!(WakeAdapterKind::BootPromptSpawn.layer(), 3);
}

#[test]
fn install_set_mismatch_is_distinct_from_already_bound() {
    let c = StreamConnectionId("bind".into());
    let mut r = wake_registry(&[(&c, "actor")]);
    let one = HarnessInstanceKey::new("wake-instance:v1:claude-code:aaa");
    let two = HarnessInstanceKey::new("wake-instance:v1:claude-code:bbb");
    let monitor = BTreeSet::from([WakeAdapterKind::ClaudeCodeMonitor]);
    let ladder = BTreeSet::from([
        WakeAdapterKind::ClaudeCodeMonitor,
        WakeAdapterKind::TmuxSendKeys,
    ]);
    assert_eq!(one.as_str(), "wake-instance:v1:claude-code:aaa");
    assert!(
        !r.bind_instance(&c, one.clone(), monitor.clone())
            .unwrap()
            .idempotent_replay
    );
    // Same connection, same instance, different set.
    assert_eq!(
        r.bind_instance(&c, one.clone(), ladder.clone()),
        Err(BindInstanceError::InstallSetMismatch {
            connection: c.clone(),
            instance: one.clone(),
            existing: monitor.clone(),
            requested: ladder,
        })
    );
    // Same connection, different instance.
    assert_eq!(
        r.bind_instance(&c, two.clone(), monitor.clone()),
        Err(BindInstanceError::AlreadyBound {
            connection: c.clone(),
            existing: one.clone(),
            requested: two,
        })
    );
    // Neither rejection changed the binding.
    assert!(r.bind_instance(&c, one, monitor).unwrap().idempotent_replay);
    let missing = StreamConnectionId("missing".into());
    assert_eq!(
        r.bind_instance(&missing, HarnessInstanceKey::new("x"), BTreeSet::new()),
        Err(BindInstanceError::ConnectionMissing(missing))
    );
}

#[test]
fn next_wake_peeks_without_draining_and_unbound_never_dispatches() {
    let c = StreamConnectionId("peek".into());
    let mut r = wake_registry(&[(&c, "actor")]);
    push_wake(&mut r, "actor", "e1");
    let peeked = r.next_wake(&c);
    assert!(peeked.is_some());
    assert_eq!(peeked, r.next_wake(&c));
    assert_eq!(r.connection_state(&c).unwrap().wakes.len(), 1);
    // An unbound connection has no dispatch path and still no drain path.
    assert_eq!(r.next_wake_dispatch(&c), None);
    assert_eq!(r.connection_state(&c).unwrap().wakes.len(), 1);
    r.bind_instance(
        &c,
        HarnessInstanceKey::new("i"),
        BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
    )
    .unwrap();
    assert_eq!(r.next_wake_dispatch(&c).unwrap().coalesced, 1);
    // In flight, the peek clones the bundle's first envelope instead.
    assert_eq!(r.next_wake(&c), peeked);
    assert_eq!(r.next_wake(&c), peeked);
}

#[test]
fn failure_reoffers_the_same_envelopes_at_the_next_layer() {
    let c = StreamConnectionId("degrade".into());
    let mut r = wake_registry(&[(&c, "actor")]);
    r.bind_instance(
        &c,
        HarnessInstanceKey::new("i"),
        BTreeSet::from([
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeAdapterKind::TmuxSendKeys,
        ]),
    )
    .unwrap();
    push_wake(&mut r, "actor", "e1");
    push_wake(&mut r, "actor", "e2");
    let first = r.next_wake_dispatch(&c).unwrap();
    assert_eq!(first.chosen, Some(WakeAdapterKind::ClaudeCodeMonitor));
    assert_eq!(first.coalesced, 2);
    assert_eq!(
        r.report_wake_delivery(
            &c,
            first.dispatch_seq,
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeDeliveryOutcome::Failed
        ),
        Ok(WakeReportDisposition::Reoffered {
            failed: WakeAdapterKind::ClaudeCodeMonitor,
            next: WakeAdapterKind::TmuxSendKeys,
            envelopes: 2,
        })
    );
    let reoffered = r.next_wake_dispatch(&c).unwrap();
    assert_eq!(reoffered.dispatch_seq, first.dispatch_seq);
    assert_eq!(reoffered.chosen, Some(WakeAdapterKind::TmuxSendKeys));
    // The exact same ordered envelopes are re-offered, never rebuilt.
    assert_eq!(reoffered.envelopes, first.envelopes);
    // The superseded kind can no longer resolve the bundle.
    assert_eq!(
        r.report_wake_delivery(
            &c,
            first.dispatch_seq,
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeDeliveryOutcome::Delivered
        ),
        Err(WakeDeliveryReportError::KindMismatch {
            expected: WakeAdapterKind::TmuxSendKeys,
            reported: WakeAdapterKind::ClaudeCodeMonitor,
        })
    );
    assert_eq!(
        r.report_wake_delivery(
            &c,
            first.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Failed
        ),
        Ok(WakeReportDisposition::Exhausted { envelopes: 2 })
    );
    let o = r.wake_dispatch_observations();
    assert_eq!(o.dispatch_units_created, 1);
    assert_eq!(o.envelopes_coalesced, 2);
    assert_eq!(o.delivery_failures, 2);
    assert_eq!(o.exhausted_dispatches, 1);
    assert_eq!(o.exhausted_envelopes, 2);
    assert_eq!(o.delivered_dispatches, 0);
    assert_eq!(o.transport_only_dispatches, 0);
    assert_eq!(r.next_wake_dispatch(&c), None);
    assert_eq!(r.next_wake(&c), None);
}

#[test]
fn success_drains_the_active_bundle_but_not_later_wakes() {
    let c = StreamConnectionId("drain".into());
    let mut r = wake_registry(&[(&c, "actor")]);
    r.bind_instance(
        &c,
        HarnessInstanceKey::new("i"),
        BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
    )
    .unwrap();
    push_wake(&mut r, "actor", "e1");
    let active = r.next_wake_dispatch(&c).unwrap();
    push_wake(&mut r, "actor", "later");
    // Re-polling returns the same unit and never absorbs the later wake.
    assert_eq!(r.next_wake_dispatch(&c), Some(active.clone()));
    assert_eq!(r.wake_dispatch_observations().dispatch_units_created, 1);
    assert_eq!(r.wake_dispatch_observations().envelopes_coalesced, 1);
    assert_eq!(
        r.report_wake_delivery(
            &c,
            active.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Delivered
        ),
        Ok(WakeReportDisposition::Delivered { envelopes: 1 })
    );
    let next = r.next_wake_dispatch(&c).unwrap();
    assert_eq!(next.dispatch_seq, active.dispatch_seq + 1);
    assert_eq!(next.coalesced, 1);
    assert_eq!(next.envelopes[0].event_ref, "later");
    assert_eq!(r.wake_dispatch_observations().delivered_dispatches, 1);
}

#[test]
fn duplicate_report_cannot_resolve_a_newer_dispatch() {
    let c = StreamConnectionId("fence".into());
    let mut r = wake_registry(&[(&c, "actor")]);
    r.bind_instance(
        &c,
        HarnessInstanceKey::new("i"),
        BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
    )
    .unwrap();
    push_wake(&mut r, "actor", "a");
    let a = r.next_wake_dispatch(&c).unwrap();
    r.report_wake_delivery(
        &c,
        a.dispatch_seq,
        WakeAdapterKind::TmuxSendKeys,
        WakeDeliveryOutcome::Delivered,
    )
    .unwrap();
    // With no later bundle, the duplicate finds nothing active.
    assert_eq!(
        r.report_wake_delivery(
            &c,
            a.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Delivered
        ),
        Err(WakeDeliveryReportError::NoActiveDispatch(c.clone()))
    );
    push_wake(&mut r, "actor", "b");
    let b = r.next_wake_dispatch(&c).unwrap();
    assert_ne!(b.dispatch_seq, a.dispatch_seq);
    // Both bundles first choose the same kind, so only the per-connection
    // sequence fence separates them.
    assert_eq!(b.chosen, a.chosen);
    assert_eq!(
        r.report_wake_delivery(
            &c,
            a.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Delivered
        ),
        Err(WakeDeliveryReportError::StaleDispatch {
            expected: b.dispatch_seq,
            reported: a.dispatch_seq,
        })
    );
    assert_eq!(r.next_wake_dispatch(&c), Some(b));
    assert_eq!(r.wake_dispatch_observations().delivered_dispatches, 1);
}

#[test]
fn reattach_keeps_the_fence_against_a_delayed_pre_reattach_report() {
    let c = StreamConnectionId("reattach-fence".into());
    let mut r = wake_registry(&[(&c, "actor")]);
    let instance = HarnessInstanceKey::new("i");
    let installed = BTreeSet::from([WakeAdapterKind::TmuxSendKeys]);
    r.bind_instance(&c, instance.clone(), installed.clone())
        .unwrap();
    push_wake(&mut r, "actor", "before");
    let old = r.next_wake_dispatch(&c).unwrap();
    assert_eq!(old.chosen, Some(WakeAdapterKind::TmuxSendKeys));
    assert_eq!(old.coalesced, 1);
    assert_eq!(old.envelopes[0].event_ref, "before");
    // The same connection identity reconnects while that report is still in
    // flight on the wire, then rebinds as the connection layer requires.
    r.attach_connection(
        c.clone(),
        BoardRenderMode::Stream,
        "actor".into(),
        BTreeSet::from([SubscriptionScope::MyTasks]),
        1,
    );
    // Reattach still drops the ephemeral binding, queue, and in-flight unit.
    assert!(r.connection_state(&c).unwrap().wake_dispatch.is_none());
    assert!(r.connection_state(&c).unwrap().wakes.is_empty());
    assert_eq!(r.next_wake(&c), None);
    r.bind_instance(&c, instance, installed).unwrap();
    push_wake(&mut r, "actor", "after");
    let later = r.next_wake_dispatch(&c).unwrap();
    // Both units first choose the same kind, so only the surviving
    // per-connection fence separates the delayed report from this one.
    assert_eq!(later.chosen, old.chosen);
    assert!(later.dispatch_seq > old.dispatch_seq);
    assert_eq!(later.coalesced, 1);
    assert_eq!(later.envelopes[0].event_ref, "after");
    // The delayed pre-reattach report is stale and changes nothing.
    assert_eq!(
        r.report_wake_delivery(
            &c,
            old.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Delivered
        ),
        Err(WakeDeliveryReportError::StaleDispatch {
            expected: later.dispatch_seq,
            reported: old.dispatch_seq,
        })
    );
    assert_eq!(r.next_wake_dispatch(&c), Some(later.clone()));
    assert_eq!(r.wake_dispatch_observations().delivered_dispatches, 0);
    // A valid report for the current sequence still resolves it.
    assert_eq!(
        r.report_wake_delivery(
            &c,
            later.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Delivered
        ),
        Ok(WakeReportDisposition::Delivered { envelopes: 1 })
    );
    assert_eq!(r.next_wake_dispatch(&c), None);
    assert_eq!(r.wake_dispatch_observations().delivered_dispatches, 1);
}

#[test]
fn rebinding_replaces_the_snapshot_without_rewriting_frozen_candidates() {
    let first = StreamConnectionId("first".into());
    let second = StreamConnectionId("second".into());
    let mut r = wake_registry(&[(&first, "actor"), (&second, "actor")]);
    let instance = HarnessInstanceKey::new("shared");
    let ladder = BTreeSet::from([
        WakeAdapterKind::ClaudeCodeMonitor,
        WakeAdapterKind::TmuxSendKeys,
    ]);
    r.bind_instance(&first, instance.clone(), ladder.clone())
        .unwrap();
    let replay = r.bind_instance(&first, instance.clone(), ladder).unwrap();
    assert!(replay.idempotent_replay);
    push_wake(&mut r, "actor", "e1");
    let in_flight = r.next_wake_dispatch(&first).unwrap();
    assert_eq!(in_flight.chosen, Some(WakeAdapterKind::ClaudeCodeMonitor));
    // Last authenticated attach wins, for FUTURE dispatches only.
    let replaced = BTreeSet::from([WakeAdapterKind::BootPromptSpawn]);
    let rebind = r
        .bind_instance(&second, instance, replaced.clone())
        .unwrap();
    assert!(!rebind.idempotent_replay);
    assert_eq!(rebind.installed, replaced);
    // The in-flight bundle keeps the candidates it froze at creation.
    assert_eq!(
        r.report_wake_delivery(
            &first,
            in_flight.dispatch_seq,
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeDeliveryOutcome::Failed
        ),
        Ok(WakeReportDisposition::Reoffered {
            failed: WakeAdapterKind::ClaudeCodeMonitor,
            next: WakeAdapterKind::TmuxSendKeys,
            envelopes: 1,
        })
    );
    // A dispatch created after the replacement freezes the new snapshot.
    assert_eq!(
        r.next_wake_dispatch(&second).unwrap().chosen,
        Some(WakeAdapterKind::BootPromptSpawn)
    );
}

#[test]
fn two_instances_never_share_snapshots_or_wakes() {
    let a = StreamConnectionId("a".into());
    let b = StreamConnectionId("b".into());
    let mut r = wake_registry(&[(&a, "actor-a"), (&b, "actor-b")]);
    r.bind_instance(
        &a,
        HarnessInstanceKey::new("instance-a"),
        BTreeSet::from([
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeAdapterKind::TmuxSendKeys,
        ]),
    )
    .unwrap();
    r.bind_instance(
        &b,
        HarnessInstanceKey::new("instance-b"),
        BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
    )
    .unwrap();
    push_wake(&mut r, "actor-a", "only-a");
    let dispatch = r.next_wake_dispatch(&a).unwrap();
    assert_eq!(dispatch.instance, HarnessInstanceKey::new("instance-a"));
    assert_eq!(dispatch.chosen, Some(WakeAdapterKind::ClaudeCodeMonitor));
    // A's wake never appears on B, and A's report never moves B.
    assert_eq!(r.next_wake_dispatch(&b), None);
    assert_eq!(r.next_wake(&b), None);
    r.report_wake_delivery(
        &a,
        dispatch.dispatch_seq,
        WakeAdapterKind::ClaudeCodeMonitor,
        WakeDeliveryOutcome::Delivered,
    )
    .unwrap();
    assert_eq!(r.next_wake_dispatch(&b), None);
    push_wake(&mut r, "actor-b", "only-b");
    let other = r.next_wake_dispatch(&b).unwrap();
    assert_eq!(other.chosen, Some(WakeAdapterKind::TmuxSendKeys));
    assert_eq!(other.envelopes[0].event_ref, "only-b");
    // Sequences are per connection, not global.
    assert_eq!(other.dispatch_seq, 0);
}

#[test]
fn teardown_clears_binding_and_wakes_without_decrementing_observations() {
    let held = StreamConnectionId("held".into());
    let idle = StreamConnectionId("idle".into());
    let mut r = wake_registry(&[(&held, "actor"), (&idle, "actor")]);
    let instance = HarnessInstanceKey::new("shared");
    let installed = BTreeSet::from([WakeAdapterKind::TmuxSendKeys]);
    r.bind_instance(&held, instance.clone(), installed.clone())
        .unwrap();
    r.bind_instance(&idle, instance, installed).unwrap();
    push_wake(&mut r, "actor", "e1");
    let dispatch = r.next_wake_dispatch(&held).unwrap();
    let before = r.wake_dispatch_observations();
    r.detach(&held);
    assert_eq!(r.next_wake(&held), None);
    assert_eq!(
        r.report_wake_delivery(
            &held,
            dispatch.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Delivered
        ),
        Err(WakeDeliveryReportError::ConnectionMissing(held))
    );
    // One connection leaving cannot delete a still-referenced instance.
    assert_eq!(r.instances.len(), 1);
    assert_eq!(r.wake_dispatch_observations(), before);
    // The idle prune takes the last reference, its binding, and its queue.
    assert_eq!(r.prune_idle_connections(11, 10), 1);
    assert!(r.instances.is_empty());
    assert_eq!(r.next_wake_dispatch(&idle), None);
    assert_eq!(r.wake_dispatch_observations(), before);
}

#[test]
fn empty_install_set_yields_one_transport_only_dispatch() {
    let c = StreamConnectionId("transport".into());
    let mut r = wake_registry(&[(&c, "actor")]);
    assert!(
        r.bind_instance(&c, HarnessInstanceKey::new("i"), BTreeSet::new())
            .unwrap()
            .installed
            .is_empty()
    );
    push_wake(&mut r, "actor", "e1");
    let dispatch = r.next_wake_dispatch(&c).unwrap();
    assert_eq!(dispatch.chosen, None);
    assert_eq!(dispatch.coalesced, 1);
    let o = r.wake_dispatch_observations();
    assert_eq!(o.transport_only_dispatches, 1);
    assert_eq!(o.dispatch_units_created, 1);
    assert_eq!(o.envelopes_coalesced, 1);
    assert_eq!(o.exhausted_dispatches, 0);
    assert_eq!(o.exhausted_envelopes, 0);
    // The terminal unit is released at once: no report is possible.
    assert_eq!(
        r.report_wake_delivery(
            &c,
            dispatch.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Delivered
        ),
        Err(WakeDeliveryReportError::NoActiveDispatch(c.clone()))
    );
    assert_eq!(r.next_wake_dispatch(&c), None);
}
