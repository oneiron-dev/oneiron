//! Frame, snapshot, coalescing and subscription-lifecycle tests.

use super::*;

pub(super) fn k(e: u64) -> BoardStreamFrame {
    BoardStreamFrame {
        epoch: e,
        kind: FrameKind::Keyframe(format!("k{e}")),
    }
}

fn d(e: u64, key: &str) -> BoardStreamFrame {
    BoardStreamFrame {
        epoch: e,
        kind: FrameKind::Delta(vec![DeltaRow {
            key: key.into(),
            line: "x".into(),
        }]),
    }
}

#[test]
fn latest() {
    let mut s = AppliedStreamState::default();
    assert!(matches!(
        s.apply(k(47)),
        FrameApplyOutcome::KeyframeTaken { .. }
    ));
    assert!(matches!(
        s.apply(d(47, "a")),
        FrameApplyOutcome::DeltaApplied { rows: 1 }
    ));
    assert!(matches!(
        s.apply(d(48, "b")),
        FrameApplyOutcome::IgnoredUntilKeyframe { .. }
    ));
    s.apply(k(48));
    s.apply(k(47));
    assert_eq!(s.epoch, Some(48));
}

#[test]
fn queue_barrier() {
    let c = StreamConnectionId("x".into());
    let mut r = BoardStreamRegistry::default();
    r.attach_connection(
        c.clone(),
        BoardRenderMode::Stream,
        "actor".into(),
        BTreeSet::new(),
        0,
    );
    r.enqueue(&c, k(1));
    r.enqueue(&c, d(1, "a"));
    r.enqueue(&c, k(1));
    assert!(matches!(
        r.next_carrier_payload(&c).unwrap().kind,
        FrameKind::Keyframe(_)
    ));
    assert!(r.next_carrier_payload(&c).is_none());
}

#[test]
fn stale_lower_delta_is_ignored() {
    let mut state = AppliedStreamState::default();
    state.apply(k(47));
    assert!(matches!(
        state.apply(d(46, "old")),
        FrameApplyOutcome::IgnoredStale {
            held_epoch: Some(47)
        }
    ));
    assert!(state.delta_overlay.is_empty());
}

#[test]
fn future_delta_is_discarded_not_replayed() {
    let mut state = AppliedStreamState::default();
    state.apply(k(47));
    assert!(matches!(
        state.apply(d(48, "future")),
        FrameApplyOutcome::IgnoredUntilKeyframe {
            held_epoch: Some(47)
        }
    ));
    assert_eq!(state.epoch, Some(47));
    state.apply(k(48));
    assert_eq!(state.epoch, Some(48));
    assert!(!state.delta_overlay.contains_key("future"));
}

#[test]
fn frame_since_removal_falls_back_to_keyframe() {
    let mut old_rows = BTreeMap::new();
    old_rows.insert("removed".into(), "line".into());
    let old = BoardSnapshot {
        epoch: 4,
        keyframe: "old".into(),
        rows: old_rows,
    };
    let current = BoardSnapshot {
        epoch: 4,
        keyframe: "new".into(),
        rows: BTreeMap::new(),
    };
    assert!(matches!(
        current.frame_since(Some(&old)).unwrap().kind,
        FrameKind::Keyframe(_)
    ));
}

#[test]
fn frame_since_deltas_are_key_sorted_and_fenced() {
    let old = BoardSnapshot {
        epoch: 4,
        keyframe: "old".into(),
        rows: BTreeMap::new(),
    };
    let mut rows = BTreeMap::new();
    rows.insert("z\n".into(), "line\r".into());
    rows.insert("a\t".into(), "line\n".into());
    let current = BoardSnapshot {
        epoch: 4,
        keyframe: "new".into(),
        rows,
    };
    let frame = current.frame_since(Some(&old)).unwrap();
    let FrameKind::Delta(rows) = frame.kind else {
        panic!("expected delta")
    };
    assert_eq!(
        rows.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
        vec!["a ", "z "]
    );
    assert!(
        rows.iter()
            .all(|row| !row.key.contains(['\n', '\r', '\t'])
                && !row.line.contains(['\n', '\r', '\t']))
    );
    let mut state = AppliedStreamState::default();
    state.apply(k(4));
    state.apply(BoardStreamFrame {
        epoch: 4,
        kind: FrameKind::Delta(rows),
    });
    assert_eq!(state.delta_overlay.len(), 2);
    assert!(
        state
            .delta_overlay
            .keys()
            .all(|key| !key.contains(['\n', '\r', '\t']))
    );
}

fn permutations(items: &mut [usize], start: usize, output: &mut Vec<Vec<usize>>) {
    if start == items.len() {
        output.push(items.to_vec());
        return;
    }
    for index in start..items.len() {
        items.swap(start, index);
        permutations(items, start + 1, output);
        items.swap(start, index);
    }
}

#[test]
fn epoch_permutations_never_decrease_and_deltas_match_held_epoch() {
    let frames = [k(47), d(47, "same"), d(46, "stale"), k(48), k(47)];
    let mut indices = [0, 1, 2, 3, 4];
    let mut orders = Vec::new();
    permutations(&mut indices, 0, &mut orders);
    assert_eq!(orders.len(), 120);
    for order in orders {
        let mut state = AppliedStreamState::default();
        let mut max_accepted_keyframe_epoch = None;
        for index in order {
            let frame = frames[index].clone();
            let epoch = frame.epoch;
            let is_delta = matches!(frame.kind, FrameKind::Delta(_));
            let held_before = state.epoch;
            let overlay_before = state.delta_overlay.clone();
            let outcome = state.apply(frame);
            if !is_delta && !matches!(outcome, FrameApplyOutcome::IgnoredStale { .. }) {
                max_accepted_keyframe_epoch =
                    Some(max_accepted_keyframe_epoch.map_or(epoch, |max: u64| max.max(epoch)));
                assert!(
                    state.epoch.expect("accepted keyframe holds epoch")
                        >= max_accepted_keyframe_epoch.expect("max epoch")
                );
            }
            if is_delta && held_before != Some(epoch) {
                assert!(matches!(
                    outcome,
                    FrameApplyOutcome::IgnoredStale { .. }
                        | FrameApplyOutcome::IgnoredUntilKeyframe { .. }
                ));
                assert_eq!(state.delta_overlay, overlay_before);
            }
        }
        assert_eq!(state.epoch, Some(48));
    }
}

#[test]
fn fenced_key_collisions_are_unique_and_sorted_after_fencing() {
    let old = BoardSnapshot {
        epoch: 1,
        keyframe: "old".into(),
        rows: BTreeMap::new(),
    };
    let mut values = BTreeMap::new();
    values.insert("a\nz".into(), "first".into());
    values.insert("a\tz".into(), "last".into());
    values.insert("a x".into(), "middle".into());
    let current = BoardSnapshot {
        epoch: 1,
        keyframe: "new".into(),
        rows: values,
    };
    let FrameKind::Delta(rows) = current.frame_since(Some(&old)).expect("delta").kind else {
        panic!("delta")
    };
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
        vec!["a x", "a z"]
    );
    assert_eq!(rows[1].line, "first");
}

#[test]
fn subscriptions_are_atomic_local_and_lifecycle_is_ephemeral() {
    let c = StreamConnectionId("a".into());
    let allowed = BTreeSet::from([SubscriptionScope::MyTasks]);
    let mut registry = BoardStreamRegistry::default();
    registry.attach_connection(c.clone(), BoardRenderMode::Stream, "a".into(), allowed, 5);
    let before = registry.connection_state(&c).unwrap().subscribed.clone();
    let requested = BTreeSet::from([SubscriptionScope::MyTasks, SubscriptionScope::Counts]);
    assert!(matches!(
        registry.subscribe(&c, &requested),
        Err(SubscriptionError::OutsideAllowedSet { .. })
    ));
    assert_eq!(registry.connection_state(&c).unwrap().subscribed, before);
    registry.detach(&c);
    assert!(registry.connection_state(&c).is_none());
    registry.attach_connection(
        c.clone(),
        BoardRenderMode::Stream,
        "a".into(),
        BTreeSet::from([SubscriptionScope::MyTasks]),
        0,
    );
    assert_eq!(registry.prune_idle_connections(11, 10), 1);
}

#[test]
fn coalesce_fences_and_requires_keyframe() {
    let mut buffer = CarrierCoalesceBuffer::default();
    assert_eq!(
        buffer.push(d(1, "x")),
        CoalesceOutcome::DroppedUntilKeyframe
    );
    assert_eq!(buffer.push(k(1)), CoalesceOutcome::ReplacedEpoch);
    assert_eq!(
        buffer.push(BoardStreamFrame {
            epoch: 1,
            kind: FrameKind::Delta(vec![DeltaRow {
                key: "x\n".into(),
                line: "done\r".into()
            }])
        }),
        CoalesceOutcome::Inserted
    );
    let _ = buffer.drain();
    let FrameKind::Delta(rows) = buffer.drain().expect("delta").kind else {
        panic!()
    };
    assert_eq!(rows[0].key, "x ");
    assert_eq!(rows[0].line, "done ");
}

#[test]
fn board_event_class_scope_totality_is_closed() {
    assert_eq!(SubscriptionScope::ALL.len(), 7);
    assert!(DeliveryClass::Wake.is_pushable());
    assert!(!DeliveryClass::OnDemand.is_pushable());
}

#[test]
fn same_epoch_keyed_deltas_leave_last_row_per_key() {
    let mut buffer = CarrierCoalesceBuffer::default();
    buffer.push(k(7));
    let _ = buffer.drain();
    for line in ["one", "two", "three"] {
        buffer.push(BoardStreamFrame {
            epoch: 7,
            kind: FrameKind::Delta(vec![DeltaRow {
                key: "task".into(),
                line: line.into(),
            }]),
        });
    }
    let FrameKind::Delta(rows) = buffer.drain().unwrap().kind else {
        panic!()
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].line, "three");
}
