//! Frame, snapshot, coalescing and subscription-lifecycle tests.

use super::*;

pub(super) fn k(e: u64) -> BoardStreamFrame {
    BoardStreamFrame {
        epoch: e,
        kind: FrameKind::Keyframe(format!("k{e}")),
    }
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
