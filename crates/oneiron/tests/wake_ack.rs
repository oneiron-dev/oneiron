//! Census L8-18 (RC99, ARCH-0067 §7 `#wake-envelope-id`): the host's
//! acknowledgement of a wake envelope id is recorded on the engine side, in
//! memory, per occurrence. A second failure's wake of the same TASK is never
//! lost to the first one's acknowledgement. Each failure's wake is routed as
//! the own-task producer routes one, under its own envelope id
//! (`<task id>:failed:<revision>`), by `oneiron::test_doors::wake_envelope_ack`,
//! built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::context_board::{
    BoardRenderMode, BoardStreamRegistry, StreamConnectionId, SubscriptionScope, WakeDelivery,
};
use oneiron::test_doors::wake_envelope_ack as doors;

const TASK: &str = "task-l818";
const OWNER: &str = "owner-l818";

fn attach(streams: &mut BoardStreamRegistry, connection: &StreamConnectionId, actor: &str) {
    streams.attach_connection(
        connection.clone(),
        BoardRenderMode::Stream,
        actor.to_owned(),
        BTreeSet::from([SubscriptionScope::MyTasks]),
        0,
    );
}

#[test]
fn acked_envelope_id_is_recorded_per_occurrence() {
    let mut streams = BoardStreamRegistry::default();
    let connection = StreamConnectionId("mcp-wake:l818-owner".into());
    let other = StreamConnectionId("mcp-wake:l818-other".into());
    attach(&mut streams, &connection, OWNER);
    attach(&mut streams, &other, "other-l818");

    // The first failure: one envelope, drained to the host.
    let first_failure = format!("{TASK}:failed:rev-1");
    let published = doors::route_task_failure(&mut streams, TASK, OWNER, &first_failure);
    assert_eq!(
        published.wake_enqueued, 1,
        "the first failure queues one wake"
    );
    let first = streams.drain_wakes(&connection);
    assert_eq!(
        first.len(),
        1,
        "the host is handed the first failure's wake"
    );
    let first_id = first[0].event_ref.clone();
    assert_eq!(
        first_id, first_failure,
        "the wake carries its occurrence's id"
    );
    assert_eq!(
        streams.wake_delivery(&connection, &first_id),
        Some(WakeDelivery::Handed),
        "a drained envelope reads handed until the host acknowledges it"
    );

    // Only the connection that was handed the envelope acknowledges it.
    assert!(
        !streams.acknowledge_wake(&other, &first_id),
        "another connection cannot acknowledge an envelope it was never handed"
    );
    assert!(
        streams.acknowledge_wake(&connection, &first_id),
        "the host acknowledges the envelope it was handed"
    );
    assert_eq!(
        streams.wake_delivery(&connection, &first_id),
        Some(WakeDelivery::Acked)
    );

    // The same TASK fails again, at a new committed state: a new occurrence
    // with its own envelope id.
    let second_failure = format!("{TASK}:failed:rev-2");
    let published = doors::route_task_failure(&mut streams, TASK, OWNER, &second_failure);
    assert_eq!(
        published.wake_enqueued, 1,
        "the second failure queues its own wake"
    );
    let second = streams.drain_wakes(&connection);
    assert_eq!(
        second.len(),
        1,
        "the second failure's wake is not lost to the first one's acknowledgement"
    );
    let second_id = second[0].event_ref.clone();
    assert_eq!(
        second_id, second_failure,
        "the wake carries its occurrence's id"
    );
    assert_eq!(
        streams.wake_delivery(&connection, &second_id),
        Some(WakeDelivery::Handed),
        "the first acknowledgement named one occurrence, not the TASK"
    );
    assert_eq!(
        streams.wake_delivery(&connection, &first_id),
        Some(WakeDelivery::Acked),
        "the first occurrence stays acknowledged"
    );

    // An id this connection was never handed records nothing.
    let never = format!("{TASK}:failed:rev-3");
    assert!(!streams.acknowledge_wake(&connection, &never));
    assert_eq!(streams.wake_delivery(&connection, &never), None);

    // The record is memory only and per connection: a detach drops it.
    streams.detach(&connection);
    assert_eq!(streams.wake_delivery(&connection, &second_id), None);
}
