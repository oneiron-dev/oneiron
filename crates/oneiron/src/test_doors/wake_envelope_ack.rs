//! Doors for `tests/wake_ack.rs` (census L8-18, RC99): a failed TASK's
//! committed board state published through the own-task producer, so a test
//! queues real failure wakes, with their `<task>:failed:<revision>` envelope
//! ids, and needs no vault. Compiled only under `--cfg oneiron_test_support`;
//! never API.

use crate::context_board::{BoardStreamRegistry, CommittedTaskBoardState, RouteObservation};

/// Publishes TASK `task_ref`, owned by `owner_ref`, as failed at committed
/// state `revision` by the attempt heads `failed_attempts` (sorted), to every
/// connection that subscribes to its owner's tasks.
#[doc(hidden)]
pub fn publish_failed_task(
    registry: &mut BoardStreamRegistry,
    task_ref: &str,
    owner_ref: &str,
    revision: &str,
    failed_attempts: &[&str],
) -> RouteObservation {
    registry.publish_task_state(
        CommittedTaskBoardState::failed_for_test_door(
            task_ref,
            owner_ref,
            revision,
            failed_attempts,
        ),
        |_| true,
    )
}
