//! Doors for `tests/wake_ack.rs` (census L8-18, RC99): a failed TASK's wake
//! routed as the own-task producer routes one, under a named envelope id, so
//! a test queues failure wakes with no vault. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::context_board::{BoardStreamRegistry, RouteObservation};

/// Routes TASK `task_ref`'s failure wake to every connection of owner
/// `owner_ref` that subscribes to its tasks, under envelope id `event_ref`
/// (`<task id>:failed:<revision>`, ARCH-0067 `#wake-envelope-id`).
#[doc(hidden)]
pub fn route_task_failure(
    registry: &mut BoardStreamRegistry,
    task_ref: &str,
    owner_ref: &str,
    event_ref: &str,
) -> RouteObservation {
    registry.route_task_failure_for_test_door(task_ref, owner_ref, event_ref)
}
