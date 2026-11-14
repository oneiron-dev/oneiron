//! Doors for `tests/board_task_wakes_restart.rs` (census L2-38): the serve
//! board publisher's TASK pass and its staged TASK wake pass, run inline over
//! an engine registry. Serve admits each connection by its bound reader's
//! read of the TASK; these doors take that answer as `admit`.

use crate::context_board::{
    BoardStreamRegistry, CommittedTaskBoardState, PendingTaskWake, StreamConnectionId, TaskWakeRead,
};
use crate::{EntityId, Result, Vault};

/// The TASK loop's pass over one committed TASK: read it, stage the wakes it
/// owes, and route what changed to the connections `admit` accepts.
pub fn publish_committed_task(
    vault: &Vault,
    registry: &mut BoardStreamRegistry,
    task: EntityId,
    admit: impl Fn(&StreamConnectionId) -> bool,
) -> Result<()> {
    let state = stage_committed_task(vault, task)?;
    route_committed_task(registry, task, state, admit);
    Ok(())
}

/// The TASK loop pass's first half: read the committed TASK and stage the
/// wakes it owes. Serve then awaits each connection's admission outside the
/// registry lock before [`route_committed_task`], so a staged wake pass can
/// run between the two.
pub fn stage_committed_task(
    vault: &Vault,
    task: EntityId,
) -> Result<Option<CommittedTaskBoardState>> {
    let state = CommittedTaskBoardState::read(vault, task)?;
    vault.stage_task_wakes(task, state.as_ref())?;
    Ok(state)
}

/// The TASK loop pass's second half: route what changed in `state` to the
/// connections `admit` accepts, or forget the wakes of a TASK the board no
/// longer shows.
pub fn route_committed_task(
    registry: &mut BoardStreamRegistry,
    task: EntityId,
    state: Option<CommittedTaskBoardState>,
    admit: impl Fn(&StreamConnectionId) -> bool,
) {
    match state {
        Some(state) => {
            registry.publish_task_state(state, admit);
        }
        None => registry.forget_task_wakes(task),
    }
}

/// The staged TASK wake pass an attach or a first bound reader starts:
/// `admit` answers whether a connection may read a wake's TASK.
pub fn publish_staged_task_wakes(
    vault: &Vault,
    registry: &mut BoardStreamRegistry,
    admit: impl Fn(&StreamConnectionId, EntityId) -> bool,
) -> Result<()> {
    let read = read_staged_task_wakes(vault)?;
    apply_staged_task_wakes(vault, registry, read, admit)
}

/// The staged pass's read: each staged wake, its TASK read again now. Serve
/// takes the registry lock only after it, so the TASK loop can stage and
/// route a later occurrence between this read and
/// [`apply_staged_task_wakes`].
pub fn read_staged_task_wakes(vault: &Vault) -> Result<TaskWakeRead> {
    PendingTaskWake::read_all(vault)
}

/// The staged pass after its read: forget the spent rows' offers, offer each
/// pending wake, and settle the spent rows.
pub fn apply_staged_task_wakes(
    vault: &Vault,
    registry: &mut BoardStreamRegistry,
    read: TaskWakeRead,
    admit: impl Fn(&StreamConnectionId, EntityId) -> bool,
) -> Result<()> {
    registry.forget_spent_task_wakes(&read.spent);
    registry.publish_task_wakes(read.pending, |connection, wake| {
        admit(connection, wake.task())
    });
    vault.settle_task_wakes(&read.spent)
}
