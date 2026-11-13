//! Doors for `tests/board_task_wakes_restart.rs` (census L2-38): the serve
//! board publisher's TASK pass and its staged TASK wake pass, run inline over
//! an engine registry. Serve admits each connection by its bound reader's
//! read of the TASK; these doors take that answer as `admit`.

use crate::context_board::{
    BoardStreamRegistry, CommittedTaskBoardState, PendingTaskWake, StreamConnectionId,
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
    let state = CommittedTaskBoardState::read(vault, task)?;
    vault.stage_task_wakes(task, state.as_ref())?;
    match state {
        Some(state) => {
            registry.publish_task_state(state, admit);
        }
        None => registry.forget_task_wakes(task),
    }
    Ok(())
}

/// The staged TASK wake pass an attach or a first bound reader starts:
/// `admit` answers whether a connection may read a wake's TASK.
pub fn publish_staged_task_wakes(
    vault: &Vault,
    registry: &mut BoardStreamRegistry,
    admit: impl Fn(&StreamConnectionId, EntityId) -> bool,
) -> Result<()> {
    let read = PendingTaskWake::read_all(vault)?;
    registry.forget_spent_task_wakes(&read.spent);
    registry.publish_task_wakes(read.pending, |connection, wake| {
        admit(connection, wake.task())
    });
    vault.settle_task_wakes(&read.spent)
}
