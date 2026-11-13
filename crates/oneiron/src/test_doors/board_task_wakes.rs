//! Doors for `tests/board_task_wakes_restart.rs` (census L2-38), as main
//! behaves: the board publisher's TASK pass only reads and routes, and no
//! pass replays a staged wake.

use crate::context_board::{BoardStreamRegistry, CommittedTaskBoardState, StreamConnectionId};
use crate::{EntityId, Result, Vault};

/// Main's TASK pass: read the committed TASK and route what changed.
pub fn publish_committed_task(
    vault: &Vault,
    registry: &mut BoardStreamRegistry,
    task: EntityId,
    admit: impl Fn(&StreamConnectionId) -> bool,
) -> Result<()> {
    if let Some(state) = CommittedTaskBoardState::read(vault, task)? {
        registry.publish_task_state(state, admit);
    }
    Ok(())
}

/// Main stages no TASK wake, so it has none to replay.
pub fn publish_staged_task_wakes(
    _vault: &Vault,
    _registry: &mut BoardStreamRegistry,
    _admit: impl Fn(&StreamConnectionId, EntityId) -> bool,
) -> Result<()> {
    Ok(())
}
