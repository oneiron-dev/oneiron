//! Own-task STREAM lines as one connection's credential may read them now:
//! the board publisher admits each event under this predicate, and the result
//! drain reads every queued `tasks:` line again before it rides. A host wake
//! adapter reads each drained wake's TASK again under the same predicate.

use super::board_setup::mcp_scope_admits_row;
use super::mcp_scoped_read;
use crate::mcp::McpResolvedActor;
use crate::server::SyncServer;

/// The frame less every queued TASK line this reader may not be shown now:
/// its TASK is gone from the board (erased, cancelled, acknowledged) or no
/// longer readable by this credential. `None` when nothing is left.
pub(super) fn mcp_live_task_lines(
    server: &SyncServer,
    actor: &McpResolvedActor,
    mut frame: oneiron::context_board::BoardStreamFrame,
) -> Option<oneiron::context_board::BoardStreamFrame> {
    let oneiron::context_board::FrameKind::Delta(rows) = &mut frame.kind else {
        return Some(frame);
    };
    rows.retain(|row| {
        row.key.strip_prefix("tasks:").is_none_or(|task| {
            oneiron::EntityId::from_hex(task)
                .is_ok_and(|task| mcp_stream_reads_task(&server.vault, actor, &task))
        })
    });
    (!rows.is_empty()).then_some(frame)
}

/// The frame less everything but its own-task `tasks:` lines: all a narrowed
/// connection's carrier may deliver, since only TASK rows are projected
/// through its world and facet ceiling. `None` when nothing is left.
pub(super) fn mcp_own_task_lines(
    mut frame: oneiron::context_board::BoardStreamFrame,
) -> Option<oneiron::context_board::BoardStreamFrame> {
    let oneiron::context_board::FrameKind::Delta(rows) = &mut frame.kind else {
        return None;
    };
    rows.retain(|row| row.key.starts_with("tasks:"));
    (!rows.is_empty()).then_some(frame)
}

/// Whether `actor` may be told about `task` now: the TASK still stands on
/// the board, and the credential reads it under the same predicate the board
/// door filters TASK rows with, its world and facet ceiling included. Any
/// failure to decide is a no.
pub(crate) fn mcp_stream_reads_task(
    vault: &oneiron::Vault,
    actor: &McpResolvedActor,
    task: &oneiron::EntityId,
) -> bool {
    mcp_stream_task_row(vault, actor, task).is_some()
}

/// A current TASK delta admitted by the same live read as tool-result riders.
pub(crate) fn mcp_stream_task_row(
    vault: &oneiron::Vault,
    actor: &McpResolvedActor,
    task: &oneiron::EntityId,
) -> Option<oneiron::context_board::DeltaRow> {
    let state = oneiron::context_board::CommittedTaskBoardState::read(vault, *task)
        .ok()
        .flatten()?;
    let readable = mcp_scoped_read(vault, actor)
        .and_then(|read| mcp_scope_admits_row(vault, actor, &read, &task.to_hex()))
        .unwrap_or(false);
    readable.then(|| state.delta_row())
}
