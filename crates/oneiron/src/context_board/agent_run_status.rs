//! AgentRunStatus contract shared by Context Board and run-tree viewers.

use crate::attempt_queue::run_tree_view::RunTreeStatus;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::context_board::agent_run_status::AgentRunStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAgentRunStatusTransition {
    pub from: AgentRunStatus,
    pub to: AgentRunStatus,
}

pub fn validate_agent_run_status_transition(
    from: AgentRunStatus,
    to: AgentRunStatus,
) -> Result<(), InvalidAgentRunStatusTransition> {
    if from.can_transition_to(to) {
        Ok(())
    } else {
        Err(InvalidAgentRunStatusTransition { from, to })
    }
}

#[must_use]
pub const fn project_agent_run_status(status: RunTreeStatus) -> AgentRunStatus {
    match status {
        RunTreeStatus::Queued => AgentRunStatus::Spawned,
        RunTreeStatus::Running => AgentRunStatus::Working,
        RunTreeStatus::Paused => AgentRunStatus::NeedsInput,
        RunTreeStatus::Completed => AgentRunStatus::Delivered,
        RunTreeStatus::Failed => AgentRunStatus::Failed,
        // Not folded onto `Failed` either: a cancel is a stop someone or the
        // runtime chose, and its cause stays on the attempt's cancel state.
        RunTreeStatus::Cancelled => AgentRunStatus::Cancelled,
        // Not folded onto `Failed`: this axis already owns a truthful terminal
        // token for a run that stopped without delivering, and reporting a
        // fault nobody observed would be the lie the fold exists to avoid.
        RunTreeStatus::Abandoned => AgentRunStatus::Abandoned,
    }
}

/// A parked Dreamer row remains `Running` in the queue projection, but is
/// presented as `NeedsInput` while the durable wait is active.
#[must_use]
pub const fn project_agent_run_status_with_park(
    status: RunTreeStatus,
    is_parked: bool,
) -> AgentRunStatus {
    let projected = project_agent_run_status(status);
    if is_parked && matches!(projected, AgentRunStatus::Working) {
        AgentRunStatus::NeedsInput
    } else {
        projected
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorTerminalCause {
    LeaseReclaimed,
    NeverAnswered,
    ExecutionFailed,
    Cancelled,
    Other,
}

#[must_use]
pub const fn project_abandoned_terminal(cause: ExecutorTerminalCause) -> Option<AgentRunStatus> {
    match cause {
        ExecutorTerminalCause::LeaseReclaimed | ExecutorTerminalCause::NeverAnswered => {
            Some(AgentRunStatus::Abandoned)
        }
        _ => None,
    }
}
