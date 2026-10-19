//! AgentRunStatus contract shared by Context Board and run-tree viewers.

use crate::run_tree::RunTreeStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunStatus {
    Spawned,
    Working,
    NeedsInput,
    Delivered,
    Archived,
    Failed,
    Abandoned,
    /// Stopped by a cancel (an owner's or an operator's force, a lease the
    /// runtime fenced, or a cancel before it started), not by a fault.
    Cancelled,
}

impl AgentRunStatus {
    pub const RATIFIED_FLOW: [Self; 5] = [
        Self::Spawned,
        Self::Working,
        Self::NeedsInput,
        Self::Delivered,
        Self::Archived,
    ];
    pub const ALL: [Self; 8] = [
        Self::Spawned,
        Self::Working,
        Self::NeedsInput,
        Self::Delivered,
        Self::Archived,
        Self::Failed,
        Self::Abandoned,
        Self::Cancelled,
    ];
    pub const TERMINAL: [Self; 4] = [
        Self::Archived,
        Self::Failed,
        Self::Abandoned,
        Self::Cancelled,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spawned => "spawned",
            Self::Working => "working",
            Self::NeedsInput => "needs_input",
            Self::Delivered => "delivered",
            Self::Archived => "archived",
            Self::Failed => "failed",
            Self::Abandoned => "abandoned",
            Self::Cancelled => "cancelled",
        }
    }
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Archived | Self::Failed | Self::Abandoned | Self::Cancelled
        )
    }
    #[must_use]
    pub const fn is_live_presence(self) -> bool {
        matches!(self, Self::Spawned | Self::Working | Self::NeedsInput)
    }
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Spawned, Self::Spawned)
                | (Self::Working, Self::Working)
                | (Self::NeedsInput, Self::NeedsInput)
                | (Self::Delivered, Self::Delivered)
                | (Self::Archived, Self::Archived)
                | (Self::Failed, Self::Failed)
                | (Self::Abandoned, Self::Abandoned)
                | (Self::Cancelled, Self::Cancelled)
                | (
                    Self::Spawned,
                    Self::Working | Self::Failed | Self::Abandoned | Self::Cancelled
                )
                | (
                    Self::Working,
                    Self::NeedsInput
                        | Self::Delivered
                        | Self::Failed
                        | Self::Abandoned
                        | Self::Cancelled
                )
                | (
                    Self::NeedsInput,
                    Self::Working | Self::Failed | Self::Abandoned | Self::Cancelled
                )
                | (Self::Delivered, Self::Archived)
        )
    }
}

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
