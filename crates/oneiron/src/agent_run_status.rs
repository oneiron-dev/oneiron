//! AgentRunStatus contract shared by Context Board and run-tree viewers.

use crate::run_tree::RunTreeStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunStatus {
    Spawned,
    Working,
    NeedsInput,
    Delivered,
    Archived,
    Failed,
    Abandoned,
}

impl AgentRunStatus {
    pub const RATIFIED_FLOW: [Self; 5] = [
        Self::Spawned,
        Self::Working,
        Self::NeedsInput,
        Self::Delivered,
        Self::Archived,
    ];
    pub const ALL: [Self; 7] = [
        Self::Spawned,
        Self::Working,
        Self::NeedsInput,
        Self::Delivered,
        Self::Archived,
        Self::Failed,
        Self::Abandoned,
    ];
    pub const TERMINAL: [Self; 3] = [Self::Archived, Self::Failed, Self::Abandoned];
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
        }
    }
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Archived | Self::Failed | Self::Abandoned)
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
                | (
                    Self::Spawned,
                    Self::Working | Self::Failed | Self::Abandoned
                )
                | (
                    Self::Working,
                    Self::NeedsInput | Self::Delivered | Self::Failed | Self::Abandoned
                )
                | (
                    Self::NeedsInput,
                    Self::Working | Self::Failed | Self::Abandoned
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
        RunTreeStatus::Failed | RunTreeStatus::Cancelled => AgentRunStatus::Failed,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_run_status_success_flow_and_terminal_matrix() {
        let expected = |from, to| {
            from == to
                || matches!(
                    (from, to),
                    (
                        AgentRunStatus::Spawned,
                        AgentRunStatus::Working
                            | AgentRunStatus::Failed
                            | AgentRunStatus::Abandoned
                    ) | (
                        AgentRunStatus::Working,
                        AgentRunStatus::NeedsInput
                            | AgentRunStatus::Delivered
                            | AgentRunStatus::Failed
                            | AgentRunStatus::Abandoned
                    ) | (
                        AgentRunStatus::NeedsInput,
                        AgentRunStatus::Working
                            | AgentRunStatus::Failed
                            | AgentRunStatus::Abandoned
                    ) | (AgentRunStatus::Delivered, AgentRunStatus::Archived)
                )
        };
        for from in AgentRunStatus::ALL {
            for to in AgentRunStatus::ALL {
                assert_eq!(
                    from.can_transition_to(to),
                    expected(from, to),
                    "{} -> {}",
                    from.as_str(),
                    to.as_str()
                );
            }
        }
    }
    #[test]
    fn run_tree_status_projects_to_agent_run_status_without_storage_mutation() {
        assert_eq!(
            project_agent_run_status(RunTreeStatus::Queued),
            AgentRunStatus::Spawned
        );
        assert_eq!(
            project_agent_run_status(RunTreeStatus::Running),
            AgentRunStatus::Working
        );
        assert_eq!(
            project_agent_run_status(RunTreeStatus::Paused),
            AgentRunStatus::NeedsInput
        );
        assert_eq!(
            project_agent_run_status(RunTreeStatus::Completed),
            AgentRunStatus::Delivered
        );
        assert_eq!(
            project_agent_run_status(RunTreeStatus::Failed),
            AgentRunStatus::Failed
        );
        assert_eq!(
            project_agent_run_status(RunTreeStatus::Cancelled),
            AgentRunStatus::Failed
        );
    }
    #[test]
    fn attempt_leased_projects_to_working_without_run_tree_leased_variant() {
        use crate::attempt_queue::AttemptState;
        let status = RunTreeStatus::from(AttemptState::Leased);
        assert_eq!(status, RunTreeStatus::Running);
        assert_eq!(project_agent_run_status(status), AgentRunStatus::Working);
    }
    #[test]
    fn paused_agent_dispatch_renders_needs_input_and_resume_renders_working() {
        assert_eq!(
            project_agent_run_status_with_park(RunTreeStatus::Running, true),
            AgentRunStatus::NeedsInput
        );
        assert_eq!(
            project_agent_run_status_with_park(RunTreeStatus::Running, false),
            AgentRunStatus::Working
        );
        assert_eq!(
            project_agent_run_status_with_park(RunTreeStatus::Paused, false),
            AgentRunStatus::NeedsInput
        );
        assert_eq!(
            project_agent_run_status_with_park(RunTreeStatus::Completed, true),
            AgentRunStatus::Delivered
        );
        assert_eq!(
            project_agent_run_status_with_park(RunTreeStatus::Queued, true),
            AgentRunStatus::Spawned
        );
    }
    #[test]
    fn abandoned_requires_lease_reclaim_or_never_answered() {
        assert_eq!(
            project_abandoned_terminal(ExecutorTerminalCause::LeaseReclaimed),
            Some(AgentRunStatus::Abandoned)
        );
        assert_eq!(
            project_abandoned_terminal(ExecutorTerminalCause::NeverAnswered),
            Some(AgentRunStatus::Abandoned)
        );
        for cause in [
            ExecutorTerminalCause::ExecutionFailed,
            ExecutorTerminalCause::Cancelled,
            ExecutorTerminalCause::Other,
        ] {
            assert_eq!(project_abandoned_terminal(cause), None);
        }
    }
    #[test]
    fn delivered_archives_failed_and_abandoned_never_reopen() {
        assert!(
            validate_agent_run_status_transition(
                AgentRunStatus::Delivered,
                AgentRunStatus::Archived
            )
            .is_ok()
        );
        for terminal in AgentRunStatus::TERMINAL {
            for live in AgentRunStatus::ALL {
                if terminal != live {
                    assert!(!terminal.can_transition_to(live));
                }
            }
        }
    }
}
