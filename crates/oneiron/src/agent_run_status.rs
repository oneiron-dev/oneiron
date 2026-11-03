//! Agent run status is part of the context-board projection vocabulary.

pub use crate::context_board::agent_run_status::{
    AgentRunStatus, ExecutorTerminalCause, InvalidAgentRunStatusTransition,
    project_abandoned_terminal, project_agent_run_status, project_agent_run_status_with_park,
    validate_agent_run_status_transition,
};
