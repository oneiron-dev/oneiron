//! Agent run status is part of the context-board projection vocabulary.

pub use crate::context_board::agent_run_status::{
    AgentRunStatus, InvalidAgentRunStatusTransition, validate_agent_run_status_transition, ExecutorTerminalCause, project_agent_run_status, project_agent_run_status_with_park, project_abandoned_terminal,
};
