//! Moved from `crates/oneiron/src/agent_dispatch/workflow/tool_wait.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::LlmRequest;
use oneiron_model::llm::LlmResponse;
use serde::Deserialize;
use serde::Serialize;

/// Full admitted request: the assistant's outstanding tool calls and every
/// completed result stay in their original message order. Objectives are
/// user text too, so they share this admitted body, not the metadata row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowToolTranscript {
    pub request: LlmRequest,
    pub objectives: Vec<String>,
    pub answer: Option<WorkflowToolAnswer>,
}

/// The paid terminal answer and the exact rung that answered it. These are
/// admitted body content, never reconstructed from the current route.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowToolAnswer {
    pub response: LlmResponse,
    pub rung: crate::dreamer_runner::step_replay::CapsuleRungBinding,
    pub route: Option<crate::dreamer_runner::step_replay::ReplayRoutePin>,
}

/// The next uncompleted call within the original assistant message. The
/// ordinal of a pending self.use is retained, not incremented on resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowToolCursor {
    pub assistant_message: usize,
    pub tool_index: usize,
    pub use_ordinal: u64,
    pub round: u64,
    pub capture_completed: bool,
}

/// Native identity of the pre-hook pause, never a permit to run its body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowToolWait {
    pub invocation: [u8; 16],
    pub ask: EntityId,
}
