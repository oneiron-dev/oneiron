//! Moved from `crates/oneiron/src/agent_dispatch/widen_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::config::context_spec::ContextSpec;
use oneiron_store::inbox::view_values::AgentInboxItemKind;
use oneiron_store::inbox::view_values::AgentInboxParticipant;
use oneiron_store::inbox::view_values::InboxImpact;
use serde::Deserialize;
use serde::Serialize;

/// Where a proposal stands: waiting on the board, approved (its child
/// enqueued), or declined (final).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WidenProposalState {
    Pending,
    Approved,
    Declined,
}

/// `vault.widen_proposals`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WidenProposalsRequest {
    /// Only proposals in this state; every state when absent.
    #[serde(default)]
    pub state: Option<WidenProposalState>,
}

/// `vault.widen_proposals.approve` and `.decline`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WidenProposalAnswer {
    /// The proposal's id (64 hex), as the list and the spawn's
    /// `proposal_ref` name it.
    pub proposal_id: String,
}

/// One proposal as the owner sees it. Contexts are descriptors, never the
/// content they name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WidenProposalView {
    pub proposal_id: String,
    pub state: WidenProposalState,
    /// The attempt that asked for the wider context (32 hex).
    pub parent_attempt: String,
    /// The board above, which answers; absent when it cannot be proven, and
    /// then approval fails closed.
    pub board_attempt: Option<String>,
    /// What the child runs: `agent` or `workflow`.
    pub target_kind: String,
    /// The agent or workflow id the child runs.
    pub target: String,
    /// The parent's context as it is.
    pub parent_context: serde_json::Value,
    /// The context the child asked for.
    pub requested_context: serde_json::Value,
    /// The parent's context once widened, as approval would set it.
    pub widened_parent_context: serde_json::Value,
    /// When it was raised, on the vault clock (seconds).
    pub recorded_at: u64,
    /// The child attempt an approval enqueued (32 hex).
    pub landed_attempt: Option<String>,
    /// Who declined it (actor hex), and when.
    pub declined_by: Option<String>,
    pub declined_at: Option<u64>,
}

/// `vault.widen_proposals`'s answer, newest first.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WidenProposalsView {
    pub proposals: Vec<WidenProposalView>,
}
