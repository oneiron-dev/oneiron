//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/grant_reads.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.agent_health.cards`: the health cards opened, updated or settled
/// in `[from, to)`, unix seconds.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCardsRequest {
    pub from: u64,
    pub to: u64,
    /// At most this many cards, most impact first; at most 500.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `vault.agent_health.calls`: one agent's call receipts since `since`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCallsRequest {
    /// The agent, by its entity id (hex).
    pub agent_ref: String,
    /// Unix seconds.
    pub since: u64,
    /// At most this many receipts, newest kept; at most 500.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `vault.diagnostics.evidence`: one attempt's failure evidence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticEvidenceRequest {
    pub attempt: AttemptId,
    /// The lease generation the evidence must be of, when known.
    #[serde(default)]
    pub generation: Option<u32>,
    /// The code run whose completed checks to report, by its entity id (hex).
    #[serde(default)]
    pub run_ref: Option<String>,
}
