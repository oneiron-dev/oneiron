//! Moved from `crates/oneiron/src/agent_def/proposed_change.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// How the owner answered a proposed change to a stored definition.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProposedAgentDefinitionChangeDecision {
    /// The proposal became the stored definition's next version.
    Approved,
    /// The stored definition stayed as it was.
    Rejected,
}
