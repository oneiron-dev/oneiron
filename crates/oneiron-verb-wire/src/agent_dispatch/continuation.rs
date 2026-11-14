//! Moved from `crates/oneiron/src/agent_dispatch/continuation.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `/v1/owner/inbox/concern/apply-prompt-inject`'s input: the one prompt
/// continuation the owner approves.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernPromptInjectRequest {
    /// The card's `health:` handle, the row's `payload_ref`.
    pub card: String,
    /// The Coach ask the owner read: its `attempt`, as 32 hex.
    pub ask: String,
    /// The approved prompt: the Coach's proposal on that ask, or the
    /// owner's own edit of it.
    pub prompt: String,
    /// The checkpoint the run continues from, as 32 hex: the healer case's
    /// or the failure card's `pre_fail_checkpoint_ref`. Absent, the failed
    /// run's own pre-fail checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<String>,
}

/// The continuation an approval made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConcernPromptInjectOutcome {
    /// The card's `health:` handle.
    pub card: String,
    /// The successor attempt, as 32 hex.
    pub successor: String,
    /// The approval's id, as 32 hex.
    pub approval: String,
    /// The checkpoint's id, as 32 hex.
    pub checkpoint: String,
    /// The same approval was applied before: this is the successor it made.
    pub replayed: bool,
}
