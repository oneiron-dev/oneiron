//! Moved from `crates/oneiron/src/verbs/connector_reply_retry.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.connectors.replies.retry_failed`: the owner returns one Failed
/// connector reply job to the queue, by its attempt id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorReplyRetryRequest {
    /// The Failed attempt, 32 hex, as `vault.runs.branches.get` names a branch.
    pub attempt_ref: String,
}

/// The retry's lineage: the Failed predecessor and its queued successor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorReplyRetryView {
    /// The Failed predecessor, 32 hex. It stays Failed history.
    pub predecessor_ref: String,
    /// The queued successor, 32 hex.
    pub successor_ref: String,
}
