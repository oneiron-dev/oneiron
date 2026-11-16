//! Moved from `crates/oneiron/src/channel_identity_provider/slack_adapter.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// Slack Web API call body after persona attribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlackPersonaOutbound {
    pub method: String,
    pub workspace_ref: String,
    pub identity_key: String,
    pub persona_handle: String,
    pub body: Value,
}
