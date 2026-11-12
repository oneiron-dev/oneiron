//! Moved from `crates/oneiron/src/connector_key/lifecycle/tool_grant.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One tool's grant and the per-grant key that governs its calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ConnectorToolGrant {
    pub tool: String,
    pub grant_id: String,
    pub key_id: String,
    /// `mcp:{server}:grant:{grant_id}`.
    pub key_connector: String,
}
