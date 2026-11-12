//! Moved from `crates/oneiron/src/share_travel/agent_pack_export.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use oneiron_authority::share_travel::TravelChoice;
use serde::Deserialize;
use serde::Serialize;

/// Which agent to share, and the born-with text to send with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackExportRequest {
    pub agent_ref: String,
    /// The born-with text to send with the pack; absent sends none (OF-491).
    #[serde(default)]
    pub travel: Option<TravelChoice>,
}
