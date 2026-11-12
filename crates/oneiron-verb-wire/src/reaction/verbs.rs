//! Moved from `crates/oneiron/src/reaction/verbs.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The provider side of a mirrored reaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageReactionExternal {
    pub connector: String,
    /// The provider's generation id.
    pub id: String,
    /// The first-party reaction claim a provider echo answers.
    #[serde(default)]
    pub origin: Option<String>,
}

/// The reaction claim a change resolved to, and its event:
/// `reaction.put`, `reaction.revoked` or `reaction.replayed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MessageReactionReceipt {
    pub id: String,
    pub event: String,
}
