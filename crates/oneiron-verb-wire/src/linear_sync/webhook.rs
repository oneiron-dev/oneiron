//! Moved from `crates/oneiron/src/linear_sync/webhook.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The provider's actor of one webhook: evidence, never a vault actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinearExternalActor {
    /// The provider's actor id.
    pub id: String,
    /// The provider's actor type (`user`, `integration`, ...).
    pub kind: String,
    /// The provider's display name, when it sent one.
    pub name: Option<String>,
}
