//! Moved from `crates/oneiron/src/verbs/explain.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.explain.memory`'s input: the memory, and the session that was
/// served it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExplainMemoryRequest {
    /// Hex entity id of the memory.
    pub entity: String,
    /// The board or pack session that was served the memory; the caller's
    /// active session when absent.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `vault.explain.gate`'s input: one gate receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExplainGateRequest {
    /// Gate receipt id, `gate:<hex>`.
    pub receipt: String,
}
