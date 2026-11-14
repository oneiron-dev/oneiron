//! Moved from `crates/oneiron/src/memory/proactivity_digest.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One saved proactivity digest, or the latest when no locator is supplied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProactivityDigestRequest {
    /// The 64-hex locator from an inbox notification's `source.result`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
