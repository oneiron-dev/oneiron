//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/digest/view.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// A delivered digest's locator from an inbox notification's `source.result`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestReadRequest {
    /// The stable digest locator, as 64 hex.
    pub id: String,
}
