//! Moved from `crates/oneiron/src/snapshot_read/strength_observations.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The next observation page, bounded by the effective snapshot page settings.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StrengthObservationsPageRequest {
    /// The preceding page's opaque cursor; absent on the first page.
    pub cursor: Option<String>,
    /// The most claims served, capped at the effective page row bound.
    pub limit: Option<u32>,
}
