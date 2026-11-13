//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/digest/after_notice.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The derived group the applied-maintenance line renders under.
pub const APPLIED_GROUP: &str = "dreamer.applied";

/// One applied write, as the owner's list names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestAppliedItem {
    /// The write's target as the revert takes it: a finding's 32 hex, an
    /// ask's 64 hex, or a project's and a fork's 32 hex joined by `:`.
    pub target: String,
    /// Its kind on the owner's list (`curator`, `reach_out`, ...).
    pub kind: String,
    pub facet: String,
    pub applied_at: u64,
    /// The receipt (`gate:<id>`) the item is keyed by: a digest carries each
    /// one once.
    pub receipt_ref: String,
}
