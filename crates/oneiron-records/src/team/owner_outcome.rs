//! Moved from `crates/oneiron/src/team/owner_outcome.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What a bound review asks the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliverableReview {
    /// Whether the team's deliverable, as pinned, is accepted.
    Acceptance,
}
