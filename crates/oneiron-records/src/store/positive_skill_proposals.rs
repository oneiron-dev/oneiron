//! Moved from `crates/oneiron/src/store/positive_skill_proposals.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What a succeeded attempt taught its skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PositiveFinding {
    /// The actor departed from the skill for `reason`, and the attempt won.
    DeviationWorked { reason: String },
    /// The actor performed a step the skill did not cover, and the attempt won.
    UncoveredStepWorked,
}
