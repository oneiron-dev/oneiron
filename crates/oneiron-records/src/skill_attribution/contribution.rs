//! Moved from `crates/oneiron/src/skill_attribution/contribution.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One fork of a matched pair: its receipt, and whether it passed the
/// anchor both forks were scored against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionFork {
    pub receipt: String,
    pub passed: bool,
}
