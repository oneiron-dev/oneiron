//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/curator.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The three questions the curator must answer from stored, verifiable facts.
/// Hosts may edit the wording through the owner-set rubric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuratorQuestions {
    pub authorship: String,
    pub freshness: String,
    pub least_force: String,
}
