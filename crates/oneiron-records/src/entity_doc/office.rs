//! Moved from `crates/oneiron/src/entity_doc/office.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_docedit::live::NodeId;
use serde::Deserialize;
use serde::Serialize;

/// Wake the proposer to re-evaluate the withdrawn units. Re-evaluation is
/// not acceptance: the Grant or an authorized independent holder answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReevalWake {
    pub proposal: String,
    pub proposer: String,
    pub withdrawn: Vec<NodeId>,
    /// The revision each withdrawn answer was judged against.
    pub judged_against: u64,
    pub head_version: u64,
    /// The quiet interval the policy row asked for, in milliseconds.
    pub quiet_for_ms: u64,
}
