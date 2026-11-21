//! Moved from `crates/oneiron/src/skill_attribution/contribution_admission.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::contribution::admission::ForkMismatch;
use serde::Deserialize;
use serde::Serialize;

/// Why a recorded pair is unmatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmatchedReason {
    /// No credited outcome of the run names the pair's outcome, axis, goal
    /// revision and anchor with a readable attribution; for a used edge's
    /// check, also one whose effective used chain holds the edge, scored by
    /// the run's pattern.
    NoCredit,
    /// The run's kept forks do not prove the pair.
    Forks(ForkMismatch),
    /// The run's outcome and target already hold the final measurement of
    /// another pair; this one is kept beside it.
    Conflicting,
    /// What would measure it could not be read or minted in this write (the
    /// credit's effective used chain, or the check's own id); the fault is
    /// logged, and the pair may be measured when it is submitted again.
    Unread,
}
