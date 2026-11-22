//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/fork_promote/project_upkeep/state.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where one revision stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpkeepState {
    /// Minted and journaled; its package, its scoring or its admission waits.
    Open,
    /// Scored strictly above the tree it revises and put in force for the
    /// project. The owner's revert of it leaves the row as it is.
    Won,
    /// Scored no better than the tree it revises.
    Lost,
    /// The tree it revises is no longer the project's, or the Candidate is
    /// no longer what was stored: it can never go in force.
    Stale,
}
