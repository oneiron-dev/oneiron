//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/fork_promote/project_upkeep/admission.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How the goal ruled one scalar win.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpkeepGoalVerdict {
    /// Every goal axis measured: none lost and at least one gained.
    VectorWin,
    /// The scalar win stands on advisory axes: no goal record, an axis left
    /// unmeasured, axes that tied, or a loss the owner's preference approved.
    ScalarWin,
    /// An axis or a preference the owner set rules the revision out.
    Failed,
}
