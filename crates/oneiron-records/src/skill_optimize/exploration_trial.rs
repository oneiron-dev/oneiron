//! Moved from `crates/oneiron/src/skill_optimize/exploration_trial.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why a trial stopped routing live runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplorationTrialClose {
    /// Its routed runs reached the host's live pull cap.
    BoundReached,
    /// The proposal's live goal-axis report was kept.
    ReportStored,
    /// The gate recorded a verdict on the proposal.
    VerdictRecorded,
    /// The board declined a run past the goal's exploration slice.
    OverrunDeclined,
    /// The overrun ask went unanswered at the top of its chain for
    /// [`EXPLORATION_ASK_LAPSE_HOURS`].
    OverrunLapsed,
    /// An offline floor regressed on the held-out set.
    FloorsRegressed,
}
