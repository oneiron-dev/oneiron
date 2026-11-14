//! Moved from `crates/oneiron/src/task_verb/run_control.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One branch to pause or resume, by the attempt id its run tree names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunControlRequest {
    /// The branch's attempt id, hex, as `vault.runs.branches.get` names it.
    pub branch: String,
    /// Kept on the branch's intervention event.
    #[serde(default)]
    pub note: Option<String>,
}

/// The queue's own effect: a repeat answers `already_*` and writes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunControlEffect {
    Paused,
    AlreadyPaused,
    Resumed,
    AlreadyResumed,
    /// A running run pauses at its next step boundary; a repeat answers it
    /// again and posts nothing more.
    PausingAtNextStep,
}
