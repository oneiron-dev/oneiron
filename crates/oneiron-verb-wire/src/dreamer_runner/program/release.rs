//! Moved from `crates/oneiron/src/dreamer_runner/program/release.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The owner's release of one held turn program's try.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTurnProgramHoldRequest {
    /// 32-hex id of the held try, as a program read's `held` names it
    /// (`job:` prefix allowed).
    pub attempt: String,
    /// The hold's exact reason and the time it was parked, as that read
    /// showed them: a hold that changed since refuses.
    pub reason: String,
    pub parked_at: u64,
    pub action: ProgramHoldReleaseAction,
    /// The owner's note: a stop's cancellation reason, or a resume's
    /// intervention note.
    #[serde(default)]
    pub note: Option<String>,
}

/// What the owner does with a held program's try.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProgramHoldReleaseAction {
    /// End the try and clear its hold; its run, checkpoint and steps stay.
    Stop,
    /// Queue the same try again: only a diverged or unfinished program's
    /// hold, once its checkpoint lines up with its run's record, its
    /// authority and pin bind and nothing it did is unsettled.
    ResumeValidated,
}

/// What releasing one program's hold did.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramHoldReleaseView {
    /// 32-hex try.
    pub attempt: String,
    pub action: ProgramHoldReleaseAction,
    /// The released hold's exact reason.
    pub released: String,
    /// The try's queue state after the release.
    pub state: String,
    /// Whether this release stopped or queued the try: a stop of a try
    /// already settled only clears its hold.
    pub effected: bool,
}
