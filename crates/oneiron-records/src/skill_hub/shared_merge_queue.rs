//! Moved from `crates/oneiron/src/skill_hub/shared_merge_queue.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::claim_refinement_control::SharedSkillDelta;

/// Where an offered shared-skill delta stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedSkillMergeState {
    /// No merge has ruled on it: never asked, or waiting on the owner's
    /// answer.
    Pending,
    /// A merge ruled it out. It may be asked again.
    Refused,
    /// A merge put it in force.
    Admitted,
}

/// One offered delta and where it stands.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SharedSkillMergeEntry {
    pub delta: SharedSkillDelta,
    pub state: SharedSkillMergeState,
}
