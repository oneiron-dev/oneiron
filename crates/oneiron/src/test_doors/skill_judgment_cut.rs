//! Door for `tests/skill_judgment_cut_instructions.rs`: score one held-out
//! replay case. The case type is `#[non_exhaustive]` with no public
//! constructor, so the test cannot build it; this door builds it beside the
//! test's scorer and instructions and puts it to the shared judgment path.

use crate::EntityId;
use crate::error::Result;
use crate::skill_optimize::{HeldOutReplayCase, HeldOutReplayNotes};

/// Score `instructions` against `held_out` under `scorer`: the whole-reserve
/// judgment state, fitted to the ladder's bound, on the shared typed-decision
/// path. No goal is resolved for the case.
/// # Errors
/// The scorer's errors, and the judgment's: an abstained or escalated finding,
/// or instructions cut to fit the decision state bound.
pub fn score_case(
    scorer: &dyn HeldOutReplayNotes,
    skill: EntityId,
    skill_id: &str,
    version: &str,
    instructions: &str,
    held_out: &[String],
) -> Result<f32> {
    scorer.score(&HeldOutReplayCase {
        skill,
        skill_id,
        version,
        instructions,
        held_out_receipts: held_out,
        goal: None,
    })
}
