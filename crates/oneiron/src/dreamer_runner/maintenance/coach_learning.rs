//! The Coach's own record (ARCH-0066 #coach: "calibration, meta-learning"):
//! each anchored outcome of the Coach's own work is evidence for a
//! `learning.reliability` cell of the Coach, one per kind of work (the cell's
//! axis). A skill edit is a held-out outcome: the gate scored the edited
//! instructions against the current ones on reserved evidence. An unknown
//! outcome is no evidence. A checked training offer is an outcome for the
//! offer skill that drafted it instead (`skill_optimize::record_offer_check`).
//!
//! The Coach's actor is the cell's subject and executor until its improver
//! recipe is a skill of its own; the cell sits at the vault tree's root,
//! since this work has no task type.
use crate::learning::{
    Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation, record_evidence,
};
use crate::{Result, Vault};

/// The Coach's skill edits, scored by the held-out gate.
pub const COACH_SKILL_EDIT_AXIS: &str = "skill_edit";

/// The Coach's reliability cell for one kind of its work.
///
/// # Errors
///
/// Storage errors reading the vault's type tree.
pub fn coach_reliability_cell(vault: &Vault, axis: &str) -> Result<LearningCell> {
    let coach = crate::dreamer_runner::authority::coach_actor_id()?;
    Ok(LearningCell::new(LearningPredicate::Reliability, coach)
        .executor(coach.to_hex())
        .type_ref(crate::task_type::type_tree(vault, None)?.root())
        .axis(axis))
}

/// One anchored outcome of the Coach's work on `axis`. Recording the same
/// receipt again replaces its row, so a replayed pass counts once.
pub(super) fn record_coach_outcome(
    vault: &Vault,
    axis: &str,
    receipt: String,
    at: u64,
    anchor: Anchor,
    success: bool,
    now: u64,
) -> Result<()> {
    // The cell's subject must exist: this seeds the Coach's actor on a vault
    // whose Coach has not run yet.
    vault.coach_authority()?;
    let cell = coach_reliability_cell(vault, axis)?;
    record_evidence(
        vault,
        &cell,
        &LearningEvidence::anchored(receipt, at, anchor, Observation::Success(success)),
        now,
    )?;
    Ok(())
}
