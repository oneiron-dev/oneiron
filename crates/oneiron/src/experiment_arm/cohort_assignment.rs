//! The mint's half of the comparison's cohorts (design pass 32 r2, section
//! 4.4): an arm still open when the comparison turns on, or of a family
//! that graduated from a new idea, takes its cohort at the two-rule mint
//! that follows, in admission order and by the same blocks as an admission
//! (`gpu_line::cohort`).

use super::EXPERIMENT_ARMS;
use crate::Vault;
use crate::gpu_line::{GpuLine, GpuLinePeriod, next_cohort_assignment_in_txn};

/// Assigns every open arm of `line` that has no cohort a position of the
/// newly minted `period`, in admission order (arm id order), on its seat's
/// track now, and writes the arm with its cohort and block (its revision
/// bumped). An arm whose family holds no seat in force, a new idea, or a
/// period with one rule takes none. A closed arm is never assigned.
///
/// # Errors
///
/// A store failure.
pub(crate) fn assign_open_arms_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    line: &GpuLine,
    period: &GpuLinePeriod,
    now_ms: u64,
) -> crate::Result<()> {
    let waiting: Vec<_> = vault
        .experiment_arms_in_txn(wtxn)?
        .into_iter()
        .filter(|arm| arm.line == line.project && arm.is_open() && arm.cohort.is_none())
        .collect();
    for mut arm in waiting {
        let Some(seat) = line.seat(&arm.family) else {
            continue;
        };
        let Some(assignment) =
            next_cohort_assignment_in_txn(vault, wtxn, &line.project, period, seat.track)?
        else {
            continue;
        };
        assignment.record_in_txn(vault, wtxn, arm.family, Some(arm.id), now_ms)?;
        arm.cohort = Some(assignment.rule());
        arm.cohort_block = Some(assignment.block());
        arm.revision += 1;
        EXPERIMENT_ARMS.put(&vault.store, wtxn, &arm.id, &arm)?;
    }
    Ok(())
}
