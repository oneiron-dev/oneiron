//! An ended run's TASK settlement, split from its parent.

use super::super::{RunnerTaskEffects, runner_refusal};
use super::*;

/// Settles one ended run's TASK in a writer of its own, after the wrapper's
/// terminal commit: the report NOTE first, then, on the binder's task-work
/// turn and under its class, one writer that re-proves the try, moves the
/// TASK and marks the run settled. A completed run reports Done, judged
/// against the TASK's done-means (`judged`, given outside the writer, or the
/// ask a missing answer opens); a failed one reports its final failure; a
/// cancelled or abandoned one closes the TASK so. A TASK that moved on is
/// marked with no move, and so is one the move lost for good, with its
/// reason (FIX 5291), or one whose report NOTE was refused for good (FIX
/// 6434). The peer-result signal goes after commit; a signal that fails is
/// logged and the wake pass replays it.
pub(crate) fn settle(
    vault: &Vault,
    end: &WorkflowRunEnd,
    judged: Option<RunnerDoneAnswer>,
    now: u64,
) -> Result<bool> {
    let Some(ended) = RunEnd::of(end.wrapper.state) else {
        return Ok(false);
    };
    let note = report_note_id(end.wrapper.id)?;
    if report_note_lost(vault, end, ended, note)? {
        return Ok(false);
    }
    let memory = vault
        .memory(end.bound_by.entity_ref(), end.bound_by.actor_class())
        .task_work_memory();
    let mut txn = vault.store.env.write_txn()?;
    let receipt = if owed_in(vault, &txn, end)? {
        // FIX 5291: a fence that refuses the binder for good, or a TASK no
        // longer there for them, settles with its typed reason in a writer
        // of its own, moving nothing; any other refusal rolls back below,
        // and the next pass tries again.
        if let Err(error) =
            memory.workflow_try_standing_in(&txn, &try_binding(&end.wrapper), end.task)
            && let Some(lost) = recorded_right::SettleLoss::of(&error)
        {
            drop(txn);
            let dispatcher = AgentDispatcher::new(vault);
            dispatcher.mark_workflow_task_lost(end.wrapper.id, ended.as_str(), lost.as_str())?;
            return Ok(false);
        }
        let right = recorded_right::binder_right_in(&memory, &txn, end, note);
        let moved = match ended {
            RunEnd::Completed | RunEnd::Failed => {
                report_in(&memory, &mut txn, end, ended, note, right, judged)
            }
            RunEnd::Cancelled | RunEnd::Abandoned => {
                close_in(&memory, &mut txn, end, ended, note, right, now)
            }
        };
        Some(moved.map_err(runner_refusal)?)
    } else {
        None
    };
    AgentDispatcher::new(vault).mark_workflow_task_settled_in(
        &mut txn,
        end.wrapper.id,
        ended.as_str(),
    )?;
    txn.commit()?;
    let Some(receipt) = receipt else {
        return Ok(false);
    };
    vault.store.notify_attempt_observers();
    vault.store.notify_task_updates([end.task]);
    if let Err(error) = RunnerTaskEffects::of(&receipt).run(vault, now) {
        tracing::warn!(kind = ?error.kind(), task = %end.task.to_hex(), "a settled workflow TASK's peer signal did not go out; the wake pass replays it");
    }
    Ok(matches!(
        receipt.outcome,
        TaskOutcome::Reported { .. } | TaskOutcome::AskedUp { .. }
    ))
}
