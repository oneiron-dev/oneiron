//! What came of a contribution fork's program, kept (FIX 3607): its
//! execution, or the shadow runner's reason it did not run. Each body an
//! executed program left (its observation, its files, the results it stored
//! and its two traces) goes through the side-row wall's body admission as a
//! fork's answer does, under the capsule's key, and is published as a body
//! the original run owns. The fork's row takes the outcome that names them
//! in the SAME writer, which reads the capsule and the fork's row again
//! first, so an erase always discovers a published body. Nothing is
//! published for a capsule erased or gone, a subject of the pair gone, or a
//! fork row that is no longer the fork that ran. A settled outcome another
//! writer committed first is kept, never replaced; only a retry replaces an
//! outcome that waits for it. The capsule's erase releases these bodies with
//! the fork's answer ([`super::erase`]).

use super::super::super::contribution::{
    ContributionForkExecution, ContributionForkReceipt, ContributionReplayUnavailable,
    ExecutedOutput, ForkExecutionOutcome,
};
use super::super::super::replay_capsule::StepReplayCapsule;
use super::admit::{Unwritten, spilling, with_spill};
use super::{
    CAPSULES, FORKS, ForkValue, ForkWrite, capsule_key, fork_capsule_in_txn, fork_row_name,
    held_body,
};
use crate::batch::secret_scan::{SidePart, admit_side_parts};
use crate::compaction::output::OutputRef;
use crate::{EntityId, Error, Result, Vault};

/// Where the wall's custody records name what they lifted from a fork's
/// executed bodies, beside the capsule's key.
const EXECUTION_PLACE: &str = "side:CODE_RUN_REPLAY_CAPSULE:fork_execution";

/// Keeps what came of `fork`'s program: each of `bodies` (its stored path
/// and its bytes, in order; none when it did not run) admitted and
/// published as a body the capsule's run owns, and the fork's row put with
/// the outcome `record` makes of their refs, in that order, all in one
/// writer. Nothing is written once the capsule is gone or the fork's row is
/// no longer `fork` (`Unreadable`), its actor's erase took its content
/// (`Erased`), or a subject of the pair is gone now: the fence's
/// `Unfinished`, never lasting (FIX 6256). A fork whose outcome another
/// writer settled or moved on first keeps that one, and it is returned.
///
/// # Errors
///
/// Storage and custody errors, and a `record` that names other bodies than
/// were kept.
pub(crate) fn store_fork_execution(
    vault: &Vault,
    capsule: &StepReplayCapsule,
    pair: &[u8; 32],
    fork: &ContributionForkReceipt,
    bodies: &[(&str, &[u8])],
    record: impl Fn(&[OutputRef]) -> Option<ForkExecutionOutcome>,
) -> Result<ForkWrite<ContributionForkReceipt>> {
    let key = capsule_key(capsule);
    let fork_key = (*pair, fork_row_name(fork.treatment).to_owned());
    let lens: Vec<usize> = bodies.iter().map(|(_, bytes)| bytes.len()).collect();
    let reserved = spilling(vault.code_result_inline_bytes(), &lens);
    with_spill(vault, reserved, |wtxn, spill| {
        let held = match fork_capsule_in_txn(vault, wtxn, &key)? {
            Ok((held, _)) => held,
            Err(reason) => return Ok(Err(reason)),
        };
        let Some(mut row) = FORKS.get(&vault.store, wtxn, &fork_key)? else {
            return Ok(Err(ContributionReplayUnavailable::Unreadable));
        };
        let ForkValue::Fork(kept) = &row.value else {
            return Ok(Err(ContributionReplayUnavailable::Unreadable));
        };
        let mut expected = fork.clone();
        expected.score = kept.score;
        expected.execution.clone_from(&kept.execution);
        if *kept != expected {
            return Ok(Err(ContributionReplayUnavailable::Unreadable));
        }
        if let Err(reason) = row.provenance.fence_in_txn(vault, wtxn) {
            return Ok(Err(reason));
        }
        let settled = kept
            .execution
            .as_ref()
            .is_some_and(ForkExecutionOutcome::settled);
        if settled || kept.execution != fork.execution {
            return Ok(Ok(kept.clone()));
        }
        let key_bytes = CAPSULES.key_bytes(&key);
        let mut admitted = Vec::with_capacity(bodies.len());
        for (_, bytes) in bodies {
            let mut parts = [SidePart::Body(bytes.to_vec())];
            let at = (EXECUTION_PLACE, key_bytes.as_slice());
            admit_side_parts(vault, wtxn, at, &mut parts, |_| true)?;
            let [SidePart::Body(bytes)] = parts else {
                return Err(Unwritten::Failed(Error::InvariantViolation(
                    "an admitted fork execution body is no longer a body",
                )));
            };
            admitted.push(bytes);
        }
        let admitted_lens: Vec<usize> = admitted.iter().map(Vec::len).collect();
        spill.holds(&admitted_lens)?;
        let mut refs = Vec::with_capacity(admitted.len());
        for ((path, _), bytes) in bodies.iter().zip(&admitted) {
            refs.push(spill.publish_in_txn(vault, wtxn, held.run, path, bytes)?);
        }
        let Some(outcome) = record(&refs) else {
            return Err(Unwritten::Failed(Error::InvariantViolation(
                "a fork execution names other bodies than it kept",
            )));
        };
        let mut receipt = kept.clone();
        receipt.execution = Some(outcome);
        row.value = ForkValue::Fork(receipt.clone());
        FORKS.put(vault, wtxn, &fork_key, &row)?;
        Ok(Ok(receipt))
    })
}

/// The observation, files and stored results `execution` names, each read
/// whole as run `run` holds it; `None` once any is released (its capsule's
/// actor was erased), gone or withheld.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn fork_execution_outputs(
    vault: &Vault,
    run: EntityId,
    execution: &ContributionForkExecution,
) -> Result<Option<Vec<ExecutedOutput>>> {
    let mut outputs = Vec::with_capacity(execution.outputs.len());
    for output in &execution.outputs {
        let path = output.stored_path.as_str();
        let Some(bytes) = held_body(vault, run, path, output.body, |_| Ok(true))? else {
            return Ok(None);
        };
        outputs.push(ExecutedOutput {
            path: output.path.clone(),
            complete: output.complete,
            bytes,
        });
    }
    Ok(Some(outputs))
}
