//! A durable step's recovery from its saved work, moved out of `execute`
//! for FIX 4816: the memo or saved payload captured in one snapshot, then
//! finished on the shared terminal writer. `execute` re-exports the two
//! functions it held. The memo index also finds a compaction step by its
//! job (FIX 4816); only the runner's own record replays here.

use super::super::{BudgetGuard, LlmRequest, LlmResponse};
use super::execute::{erased_step, failure_policy, step_legibility};
use super::step_claim::{
    decode_step_claim_value, load_step_response_in_txn, log_terminal_step,
    step_claim_matches_request, step_index_lookup_in_txn,
};
use super::step_index::step_claim_is_runner_execution;
use super::step_state::{step_state_delete, step_state_read_in_txn};
use super::types::{DurableStepContext, DurableStepResult, StepOutcome, StepProgression};
use crate::dreamer_wake::StepTerminal;
use crate::error::Error;

/// A saved response captured before any new execution. Owning the payload
/// closes a recovery probe's race with a later memo removal; a miss never
/// becomes a synthetic provider failure.
pub(super) enum StepRecovery {
    Erased,
    Memo(LlmResponse),
    Payload(Vec<u8>),
}

/// Read the existing memo/checkpoint recovery path in one snapshot. This
/// can run beside a submission's queue claim, without a backend or meter.
pub(super) fn recovery_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    attempt_id: crate::attempt_queue::AttemptId,
    step_hash: &[u8; 32],
    request: &LlmRequest,
) -> DurableStepResult<Option<StepRecovery>> {
    let state = step_state_read_in_txn(vault, txn, attempt_id, step_hash)?;
    if state.as_ref().is_some_and(|row| row.erased) {
        return Ok(Some(StepRecovery::Erased));
    }
    // ONE-1344: the memo still has to match this frozen request's
    // model/purpose/params identity. A foreign response is a miss.
    // FIX 4816: so is a step the runner did not execute, such as an
    // indexed compaction step under the same job and hash.
    if let Some(claim_id) = step_index_lookup_in_txn(vault, txn, attempt_id, step_hash)? {
        let body = vault
            .get_claim_in_txn(txn, &claim_id)?
            .ok_or(Error::InvalidClaimBody("dreamer step index claim missing"))?;
        let decoded = decode_step_claim_value(&body.value)?;
        if step_claim_is_runner_execution(&decoded, &body)
            && step_claim_matches_request(&decoded, request)?
        {
            let response = load_step_response_in_txn(vault, txn, &decoded)?;
            return Ok(Some(StepRecovery::Memo(response)));
        }
    }
    Ok(state.and_then(|row| {
        if matches!(
            row.progression,
            StepProgression::ResponseReceived | StepProgression::Logged
        ) {
            row.response_payload.map(StepRecovery::Payload)
        } else {
            None
        }
    }))
}

/// Finish only the captured saved work. The terminal writer, erase fence,
/// exact payload and memoized result are shared with ordinary execution.
pub(super) fn recover_step(
    ctx: &DurableStepContext<'_>,
    step_hash: &[u8; 32],
    request: &LlmRequest,
    recovery: StepRecovery,
    guard: Option<&BudgetGuard>,
) -> DurableStepResult<StepOutcome> {
    let (response, failure_policy) = match recovery {
        StepRecovery::Erased => return Err(erased_step()),
        StepRecovery::Memo(response) => {
            let policy = failure_policy(ctx.vault, &response)?;
            (response, policy)
        }
        StepRecovery::Payload(payload) => {
            let response: LlmResponse = serde_json::from_slice(&payload)?;
            // Resolve the same policy before any terminal write, as on
            // the original stored-payload recovery path.
            let policy = failure_policy(ctx.vault, &response)?;
            if log_terminal_step(
                ctx,
                step_hash,
                request,
                &response,
                &payload,
                StepTerminal::Recovered,
            )?
            .is_none()
            {
                return Err(erased_step());
            }
            step_state_delete(ctx.vault, ctx.attempt_id, step_hash)?;
            (response, policy)
        }
    };
    Ok(StepOutcome::Finished {
        response,
        memoized: true,
        legibility: guard.and_then(|guard| step_legibility(ctx, guard)),
        failure_policy,
    })
}
