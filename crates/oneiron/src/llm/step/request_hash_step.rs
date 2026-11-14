//! Request-hash durable steps: bound submits and receipts without a submission row.
//!
//! A bound extraction step keys its durable work by the request content hash, never by a
//! call-site key. Its submit runs the standard durable execution and saves no submission row;
//! its receipt reads the terminal record in one snapshot. Both share the moved result
//! converter with the owner doors.

#[cfg(oneiron_test_support)]
use std::ops::Bound;

use super::super::{
    BudgetGuard, FallbackRegistry, LlmBackend, LlmRequest, LlmUsage, ResponseFormat,
};
use super::public::ModelStepReceipt;
use super::step_claim::{decode_step_claim_value, load_step_response_in_txn};
#[cfg(oneiron_test_support)]
use super::step_index::{STEP_INDEX_FORWARD, StepIndexKey};
use super::step_index::{
    step_claim_is_runner_execution, step_index_lookup, step_index_lookup_in_txn,
    terminal_step_identity,
};
use super::step_result::step_result;
#[cfg(oneiron_test_support)]
use super::step_state::STEP_STATE;
use super::step_state::step_state_read;
use super::{
    DREAMER_STEP_RETRY_BACKOFF_MS, DurableStepContext, DurableStepError, DurableStepResult,
    StepOutcome, StepProgression,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::model_step_effect::StepEffectBinding;
use crate::store::model_step_submission::{ModelStepResult, ModelStepRetryPolicy};

/// Runs the standard durable execution and keeps the unsaved usage of a fresh response that
/// could not be saved. Errors and saved-response recovery keep their ordinary meaning.
pub(crate) async fn call_as_step_with_unsaved_usage(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
) -> (DurableStepResult<StepOutcome>, Option<LlmUsage>) {
    let mut unsaved_usage = None;
    let outcome = super::execute::durable_step(
        ctx,
        backend,
        guard,
        request,
        &FallbackRegistry::standard(),
        None,
        DREAMER_STEP_RETRY_BACKOFF_MS.len(),
        Some(&mut unsaved_usage),
    )
    .await;
    (outcome, unsaved_usage)
}

/// Builds the receipt of a bound submit from its execution outcome. The hash comes from the
/// request, the model and format ride the request, and the terminal lookup runs inside.
pub(crate) fn request_hash_submit_receipt(
    vault: &Vault,
    attempt: AttemptId,
    request: &LlmRequest,
    outcome: DurableStepResult<StepOutcome>,
) -> MemoryResult<ModelStepReceipt> {
    let step_hash = request
        .canonical_hash()
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let result = step_result(outcome, &request.envelope.response_format, || {
        step_index_lookup(vault, attempt, &step_hash)
    })?;
    let progression = match &result {
        ModelStepResult::Finished { .. } => Some(StepProgression::Finished),
        _ => step_state_read(vault, attempt, &step_hash)?.map(|state| state.progression),
    };
    Ok(ModelStepReceipt {
        step_ref: bytes_to_hex_lower(&step_hash),
        step_hash: bytes_to_hex_lower(&step_hash),
        model: request.model.clone(),
        retry: ModelStepRetryPolicy::default(),
        progression,
        result: Some(result),
    })
}

/// Reads the finished receipt of one request-hash step in the caller's snapshot. Terminal
/// records only; anything else is not found.
pub(crate) fn request_hash_step_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    step_hash: &[u8; 32],
) -> Result<ModelStepReceipt> {
    let Some(claim_id) = step_index_lookup_in_txn(vault, txn, attempt, step_hash)? else {
        return Err(Error::EntityNotFound);
    };
    let Some(body) = vault.get_claim_in_txn(txn, &claim_id)? else {
        return Err(Error::EntityNotFound);
    };
    let Some((bound_attempt, bound_hash, model)) = terminal_step_identity(&body) else {
        return Err(Error::EntityNotFound);
    };
    if bound_attempt != attempt || bound_hash != *step_hash {
        return Err(Error::EntityNotFound);
    }
    let decoded = decode_step_claim_value(&body.value)?;
    if !step_claim_is_runner_execution(&decoded, &body) {
        return Err(Error::EntityNotFound);
    }
    let response =
        load_step_response_in_txn(vault, txn, &decoded).map_err(|error| match error {
            DurableStepError::Engine(error) => error,
            _ => Error::InvalidClaimBody("dreamer step response did not decode"),
        })?;
    let outcome = Ok(StepOutcome::Finished {
        binding: StepEffectBinding {
            attempt_id: attempt,
            step_hash: *step_hash,
        },
        response,
        memoized: true,
        legibility: None,
        failure_policy: None,
    });
    // The converter cannot fail here: the claim is present, the format is text so no JSON
    // parses, and the lookup never errors. Any failure maps to a corrupt record.
    let result = step_result(outcome, &ResponseFormat::Text, || Ok(Some(claim_id)))
        .map_err(|_| Error::InvalidClaimBody("dreamer step response did not decode"))?;
    Ok(ModelStepReceipt {
        step_ref: bytes_to_hex_lower(step_hash),
        step_hash: bytes_to_hex_lower(step_hash),
        model,
        retry: ModelStepRetryPolicy::default(),
        progression: Some(StepProgression::Finished),
        result: Some(result),
    })
}

/// Tells whether `attempt` holds any durable step state, started or terminal. A finished step
/// deletes its live row, so the memo index covers the terminal side.
#[cfg(oneiron_test_support)]
pub(crate) fn step_state_present_for_attempt(vault: &Vault, attempt: AttemptId) -> Result<bool> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let state_has = STEP_STATE
        .iter_range(
            &vault.store,
            &txn,
            Bound::Included(&(attempt, [0; 32])),
            Bound::Included(&(attempt, [u8::MAX; 32])),
        )?
        .next()
        .transpose()?
        .is_some();
    if state_has {
        return Ok(true);
    }
    let index_has = STEP_INDEX_FORWARD
        .iter_range(
            &vault.store,
            &txn,
            Bound::Included(&StepIndexKey {
                attempt_id: attempt,
                step_hash: [0; 32],
            }),
            Bound::Included(&StepIndexKey {
                attempt_id: attempt,
                step_hash: [u8::MAX; 32],
            }),
        )?
        .next()
        .transpose()?
        .is_some();
    Ok(index_has)
}
