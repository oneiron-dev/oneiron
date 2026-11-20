//! Request-hash durable steps: bound submits and receipts without a submission row.
//!
//! A bound extraction step keys its durable work by the request content hash, never by a
//! call-site key. Its submit uses the shared checked execution and saves no submission row;
//! its receipt reads the terminal record in one snapshot. Both share the moved result
//! converter with the owner doors. The request names the version of every source row it was
//! read from, and the terminal record keeps them, so a receipt answers only while each of
//! them still reads for its caller at that version.

#[cfg(oneiron_test_support)]
use std::ops::Bound;

use super::super::{LlmRequest, ResponseFormat};
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
use super::step_state::{step_state_erased, step_state_read};
use super::types::KEY_INPUT_VERSIONS;
use super::{DurableStepError, DurableStepResult, StepOutcome, StepProgression};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::code_run::HOST_PROVIDER_OPTIONS;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::model_step_effect::StepEffectBinding;
use crate::snapshot_read::SourceVersion;
use crate::store::model_step_submission::{ModelStepResult, ModelStepRetryPolicy};

/// Names `versions` in `request`'s host provider options, the versions of every source row
/// the request was read from. They are part of the request hash, and the terminal record
/// keeps them for the receipt.
///
/// # Errors
///
/// A version that does not serialize.
pub(crate) fn bind_step_input_versions(
    request: &mut LlmRequest,
    versions: &[SourceVersion],
) -> Result<()> {
    let value = serde_json::to_value(versions)
        .map_err(|_| Error::InvariantViolation("dreamer step input versions did not encode"))?;
    let options = request
        .provider_options
        .entry(HOST_PROVIDER_OPTIONS.to_owned())
        .or_insert(serde_json::Value::Null);
    if !options.is_object() {
        *options = serde_json::Value::Object(serde_json::Map::new());
    }
    if let serde_json::Value::Object(options) = options {
        options.insert(KEY_INPUT_VERSIONS.to_owned(), value);
    }
    Ok(())
}

/// The source versions `request` names in its host provider options, as the one JSON
/// string the terminal record keeps; `None` when it names none.
///
/// # Errors
///
/// A named value that is not a list of source versions.
pub(super) fn step_input_versions(request: &LlmRequest) -> Result<Option<String>> {
    let Some(value) = request
        .provider_options
        .get(HOST_PROVIDER_OPTIONS)
        .and_then(|options| options.get(KEY_INPUT_VERSIONS))
    else {
        return Ok(None);
    };
    let versions: Vec<SourceVersion> = serde_json::from_value(value.clone())
        .map_err(|_| Error::InvalidClaimBody("dreamer step input versions did not decode"))?;
    serde_json::to_string(&versions)
        .map(Some)
        .map_err(|_| Error::InvalidClaimBody("dreamer step input versions did not encode"))
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

/// [`request_hash_submit_receipt`] for a step an owner's erase may take while its call is in
/// flight (KS-2B1, FIX 6226): a refused outcome whose step-state row reads erased answers
/// [`ModelStepResult::Erased`], typed, so the job ends its attempt; the step is over and is
/// never asked, or paid for, again. Every other outcome converts as there.
pub(crate) fn request_hash_submit_receipt_keeping_erased(
    vault: &Vault,
    attempt: AttemptId,
    request: &LlmRequest,
    outcome: DurableStepResult<StepOutcome>,
) -> MemoryResult<ModelStepReceipt> {
    let refused = matches!(&outcome, Err(DurableStepError::Engine(Error::Refused(_))));
    let receipt = request_hash_submit_receipt(vault, attempt, request, outcome);
    if !refused || receipt.is_ok() {
        return receipt;
    }
    let step_hash = request
        .canonical_hash()
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    if !step_state_erased(vault, attempt, &step_hash)? {
        return receipt;
    }
    Ok(ModelStepReceipt {
        step_ref: bytes_to_hex_lower(&step_hash),
        step_hash: bytes_to_hex_lower(&step_hash),
        model: request.model.clone(),
        retry: ModelStepRetryPolicy::default(),
        progression: None,
        result: Some(ModelStepResult::Erased),
    })
}

/// Reads the finished receipt of one request-hash step in the caller's snapshot. Terminal
/// records only; anything else is not found.
///
/// The saved response may quote any row the request was read from, so the record must name
/// the version of each, and `still_reads` must hold for every one of them: the caller's live
/// read serves that row at that version. A record that names none, or a row that no longer
/// reads at its version, answers as an unknown hash does, before the response is loaded.
pub(crate) fn request_hash_step_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    step_hash: &[u8; 32],
    still_reads: impl Fn(&SourceVersion) -> Result<bool>,
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
    let Some(versions) = decoded.input_versions.as_ref() else {
        return Err(Error::EntityNotFound);
    };
    for version in versions {
        if !still_reads(version)? {
            return Err(Error::EntityNotFound);
        }
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
