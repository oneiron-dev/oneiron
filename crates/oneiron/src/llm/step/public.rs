//! Owner-submitted durable model steps over the engine's existing step executor.
use serde::{Deserialize, Serialize};

use super::super::{
    BudgetGuard, ContentPart, FallbackRegistry, LlmBackend, LlmError, ResponseFormat,
};
use super::step_claim::{step_index_lookup, step_index_lookup_in_txn};
use super::step_state::step_state_read;
use super::submission_custody::{SUBMISSIONS, Submission, erased, put_submission_in_txn};
use super::{
    DREAMER_STEP_RETRY_BACKOFF_MS, DreamerTrapState, DurableStepContext, DurableStepError,
    StepOutcome, StepProgression,
};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
    FailAttempt,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{DreamerAttemptPayload, encode_dreamer_attempt_payload};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::runtime_hooks::InvocationId;
use crate::runtime_hooks::verb::InvocationEntry;
use crate::{EdgeActorClass, Vault, WriteActor};

pub use super::media_step::media_step_key;
pub use super::settled::{SettledStepRequest, SettledStepView, settled_step_as_owner};

pub(crate) use crate::model_step_record::MODEL_STEP_ATTEMPT_KIND;
pub use crate::store::model_step_submission::{
    ModelStepFailure, ModelStepFailureClass, ModelStepResult, ModelStepRetryPolicy, ModelStepSubmit,
};
const WORKER: &str = "model-step-door";

impl Default for ModelStepRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: (DREAMER_STEP_RETRY_BACKOFF_MS.len() + 1) as u8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepReceiptRequest {
    pub step_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStepReceipt {
    pub step_ref: String,
    pub step_hash: String,
    pub model: super::super::ModelId,
    pub retry: ModelStepRetryPolicy,
    pub progression: Option<StepProgression>,
    /// None while an admitted request is running or recovering.
    pub result: Option<ModelStepResult>,
}

/// Submit or resume the caller's own logical step. Successes AND terminal
/// failures are durable; replay neither multiplies retries nor sends a failed
/// request again. The invocation claim only serializes live entries, while
/// the step's own checkpoints recover across process restarts.
pub async fn submit_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ModelStepSubmit,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
) -> MemoryResult<ModelStepReceipt> {
    submit(vault, owner, input, Some((backend, guard)))
        .await?
        .ok_or_else(|| {
            MemoryError::from(Error::InvariantViolation(
                "admitted model step returned no receipt".into(),
            ))
        })
}

/// Resume this owner's frozen saved work before provider admission. A new
/// or Started-only step returns `None`, without a queue lease or model call.
/// Saved terminals, including a still-waiting budget trap, keep their
/// existing receipt path; a consumed trap needs the ordinary admitted path
/// unless an actual response has since been saved.
pub async fn resume_saved_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ModelStepSubmit,
) -> MemoryResult<Option<ModelStepReceipt>> {
    if let Some(receipt) = saved_terminal_as_owner(vault, owner, input)? {
        return Ok(Some(receipt));
    }
    let actor = owner.revalidate(vault)?;
    let id = identity(actor, &input.step_key)?;
    let frozen = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        SUBMISSIONS
            .get(&vault.store, &txn, &id)?
            .filter(|row| row.actor == actor && same_frozen_request(&row.input, input))
            .map(|row| row.input)
    };
    let Some(frozen) = frozen else {
        return Ok(None);
    };
    submit(vault, owner, frozen, None).await
}

async fn submit(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ModelStepSubmit,
    execution: Option<(&dyn LlmBackend, &BudgetGuard)>,
) -> MemoryResult<Option<ModelStepReceipt>> {
    validate(&input)?;
    let actor = owner.revalidate(vault)?;
    let id = identity(actor, &input.step_key)?;
    let digest = input
        .request
        .canonical_hash()
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let invocation = InvocationId::of_run_step(id.as_bytes(), 0);
    let call = super::super::canonical_json_bytes(&input)
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let _claim = match vault.claim_invocation(invocation, *blake3::hash(&call).as_bytes()) {
        InvocationEntry::Claimed(claim) => claim,
        InvocationEntry::Busy(_) => {
            return receipt_as_owner(
                vault,
                owner,
                &ModelStepReceiptRequest {
                    step_key: input.step_key.clone(),
                },
            )
            .map(Some);
        }
        InvocationEntry::Conflict => {
            return Err(MemoryError::bad_request(
                "model-step key is already running another request",
            ));
        }
    };
    let prepared = vault.try_with_write_txn(|txn| -> MemoryResult<_> {
        owner.revalidate_in_txn(vault, txn)?;
        let queue = AttemptQueue::new(vault);
        let mut row = match SUBMISSIONS.get(&vault.store, txn, &id)? {
            Some(row) => {
                // An erased row's request is gone: its key answers erased.
                if row.actor != actor || (!erased(&row) && row.input != input) {
                    return Err(Error::InvalidConfig(
                        "model-step key already names another request or retry policy".into(),
                    )
                    .into());
                }
                row
            }
            None if execution.is_none() => return Ok(None),
            None => {
                let mut row = Submission {
                    actor,
                    input: input.clone(),
                    step_hash: digest,
                    result: None,
                };
                let payload = encode_dreamer_attempt_payload(&DreamerAttemptPayload {
                    attempt_type: MODEL_STEP_ATTEMPT_KIND.into(),
                    input: rmpv::Value::Nil,
                    parent_attempt: None,
                })?;
                queue.enqueue_with_id_in_txn(
                    txn,
                    id,
                    EnqueueAttempt {
                        kind: MODEL_STEP_ATTEMPT_KIND.into(),
                        payload,
                        dedupe_key: None,
                        run_id: Some(hex(id)),
                        now: vault.now_recorded_at(),
                    },
                )?;
                put_submission_in_txn(vault, txn, &id, &mut row)?;
                row
            }
        };
        if terminal_result(vault, txn, &row) {
            return Ok(Some((row, None, None)));
        }
        // Capture the real saved response in THIS writer before taking the
        // same attempt's lease. A miss leaves all queue state untouched.
        let recovery = if execution.is_none() {
            let Some(recovery) =
                super::execute::recovery_in_txn(vault, txn, id, &row.step_hash, &row.input.request)
                    .map_err(super::settled::step_error)?
            else {
                return Ok(None);
            };
            Some(recovery)
        } else {
            None
        };
        // A consumed budget trap's suspension answers no longer: the SAME
        // attempt and step hash resume (FIX 9928).
        if row.result.take().is_some() {
            put_submission_in_txn(vault, txn, &id, &mut row)?;
        }
        // A dropped or interrupted HTTP call may leave its lease. Only this
        // key's live invocation can re-enter, and it resumes the SAME attempt.
        queue.release_lease_in_txn(txn, id, WORKER, vault.now_recorded_at())?;
        let attempt = match queue.claim_id_in_txn(
            txn,
            id,
            ClaimAttempt {
                lease_owner: WORKER.into(),
                now: vault.now_recorded_at(),
            },
        )? {
            ClaimOutcome::Claimed(attempt) => attempt,
            _ => {
                return Err(
                    Error::InvalidConfig("model-step attempt is not runnable".into()).into(),
                );
            }
        };
        Ok(Some((row, Some(attempt), recovery)))
    })?;
    let Some((mut row, attempt, recovery)) = prepared else {
        return Ok(None);
    };
    let Some(attempt) = attempt else {
        if let Some(ModelStepResult::Finished { memoized, .. }) = &mut row.result {
            *memoized = true;
        }
        return view(vault, id, &row).map(Some).map_err(MemoryError::from);
    };
    let context = DurableStepContext {
        vault,
        attempt_id: id,
        run_id: attempt.run_id.clone(),
        envelope_actor: WriteActor::new(actor, EdgeActorClass::Human),
        subject: actor,
        deadline: None,
        now_ms: vault.now_recorded_at().saturating_mul(1000),
    };
    let outcome = if let Some((backend, guard)) = execution {
        super::execute::call_as_step_with_fallbacks_and_retries(
            &context,
            backend,
            guard,
            row.input.request.clone(),
            &FallbackRegistry::standard(),
            usize::from(row.input.retry.max_attempts - 1),
        )
        .await
    } else {
        let recovery = recovery.ok_or_else(|| {
            MemoryError::from(Error::InvariantViolation(
                "saved model step lost its captured recovery".into(),
            ))
        })?;
        super::execute::recover_step(&context, &row.step_hash, &row.input.request, recovery, None)
    };
    row.result = Some(match outcome {
        Ok(StepOutcome::Finished {
            response, memoized, ..
        }) => {
            let claim = step_index_lookup(vault, id, &row.step_hash)?.ok_or(
                Error::InvalidClaimBody("finished model step has no terminal claim"),
            )?;
            let json = if matches!(
                row.input.request.envelope.response_format,
                ResponseFormat::Json { .. }
            ) {
                let text: String = response
                    .message
                    .content
                    .iter()
                    .filter_map(|part| match part {
                        ContentPart::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                Some(
                    serde_json::from_str(&text)
                        .map_err(|error| MemoryError::bad_request(error.to_string()))?,
                )
            } else {
                None
            };
            let fallback_source = FallbackRegistry::source_of(&response);
            ModelStepResult::Finished {
                response,
                json,
                memoized,
                fallback_source,
                claim_ref: claim.to_hex(),
            }
        }
        Ok(StepOutcome::Trapped { trap, .. }) => ModelStepResult::BudgetDenied {
            trap_ref: trap.trap_claim_id.to_hex(),
        },
        // Persistence faults leave the engine's recoverable payload intact;
        // a later submission must be allowed to finish that write path.
        Err(DurableStepError::Engine(error)) => return Err(error.into()),
        Err(DurableStepError::Canonical(error)) => {
            return Err(MemoryError::bad_request(error.to_string()));
        }
        Err(error) => ModelStepResult::Failed {
            failure: failure(error),
        },
    });
    vault.with_write_txn(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let queue = AttemptQueue::new(vault);
        let now = vault.now_recorded_at();
        match row.result.as_ref() {
            Some(ModelStepResult::Finished { .. }) => {
                queue.complete_in_txn(
                    txn,
                    CompleteAttempt {
                        id,
                        lease_owner: WORKER.into(),
                        attempt_count: attempt.attempt_count,
                        now,
                    },
                )?;
            }
            Some(ModelStepResult::Failed { failure }) => {
                queue.fail_in_txn(
                    txn,
                    FailAttempt {
                        id,
                        lease_owner: WORKER.into(),
                        attempt_count: attempt.attempt_count,
                        reason: failure.message.clone(),
                        now,
                    },
                )?;
            }
            _ => {}
        }
        // The attempt settles on the outcome; a terminal claim erased since it
        // logged keeps this copy erased too (FIX 9929).
        put_submission_in_txn(vault, txn, &id, &mut row)?;
        Ok(())
    })?;
    view(vault, id, &row).map(Some).map_err(MemoryError::from)
}

/// The saved terminal of the caller's own step `input` names, read before
/// any fresh provider admission (FIX 8180): a finished or failed step
/// answers as its replay does, with no model, route or meter needed, so a
/// model removed since still answers its completed work. A budget trap
/// still waiting answers too, with no new lease. `None` when the step is
/// new, unfinished, its budget trap was consumed (FIX 9928), or the key
/// froze another request; that call is admitted and submitted as before. The frozen request is matched
/// apart from what admission writes into it from the host's current
/// configuration ([`same_frozen_request`]), so a saved hit never keys on it.
pub fn saved_terminal_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ModelStepSubmit,
) -> MemoryResult<Option<ModelStepReceipt>> {
    validate(input)?;
    let actor = owner.revalidate(vault)?;
    let id = identity(actor, &input.step_key)?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let row = SUBMISSIONS
        .get(&vault.store, &txn, &id)?
        .filter(|row| row.actor == actor && terminal_result(vault, &txn, row));
    drop(txn);
    let Some(mut row) = row.filter(|row| erased(row) || same_frozen_request(&row.input, input))
    else {
        return Ok(None);
    };
    if let Some(ModelStepResult::Finished { memoized, .. }) = &mut row.result {
        *memoized = true;
    }
    view(vault, id, &row).map(Some).map_err(MemoryError::from)
}

/// Whether the row's saved result answers a submission. Finished and Failed
/// are terminal. A budget trap is a suspension (FIX 9928): it answers while
/// its trap is unanswered, or its trap does not read, and gives way once the
/// trap is consumed, so the SAME attempt and step hash resume.
fn terminal_result(vault: &Vault, txn: &heed::RoTxn<'_>, row: &Submission) -> bool {
    match &row.result {
        None => false,
        Some(ModelStepResult::BudgetDenied { trap_ref }) => !EntityId::from_hex(trap_ref)
            .and_then(|trap| super::trap::trap_head_in_txn(vault, txn, &trap))
            .is_ok_and(|(_, head)| head.state == DreamerTrapState::Consumed),
        Some(_) => true,
    }
}

/// Whether `submitted` is the step `frozen` froze, apart from the fields a
/// raw call's admission writes from the host's current configuration: the
/// purpose's default tier, the model's catalog locality, the world it
/// clears, and the host-only keyless stamp.
fn same_frozen_request(frozen: &ModelStepSubmit, submitted: &ModelStepSubmit) -> bool {
    let mut submitted = submitted.clone();
    let envelope = &mut submitted.request.envelope;
    envelope.scope.world = None;
    envelope.tier.purpose_default = frozen.request.envelope.tier.purpose_default.clone();
    envelope.locality = frozen.request.envelope.locality.clone();
    envelope.host_keyless = frozen.request.envelope.host_keyless;
    submitted == *frozen
}

/// Read this owner's persisted receipt without a model backend or new lease.
pub fn receipt_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ModelStepReceiptRequest,
) -> MemoryResult<ModelStepReceipt> {
    let actor = owner.revalidate(vault)?;
    if input.step_key.trim().is_empty() {
        return Err(MemoryError::bad_request("step_key must not be empty"));
    }
    let id = identity(actor, &input.step_key)?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let row = SUBMISSIONS
        .get(&vault.store, &txn, &id)?
        .filter(|row| row.actor == actor)
        .ok_or(Error::EntityNotFound)?;
    drop(txn);
    view(vault, id, &row).map_err(MemoryError::from)
}

pub use crate::model_step_record::ModelStepCheckpoint;

pub(crate) fn resume_checkpoint(
    vault: &Vault,
    id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<Option<ModelStepCheckpoint>> {
    let state = step_state_read(vault, id, step_hash)?;
    let claim_ref = step_index_lookup(vault, id, step_hash)?.map(|id| id.to_hex());
    Ok(match state {
        Some(state) => Some(ModelStepCheckpoint {
            progression: state.progression,
            updated_ms: Some(state.updated_at),
            claim_ref,
        }),
        None => claim_ref.map(|claim_ref| ModelStepCheckpoint {
            progression: StepProgression::Finished,
            updated_ms: None,
            claim_ref: Some(claim_ref),
        }),
    })
}

fn view(vault: &Vault, id: AttemptId, row: &Submission) -> Result<ModelStepReceipt> {
    let progression = match &row.result {
        Some(ModelStepResult::Finished { .. }) => Some(StepProgression::Finished),
        _ => step_state_read(vault, id, &row.step_hash)?.map(|state| state.progression),
    };
    Ok(ModelStepReceipt {
        step_ref: hex(id),
        step_hash: bytes_to_hex_lower(&row.step_hash),
        model: row.input.request.model.clone(),
        retry: row.input.retry,
        progression,
        result: row.result.clone(),
    })
}

fn validate(input: &ModelStepSubmit) -> MemoryResult<()> {
    if input.step_key.trim().is_empty() {
        return Err(MemoryError::bad_request("step_key must not be empty"));
    }
    if input.retry.max_attempts == 0 {
        return Err(MemoryError::bad_request(
            "max_attempts must be at least one",
        ));
    }
    Ok(())
}

fn identity(actor: EntityId, key: &str) -> Result<AttemptId> {
    let mut hash = blake3::Hasher::new_derive_key("oneiron public model step v1");
    hash.update(actor.as_bytes());
    hash.update(key.as_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    // Ordinary attempt ids never enter the owner-retained queue range.
    id[0] &= 0x7f;
    AttemptId::from_bytes(&id)
}

fn hex(id: AttemptId) -> String {
    bytes_to_hex_lower(id.as_bytes())
}

fn failure(error: DurableStepError) -> ModelStepFailure {
    let message = error.to_string();
    let mut out = ModelStepFailure {
        class: ModelStepFailureClass::Engine,
        message,
        llm: None,
        validation_attempts: None,
        validation_errors: Vec::new(),
        spent_usage: None,
    };
    match error {
        DurableStepError::Llm(source) | DurableStepError::ClassifiedLlm { source, .. } => {
            out.class = llm_class(&source);
            out.llm = Some(source);
        }
        DurableStepError::SpentLlm { source, usage } => {
            out.class = llm_class(&source);
            out.llm = Some(source);
            out.spent_usage = Some(*usage);
        }
        DurableStepError::SchemaValidation { attempts, errors } => {
            out.class = ModelStepFailureClass::SchemaValidation;
            out.validation_attempts = Some(attempts);
            out.validation_errors = errors;
        }
        DurableStepError::SpentSchemaValidation {
            attempts,
            errors,
            usage,
        } => {
            out.class = ModelStepFailureClass::SchemaValidation;
            out.validation_attempts = Some(attempts);
            out.validation_errors = errors;
            out.spent_usage = Some(*usage);
        }
        DurableStepError::Fallback(_) => out.class = ModelStepFailureClass::Fallback,
        DurableStepError::SpentFallback { usage, .. } => {
            out.class = ModelStepFailureClass::Fallback;
            out.spent_usage = Some(*usage);
        }
        DurableStepError::FinalizeRefused => out.class = ModelStepFailureClass::FinalizeRefused,
        DurableStepError::SpentFinalizeRefused { usage } => {
            out.class = ModelStepFailureClass::FinalizeRefused;
            out.spent_usage = Some(*usage);
        }
        DurableStepError::DeadlineHardCut => out.class = ModelStepFailureClass::DeadlineHardCut,
        DurableStepError::Engine(_) | DurableStepError::Canonical(_) => {}
    }
    out
}

fn llm_class(error: &LlmError) -> ModelStepFailureClass {
    match error {
        LlmError::Retryable(_) => ModelStepFailureClass::Retryable,
        LlmError::Fatal(_) => ModelStepFailureClass::Fatal,
        LlmError::BudgetDenied(_) => ModelStepFailureClass::BudgetDenied,
    }
}

/// The terminal claim `attempt_id`'s step `step_hash` answers with: the paid
/// generation behind its answer. A re-ask after the step's memo is forgotten
/// answers with a new claim, so a caller tells a paid re-ask from a memo
/// replay by it (FIX 7489).
///
/// # Errors
///
/// Returns an error when the step index cannot be read.
pub(crate) fn step_terminal_claim(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<Option<EntityId>> {
    step_index_lookup(vault, attempt_id, step_hash)
}

/// [`step_terminal_claim`] in the caller's snapshot, so a paid receipt pinned
/// in the same writer names the claim its charge paid for (FIX 7489).
///
/// # Errors
///
/// Returns an error when the step index cannot be read.
pub(crate) fn step_terminal_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<Option<EntityId>> {
    step_index_lookup_in_txn(vault, txn, attempt_id, step_hash)
}
