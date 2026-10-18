//! Owner-submitted durable model steps over the engine's existing step executor.
use serde::{Deserialize, Serialize};

use super::super::{
    BudgetGuard, ContentPart, FallbackRegistry, FatalLlmError, LlmBackend, LlmError, LlmRequest,
    LlmResponse, LlmUsage, ResponseFormat,
};
use super::step_claim::step_index_lookup;
use super::step_state::step_state_read;
use super::{
    DREAMER_STEP_RETRY_BACKOFF_MS, DurableStepContext, DurableStepError, StepOutcome,
    StepProgression,
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
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, Vault, WriteActor};

pub use super::settled::{SettledStepRequest, SettledStepView, settled_step_as_owner};

pub(crate) const MODEL_STEP_ATTEMPT_KIND: &str = "model-step";
const WORKER: &str = "model-step-door";
const SUBMISSIONS: SideTable<AttemptId, Submission, Named> =
    SideTable::new(&side_table::MODEL_STEP_SUBMISSION);

/// Transport attempts per model request, including the first send. Schema
/// corrections remain the existing one/native or three/shim paid calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepRetryPolicy {
    pub max_attempts: u8,
}

impl Default for ModelStepRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: (DREAMER_STEP_RETRY_BACKOFF_MS.len() + 1) as u8,
        }
    }
}

/// A caller-owned stable key freezes one exact request and its retry policy.
/// The envelope's CallClass declares the deterministic fallback, if any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepSubmit {
    pub step_key: String,
    pub request: LlmRequest,
    #[serde(default)]
    pub retry: ModelStepRetryPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepReceiptRequest {
    pub step_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelStepFailureClass {
    Retryable,
    Fatal,
    BudgetDenied,
    SchemaValidation,
    Fallback,
    FinalizeRefused,
    DeadlineHardCut,
    Engine,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStepFailure {
    pub class: ModelStepFailureClass,
    pub message: String,
    pub llm: Option<LlmError>,
    pub validation_attempts: Option<u8>,
    pub validation_errors: Vec<String>,
    pub spent_usage: Option<LlmUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ModelStepResult {
    Finished {
        response: LlmResponse,
        /// Present only for ResponseFormat::Json, parsed after the engine's validation.
        json: Option<serde_json::Value>,
        memoized: bool,
        fallback_source: Option<FatalLlmError>,
        claim_ref: String,
    },
    Failed {
        failure: ModelStepFailure,
    },
    /// The existing step executor parked this attempt on its budget trap.
    BudgetDenied {
        trap_ref: String,
    },
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Submission {
    actor: EntityId,
    input: ModelStepSubmit,
    step_hash: [u8; 32],
    result: Option<ModelStepResult>,
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
            );
        }
        InvocationEntry::Conflict => {
            return Err(MemoryError::bad_request(
                "model-step key is already running another request",
            ));
        }
    };
    let (mut row, attempt) = vault.with_write_txn(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let queue = AttemptQueue::new(vault);
        let row = match SUBMISSIONS.get(&vault.store, txn, &id)? {
            Some(row) => {
                if row.actor != actor || row.input != input {
                    return Err(Error::InvalidConfig(
                        "model-step key already names another request or retry policy".into(),
                    ));
                }
                row
            }
            None => {
                let row = Submission {
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
                SUBMISSIONS.put(vault, txn, &id, &row)?;
                row
            }
        };
        if row.result.is_some() {
            return Ok((row, None));
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
                return Err(Error::InvalidConfig(
                    "model-step attempt is not runnable".into(),
                ));
            }
        };
        Ok((row, Some(attempt)))
    })?;
    let Some(attempt) = attempt else {
        if let Some(ModelStepResult::Finished { memoized, .. }) = &mut row.result {
            *memoized = true;
        }
        return view(vault, id, &row).map_err(MemoryError::from);
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
    let outcome = super::execute::call_as_step_with_fallbacks_and_retries(
        &context,
        backend,
        guard,
        row.input.request.clone(),
        &FallbackRegistry::standard(),
        usize::from(row.input.retry.max_attempts - 1),
    )
    .await;
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
        SUBMISSIONS.put(vault, txn, &id, &row)?;
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
        Ok(())
    })?;
    view(vault, id, &row).map_err(MemoryError::from)
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

/// Payload-free projection of the existing live checkpoint or terminal step claim.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStepCheckpoint {
    pub progression: StepProgression,
    /// The live row is retired at completion; its timestamp is then absent.
    pub updated_ms: Option<u64>,
    pub claim_ref: Option<String>,
}

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
    if input.retry.max_attempts == 0
        || usize::from(input.retry.max_attempts) > DREAMER_STEP_RETRY_BACKOFF_MS.len() + 1
    {
        return Err(MemoryError::bad_request(
            "max_attempts must select a nonempty prefix of the engine retry schedule",
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
