//! Durable model steps a caller submits over the engine's existing step
//! executor: the vault owner on their proof, or a live run's own actor on
//! its lease (slice 6.5c, primitive D).
use std::collections::HashSet;
use std::time::Duration;

use super::super::{
    BudgetGuard, ContentPart, FallbackRegistry, LlmBackend, LlmError, LlmResponse, ResponseFormat,
};
use super::retry::TransportRetries;
use super::step_claim::{step_index_lookup, step_index_lookup_in_txn};
use super::step_state::step_state_read;
use super::submission_custody::{SUBMISSIONS, Submission, erased, put_submission_in_txn};
use super::{
    DreamerTrapState, DurableStepContext, DurableStepError, StepOutcome, StepProgression,
    StepSpendScope,
};
use crate::agent_def::{AgentDefinition, ensure_listed};
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt, FailAttempt,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DreamerAttemptPayload, decode_dreamer_attempt_payload, encode_dreamer_attempt_payload,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use crate::runtime_hooks::InvocationId;
use crate::runtime_hooks::verb::InvocationEntry;
use crate::task_verb::HostBinding;
use crate::{EdgeActorClass, Vault, WriteActor};

pub use super::media_step::media_step_key;
pub use super::settled::{SettledStepRequest, SettledStepView, settled_step_as_owner};

pub(crate) use crate::model_step_record::MODEL_STEP_ATTEMPT_KIND;
pub use crate::store::model_step_submission::{
    ModelStepFailure, ModelStepFailureClass, ModelStepResult, ModelStepRetryPolicy,
    ModelStepSubmit, StepBudgetRefusal,
};
const WORKER: &str = "model-step-door";

#[doc(hidden)]
pub use oneiron_verb_wire::llm::step::public::{
    ModelStepReceipt, ModelStepReceiptRequest, ModelStepSubmitRequest,
};

/// Submit or resume the caller's own logical step. Successes AND terminal
/// failures are durable; replay neither multiplies retries nor sends a failed
/// request again. The invocation claim only serializes live entries, while
/// the step's own checkpoints recover across process restarts. A send the
/// backend holds unsent while its offer rests for its health spends no
/// declared attempt: the step waits for the offer back up to `rest_wait`, in
/// all (FIX 11226).
pub async fn submit_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ModelStepSubmit,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    rest_wait: Duration,
) -> MemoryResult<ModelStepReceipt> {
    admitted(
        submit(
            vault,
            Submitter::Owner(owner),
            input,
            Some((backend, guard, None, rest_wait)),
        )
        .await?,
    )
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
    resume_saved(vault, Submitter::Owner(owner), input).await
}

/// A live run's own actor at the step doors (slice 6.5c, primitive D). The
/// host that holds the run builds it from the run's registration: the agent
/// the leased try was dispatched as, the lease the host sealed, and the
/// definition the run entered with. Nothing in it comes from the request.
#[derive(Clone, Copy)]
pub struct RunStepCaller<'a> {
    pub actor: WriteActor,
    pub lease: &'a HostBinding,
    pub definition: &'a AgentDefinition,
    /// Whether the host still holds the run attached for this caller, which
    /// the lease alone does not say: a credential that no longer holds ends
    /// it. Asked outside any transaction, before a step is read or prepared
    /// and before the call is answered and its try settled.
    pub attached: &'a (dyn Fn() -> bool + Send + Sync),
}

/// [`submit_as_owner`] for a live run's own actor. The step is kept under
/// the agent and the first try of its run's retry lineage, so a retried try
/// replays it and no other run of the agent shares its key. The lease and
/// the actor are read before the identity, in the preparing writer and in
/// the final writer, and the host's attachment is asked before each writer.
/// The definition's model list holds a fresh call.
///
/// `guard` is the step's logical allowance, as the owner's is. The host
/// books what the step's physical calls spend on the run's spend scope, on
/// its own live lease, so a replay of a saved step, which makes no call,
/// books nothing.
///
/// A send held unsent while its offer rests for its health returns at once
/// here, spending no attempt; [`submit_as_run_actor_on_scope`] takes the
/// wait the host's ladder allows (FIX 11226).
pub async fn submit_as_run_actor(
    vault: &Vault,
    caller: RunStepCaller<'_>,
    input: ModelStepSubmit,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
) -> MemoryResult<ModelStepReceipt> {
    submit_as_run_actor_on_scope(vault, caller, input, backend, guard, None, Duration::ZERO).await
}

/// A run's step on its spend scope's guard, for a typed budget wait. The host
/// read `spend_scope`'s cap generation before it built `guard`
/// ([`StepSpendScope::read_before_guards`]). A send held unsent while its
/// offer rests for its health waits for the offer back up to `rest_wait`, in
/// all, as the owner's does (FIX 11226).
pub async fn submit_as_run_actor_on_scope(
    vault: &Vault,
    caller: RunStepCaller<'_>,
    input: ModelStepSubmit,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    spend_scope: Option<&StepSpendScope>,
    rest_wait: Duration,
) -> MemoryResult<ModelStepReceipt> {
    let execution = Some((backend, guard, spend_scope.cloned(), rest_wait));
    admitted(submit(vault, Submitter::Run(caller), input, execution).await?)
}

/// [`resume_saved_as_owner`] for a live run's own actor.
pub async fn resume_saved_as_run_actor(
    vault: &Vault,
    caller: RunStepCaller<'_>,
    input: &ModelStepSubmit,
) -> MemoryResult<Option<ModelStepReceipt>> {
    resume_saved(vault, Submitter::Run(caller), input).await
}

/// [`receipt_as_owner`] for a live run's own actor: the receipt of a step
/// its own run submitted, and no other's.
pub fn receipt_as_run_actor(
    vault: &Vault,
    caller: RunStepCaller<'_>,
    input: &ModelStepReceiptRequest,
) -> MemoryResult<ModelStepReceipt> {
    receipt(vault, Submitter::Run(caller), input)
}

/// Who submits a step: the vault owner on their proof, or a live run's own
/// actor on its lease.
#[derive(Clone, Copy)]
enum Submitter<'a> {
    Owner(&'a AuthenticatedOwner),
    Run(RunStepCaller<'a>),
}

/// What a submitter's check answers in one snapshot: the actor the step is
/// kept under, and the step's identity.
struct Standing {
    actor: WriteActor,
    id: AttemptId,
}

impl Submitter<'_> {
    /// Refuses a run its host no longer holds attached. Asked outside any
    /// transaction: the host's answer reads the vault itself.
    fn attached(&self) -> MemoryResult<()> {
        match self {
            Self::Run(caller) if !(caller.attached)() => Err(not_the_runs_actor()),
            _ => Ok(()),
        }
    }

    /// [`Self::standing_in_txn`] in its own read transaction.
    fn standing(&self, vault: &Vault, step_key: &str) -> MemoryResult<Standing> {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        self.standing_in_txn(vault, &txn, step_key)
    }

    /// The submitter's standing in `txn` for the step `step_key` names, or
    /// its refusal: the owner's proof, or the run's lease under its own
    /// actor.
    fn standing_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        step_key: &str,
    ) -> MemoryResult<Standing> {
        match self {
            Self::Owner(owner) => {
                let actor = owner.revalidate_in_txn(vault, txn)?;
                Ok(Standing {
                    actor: WriteActor::new(actor, EdgeActorClass::Human),
                    id: identity(actor, step_key)?,
                })
            }
            Self::Run(caller) => {
                let record =
                    run_lease_in_txn(vault, txn, *caller)?.ok_or_else(not_the_runs_actor)?;
                let launch = first_try_in_txn(vault, txn, &record)?;
                Ok(Standing {
                    actor: caller.actor,
                    id: run_identity(caller.actor.entity_ref(), launch, step_key)?,
                })
            }
        }
    }

    /// Whether the submitter still stands in `txn`, the writer's own
    /// snapshot.
    fn revalidate_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        match self {
            Self::Owner(owner) => owner.revalidate_in_txn(vault, txn).map(drop)?,
            Self::Run(caller) => {
                run_lease_in_txn(vault, txn, *caller)?.ok_or_else(not_the_runs_actor)?;
            }
        }
        Ok(())
    }
}

/// The try `caller`'s lease sealed, read in `txn`, while the lease holds
/// and the try is `caller`'s own agent dispatch. `None` otherwise: one
/// answer for a lapsed lease and for another actor's run.
fn run_lease_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: RunStepCaller<'_>,
) -> Result<Option<AttemptRecord>> {
    Ok(caller
        .lease
        .leased_record_in_txn(vault, txn)?
        .filter(|record| {
            decode_dreamer_attempt_payload(&record.payload)
                .ok()
                .filter(|payload| payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE)
                .and_then(|payload| decode_agent_dispatch_input(&payload.input).ok())
                .and_then(|input| agent_dispatch_actor(&input).ok())
                == Some(caller.actor)
        }))
}

/// The first try of `record`'s retry lineage: the launch every retry of it
/// stands for, as its spend scope does.
fn first_try_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> Result<AttemptId> {
    let queue = AttemptQueue::new(vault);
    let mut seen = HashSet::from([record.id]);
    let (mut first, mut earlier) = (record.id, record.retry_of);
    while let Some(previous) = earlier {
        if !seen.insert(previous) {
            return Err(Error::InvariantViolation(
                "model step retry lineage cycle".into(),
            ));
        }
        first = previous;
        earlier = queue
            .get_in_txn(txn, previous)?
            .and_then(|row| row.retry_of);
    }
    Ok(first)
}

fn not_the_runs_actor() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "a run's model step needs the run's own actor on its live lease",
        &["Submit from the agent run that still holds its try's lease and its attachment."],
    )
}

fn admitted(receipt: Option<ModelStepReceipt>) -> MemoryResult<ModelStepReceipt> {
    receipt.ok_or_else(|| {
        MemoryError::from(Error::InvariantViolation(
            "admitted model step returned no receipt".into(),
        ))
    })
}

async fn resume_saved(
    vault: &Vault,
    submitter: Submitter<'_>,
    input: &ModelStepSubmit,
) -> MemoryResult<Option<ModelStepReceipt>> {
    if let Some(receipt) = saved_terminal(vault, submitter, input)? {
        return Ok(Some(receipt));
    }
    let Standing { actor, id } = submitter.standing(vault, &input.step_key)?;
    let frozen = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        SUBMISSIONS
            .get(&vault.store, &txn, &id)?
            .filter(|row| row.actor == actor.entity_ref() && same_frozen_request(&row.input, input))
            .map(|row| row.input)
    };
    let Some(frozen) = frozen else {
        return Ok(None);
    };
    submit(vault, submitter, frozen, None).await
}

async fn submit(
    vault: &Vault,
    submitter: Submitter<'_>,
    input: ModelStepSubmit,
    execution: Option<(
        &dyn LlmBackend,
        &BudgetGuard,
        Option<StepSpendScope>,
        Duration,
    )>,
) -> MemoryResult<Option<ModelStepReceipt>> {
    validate(&input)?;
    submitter.attached()?;
    let standing = submitter.standing(vault, &input.step_key)?;
    let (actor, id) = (standing.actor.entity_ref(), standing.id);
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
            return receipt(
                vault,
                submitter,
                &ModelStepReceiptRequest {
                    live_run: None,
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
        submitter.revalidate_in_txn(vault, txn)?;
        let queue = AttemptQueue::new(vault);
        let mut row = match SUBMISSIONS.get(&vault.store, txn, &id)? {
            Some(mut row) => {
                // An erased row's request is gone: its key answers erased.
                if row.actor != actor
                    || (!erased(&row) && !same_apart_from_host_stamps(&row.input, &input))
                {
                    return Err(Error::InvalidConfig(
                        "model-step key already names another request or retry policy".into(),
                    )
                    .into());
                }
                // The saved row never keeps the host-only stamps (serde skips
                // them): this admission's fresh attestation rides the resumed
                // request, so a paid on-device step resumes on its paid line
                // (FIX 18407).
                let envelope = &mut row.input.request.envelope;
                envelope.host_keyless = input.request.envelope.host_keyless;
                envelope.host_paid = input.request.envelope.host_paid;
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
        // A fresh call is held to the run's model list. Saved work answered
        // above without it, as a model removed since does (FIX 8180), and a
        // refusal here leaves nothing written.
        if let (Submitter::Run(caller), Some(_)) = (&submitter, &execution) {
            ensure_listed(caller.definition, &input.request.model)?;
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
    let spend_scope = execution
        .as_ref()
        .and_then(|(_, _, scope, _)| scope.clone());
    let context = DurableStepContext {
        vault,
        attempt_id: id,
        run_id: attempt.run_id.clone(),
        envelope_actor: standing.actor,
        subject: actor,
        deadline: None,
        now_ms: vault.now_recorded_at().saturating_mul(1000),
        spend_scope,
        wake_pass_bound: false,
    };
    let outcome = if let Some((backend, guard, _, rest_wait)) = execution {
        super::execute::call_as_step_with_fallbacks_and_retries(
            &context,
            backend,
            guard,
            row.input.request.clone(),
            &FallbackRegistry::standard(),
            TransportRetries {
                max: usize::from(row.input.retry.max_attempts - 1),
                rest_wait,
            },
        )
        .await
    } else {
        let recovery = recovery.ok_or_else(|| {
            MemoryError::from(Error::InvariantViolation(
                "saved model step lost its captured recovery".into(),
            ))
        })?;
        super::execute::recover_step(&context, &row.input.request, recovery, None)
    };
    row.result = Some(step_result(vault, id, &row, outcome)?);
    // A run its host let go, or whose lease lapsed, while the call ran gets
    // no answer, and its try is not settled under a standing it no longer
    // has. An answer the provider gave is already kept by the durable step
    // (its checkpoint and terminal claim: a paid call is never asked twice),
    // so the key's next call from the run's own standing actor resumes the
    // same attempt and replays that answer with no model call.
    submitter.attached()?;
    vault.try_with_write_txn(|txn| -> MemoryResult<()> {
        submitter.revalidate_in_txn(vault, txn)?;
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
                // A typed budget refusal settles on the step's own row beside
                // its text, so its run tree and receipt read it typed.
                queue.fail_with_refusal_in_txn(
                    txn,
                    FailAttempt {
                        id,
                        lease_owner: WORKER.into(),
                        attempt_count: attempt.attempt_count,
                        reason: failure.message.clone(),
                        now,
                    },
                    failure.budget_refusal.clone(),
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

/// The result a step's outcome is saved as. A persistence fault is no
/// result: it leaves the engine's recoverable payload intact, and a later
/// submission must be allowed to finish that write path.
fn step_result(
    vault: &Vault,
    id: AttemptId,
    row: &Submission,
    outcome: std::result::Result<StepOutcome, DurableStepError>,
) -> MemoryResult<ModelStepResult> {
    Ok(match outcome {
        Ok(StepOutcome::Finished {
            response, memoized, ..
        }) => {
            let claim = step_index_lookup(vault, id, &row.step_hash)?.ok_or(
                Error::InvalidClaimBody("finished model step has no terminal claim"),
            )?;
            let json = response_json(row, &response)?;
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
        Err(DurableStepError::Engine(error)) => return Err(error.into()),
        Err(DurableStepError::Canonical(error)) => {
            return Err(MemoryError::bad_request(error.to_string()));
        }
        Err(error) => ModelStepResult::Failed {
            failure: failure(error),
        },
    })
}

/// The parsed JSON of a response whose request asked for JSON.
fn response_json(
    row: &Submission,
    response: &LlmResponse,
) -> MemoryResult<Option<serde_json::Value>> {
    if !matches!(
        row.input.request.envelope.response_format,
        ResponseFormat::Json { .. }
    ) {
        return Ok(None);
    }
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|error| MemoryError::bad_request(error.to_string()))
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
    saved_terminal(vault, Submitter::Owner(owner), input)
}

fn saved_terminal(
    vault: &Vault,
    submitter: Submitter<'_>,
    input: &ModelStepSubmit,
) -> MemoryResult<Option<ModelStepReceipt>> {
    validate(input)?;
    submitter.attached()?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let Standing { actor, id } = submitter.standing_in_txn(vault, &txn, &input.step_key)?;
    let row = SUBMISSIONS
        .get(&vault.store, &txn, &id)?
        .filter(|row| row.actor == actor.entity_ref() && terminal_result(vault, &txn, row));
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
/// clears, and the host-only keyless and paid stamps.
fn same_frozen_request(frozen: &ModelStepSubmit, submitted: &ModelStepSubmit) -> bool {
    let mut submitted = submitted.clone();
    let envelope = &mut submitted.request.envelope;
    envelope.scope.world = None;
    envelope.tier.purpose_default = frozen.request.envelope.tier.purpose_default.clone();
    envelope.locality = frozen.request.envelope.locality.clone();
    envelope.host_keyless = frozen.request.envelope.host_keyless;
    envelope.host_paid = frozen.request.envelope.host_paid;
    submitted == *frozen
}

/// Whether `saved`, a submission read back from its row, and `submitted`
/// are one request apart from the host-only keyless and paid stamps, which
/// the row never keeps and each admission attests afresh (FIX 18407).
fn same_apart_from_host_stamps(saved: &ModelStepSubmit, submitted: &ModelStepSubmit) -> bool {
    let mut submitted = submitted.clone();
    let envelope = &mut submitted.request.envelope;
    envelope.host_keyless = saved.request.envelope.host_keyless;
    envelope.host_paid = saved.request.envelope.host_paid;
    submitted == *saved
}

/// Read this owner's persisted receipt without a model backend or new lease.
pub fn receipt_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ModelStepReceiptRequest,
) -> MemoryResult<ModelStepReceipt> {
    receipt(vault, Submitter::Owner(owner), input)
}

fn receipt(
    vault: &Vault,
    submitter: Submitter<'_>,
    input: &ModelStepReceiptRequest,
) -> MemoryResult<ModelStepReceipt> {
    submitter.attached()?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    // The submitter is checked before the key is judged, as before.
    let Standing { actor, id } = submitter.standing_in_txn(vault, &txn, &input.step_key)?;
    if input.step_key.trim().is_empty() {
        return Err(MemoryError::bad_request("step_key must not be empty"));
    }
    let row = SUBMISSIONS
        .get(&vault.store, &txn, &id)?
        .filter(|row| row.actor == actor.entity_ref())
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

/// A run's step: the agent, the first try of its run's retry lineage and
/// the key, under a domain of their own, so no owner step and no other
/// run's step shares the id. The two ids are fixed-width, so the key's
/// bytes begin at one place.
fn run_identity(actor: EntityId, launch: AttemptId, key: &str) -> Result<AttemptId> {
    let mut hash = blake3::Hasher::new_derive_key("oneiron run model step v1");
    hash.update(actor.as_bytes());
    hash.update(launch.as_bytes());
    hash.update(key.as_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
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
        budget_refusal: None,
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
        DurableStepError::BudgetRefused(refusal) => {
            out.class = ModelStepFailureClass::BudgetRefused;
            out.budget_refusal = Some(refusal);
        }
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
