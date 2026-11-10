//! Model steps on the owner's proof, or on a live run's own actor (slice
//! 6.5c); HTTP, SDK and MCP reach the same typed door.
//! Saved terminals and response checkpoints answer before fresh provider admission.
use std::sync::Arc;

use axum::response::Response;
use oneiron::agent_def::AgentDefinition;
use oneiron::llm::model_step::{
    self, ModelStepReceipt, ModelStepReceiptRequest, ModelStepResult, ModelStepSubmit,
    ModelStepSubmitRequest, RunStepCaller,
};
use oneiron::llm::run_admission::{RunAdmission, WorkPhysical};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError,
    MemoryResult,
};
use oneiron::task_verb::HostBinding;
use oneiron::{
    BudgetGuard, BudgetLease, EdgeActorClass, EntityId, FatalLlmError, LlmBackend, LlmCapability,
    LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId, WriteActor,
};

use super::facade_actor;
use super::host_doors::support::{Listed, internal, owner_proof};
use super::live_run_doors::hold_live_run;
use crate::auth::CoreAuth;
use crate::mcp::ScopeMeter;
use crate::models::OfferLadder;
use crate::server::{HeldLiveRun, SyncServer};

/// The run a scoped run's physical step call is admitted in.
const MODEL_STEP_RUN: &str = "model-step";

/// `model_step_caller`, the pre-check of `ai.steps.submit` and
/// `ai.steps.receipt`: the vault owner on their proof, or an agent on its
/// own verified credential that still reads. The door then holds the live
/// run an agent's call names; an agent that names none meets the owner's
/// check there.
pub(in crate::api::facade) fn step_caller_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    let refusal = match owner_proof(auth, server, verb) {
        Ok(_) => return Ok(()),
        Err(refusal) => refusal,
    };
    let agent =
        facade_actor(server, auth).is_ok_and(|(_, class)| class == EdgeActorClass::Agent);
    let reads = auth.verified_slip().is_some_and(|slip| {
        server
            .vault()
            .credential_read_key(slip)
            .is_ok_and(|key| key.is_some())
    });
    if agent && reads { Ok(()) } else { Err(refusal) }
}

pub(crate) async fn ai_steps_submit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    input: ModelStepSubmitRequest,
) -> Listed<ModelStepReceipt> {
    let (live_run, mut input) = input.into_parts();
    let answer = match live_run {
        None => submit(server, auth, &mut input).await,
        Some(handle) => submit_on_run(server, auth, session, &handle, input).await,
    };
    listed(answer)
}

async fn submit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: &mut ModelStepSubmit,
) -> MemoryResult<ModelStepReceipt> {
    let owner = owner_proof(auth, server, "ai.steps.submit")?;
    // Saved terminals and actual response checkpoints need no new model,
    // route or meter (FIX 8180/8512). A miss or unavailable lookup keeps
    // the admitted path below unchanged.
    let saved = {
        let (server, owner, probe) = (Arc::clone(server), owner.clone(), input.clone());
        let runtime = tokio::runtime::Handle::current();
        super::clock_ingress::run_blocking(move || {
            runtime.block_on(model_step::resume_saved_as_owner(
                server.vault(),
                &owner,
                &probe,
            ))
        })
        .await
    };
    if let Ok(Ok(Some(receipt))) = saved {
        return Ok(receipt);
    }
    // Identical owner, inference policy, route-selector refusal, configured
    // model binding, and physical-call meter as the raw inference sibling.
    let (ladder, run) =
        crate::api::llm::admit(server, auth, &mut input.request).map_err(inference_refusal)?;
    let run = exact_step_run(&ladder, run, input)?;
    let guard = raw_step_guard(server)?;
    let backend = StepBackend { ladder, run };
    let runtime = tokio::runtime::Handle::current();
    let server = Arc::clone(server);
    let input = input.clone();
    super::clock_ingress::run_blocking(move || {
        runtime.block_on(model_step::submit_as_owner(
            server.vault(),
            &owner,
            input,
            &backend,
            &guard,
        ))
    })
    .await
    .map_err(|_| internal("ai.steps.submit"))?
}

/// The run's own actor (slice 6.5c): `handle` names the live run the
/// caller's credential attached. The run stays held for the whole call, as
/// it does for an attached model call, and the engine keeps the step under
/// the run's actor, its lease, its definition's model list and its spend
/// scope.
async fn submit_on_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    handle: &str,
    mut input: ModelStepSubmit,
) -> MemoryResult<ModelStepReceipt> {
    let (actor, _run, held) = hold_live_run(server, auth, session, handle).await?;
    let parts = RunStepParts::of(actor, &held);
    // Saved work answers with no new model, route or meter, as the owner's
    // does. The same read names the scope a fresh call spends under.
    let (saved, scope) = {
        let (server, parts, probe) = (Arc::clone(server), parts.clone(), input.clone());
        let runtime = tokio::runtime::Handle::current();
        super::clock_ingress::run_blocking(move || {
            let saved = runtime.block_on(model_step::resume_saved_as_run_actor(
                server.vault(),
                parts.caller(),
                &probe,
            ));
            let scope = model_step::run_step_spend_scope(server.vault(), parts.caller());
            (saved, scope)
        })
        .await
        .map_err(|_| internal("ai.steps.submit"))?
    };
    if let Ok(Some(receipt)) = saved {
        return still_attached(server, auth, &held).map(|()| receipt);
    }
    let scope = scope?;
    // The vault's inference policy for the model the step names, and its
    // route. The caller was admitted above as the run's own actor.
    let (ladder, raw_run) = crate::api::llm::admit_live_run(server, &mut input.request)
        .map_err(inference_refusal)?;
    let (run, unscoped_guard) = match &scope {
        // The physical call goes out on a line this scope bounds and its
        // payer funds. The engine books the scope once, from the step's own
        // guard, so this line carries no booking of its own. A scope whose
        // line does not open never falls back to the host's line.
        Some(scope) => {
            let meter = ScopeMeter::open(server.vault(), scope).map_err(|_| {
                MemoryError::bad_request("the attached run's spend line did not open")
            })?;
            let run = server.ai.model_runtime().funded_run(
                MODEL_STEP_RUN,
                meter.guard.clone(),
                meter.payer,
            );
            (run, meter.guard)
        }
        // A run with no scope steps on the raw routes' meter, as the owner
        // does.
        None => (raw_run, raw_step_guard(server)?),
    };
    let run = exact_step_run(&ladder, run, &mut input)?;
    let backend = StepBackend { ladder, run };
    let receipt = {
        let (server, parts) = (Arc::clone(server), parts.clone());
        let runtime = tokio::runtime::Handle::current();
        super::clock_ingress::run_blocking(move || {
            runtime.block_on(model_step::submit_as_run_actor(
                server.vault(),
                parts.caller(),
                input,
                &backend,
                &unscoped_guard,
            ))
        })
        .await
        .map_err(|_| internal("ai.steps.submit"))??
    };
    still_attached(server, auth, &held).map(|()| receipt)
}

pub(crate) async fn ai_steps_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    input: ModelStepReceiptRequest,
) -> Listed<ModelStepReceipt> {
    let answer = match input.live_run.clone() {
        None => receipt(server, auth, input).await,
        Some(handle) => receipt_on_run(server, auth, session, &handle, input).await,
    };
    listed(answer)
}

async fn receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStepReceiptRequest,
) -> MemoryResult<ModelStepReceipt> {
    let owner = owner_proof(auth, server, "ai.steps.receipt")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        model_step::receipt_as_owner(server.vault(), &owner, &input)
    })
    .await
    .unwrap_or_else(|_| Err(internal("ai.steps.receipt")))
}

/// The receipt of a step the caller's own held run submitted.
async fn receipt_on_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    handle: &str,
    input: ModelStepReceiptRequest,
) -> MemoryResult<ModelStepReceipt> {
    let (actor, _run, held) = hold_live_run(server, auth, session, handle).await?;
    let parts = RunStepParts::of(actor, &held);
    let vault_server = Arc::clone(server);
    let receipt = super::clock_ingress::run_blocking(move || {
        model_step::receipt_as_run_actor(vault_server.vault(), parts.caller(), &input)
    })
    .await
    .map_err(|_| internal("ai.steps.receipt"))??;
    still_attached(server, auth, &held).map(|()| receipt)
}

/// What a step call names of the live run it holds, owned so a blocking
/// task can carry it while the door keeps the run held.
#[derive(Clone)]
struct RunStepParts {
    actor: WriteActor,
    proof: HostBinding,
    definition: Arc<AgentDefinition>,
}

impl RunStepParts {
    fn of(actor: WriteActor, held: &HeldLiveRun) -> Self {
        Self {
            actor,
            proof: held.proof(),
            definition: Arc::new(held.definition().clone()),
        }
    }

    fn caller(&self) -> RunStepCaller<'_> {
        RunStepCaller {
            actor: self.actor,
            lease: &self.proof,
            definition: &self.definition,
        }
    }
}

/// Refuses an answer to an attachment that no longer stands: the lease, the
/// binding or the credential's read key went while the call ran.
fn still_attached(server: &SyncServer, auth: &CoreAuth, held: &HeldLiveRun) -> MemoryResult<()> {
    let stands = match auth.verified_slip() {
        Some(credential) => held.attachment_stands(server, credential)?,
        None => false,
    };
    if stands {
        return Ok(());
    }
    Err(MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "the live-run credential or lease no longer holds",
        &[],
    ))
}

fn inference_refusal(response: Box<Response>) -> MemoryError {
    let code = match response.status().as_u16() {
        401 | 403 => MEMORY_CODE_FORBIDDEN,
        503 => MEMORY_CODE_MODEL_UNAVAILABLE,
        _ => MEMORY_CODE_BAD_REQUEST,
    };
    MemoryError::new(
        code,
        "the inference door refused this model-step request",
        &[],
    )
}

/// Holds a step to one exact configured model, stamps its request with what
/// its ladder attests, and names the run's physical work.
fn exact_step_run(
    ladder: &OfferLadder,
    run: RunAdmission,
    input: &mut ModelStepSubmit,
) -> MemoryResult<RunAdmission> {
    if ladder.exact_prompt().is_none() {
        return Err(MemoryError::bad_request(
            "a durable model step names one exact configured model, not a multi-offer seat",
        ));
    }
    // FIX 10592: the durable step below admits on this request, so it carries
    // whether its ladder may only serve free keyless own-server work.
    // Unstamped stays paid. FIX 18407: it also carries whether a rung is paid
    // work, so a paid on-device step reserves on the step's own budget line.
    input.request.envelope.host_keyless = ladder.all_keyless_own_server();
    input.request.envelope.host_paid = !ladder.all_free_work();
    let mut context = run.work_context();
    // A free on-device step is free work too, as physical_for says.
    context.physical = if ladder.all_free_work() {
        WorkPhysical::KeylessOwnServer
    } else {
        WorkPhysical::Paid
    };
    Ok(run.with_work_context(context))
}

/// The logical allowance of a step on the raw routes' meter.
fn raw_step_guard(server: &SyncServer) -> MemoryResult<BudgetGuard> {
    let meter = server
        .llm
        .as_ref()
        .ok_or_else(|| internal("ai.steps.submit"))?
        .meter();
    let read = meter.read();
    // This logical-step allowance is bounded by the host's remaining raw
    // allowance. Physical calls still reserve and settle on the shared run
    // meter, so the engine's logical lease does not charge that meter twice.
    // An uncapped raw meter leaves the step uncapped, its limit the type's
    // maximum, so every read of it reports no cap (FIX 10593).
    Ok(BudgetGuard::with_reserve_units(
        "model-step",
        read.capped_remaining_units().unwrap_or(u64::MAX),
        meter.reserve_units(),
        read.on_budget_exhausted,
    ))
}

fn listed(answer: MemoryResult<ModelStepReceipt>) -> Listed<ModelStepReceipt> {
    let refs = match answer
        .as_ref()
        .ok()
        .and_then(|receipt| receipt.result.as_ref())
    {
        Some(ModelStepResult::Finished { claim_ref, .. }) => {
            EntityId::from_hex(claim_ref).ok().into_iter().collect()
        }
        Some(ModelStepResult::BudgetDenied { trap_ref }) => {
            EntityId::from_hex(trap_ref).ok().into_iter().collect()
        }
        _ => Vec::new(),
    };
    (answer, refs)
}

/// A single gated provider attempt. Only the engine step layer retries it.
struct StepBackend {
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
}

impl LlmBackend for StepBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.ladder.supports(model, &capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(self.ladder.generate_step_attempt(&self.run, request))
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}
