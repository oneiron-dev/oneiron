//! Model steps on the owner's proof, or on a live run's own actor (slice
//! 6.5c); HTTP, SDK and MCP reach the same typed door.
//! Saved terminals and response checkpoints answer before fresh provider admission.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::response::Response;
use oneiron::agent_dispatch::AgentDispatcher;
use oneiron::llm::model_step::{
    self, ModelStepReceipt, ModelStepReceiptRequest, ModelStepResult, ModelStepSubmit,
    ModelStepSubmitRequest, RunStepCaller,
};
use oneiron::llm::run_admission::{RunAdmission, WorkPhysical};
use oneiron::llm::{BudgetDenied, StepSpendScope};
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
use crate::ai_host::live_lease::{LeaseLine, LiveLease};
use crate::ai_host::payer_funding::{attempt_grant_funding, scope_run_funding};
use crate::auth::CoreAuth;
use crate::models::OfferLadder;
use crate::server::{HeldLiveRun, SyncServer};

/// The run a live run's own physical step calls are admitted in, on its
/// scope's meter or its Grant's wallet.
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
    let agent = facade_actor(server, auth).is_ok_and(|(_, class)| class == EdgeActorClass::Agent);
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
    // A send held unsent while its offer rests for its health spends no
    // attempt; the step waits for the offer as any call does (FIX 11226).
    let rest_wait = ladder.step_rest_wait();
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
            rest_wait,
        ))
    })
    .await
    .map_err(|_| internal("ai.steps.submit"))?
}

/// The run's own actor (slice 6.5c): `handle` names the live run the
/// caller's credential attached. The engine keeps the step under the run's
/// actor, its lease and its definition's model list; this host admits its
/// physical calls on the run's own spend line.
async fn submit_on_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    handle: &str,
    input: ModelStepSubmit,
) -> MemoryResult<ModelStepReceipt> {
    let step = RunStep::hold(server, auth, session, handle).await?;
    let runtime = tokio::runtime::Handle::current();
    super::clock_ingress::run_blocking(move || step.submit(&runtime, input))
        .await
        .map_err(|_| internal("ai.steps.submit"))?
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
    let step = RunStep::hold(server, auth, session, handle).await?;
    super::clock_ingress::run_blocking(move || step.receipt(&input))
        .await
        .map_err(|_| internal("ai.steps.receipt"))?
}

/// A held live run at the step doors. The blocking task that serves the
/// call owns it, so the run stays held until the step and all its writes
/// finish, whether or not the caller still waits (as `on_live_run` keeps
/// it).
struct RunStep {
    server: Arc<SyncServer>,
    held: HeldLiveRun,
    actor: WriteActor,
    proof: HostBinding,
    /// Whether the attachment the call came in on still stands. Once it
    /// answers no it answers no for the rest of the call.
    attached: Box<dyn Fn() -> bool + Send + Sync>,
}

/// What a run's fresh step call goes out on.
struct StepLine {
    /// The run its physical calls are admitted in.
    run: RunAdmission,
    /// The step's logical allowance.
    guard: BudgetGuard,
    /// The live lease of the physical calls' meter on the run's scope.
    lease: Option<LeaseLine>,
    /// The run's scope, with the cap generation read before the meter and
    /// the guard read their room.
    spend: Option<StepSpendScope>,
}

impl RunStep {
    /// Holds the live run `handle` names on the caller's own credential.
    async fn hold(
        server: &Arc<SyncServer>,
        auth: &CoreAuth,
        session: Option<EntityId>,
        handle: &str,
    ) -> MemoryResult<Self> {
        let (actor, _run, held) = hold_live_run(server, auth, session, handle).await?;
        let credential = auth.verified_slip().cloned().ok_or_else(detached)?;
        let watch = held.attachment_watch(server, credential);
        // A watch that answered no once, a failed read included, stays no:
        // a call the host stopped saves no result on a later yes.
        let lost = AtomicBool::new(false);
        let attached = move || {
            if lost.load(Ordering::Relaxed) {
                return false;
            }
            let stands = watch();
            if !stands {
                lost.store(true, Ordering::Relaxed);
            }
            stands
        };
        Ok(Self {
            attached: Box::new(attached),
            proof: held.proof(),
            server: Arc::clone(server),
            held,
            actor,
        })
    }

    /// The run's own actor as the engine checks it: nothing in it comes
    /// from the request.
    fn caller(&self) -> RunStepCaller<'_> {
        RunStepCaller {
            actor: self.actor,
            lease: &self.proof,
            definition: self.held.definition(),
            attached: self.attached.as_ref(),
        }
    }

    fn submit(
        &self,
        runtime: &tokio::runtime::Handle,
        mut input: ModelStepSubmit,
    ) -> MemoryResult<ModelStepReceipt> {
        let vault = self.server.vault();
        // Saved work answers with no new model, route or meter, as the
        // owner's does. A miss or unavailable lookup keeps the admitted path.
        let saved = runtime.block_on(model_step::resume_saved_as_run_actor(
            vault,
            self.caller(),
            &input,
        ));
        if let Ok(Some(receipt)) = saved {
            // A saved answer's spend was staged before it was saved: what a
            // booking that failed, or a process that died, left staged on
            // the run's scope books now, once.
            self.drain_staged_spend()?;
            return self.answer(receipt);
        }
        // The vault's inference policy for the model the step names, and its
        // route. The caller was admitted above as the run's own actor.
        let (ladder, raw_run) = crate::api::llm::admit_live_run(&self.server, &mut input.request)
            .map_err(inference_refusal)?;
        let line = self.line(raw_run)?;
        let run = exact_step_run(&ladder, line.run, &mut input)?;
        // The run's step waits out its offer's health rest as the owner's
        // does (FIX 11226).
        let rest_wait = ladder.step_rest_wait();
        let backend = RunStepBackend {
            step: StepBackend { ladder, run },
            lease: line.lease.as_ref().map(|lease| lease.on(vault)),
            attached: self.attached.as_ref(),
            detached: AtomicBool::new(false),
        };
        let receipt = runtime.block_on(model_step::submit_as_run_actor_on_scope(
            vault,
            self.caller(),
            input,
            &backend,
            &line.guard,
            line.spend.as_ref(),
            rest_wait,
        ));
        // What the step's calls spent and no look booked goes on the scope
        // whatever the step answered. A booking that fails is an error of
        // the call, as it is at the run's other model door.
        let booked = backend.book_rest();
        let receipt = receipt?;
        booked?;
        self.answer(receipt)
    }

    /// Books on the run's scope what its leases staged and no drain booked
    /// ([RUN-STEP-CHARGE-LOST-ON-PROCESS-DEATH]). A booking that fails is an
    /// error of the call, as at a fresh call's end; the rows stay staged.
    fn drain_staged_spend(&self) -> MemoryResult<()> {
        let Some(scope) = self.held.spend_scope() else {
            return Ok(());
        };
        AgentDispatcher::new(self.server.vault()).drain_lease_spend(scope)?;
        Ok(())
    }

    fn receipt(&self, input: &ModelStepReceiptRequest) -> MemoryResult<ModelStepReceipt> {
        let receipt = model_step::receipt_as_run_actor(self.server.vault(), self.caller(), input)?;
        self.answer(receipt)
    }

    /// The line a fresh call of the run's step goes out on. A run that
    /// spends under a scope is admitted on a meter that scope bounds, which
    /// its live lease reads and books (FIX 1819), and bills the scope's
    /// payer (OF-531). Work an owner's agent Grant funds holds on that
    /// Grant's wallet, scoped or not (FIX 7766). A line that does not open
    /// never falls back to the host's.
    fn line(&self, raw_run: RunAdmission) -> MemoryResult<StepLine> {
        let vault = self.server.vault();
        let unopened = || MemoryError::bad_request("the attached run's spend line did not open");
        let funding =
            attempt_grant_funding(vault, self.held.leased_try()).map_err(|_| unopened())?;
        let models = self.server.ai.model_runtime();
        let Some(scope) = self.held.spend_scope() else {
            // A run with no scope steps on the raw routes' meter, as the
            // owner does.
            let run = match funding {
                None => raw_run,
                Some(funding) => models.grant_funded_run(
                    MODEL_STEP_RUN,
                    raw_meter(&self.server)?.clone(),
                    None,
                    Some(funding),
                ),
            };
            return Ok(StepLine {
                run,
                guard: raw_step_guard(&self.server)?,
                lease: None,
                spend: None,
            });
        };
        // The payer is read as the run's own steps read theirs: a room-bound
        // or member-bound run whose root names no payer, its payer erased
        // while it holds its lease included, does not open its line
        // (LIVE-RUN-PAYER-REQUIRED).
        let payer_required = self.held.payer_required(vault).map_err(|_| unopened())?;
        let (payer, _) =
            scope_run_funding(vault, Some(scope), payer_required).map_err(|_| unopened())?;
        let dispatcher = AgentDispatcher::new(vault);
        // The cap generation first: a top-up after the two guards read their
        // room then moves it, and the step's budget park wakes itself.
        let spend =
            StepSpendScope::read_before_guards(vault, scope.clone()).map_err(|_| unopened())?;
        // The physical calls' meter, and beside it the step's own logical
        // allowance, so the engine's logical lease does not charge the
        // meter twice. Only the meter's spend is booked on the scope.
        let meter = dispatcher.guard_for_scope(scope).map_err(|_| unopened())?;
        let guard = dispatcher.guard_for_scope(scope).map_err(|_| unopened())?;
        Ok(StepLine {
            run: models.grant_funded_run(MODEL_STEP_RUN, meter.clone(), payer, funding),
            guard,
            lease: Some(LeaseLine::new(scope.clone(), meter)),
            spend: Some(spend),
        })
    }

    /// Refuses an answer to an attachment that no longer stands: the lease,
    /// the binding or the credential's read key went while the call ran.
    fn answer(&self, receipt: ModelStepReceipt) -> MemoryResult<ModelStepReceipt> {
        if (self.attached)() {
            Ok(receipt)
        } else {
            Err(detached())
        }
    }
}

fn detached() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "the live-run credential or lease no longer holds",
        &[],
    )
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

/// The raw routes' meter.
fn raw_meter(server: &SyncServer) -> MemoryResult<&BudgetGuard> {
    Ok(server
        .llm
        .as_ref()
        .ok_or_else(|| internal("ai.steps.submit"))?
        .meter())
}

/// The logical allowance of a step on the raw routes' meter.
fn raw_step_guard(server: &SyncServer) -> MemoryResult<BudgetGuard> {
    let meter = raw_meter(server)?;
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

/// [`StepBackend`] for a held live run. Each physical admission first asks
/// whether the caller's attachment still stands, then looks at the run's
/// spend scope: the look books what the step's calls spent so far and
/// bounds the next by what the scope has left now, its siblings' spend
/// included.
struct RunStepBackend<'a> {
    step: StepBackend,
    lease: Option<LiveLease<'a>>,
    attached: &'a (dyn Fn() -> bool + Send + Sync),
    /// Set once an admission met an attachment that no longer stands.
    detached: AtomicBool,
}

impl RunStepBackend<'_> {
    fn look(&self) {
        if let Some(lease) = &self.lease {
            lease.book_and_revise();
        }
    }

    /// The look after a call answered: it stages the call's spend before
    /// the engine may save the answer.
    fn stage_answer(&self) -> oneiron::Result<()> {
        match &self.lease {
            Some(lease) => lease.stage_and_revise(),
            None => Ok(()),
        }
    }

    /// Books on the scope what the step's calls spent and no look booked.
    fn book_rest(&self) -> oneiron::Result<()> {
        let Some(lease) = &self.lease else {
            return Ok(());
        };
        lease.book_rest().inspect_err(|error| {
            tracing::warn!(kind = ?error.kind(), "a run's model-step spend was not booked");
        })
    }
}

impl LlmBackend for RunStepBackend<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.step.supports(model, capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let may_send = || {
                if !(self.attached)() {
                    self.detached.store(true, Ordering::Relaxed);
                    return false;
                }
                self.look();
                true
            };
            let answer = self
                .step
                .ladder
                .generate_step_attempt_while(&self.step.run, request, &may_send)
                .await;
            let staged = self.stage_answer();
            // An attempt stopped for its attachment is an admission the
            // host denied, never a model failure: the step neither retries
            // it nor answers it with its deterministic fallback, and the
            // engine saves no result for a run its host no longer holds
            // attached. The key's next call asks the model again.
            if self.detached.load(Ordering::Relaxed) {
                return Err(BudgetDenied::AdmissionDenied.into());
            }
            // An answer whose spend did not stage is refused the same way,
            // so the engine never saves an answer on a charge that lives
            // only in memory. The paid answer is lost: a failed local commit
            // is rare, and a charge that is not durable is worse (the
            // Engine, 12 Nov 19:40).
            if let Err(error) = staged
                && answer.is_ok()
            {
                tracing::error!(
                    kind = ?error.kind(),
                    "a run step's answer was refused: its spend did not stage"
                );
                return Err(BudgetDenied::AdmissionDenied.into());
            }
            answer
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}
