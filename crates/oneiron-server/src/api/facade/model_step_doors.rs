//! Owner-proof model steps; HTTP, SDK and MCP reach the same typed door.
//! Saved terminals and response checkpoints answer before fresh provider admission.
//! A step parked on its offer's health resumes on its own once the offer is back.
use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::model_step::{
    self, ModelStepReceipt, ModelStepReceiptRequest, ModelStepResult, ModelStepSubmit,
};
use oneiron::llm::run_admission::{RunAdmission, WorkPhysical};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError,
    MemoryResult,
};
use oneiron::{
    BudgetGuard, BudgetLease, EntityId, FatalLlmError, LlmBackend, LlmCapability,
    LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
};

use super::host_doors::support::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::models::OfferLadder;
use crate::server::SyncServer;

pub(crate) async fn ai_steps_submit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    mut input: ModelStepSubmit,
) -> Listed<ModelStepReceipt> {
    let submitted = input.clone();
    let answer = submit(server, auth, &mut input).await;
    if let Ok(ModelStepReceipt {
        result: Some(ModelStepResult::Parked { until, .. }),
        ..
    }) = &answer
    {
        resume_when_back(server, auth, submitted, *until);
    }
    listed(answer)
}

/// How long a parked step whose offer names no end to its rest (a probation
/// request is out) waits before it asks again.
const RESUME_POLL: Duration = Duration::from_secs(1);

/// A step parked on its offer's health resumes on its own (FIX 11226): a task
/// on this server waits until the offer is back, at `until` on the vault's
/// clock, and submits the step again as its owner did. Each resume admits it
/// afresh under the owner's live proof, so a credential withdrawn meanwhile
/// ends it, and keeps the sends the step made. A step that parks again waits
/// again; one its owner submits meanwhile is serialized by its invocation
/// claim. The task holds the server weakly and ends with it. A restart drops
/// it: a later submission of the same key resumes the step.
fn resume_when_back(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStepSubmit,
    until: Option<u64>,
) {
    let server = Arc::downgrade(server);
    let auth = auth.clone();
    tokio::spawn(async move {
        let mut until = until;
        loop {
            let wait = {
                let Some(live) = server.upgrade() else {
                    return;
                };
                let now = live.vault().now_recorded_at();
                until.map_or(RESUME_POLL, |until| {
                    Duration::from_secs(until.saturating_sub(now))
                })
            };
            tokio::time::sleep(wait).await;
            let Some(live) = server.upgrade() else {
                return;
            };
            let mut resumed = input.clone();
            match submit(&live, &auth, &mut resumed).await {
                Ok(ModelStepReceipt {
                    result: Some(ModelStepResult::Parked { until: next, .. }),
                    ..
                }) => until = next,
                Ok(_) => return,
                Err(error) => {
                    tracing::warn!(
                        code = %error.code,
                        "a parked model step did not resume; a submission of its key resumes it"
                    );
                    return;
                }
            }
        }
    });
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
        crate::api::llm::admit(server, auth, &mut input.request).map_err(|response| {
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
        })?;
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
    let run = run.with_work_context({
        let mut context = run.work_context();
        // A free on-device step is free work too, as physical_for says.
        context.physical = if ladder.all_free_work() {
            WorkPhysical::KeylessOwnServer
        } else {
            WorkPhysical::Paid
        };
        context
    });
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
    let guard = BudgetGuard::with_reserve_units(
        "model-step",
        read.capped_remaining_units().unwrap_or(u64::MAX),
        meter.reserve_units(),
        read.on_budget_exhausted,
    );
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

pub(crate) async fn ai_steps_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStepReceiptRequest,
) -> Listed<ModelStepReceipt> {
    let owner = match owner_proof(auth, server, "ai.steps.receipt") {
        Ok(owner) => owner,
        Err(error) => return (Err(error), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        model_step::receipt_as_owner(server.vault(), &owner, &input)
    })
    .await
    .unwrap_or_else(|_| Err(internal("ai.steps.receipt")));
    listed(answer)
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
