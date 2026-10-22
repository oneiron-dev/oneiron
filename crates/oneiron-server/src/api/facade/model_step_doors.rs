//! Owner-proof model steps; HTTP, SDK and MCP reach the same typed door.
//! A saved terminal answers before fresh provider admission (FIX 8180).
use std::sync::Arc;

use oneiron::llm::model_step::{
    self, ModelStepReceipt, ModelStepReceiptRequest, ModelStepResult, ModelStepSubmit,
};
use oneiron::llm::run_admission::RunAdmission;
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
    let answer = submit(server, auth, &mut input).await;
    listed(answer)
}

async fn submit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: &mut ModelStepSubmit,
) -> MemoryResult<ModelStepReceipt> {
    let owner = owner_proof(auth, server, "ai.steps.submit")?;
    // A saved terminal answers before any fresh provider admission (FIX
    // 8180): completed work needs no model, route or meter. Anything else,
    // and any failed lookup, takes the admission below exactly as before.
    let saved = {
        let (server, owner, probe) = (Arc::clone(server), owner.clone(), input.clone());
        tokio::task::spawn_blocking(move || {
            model_step::saved_terminal_as_owner(server.vault(), &owner, &probe)
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
    let meter = server
        .llm
        .as_ref()
        .ok_or_else(|| internal("ai.steps.submit"))?
        .meter();
    let read = meter.read();
    // This logical-step allowance is bounded by the host's remaining raw
    // allowance. Physical calls still reserve and settle on the shared run
    // meter, so the engine's logical lease does not charge that meter twice.
    let guard = BudgetGuard::with_reserve_units(
        "model-step",
        read.remaining_units,
        meter.reserve_units(),
        read.on_budget_exhausted,
    );
    let backend = StepBackend { ladder, run };
    let runtime = tokio::runtime::Handle::current();
    let server = Arc::clone(server);
    let input = input.clone();
    tokio::task::spawn_blocking(move || {
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
    let answer = tokio::task::spawn_blocking(move || {
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
