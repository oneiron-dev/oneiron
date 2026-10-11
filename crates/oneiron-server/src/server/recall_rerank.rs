//! The reranker recall at high, xhigh and max runs on: the `reranker` role's
//! seat from `[models]` (ARCH-0036), called on the recall's own budget line
//! under a run (ARCH-0053 `#run-admission`). Each rung a call reaches is
//! admitted on a one-use permit, sent through the run's gate and settled, an
//! answer at its usage and a call that went out and failed at its
//! reservation. Nothing a request carries picks the model, its endpoint or
//! the lease: the door holds them.
use std::sync::Arc;
use std::time::Instant;

use oneiron::llm::BudgetDenied;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{
    Effort, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
    RecallRerank, RecallRerankHost, RerankDocument, RerankScores,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetLease, EdgeActorClass, EntityId, LlmError, ModelLocality, Vault,
    WriteActor,
};
use rand_core::RngCore;

use super::core::SyncServer;
use crate::ai_host::AiHandle;
use crate::config::models::role_key;
use crate::models::{rerank_request, rerank_scores};

/// How one recall door serves a paid effort.
pub(super) enum DoorRerank {
    /// Below high, no reranker is asked for.
    Unpaid,
    /// `[models]` routes no reranker: the paid expansion runs unreranked.
    Unavailable,
    Served(ServedRerank),
}

impl DoorRerank {
    pub(super) fn engine(&self) -> RecallRerank<'_> {
        match self {
            Self::Unpaid => RecallRerank::Required,
            Self::Unavailable => RecallRerank::Unavailable,
            Self::Served(served) => RecallRerank::Host(served),
        }
    }
}

/// The reranker seat one recall calls, on that recall's line.
pub(super) struct ServedRerank {
    vault: Arc<Vault>,
    ai: AiHandle,
    run: RunAdmission,
    /// The line's word that it admitted this recall. Every rerank call is
    /// admitted and settled on the same line on its own permit, so this
    /// lease holds no reservation.
    lease: BudgetLease,
    runtime: tokio::runtime::Handle,
}

impl SyncServer {
    /// The reranker a recall door at `effort` brings for `actor`. Refused when
    /// `[models]` routes a reranker none of whose rungs can serve, or when
    /// the recall's line admits nothing.
    pub(super) fn door_rerank(
        &self,
        effort: Effort,
        actor: EntityId,
        class: EdgeActorClass,
    ) -> MemoryResult<DoorRerank> {
        if !effort.requires_rerank() {
            return Ok(DoorRerank::Unpaid);
        }
        if self.ai.seat(ModelRole::Reranker).is_none() {
            let routed = self
                .ai
                .models_status()
                .seats
                .iter()
                .any(|seat| seat.role == role_key(ModelRole::Reranker));
            if routed {
                return Err(unavailable(
                    "the reranker role's [models] route has no rung that can serve",
                ));
            }
            return Ok(DoorRerank::Unavailable);
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| unavailable("this door has no runtime to call the reranker on"))?;
        let run_id = format!("recall-rerank:{:016x}", rand_core::OsRng.next_u64());
        let units = self.ai.rerank_budget_units();
        let meter = self.vault.policy_budget_guard(
            run_id.clone(),
            units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(units),
            BudgetExhaustionPolicy::Suspend,
            WriteActor::new(actor, class),
        )?;
        let lease = meter
            .admit()
            .and_then(|admission| meter.abort(&admission.lease).map(|_| admission.lease))
            .map_err(spent)?;
        Ok(DoorRerank::Served(ServedRerank {
            vault: Arc::clone(&self.vault),
            ai: self.ai.clone(),
            run: self.ai.undeclared_run(run_id, meter),
            lease,
            runtime,
        }))
    }
}

impl RecallRerankHost for ServedRerank {
    fn lease(&self) -> &BudgetLease {
        &self.lease
    }

    fn score(
        &self,
        query: &str,
        documents: &[RerankDocument<'_>],
        answer_at: Option<Instant>,
    ) -> MemoryResult<RerankScores> {
        let texts: Vec<&str> = documents.iter().map(|document| document.text).collect();
        // The vault's model policy places the call: its manifest's binding
        // for the role when it has one, the role's seat otherwise.
        let call = self
            .ai
            .admit_role(
                &self.vault,
                ModelRole::Reranker,
                rerank_request(query, &texts, ModelLocality::OwnServer),
            )
            .map_err(|refusal| unavailable(&format!("the reranker call was refused: {refusal}")))?;
        let model = call.request.model.clone();
        let generate = call.ladder.generate(&self.run, call.request, None);
        let answered = match answer_at {
            Some(at) => self
                .runtime
                .block_on(tokio::time::timeout_at(at.into(), generate))
                .map_err(|_| unavailable("the reranker did not answer before the deadline"))?,
            None => self.runtime.block_on(generate),
        };
        let response = answered.map_err(|error| match error {
            LlmError::BudgetDenied(denied) => spent(denied),
            error => unavailable(&format!("the reranker call failed: {error}")),
        })?;
        let scores = rerank_scores(&response)
            .ok_or_else(|| unavailable("the reranker's answer holds no scores"))?;
        // The seat's receipt names the rung that answered, as `[models]`
        // spells it, and what the provider said served it.
        let receipt = &response.usage.raw_provider;
        let named = |key: &str| receipt.get(key).and_then(serde_json::Value::as_str);
        let model = match (named("provider"), named("requested_model")) {
            (Some(provider), Some(wire)) => format!("{provider}:{wire}"),
            _ => model.as_str().to_owned(),
        };
        Ok(RerankScores {
            scores,
            model,
            served_model: named("reported_model").map(str::to_owned),
        })
    }
}

fn unavailable(reason: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        reason,
        &["Check the reranker route in [models], or recall at medium."],
    )
}

fn spent(denied: BudgetDenied) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_BUDGET_SPENT,
        format!("the recall's budget line refused its rerank call: {denied}"),
        &["Recall at medium, or raise [models.recall] rerank_budget_units."],
    )
}
