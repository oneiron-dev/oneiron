//! Request-scoped production memory reasoning over the configured model roles.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{BudgetGuard, BudgetLease, DEFAULT_BUDGET_RESERVE_UNITS};
use oneiron::rerank::RerankCandidate;
use oneiron::retrieval_depth::{
    BackendSpend, DeepSearchBackend, RetrievalError, RetrievalResult, SessionScope,
};
use oneiron::{BudgetExhaustionPolicy, EntityId, Error};
use serde::Deserialize;
use serde_json::json;

use super::{
    DeepRetrievalHost, MemoryReasonBackend, MemoryReasonComposeRequest, MemoryReasonComposition,
};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::models::{RerankOutcome, rerank_outcome, rerank_request};
use crate::server::SyncServer;

mod call;
mod composition;
mod frame;
mod sources;
mod usage;

pub(super) struct Backend {
    server: Arc<SyncServer>,
    auth: CoreAuth,
    scope: SessionScope,
    meter: BudgetGuard,
    run_id: String,
    runtime: tokio::runtime::Handle,
    receipts: Arc<call::Receipts>,
    complete: AtomicBool,
    reads: Mutex<Vec<oneiron::claim::ScopedReadReceipt>>,
}

pub(super) fn production_host(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    token_budget: u64,
    scope: &SessionScope,
    anonymous_at_arrival: bool,
) -> Result<DeepRetrievalHost, ApiError> {
    if server.ai.seat(ModelRole::GenerativeReasoner).is_none()
        || server.ai.seat(ModelRole::Reranker).is_none()
    {
        return Err(ApiError::deep_retrieval_unavailable());
    }
    let memory = super::answer_admission::answer_memory(&server.vault, auth)?;
    let actor = oneiron::WriteActor::new(memory.actor(), memory.actor_class());
    let run_id = format!("memory-reason:{}", EntityId::now().to_hex());
    let reserve = DEFAULT_BUDGET_RESERVE_UNITS.min(token_budget);
    let meter = server
        .vault
        .policy_budget_guard(
            run_id.clone(),
            token_budget,
            reserve,
            BudgetExhaustionPolicy::Suspend,
            actor,
        )
        .map_err(|error| crate::api::core_engine_error("memory reason budget failed", error))?;
    let runtime = match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            handle
        }
        _ => server
            .rerank_runtime
            .handle()
            .map_err(|_| ApiError::deep_retrieval_unavailable())?,
    };
    let backend = Arc::new(Backend {
        server: Arc::clone(server),
        auth: auth.clone(),
        scope: scope.clone(),
        meter,
        run_id: run_id.clone(),
        runtime,
        receipts: Arc::new(call::Receipts::new(server, auth, anonymous_at_arrival)),
        complete: AtomicBool::new(true),
        reads: Mutex::new(Vec::new()),
    });
    // Capacity for the whole read is not the native permits' accounting state.
    let capacity = BudgetGuard::with_reserve_units(
        run_id,
        token_budget,
        reserve,
        BudgetExhaustionPolicy::Suspend,
    );
    Ok(DeepRetrievalHost::new(backend, capacity))
}

impl DeepSearchBackend for Backend {
    fn decompose(
        &self,
        query: &str,
        already_run: &[String],
        max_queries: usize,
        token_budget: Option<u64>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Decomposed {
            queries: Vec<String>,
        }
        let schema = json!({"type":"object","properties":{"queries":{"type":"array","items":{"type":"string"},"maxItems":max_queries}},"required":["queries"],"additionalProperties":false});
        let data = json!({"operation":"decompose","query":query,"alreadyRun":already_run,"maxQueries":max_queries});
        let answered = self.generate_json(data, schema, &[], token_budget)?;
        let tokens_used = answered.tokens_used;
        let parsed: Decomposed =
            serde_json::from_str(&call::text(&answered.value)).map_err(|_| RetrievalError {
                error: invalid("memory reason decomposition is not the requested JSON"),
                tokens_used,
            })?;
        Ok(BackendSpend {
            value: parsed.queries,
            tokens_used,
        })
    }

    fn rerank(
        &self,
        query: &str,
        candidates: &[RerankCandidate<'_>],
        token_budget: Option<u64>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        if candidates.is_empty() {
            return Ok(BackendSpend::free(Vec::new()));
        }
        let pins = sources::rerank_pins(self, candidates)?;
        let texts: Vec<&str> = pins.iter().map(|pin| pin.text.as_str()).collect();
        let request = rerank_request(query, &texts, oneiron::ModelLocality::OwnServer);
        let line = SyncServer::rerank_line_for_payload(&self.meter, query, &texts)
            .map_err(|error| invalid(&format!("memory reason rerank budget: {error}")))?;
        let answered = self.generate(
            ModelRole::Reranker,
            request,
            &pins,
            token_budget,
            Some(line),
        )?;
        let tokens_used = answered.tokens_used;
        let fail = || RetrievalError {
            error: invalid("memory reason rerank score coverage is incomplete"),
            tokens_used,
        };
        let Some(RerankOutcome::Scored(scores)) = rerank_outcome(&answered.value) else {
            return Err(fail());
        };
        if scores.len() != candidates.len() || scores.iter().any(|score| !score.is_finite()) {
            return Err(fail());
        }
        Ok(BackendSpend {
            value: scores,
            tokens_used,
        })
    }
}

impl MemoryReasonBackend for Backend {
    fn usage_complete(&self) -> bool {
        self.complete.load(Ordering::Relaxed)
    }

    fn read_receipts(&self) -> Vec<oneiron::claim::ScopedReadReceipt> {
        self.reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn compose(
        &self,
        request: &MemoryReasonComposeRequest<'_>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<MemoryReasonComposition>> {
        composition::compose(self, request)
    }
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
