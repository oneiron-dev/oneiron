//! The reranker recall at high, xhigh and max runs on: the `reranker` role's
//! seat from `[models]` (ARCH-0036), called on the recall's own budget line
//! under a run (ARCH-0053 `#run-admission`). Each rung a call reaches is
//! admitted on a one-use permit, sent through the run's gate and settled, an
//! answer at its usage and a call that went out and failed at its
//! reservation. Nothing a request carries picks the model, its endpoint or
//! the lease: the door holds them. The words a call sends are known before
//! it leaves, so it is priced on them first ([`payload_units`]), and a line
//! that cannot cover them refuses the call unsent. A `[models]` rung is
//! reached over HTTP, never in this process, so this host does not run on
//! the device (`RecallRerankHost::runs_on_device`): a row a device-only world
//! keeps is sent to it empty. Each rung a call reaches reserves that price,
//! so a fallback rung goes out only while the line still covers the whole
//! payload, and a rung that failed after it went out is charged what it may
//! have billed. Each rung, the first too, goes out only while the
//! device-only verdict, run again, keeps none of the rows it sends with words
//! ([`RerankEgress::holds`]).
//!
//! A call is driven on its caller's runtime when that runtime is
//! multi-thread. A synchronous door holds its caller's thread until the
//! recall answers, and a current-thread runtime has no other thread to drive
//! the call on (outside a runtime there is none at all), so there the call
//! runs on the server's own [`CallRuntime`]. Every door of such a host takes
//! it, so no pooled connection belongs to a thread that is waiting.
use std::sync::{Arc, Mutex};
use std::time::Instant;

use oneiron::llm::BudgetDenied;
use oneiron::llm::manifest::ModelRole;
use oneiron::memory::{
    Effort, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
    RecallRerank, RecallRerankHost, RerankDocument, RerankEgress, RerankScores,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, EdgeActorClass, EntityId, LlmError,
    ModelLocality, Vault, WriteActor,
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
    /// The recall's run: each call is admitted and settled under it.
    run_id: String,
    /// The recall's line, which the run admits and settles every call on.
    meter: BudgetGuard,
    /// What a call reserves on the line at least, whatever its payload.
    reserve_units: u64,
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
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                handle
            }
            _ => self.rerank_runtime.handle()?,
        };
        let run_id = format!("recall-rerank:{:016x}", rand_core::OsRng.next_u64());
        let units = self.ai.rerank_budget_units();
        let reserve_units = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(units);
        let meter = self.vault.policy_budget_guard(
            run_id.clone(),
            units,
            reserve_units,
            BudgetExhaustionPolicy::Suspend,
            WriteActor::new(actor, class),
        )?;
        // Taken for the rerank purpose, as each rung's permit is, so a policy
        // row that funds that purpose funds this check too.
        let purpose = rerank_request("", &[], ModelLocality::OwnServer);
        let lease = meter
            .admit_for_request(&purpose)
            .inspect_err(|denied| {
                self.vault
                    .budget_denied_hooks(denied, &meter, &run_id, Some(actor));
            })
            .and_then(|admission| meter.abort(&admission.lease).map(|_| admission.lease))
            .map_err(spent)?;
        Ok(DoorRerank::Served(ServedRerank {
            vault: Arc::clone(&self.vault),
            ai: self.ai.clone(),
            run_id,
            meter,
            reserve_units,
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
        egress: &RerankEgress<'_>,
        answer_at: Option<Instant>,
    ) -> MemoryResult<RerankScores> {
        let texts: Vec<&str> = documents.iter().map(|document| document.text).collect();
        let price = payload_units(query, &texts);
        let line = self.meter.read();
        if price > line.remaining_units {
            return Err(spent(BudgetDenied::Exhausted));
        }
        self.meter
            .revise_line(line.limit_units, price.max(self.reserve_units));
        let run = self
            .ai
            .undeclared_run(self.run_id.clone(), self.meter.clone());
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
        let may_send = || egress.holds();
        let generate = call
            .ladder
            .generate_while(&run, call.request, None, &may_send);
        // The timer is made inside the runtime that drives it: a sync door's
        // thread has none of its own.
        let answered = match answer_at {
            Some(at) => self
                .runtime
                .block_on(async move { tokio::time::timeout_at(at.into(), generate).await })
                .map_err(|_| unavailable("the reranker did not answer before the deadline"))?,
            None => self.runtime.block_on(generate),
        };
        let response = answered.map_err(|error| match error {
            _ if egress.refused() => {
                unavailable("a row became device-only while the reranker was called")
            }
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

/// The tokens a cross-encoder adds to each query and document pair beside
/// their words: its start, separator and end marks (three for a BERT-style
/// pair), with room to spare.
const PAIR_FRAMING_UNITS: usize = 16;

/// The most a rerank call that sends `query` and `documents` can bill, in
/// the line's unit (tokens): a token per byte at most, the query counted once
/// beside each document, as a cross-encoder reads each pair, and each pair's
/// framing ([`PAIR_FRAMING_UNITS`]). A model whose template wraps each pair
/// in a longer prompt bills more than this.
fn payload_units(query: &str, documents: &[&str]) -> u64 {
    let pairs = documents
        .iter()
        .map(|document| {
            query
                .len()
                .saturating_add(document.len())
                .saturating_add(PAIR_FRAMING_UNITS)
        })
        .fold(0_usize, usize::saturating_add);
    u64::try_from(pairs).unwrap_or(u64::MAX)
}

/// The server's runtime for rerank calls its doors cannot drive on their
/// caller's (see the module doc): one worker, built on first use, dropped
/// without waiting for a call still out.
#[derive(Default)]
pub(crate) struct CallRuntime(Mutex<Option<tokio::runtime::Runtime>>);

impl CallRuntime {
    fn handle(&self) -> MemoryResult<tokio::runtime::Handle> {
        let not_started =
            || unavailable("the server could not start a runtime to call the reranker on");
        let mut slot = self.0.lock().map_err(|_| not_started())?;
        if let Some(runtime) = slot.as_ref() {
            return Ok(runtime.handle().clone());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("oneiron-rerank")
            .enable_all()
            .build()
            .map_err(|_| not_started())?;
        Ok(slot.insert(runtime).handle().clone())
    }
}

impl Drop for CallRuntime {
    fn drop(&mut self) {
        // A server may drop on a runtime worker, where a blocking shutdown
        // would panic.
        if let Some(runtime) = self.0.get_mut().ok().and_then(Option::take) {
            runtime.shutdown_background();
        }
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
