//! One saved-workflow step on a model seat.
//!
//! A step's prompt is data the vault already holds: the agent definition's
//! `instructions` as the system message, then the step's resolved context
//! (briefing, then each earlier step's output) as user messages. A first step
//! with no context is asked its definition's own `desc`. No text is invented
//! here; the output's raw bytes become the step's durable result.
use std::collections::{BTreeMap, HashMap};

use std::sync::{Arc, Mutex};

use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{AgentDispatchStatus, AgentDispatcher, agent_dispatch_actor};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use oneiron::compaction::output::restore_output;
use oneiron::context_projection::ResolvedContextProjection;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, Error, LlmMessage,
    LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence, Vault, WriteActor,
};

use super::CHAT_ROLE;
use crate::models::ModelRuntime;

/// The purpose a workflow step's calls are metered and routed under.
const STEP_PURPOSE: &str = "workflow_step";

pub(super) struct StepRunner {
    /// Steps run on the generative role, admitted against the vault's live
    /// model policy like chat turns.
    pub(super) models: Arc<ModelRuntime>,
    /// One logical step's budget, shared by all its tries; at least one
    /// call's reservation (config refuses less).
    pub(super) budget_units: u64,
    /// How long a failed step waits before its next try, times the tries.
    pub(super) retry_backoff_secs: u64,
    /// What each step's tries spent in all, by the failed try a retry
    /// follows: the next try replays exactly that. Held only while a retry
    /// may follow, and only in this process.
    pub(super) spent: Mutex<HashMap<AttemptId, u64>>,
}

/// One model-backed step, with instructions supplied by its stored definition.
pub(super) struct ModelStep<'a> {
    pub(super) definition: &'a AgentDefinition,
    pub(super) attempt: &'a AttemptRecord,
    pub(super) actor: WriteActor,
    pub(super) purpose: &'a str,
    pub(super) messages: Vec<LlmMessage>,
    pub(super) response_format: ResponseFormat,
}

/// Why a step did not produce its output, and whether a later try of the
/// same call may succeed (a model call the provider answered with a
/// retryable error).
pub(super) struct StepFault {
    pub(super) retryable: bool,
    /// The step's meter ran out (`BudgetDenied::Exhausted`) before the call
    /// was answered: its run holds at the cap, paused with its checkpoint,
    /// and is neither failed nor retried (OF-541).
    pub(super) exhausted: bool,
    pub(super) error: Error,
}

impl From<Error> for StepFault {
    fn from(error: Error) -> Self {
        Self {
            retryable: false,
            exhausted: false,
            error,
        }
    }
}

/// Hands a held run's owed notice to its owners, then records it delivered
/// (OF-541). A refusal leaves it owed, and the next pump delivers it.
pub(super) fn deliver_hold_notice(dispatcher: &AgentDispatcher<'_>, root: AttemptId, now: u64) {
    let delivered = dispatcher
        .deliver_budget_notice(root)
        .and_then(|owed| match owed {
            Some(_) => dispatcher.acknowledge_budget_notice(root, now).map(Some),
            None => Ok(None),
        });
    match delivered {
        Ok(Some(hold)) => {
            let notice = hold.notice.as_ref().map(|notice| notice.text.as_str());
            tracing::info!(?root, notice, "a held run's notice reached its owners");
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(kind = ?error.kind(), ?root, "a held run's notice was not delivered");
        }
    }
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}

impl StepRunner {
    /// Drops what a failed try spent once no retry follows it.
    pub(super) fn forget(&self, attempt: AttemptId) {
        self.spent
            .lock()
            .expect("step spend mutex poisoned")
            .remove(&attempt);
    }

    /// Runs on the pump thread, which owns `runtime`: blocking on the model
    /// call here never stalls a request worker.
    pub(super) fn run(
        &self,
        runtime: &tokio::runtime::Runtime,
        vault: &Vault,
        step: &AgentDispatchStatus,
        context: ResolvedContextProjection,
    ) -> Result<Vec<u8>, StepFault> {
        let definition = &step.input.definition;
        let mut messages = Vec::new();
        if let Some(instructions) = definition
            .instructions
            .as_ref()
            .filter(|text| !text.trim().is_empty())
        {
            messages.push(message(LlmMessageRole::System, instructions.clone()));
        }
        if let Some(briefing) = context.briefing.filter(|text| !text.trim().is_empty()) {
            messages.push(message(LlmMessageRole::User, briefing));
        }
        for earlier in &context.workflow_output_refs {
            let bytes = restore_output(vault, earlier.source)?;
            messages.push(message(
                LlmMessageRole::User,
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
        if !messages.iter().any(|m| m.role == LlmMessageRole::User) {
            messages.push(message(LlmMessageRole::User, definition.desc.clone()));
        }
        self.generate(
            runtime,
            vault,
            ModelStep {
                definition,
                attempt: &step.attempt,
                actor: agent_dispatch_actor(&step.input)?,
                purpose: STEP_PURPOSE,
                messages,
                response_format: ResponseFormat::Text,
            },
        )
    }

    pub(super) fn generate(
        &self,
        runtime: &tokio::runtime::Runtime,
        vault: &Vault,
        input: ModelStep<'_>,
    ) -> Result<Vec<u8>, StepFault> {
        let ModelStep {
            definition,
            attempt,
            actor,
            purpose,
            messages,
            response_format,
        } = input;
        let seat = self
            .models
            .seat(CHAT_ROLE)
            .ok_or_else(|| Error::InvalidConfig("no [models] rung serves workflow steps".into()))?;
        let call_purpose = CallPurpose::Other {
            name: purpose.to_owned(),
        };
        let request = LlmRequest {
            model: seat.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                // No world: the world a step was dispatched in does not vouch
                // for its text (Astra R3). Its definition, its briefing and
                // earlier steps' outputs may come from any world the
                // dispatcher read, so the vault-wide floor holds its fallback
                // on the device while any world stays on it.
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(
                    &call_purpose,
                    definition
                        .model_tier
                        .clone()
                        .unwrap_or_else(|| ModelTierRef(purpose.to_owned())),
                ),
                purpose: call_purpose,
                class: CallClass::BestEffort,
                response_format,
                locality: seat.locality,
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        // A route the vault narrowed past what this server serves ends the
        // step here, before any call leaves.
        let call = self
            .models
            .admit_role(vault, CHAT_ROLE, request)
            .map_err(|refusal| Error::InvalidConfig(format!("workflow step refused: {refusal}")))?;
        let request = call.request;
        // The agent pays: its live budget policy rows, its own meter. Every
        // earlier try of this step failed its model call, and each rung it
        // sent was charged its reservation. Those charges are replayed into
        // this try's meter, so the step's budget and every policy row it
        // matches (the agent's cap, the purpose's) see them: retries share
        // one budget, never renew it. The try this one follows left what the
        // chain spent. After a restart nothing is left, and each earlier try
        // is replayed at one reservation per rung of the ladder it has now:
        // an estimate, exact only when every earlier rung went out metered on
        // the same ladder and routes.
        let reserve = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
        let earlier = AttemptQueue::new(vault).retry_chain_depth(attempt.id)?;
        let carried = attempt.retry_of.and_then(|parent| {
            self.spent
                .lock()
                .expect("step spend mutex poisoned")
                .remove(&parent)
        });
        let run_id = format!(
            "workflow-step:{}",
            oneiron::EntityId::from_bytes(*attempt.id.as_bytes())?.to_hex()
        );
        let charged = match carried {
            Some(units) => units.div_ceil(reserve),
            None => u64::from(earlier).saturating_mul(call.ladder.rungs() as u64),
        };
        // A step launched under a spend lease (OF-532) is bounded by it too:
        // beside its policy rows, this try may spend no more than the lease
        // has left. Replayed charges are already on the lease, so they sit
        // on top of that bound, not inside it.
        let dispatcher = AgentDispatcher::new(vault);
        let lease = dispatcher.spend_scope_for_attempt(attempt.id)?;
        let budget_units = match &lease {
            Some(scope) => self.budget_units.min(
                charged
                    .saturating_mul(reserve)
                    .saturating_add(dispatcher.guard_for_scope(scope)?.read().remaining_units),
            ),
            None => self.budget_units,
        };
        let guard = vault.policy_budget_guard(
            run_id.clone(),
            budget_units,
            reserve,
            BudgetExhaustionPolicy::Suspend,
            actor,
        )?;
        let budget = |denied: oneiron::llm::BudgetDenied| StepFault {
            retryable: false,
            exhausted: matches!(denied, oneiron::llm::BudgetDenied::Exhausted),
            error: Error::InvalidConfig(format!("workflow step budget: {denied:?}")),
        };
        for _ in 0..charged {
            let spent = guard.admit_for_request(&request).map_err(budget)?.lease;
            guard.settle_reserved(&spent).map_err(budget)?;
        }
        let replayed = guard.read().used_units;
        // The step is a run on that meter: each rung its call reaches is
        // admitted on its own permit, sent through the run's gate and
        // settled. An answer pays its tokens, or the reservation when it
        // reports none; a rung that went out and failed pays its reservation.
        let run = self.models.undeclared_run(run_id, guard);
        let generated = runtime.block_on(call.ladder.generate(&run, request, None));
        // What this try spent goes on the lease whatever the call answered;
        // the replayed tries recorded their own.
        if let Some(scope) = &lease {
            dispatcher.record_guard_spend(scope, run.read().used_units.saturating_sub(replayed))?;
        }
        let response = match generated {
            Ok(response) => response,
            Err(oneiron::llm::LlmError::BudgetDenied(denied)) => return Err(budget(denied)),
            Err(error) => {
                let retryable = matches!(error, oneiron::llm::LlmError::Retryable(_));
                if retryable {
                    let chain = run.read().used_units;
                    self.spent
                        .lock()
                        .expect("step spend mutex poisoned")
                        .insert(attempt.id, chain);
                }
                return Err(StepFault {
                    retryable,
                    exhausted: false,
                    error: Error::InvalidConfig(format!(
                        "workflow step model call failed: {error}"
                    )),
                });
            }
        };
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        Ok(text.into_bytes())
    }
}
