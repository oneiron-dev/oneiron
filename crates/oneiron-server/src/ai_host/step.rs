//! One saved-workflow step on a model seat.
//!
//! A step's prompt is data the vault already holds: the agent definition's
//! `instructions` as the system message, then the step's resolved context
//! (briefing, then each earlier step's output) as user messages. A first step
//! with no context is asked its definition's own `desc`. No text is invented
//! here; the output's raw bytes become the step's durable result.
use std::collections::{BTreeMap, HashMap};

use std::sync::{Arc, Mutex};

use oneiron::agent_dispatch::{AgentDispatchStatus, agent_dispatch_actor};
use oneiron::attempt_queue::{AttemptId, AttemptQueue};
use oneiron::compaction::output::restore_output;
use oneiron::context_projection::ResolvedContextProjection;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, Error, LlmMessage,
    LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
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
    /// follows: the next try replays exactly that.
    pub(super) spent: Mutex<HashMap<AttemptId, u64>>,
}

/// Failed tries whose spend is kept for a retry. A chain past its last try
/// keeps its entry, so the map is cleared at this size; a retry it forgot
/// replays the bound instead.
const KEPT_SPENDS: usize = 1024;

/// Why a step did not produce its output, and whether a later try of the
/// same call may succeed (a model call the provider answered with a
/// retryable error).
pub(super) struct StepFault {
    pub(super) retryable: bool,
    pub(super) error: Error,
}

impl From<Error> for StepFault {
    fn from(error: Error) -> Self {
        Self {
            retryable: false,
            error,
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
        let seat = self
            .models
            .seat(CHAT_ROLE)
            .ok_or_else(|| Error::InvalidConfig("no [models] rung serves workflow steps".into()))?;
        let purpose = CallPurpose::Other {
            name: STEP_PURPOSE.to_owned(),
        };
        let request = LlmRequest {
            model: seat.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(
                    &purpose,
                    definition
                        .model_tier
                        .clone()
                        .unwrap_or_else(|| ModelTierRef(STEP_PURPOSE.to_owned())),
                ),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
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
        // chain spent; after a restart, each earlier try is replayed at one
        // reservation per rung of the ladder, the most it could have sent.
        let reserve = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
        let earlier = AttemptQueue::new(vault).retry_chain_depth(step.attempt.id)?;
        let carried = step.attempt.retry_of.and_then(|parent| {
            self.spent
                .lock()
                .expect("step spend mutex poisoned")
                .remove(&parent)
        });
        let run_id = format!(
            "workflow-step:{}",
            oneiron::EntityId::from_bytes(*step.attempt.id.as_bytes())?.to_hex()
        );
        let guard = vault.policy_budget_guard(
            run_id.clone(),
            self.budget_units,
            reserve,
            BudgetExhaustionPolicy::Suspend,
            agent_dispatch_actor(&step.input)?,
        )?;
        let budget = |denied: oneiron::llm::BudgetDenied| {
            Error::InvalidConfig(format!("workflow step budget: {denied:?}"))
        };
        let charged = match carried {
            Some(units) => units.div_ceil(reserve),
            None => u64::from(earlier).saturating_mul(call.ladder.rungs() as u64),
        };
        for _ in 0..charged {
            let spent = guard.admit_for_request(&request).map_err(budget)?.lease;
            guard.settle_reserved(&spent).map_err(budget)?;
        }
        // The step is a run on that meter: each rung its call reaches is
        // admitted on its own permit, sent through the run's gate and
        // settled. An answer pays its tokens, or the reservation when it
        // reports none; a rung that went out and failed pays its reservation.
        let run = self.models.undeclared_run(run_id, guard);
        let response = match runtime.block_on(call.ladder.generate(&run, request, None)) {
            Ok(response) => response,
            Err(oneiron::llm::LlmError::BudgetDenied(denied)) => return Err(budget(denied).into()),
            Err(error) => {
                let retryable = matches!(error, oneiron::llm::LlmError::Retryable(_));
                if retryable {
                    let mut spent = self.spent.lock().expect("step spend mutex poisoned");
                    if spent.len() >= KEPT_SPENDS {
                        spent.clear();
                    }
                    spent.insert(step.attempt.id, run.read().used_units);
                }
                return Err(StepFault {
                    retryable,
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
