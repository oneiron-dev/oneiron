//! One saved-workflow step on a model seat.
//!
//! A step's prompt is data the vault already holds: the agent definition's
//! `instructions` as the system message, then the step's resolved context
//! (briefing, then each earlier step's output) as user messages. A first step
//! with no context is asked its definition's own `desc`. No text is invented
//! here; the output's raw bytes become the step's durable result.
use std::collections::BTreeMap;

use std::sync::Arc;

use oneiron::agent_dispatch::{AgentDispatchStatus, agent_dispatch_actor};
use oneiron::attempt_queue::AttemptQueue;
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
    /// One logical step's budget, shared by all its tries.
    pub(super) budget_units: u64,
    /// How long a failed step waits before its next try, times the tries.
    pub(super) retry_backoff_secs: u64,
}

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
        // earlier try of this step failed its model call and was charged its
        // reservation. Those charges are replayed into this try's meter, so
        // the step's budget and every policy row it matches (the agent's
        // cap, the purpose's) see them: retries share one budget, never renew
        // it.
        let reserve = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(self.budget_units);
        let earlier = AttemptQueue::new(vault).retry_chain_depth(step.attempt.id)?;
        let guard = vault.policy_budget_guard(
            format!(
                "workflow-step:{}",
                oneiron::EntityId::from_bytes(*step.attempt.id.as_bytes())?.to_hex()
            ),
            self.budget_units,
            reserve,
            BudgetExhaustionPolicy::Suspend,
            agent_dispatch_actor(&step.input)?,
        )?;
        let budget = |denied: oneiron::llm::BudgetDenied| {
            Error::InvalidConfig(format!("workflow step budget: {denied:?}"))
        };
        for _ in 0..earlier {
            let spent = guard.admit_for_request(&request).map_err(budget)?.lease;
            guard.settle_reserved(&spent).map_err(budget)?;
        }
        let lease = guard.admit_for_request(&request).map_err(budget)?.lease;
        let response = match runtime.block_on(call.backend.generate(request, &lease)) {
            Ok(response) => response,
            Err(error) => {
                let _ = guard.settle_reserved(&lease);
                return Err(StepFault {
                    retryable: matches!(error, oneiron::llm::LlmError::Retryable(_)),
                    error: Error::InvalidConfig(format!(
                        "workflow step model call failed: {error}"
                    )),
                });
            }
        };
        guard
            .settle_per_call(&lease, &response.usage)
            .map_err(|denied| {
                Error::InvalidConfig(format!("workflow step settlement: {denied:?}"))
            })?;
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
