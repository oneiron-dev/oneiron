//! One saved-workflow step on a model seat.
//!
//! A step's prompt is data the vault already holds: the agent definition's
//! `instructions` as the system message, then the step's resolved context
//! (briefing, then each earlier step's output) as user messages. A first step
//! with no context is asked its definition's own `desc`. No text is invented
//! here; the output's raw bytes become the step's durable result.
use std::collections::BTreeMap;

use oneiron::agent_dispatch::{AgentDispatchStatus, agent_dispatch_actor};
use oneiron::compaction::output::restore_output;
use oneiron::context_projection::ResolvedContextProjection;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, Error, LlmMessage,
    LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

use crate::models::Seat;

/// The purpose a workflow step's calls are metered and routed under.
const STEP_PURPOSE: &str = "workflow_step";

pub(super) struct StepRunner {
    pub(super) seat: Seat,
    pub(super) budget_units: u64,
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
    ) -> oneiron::Result<Vec<u8>> {
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
        let purpose = CallPurpose::Other {
            name: STEP_PURPOSE.to_owned(),
        };
        let request = LlmRequest {
            model: self.seat.model.clone(),
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
                locality: self.seat.locality,
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        let request = vault
            .authorize_raw_inference(
                request,
                &HostInferenceContext {
                    binding: HostInferenceBinding::Advertised {
                        model: self.seat.model.clone(),
                        locality: self.seat.locality,
                    },
                    extraction_egress: None,
                },
            )?
            .into_request();
        // The agent pays: its live budget policy row, its own meter.
        let guard = vault.policy_budget_guard(
            format!(
                "workflow-step:{}",
                oneiron::EntityId::from_bytes(*step.attempt.id.as_bytes())?.to_hex()
            ),
            self.budget_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(self.budget_units),
            BudgetExhaustionPolicy::Suspend,
            agent_dispatch_actor(&step.input)?,
        )?;
        let lease = guard
            .admit_for_request(&request)
            .map_err(|denied| Error::InvalidConfig(format!("workflow step budget: {denied:?}")))?
            .lease;
        let response = match runtime.block_on(self.seat.backend.generate(request, &lease)) {
            Ok(response) => response,
            Err(error) => {
                let _ = guard.settle_reserved(&lease);
                return Err(Error::InvalidConfig(format!(
                    "workflow step model call failed: {error}"
                )));
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
