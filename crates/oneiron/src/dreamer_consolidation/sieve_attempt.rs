//! The sieve's owed novelty/typing rungs and its sampled expensive-path audit.
//! Calls use the host's existing extraction and verdict roles; receipts and
//! wake charges use the same durable step layer as consolidation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::executor::ConsolidationExecutor;
use super::roles::{DREAMER_EXTRACTION_ROLE, DREAMER_VERDICT_ROLE, RoleCall};
use super::step_charge::StepChargeTally;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::sieve::{self, RungInput};
use crate::dreamer_wake::{DreamerAttemptExecution, SieveRung, SpanKind, WakeAttemptContext};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext, DurableStepError,
    LlmMessage, LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, StepOutcome,
    TierPrecedence, call_as_step_checked,
};
use crate::{EntityId, Error, Result};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reading {
    kind: SpanKind,
    novel: bool,
    confidence: u8,
    entity: Option<EntityId>,
}

impl ConsolidationExecutor<'_> {
    pub(super) async fn run_sieve_rungs(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if self.scope.is_some() {
            return Err(Error::InvalidConfig(
                "sieve rungs do not accept a branch scope".into(),
            ));
        }
        let input: RungInput =
            serde_json::from_str(attempt.status.payload.input.as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        if let Some(completed_units) =
            sieve::rung_result_units(ctx.vault, attempt.status.attempt.id)?
        {
            return Ok(DreamerAttemptExecution::Completed { completed_units });
        }
        if sieve::rung_superseded(ctx.vault, &input)?
            || (!input.audit && input.span.owed.is_empty())
        {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }
        let Some(evidence) = sieve::rung_evidence(ctx.vault, &input)? else {
            // The source may be withheld temporarily. Keep the job and queue
            // entry, rather than completing the only owed-rung receipt.
            return Ok(DreamerAttemptExecution::Deferred {
                completed_units: 0,
                retry_at: ctx
                    .now_ms
                    .div_ceil(1_000)
                    .saturating_add(input.policy.rung_retry_secs),
            });
        };
        let mut charges = StepChargeTally::default();
        let mut reading = Reading {
            kind: input.span.kind,
            novel: input.span.novel.unwrap_or(true),
            confidence: input.span.confidence,
            entity: input.span.entity,
        };
        let rungs = if input.audit {
            vec![SieveRung::Novelty, SieveRung::Typing]
        } else {
            input.span.owed.clone()
        };
        for rung in rungs {
            let role = match rung {
                SieveRung::Novelty => DREAMER_EXTRACTION_ROLE,
                SieveRung::Typing => DREAMER_VERDICT_ROLE,
            };
            let call = RoleCall::resolve(
                &self.roles,
                role,
                self.backend,
                &self.model,
                &self.inference.binding,
                self.inference.extraction_egress,
            );
            let instruction = match rung {
                SieveRung::Novelty => &input.policy.novelty_instruction,
                SieveRung::Typing => &input.policy.typing_instruction,
            };
            let locality = match call.inference.selected_locality() {
                Some(locality) => locality,
                None => return Ok(charges.park("sieve host binding needs locality")),
            };
            let data = serde_json::json!({
                "span": input.span, "context": evidence.text,
                "entity_candidates": evidence.entities, "previous": reading,
            });
            let mut request = LlmRequest {
                model: call.model.clone(),
                envelope: CallEnvelope {
                    seat_effort: None,
                    scope: evidence.scope.clone(),
                    purpose: CallPurpose::Extraction,
                    class: CallClass::BestEffort,
                    tier: TierPrecedence::for_purpose(
                        &CallPurpose::Extraction,
                        ModelTierRef("consolidation".into()),
                    ),
                    response_format: ResponseFormat::Text,
                    locality,
                }
                .with_purpose_defaults(),
                messages: vec![
                    LlmMessage {
                        role: LlmMessageRole::System,
                        content: vec![ContentPart::Text {
                            text: instruction.clone(),
                        }],
                    },
                    LlmMessage {
                        role: LlmMessageRole::User,
                        content: vec![ContentPart::Text {
                            text: data.to_string(),
                        }],
                    },
                ],
                tools: Vec::new(),
                params: BTreeMap::new(),
                provider_options: BTreeMap::new(),
            };
            request = match ctx
                .vault
                .authorize_model_role(role, request, &call.inference)
            {
                Ok(request) => request.into_request(),
                Err(error) => return Ok(charges.park(&error.to_string())),
            };
            if let Err(error) = super::roles::bind_reasoning(ctx.vault, call.backend, &mut request)
            {
                return Ok(charges.park(&error.to_string()));
            }
            let step_hash = match request.canonical_hash() {
                Ok(hash) => hash,
                Err(_) => return Ok(charges.park("sieve request did not hash")),
            };
            let step = DurableStepContext {
                vault: ctx.vault,
                attempt_id: attempt.status.attempt.id,
                run_id: attempt.status.attempt.run_id.clone(),
                envelope_actor: self.actor,
                subject: input.span.turn,
                deadline: Some(ctx.deadline),
                now_ms: ctx.now_ms,
            };
            let entities = evidence.entities.clone();
            let check = move |response: &crate::llm::LlmResponse| {
                decode_reading(response, &entities).map(|_| ())
            };
            let response = match call_as_step_checked(
                &step,
                call.backend,
                self.guard,
                request,
                &check,
            )
            .await
            {
                Ok(StepOutcome::Finished {
                    response,
                    failure_policy,
                    ..
                }) => {
                    charges.record_terminal(
                        ctx.vault,
                        attempt.status.attempt.id,
                        step_hash,
                        &response.usage,
                    )?;
                    if failure_policy.is_some() {
                        return Ok(charges.park("sieve rung requires a model reading"));
                    }
                    response
                }
                Ok(StepOutcome::Trapped { .. }) => {
                    return Ok(charges
                        .park_for("durable step trapped for resume", DreamerParkCause::Signal));
                }
                Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.checkpoint());
                }
                Err(DurableStepError::SpentSchemaValidation { usage, .. }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.park("sieve reading schema refused"));
                }
                Err(DurableStepError::Engine(error)) if charges.units == 0 => return Err(error),
                Err(error) => {
                    return Ok(
                        charges.park_for(&error.to_string(), DreamerParkCause::of_step(&error))
                    );
                }
            };
            if ctx.deadline.expired() {
                return Ok(charges.checkpoint());
            }
            reading = match decode_reading(&response, &evidence.entities) {
                Ok(reading) => reading,
                Err(reason) => return Ok(charges.park(&reason)),
            };
            // Novelty can move a sure rule reading into the uncertain band.
            // Such a reading owes typing even if the rule did not owe it.
            if rung == SieveRung::Novelty
                && !input.audit
                && !input.span.owed.contains(&SieveRung::Typing)
            {
                let policy = match ctx.vault.dreamer_sieve_policy() {
                    Ok(policy) => policy,
                    Err(error) => return Ok(charges.park(&error.to_string())),
                };
                if reading.confidence >= policy.uncertain_low
                    && reading.confidence < policy.uncertain_high
                {
                    // Finish novelty with typing still owed; the next bounded
                    // continuous pass schedules that remaining rung.
                    return self.save_sieve_reading(
                        attempt, ctx, &input, &evidence, reading, &charges, true,
                    );
                }
            }
        }
        self.save_sieve_reading(attempt, ctx, &input, &evidence, reading, &charges, false)
    }

    fn save_sieve_reading(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        input: &RungInput,
        evidence: &sieve::RungEvidence,
        reading: Reading,
        charges: &StepChargeTally,
        typing_owed: bool,
    ) -> Result<DreamerAttemptExecution> {
        match sieve::finish_rungs(
            ctx.vault,
            attempt.status.attempt.id,
            input,
            evidence,
            reading.kind,
            reading.entity,
            reading.novel,
            reading.confidence,
            typing_owed,
            charges.units,
            charges.step_hashes.clone(),
            ctx.now_ms / 1_000,
        ) {
            Ok(true) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
            }),
            Ok(false) => Ok(DreamerAttemptExecution::Deferred {
                completed_units: charges.units,
                retry_at: ctx
                    .now_ms
                    .div_ceil(1_000)
                    .saturating_add(input.policy.rung_retry_secs),
            }),
            Err(error) => Ok(charges.park(&error.to_string())),
        }
    }
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid sieve rung payload".into())
}

fn decode_reading(
    response: &crate::llm::LlmResponse,
    entities: &[EntityId],
) -> std::result::Result<Reading, String> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let reading: Reading =
        serde_json::from_str(text.trim()).map_err(|_| "invalid sieve reading JSON".to_owned())?;
    if reading.confidence > 100 || reading.entity.is_some_and(|id| !entities.contains(&id)) {
        return Err("sieve reading confidence or entity outside contract".into());
    }
    Ok(reading)
}
