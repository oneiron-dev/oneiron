//! The sieve's owed novelty/typing rungs and its sampled expensive-path audit.
//! Calls use the host's existing extraction and verdict roles; receipts and
//! wake charges use the same durable step layer as consolidation.

mod audit;

use serde::Deserialize;
use std::collections::BTreeMap;

use super::call_labels::{CallLabel, CallLabelMap, LabelKind};
use super::executor::ConsolidationExecutor;
use super::roles::{DREAMER_EXTRACTION_ROLE, DREAMER_VERDICT_ROLE, RoleCall};
use super::step_charge::StepChargeTally;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::sieve::{self, RungInput};
use crate::dreamer_wake::{
    DreamerAttemptExecution, SieveRung, SieveSpan, SpanKind, SpanOrigin, WakeAttemptContext,
};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext, DurableStepError,
    LlmMessage, LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, StepOutcome,
    TierPrecedence, call_as_step_checked,
};
use crate::{EntityId, Error, Result};

#[derive(Clone)]
struct Reading {
    kind: SpanKind,
    novel: bool,
    confidence: u8,
    entity: Option<EntityId>,
}

/// A reading as the model writes it (FIX 7506): its entity is one of the
/// call's `P<n>` labels, never an id.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReading {
    kind: SpanKind,
    novel: bool,
    confidence: u8,
    entity: Option<String>,
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
        let payload = attempt.status.payload.input.as_str().ok_or_else(invalid)?;
        let input: RungInput = match serde_json::from_str(payload) {
            Ok(input) => input,
            // An unflagged window's audit rides the same attempt type with
            // its own input (OF-498f); every span input reads as before.
            Err(_) => {
                let window: sieve::WindowAuditInput =
                    serde_json::from_str(payload).map_err(|_| invalid())?;
                return self.run_sieve_window_audit(attempt, ctx, window).await;
            }
        };
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
        // Every rung's call names the span's turn, source and entities by
        // its own labels (FIX 7506), built before any renders.
        let labels = rung_labels(&input.span, &evidence.entities);
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
                // A missing locality, a request that did not hash and an
                // unreadable reading wait on no owner act: each resumes
                // after its retry delay (OF-193a).
                None => {
                    return Ok(charges
                        .park_for("sieve host binding needs locality", DreamerParkCause::Retry));
                }
            };
            let candidates: Vec<String> = evidence
                .entities
                .iter()
                .filter_map(|id| labels.label(LabelKind::Entity, *id))
                .map(label_text)
                .collect();
            let data = serde_json::json!({
                "span": span_view(&input.span, &evidence.text, &labels),
                "context": evidence.text,
                "entity_candidates": candidates,
                "previous": reading_view(&reading, &labels),
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
            labels.bind_request(&mut request, None);
            request = match ctx
                .vault
                .authorize_model_role(role, request, &call.inference)
            {
                Ok(request) => request.into_request(),
                Err(error) => return Ok(charges.park_on_error(&error)),
            };
            if let Err(error) = super::roles::bind_reasoning(ctx.vault, call.backend, &mut request)
            {
                return Ok(charges.park_on_error(&error));
            }
            let step_hash = match request.canonical_hash() {
                Ok(hash) => hash,
                Err(_) => {
                    return Ok(
                        charges.park_for("sieve request did not hash", DreamerParkCause::Retry)
                    );
                }
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
            let check_labels = labels.clone();
            // A fallback whose park would resume as a Retry is refused inside
            // the step too, never memoized, so the Retry asks again (FIX 7431).
            let check = move |response: &crate::llm::LlmResponse| {
                if super::step_charge::retry_fallback(response) {
                    return Err(SIEVE_FALLBACK.to_owned());
                }
                decode_reading(response, &check_labels, &entities).map(|_| ())
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
                        return charges.park_on_fallback(
                            ctx.vault,
                            attempt.status.attempt.id,
                            step_hash,
                            SIEVE_FALLBACK,
                            &response,
                        );
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
                // A refused reading asks again after its retry delay (FIX
                // 7218, Engine 10-21).
                Err(DurableStepError::SpentSchemaValidation { usage, .. }) => {
                    charges.record_usage(&usage);
                    return Ok(
                        charges.park_for("sieve reading schema refused", DreamerParkCause::Retry)
                    );
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
            reading = match decode_reading(&response, &labels, &evidence.entities) {
                Ok(reading) => reading,
                Err(reason) => return Ok(charges.park_for(&reason, DreamerParkCause::Retry)),
            };
            // Novelty can move a sure rule reading into the uncertain band.
            // Such a reading owes typing even if the rule did not owe it.
            if rung == SieveRung::Novelty
                && !input.audit
                && !input.span.owed.contains(&SieveRung::Typing)
            {
                let policy = match ctx.vault.dreamer_sieve_policy() {
                    Ok(policy) => policy,
                    Err(error) => return Ok(charges.park_on_error(&error)),
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
            Err(error) => Ok(charges.park_on_error(&error)),
        }
    }
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid sieve rung payload".into())
}

/// Why a rung parks on a deterministic fallback.
const SIEVE_FALLBACK: &str = "sieve rung requires a model reading";

/// The labels one span's rungs call with: its turn `T1`, the MESSAGE its
/// offsets index `S1` (none when that is the turn itself), and each entity
/// candidate `P<n>` in order, then the span's own entity when it is none of
/// them.
fn rung_labels(span: &SieveSpan, entities: &[EntityId]) -> CallLabelMap {
    let mut labels = CallLabelMap::default();
    labels.assign(LabelKind::Turn, span.turn);
    if span.source != span.turn {
        labels.assign(LabelKind::Source, span.source);
    }
    for id in entities.iter().copied().chain(span.entity) {
        labels.assign(LabelKind::Entity, id);
    }
    labels
}

/// What the model reads of a span: its words in place of its offsets, each
/// id as its call's label, and every other reading it carries. Its own id,
/// digests and offsets stay the engine's.
fn span_view(span: &SieveSpan, text: &str, labels: &CallLabelMap) -> serde_json::Value {
    let words = usize::try_from(span.start)
        .ok()
        .zip(usize::try_from(span.end).ok())
        .and_then(|(start, end)| text.get(start..end));
    let source = labels
        .label(LabelKind::Source, span.source)
        .or_else(|| labels.label(LabelKind::Turn, span.source));
    let origin = match span.origin {
        SpanOrigin::Rule { rules, class } => {
            serde_json::json!({"rule": {"rules": rules, "class": class}})
        }
        SpanOrigin::SavedTag { index, .. } => serde_json::json!({"saved_tag": {"index": index}}),
    };
    serde_json::json!({
        "turn": labels.label(LabelKind::Turn, span.turn).map(label_text),
        "source": source.map(label_text),
        "text": words,
        "kind": span.kind,
        "entity": entity_view(span.entity, labels),
        "novel": span.novel,
        "origin": origin,
        "confidence": span.confidence,
        "score": span.score,
        "band": span.band,
        "owed": span.owed,
        "queued_at": span.queued_at,
    })
}

/// A reading as the model reads it back, its entity as its label.
fn reading_view(reading: &Reading, labels: &CallLabelMap) -> serde_json::Value {
    serde_json::json!({
        "kind": reading.kind,
        "novel": reading.novel,
        "confidence": reading.confidence,
        "entity": entity_view(reading.entity, labels),
    })
}

fn label_text(label: CallLabel) -> String {
    label.to_string()
}

fn entity_view(entity: Option<EntityId>, labels: &CallLabelMap) -> Option<String> {
    entity
        .and_then(|id| labels.label(LabelKind::Entity, id))
        .map(label_text)
}

/// `response`'s reading, its entity label read back through `labels`; a
/// label the call did not show, or an entity outside the span's candidates,
/// is outside the contract.
fn decode_reading(
    response: &crate::llm::LlmResponse,
    labels: &CallLabelMap,
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
    let reading: WireReading =
        serde_json::from_str(text.trim()).map_err(|_| "invalid sieve reading JSON".to_owned())?;
    let outside = || "sieve reading confidence or entity outside contract".to_owned();
    let entity = reading
        .entity
        .as_deref()
        .map(|label| {
            labels
                .resolve_as(LabelKind::Entity, label)
                .ok_or_else(outside)
        })
        .transpose()?;
    if reading.confidence > 100 || entity.is_some_and(|id| !entities.contains(&id)) {
        return Err(outside());
    }
    Ok(Reading {
        kind: reading.kind,
        novel: reading.novel,
        confidence: reading.confidence,
        entity,
    })
}
