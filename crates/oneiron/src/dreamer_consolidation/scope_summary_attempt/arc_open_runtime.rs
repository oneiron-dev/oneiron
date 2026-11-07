//! Advisory typed openings: the narrative reader remains free to open any TURN.

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::executor::{ConsolidationDecisions, Decider, ScopedRead};
use super::super::roles::{DREAMER_VERDICT_ROLE, RoleCall, bind_reasoning};
use super::super::step_charge::StepChargeTally;
use super::super::support::invalid_consolidation;
use super::arc_open_backend::FreshBackend;
use super::arc_open_questions::OpenQuestion;
use super::window::framed_tokens;
use super::{CallLabelMap, EntityId, ScopeSummaryEvidence, ScopeSummaryExecutor};
use crate::dreamer_runner::DreamerParkCause;
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::Result;
use crate::llm::decision::AskTo;
use crate::model_decision::{DecisionAnswer, DecisionRung, EvidenceVersion};
use crate::model_step_context::DurableStepContext;
use crate::model_step_error::DurableStepError;
use oneiron_model::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, LlmRequest,
    ModelTierRef, ResponseFormat, Scope, TierPrecedence,
};

/// The first generation is observable. Staffed stronger providers need their own
/// per-read accounting before this advisory can use them under the Arc's pace.
fn generated_only(decisions: &ConsolidationDecisions) -> bool {
    let first = decisions.dial.first;
    let ceiling = decisions.dial.ceiling.min(DecisionRung::Big);
    if !matches!(
        first,
        DecisionRung::Local | DecisionRung::SystemOne | DecisionRung::Big
    ) || first > ceiling
    {
        return false;
    }
    [
        (DecisionRung::SystemOne, &decisions.ladder.system_one),
        (DecisionRung::Escalation, &decisions.ladder.escalation),
        (DecisionRung::Big, &decisions.ladder.big),
    ]
    .into_iter()
    .all(|(rung, provider)| rung <= first || rung > ceiling || provider.is_none())
}

impl<E> ScopeSummaryExecutor<'_, E> {
    #[expect(
        clippy::too_many_arguments,
        reason = "one scoped read shares the composition's input, clock and spend"
    )]
    pub(super) async fn arc_open_turns(
        &self,
        ctx: &WakeAttemptContext<'_>,
        step: &DurableStepContext<'_>,
        evidence: &ScopeSummaryEvidence,
        user: &str,
        labels: &CallLabelMap,
        candidates: &[EntityId],
        calls: &mut u32,
        limit: Option<u32>,
        charges: &mut StepChargeTally,
    ) -> Result<ControlFlow<DreamerAttemptExecution, Vec<EntityId>>> {
        let mut opens = Vec::new();
        let (Some((decisions, roles)), Some(limit)) = (&self.arc_decisions, limit) else {
            return Ok(ControlFlow::Continue(opens));
        };
        if !generated_only(decisions) {
            return Ok(ControlFlow::Continue(opens));
        }
        let Ok(input) = serde_json::from_str::<serde_json::Value>(user) else {
            return Ok(ControlFlow::Continue(opens));
        };
        let mut versions = Vec::new();
        let mut rows = Vec::new();
        for pin in &evidence.source_versions {
            let Ok(id) = EntityId::from_hex(&pin.id) else {
                return Ok(ControlFlow::Continue(opens));
            };
            if let Some(body_hash) = pin.revision {
                versions.push(EvidenceVersion { id, body_hash });
                rows.push(id);
            }
        }
        let correlation = EntityId::from_bytes(*step.attempt_id.as_bytes())?;
        let to = AskTo::owner();
        for turn in candidates {
            // Keep one call for the original narrative reader. Memos spend no pace.
            if *calls >= limit.saturating_sub(1) {
                break;
            }
            if ctx.deadline.expired() {
                return Ok(ControlFlow::Break(charges.checkpoint()));
            }
            let pack = match OpenQuestion::of(
                &decisions.arc_open_wording,
                step.attempt_id.as_bytes(),
                *turn,
                &input,
                labels,
            ) {
                Ok(Some(pack)) => pack,
                _ => continue,
            };
            let mut labels = pack.labels;
            for question in decisions
                .ladder
                .paired
                .iter()
                .chain(&decisions.ladder.person)
            {
                labels.assign(super::super::call_labels::LabelKind::Question, question.id);
            }
            let role = RoleCall::resolve(
                roles,
                DREAMER_VERDICT_ROLE,
                self.backend,
                &self.model,
                &self.inference.binding,
                self.inference.extraction_egress,
            );
            let Some(locality) = role.inference.selected_locality() else {
                continue;
            };
            let sources: Vec<_> = rows.iter().copied().chain(labels.rows()).collect();
            let route = role.call_backend(Some(sources));
            let backend = FreshBackend {
                inner: route.get(),
                fresh: AtomicBool::new(false),
            };
            let call = RoleCall {
                backend: &backend,
                model: role.model,
                inference: role.inference,
                sourced: None,
            };
            let shell = LlmRequest {
                model: call.model.clone(),
                envelope: CallEnvelope {
                    seat_effort: None,
                    scope: Scope {
                        readable: evidence.readable.clone(),
                        ..Scope::default()
                    },
                    purpose: CallPurpose::Extraction,
                    class: CallClass::Durable {
                        fallback: DeterministicFallback {
                            name: "json_rules_v1".into(),
                            config: None,
                        },
                    },
                    tier: TierPrecedence::for_purpose(
                        &CallPurpose::Extraction,
                        ModelTierRef("consolidation".into()),
                    ),
                    response_format: ResponseFormat::Text,
                    locality,
                    host_keyless: call.inference.selected_keyless(),
                    host_paid: call.inference.selected_paid(),
                }
                .with_purpose_defaults(),
                messages: Vec::new(),
                tools: Vec::new(),
                params: Default::default(),
                provider_options: Default::default(),
                host_segments: None,
            };
            let window = ctx
                .vault
                .model_registry_row(call.model)
                .ok()
                .flatten()
                .and_then(|row| {
                    let context = row.catalog.context_window_tokens;
                    let output = row
                        .catalog
                        .max_output_tokens
                        .filter(|output| *output < context)
                        .unwrap_or(0);
                    (context > 0).then_some(context - output)
                });
            let seal = |request: LlmRequest| -> Result<LlmRequest> {
                let mut request = ctx
                    .vault
                    .authorize_model_role(DREAMER_VERDICT_ROLE, request, &call.inference)?
                    .into_request();
                bind_reasoning(ctx.vault, call.backend, &mut request)?;
                if let (Some(window), ResponseFormat::Json { schema }) =
                    (window, &request.envelope.response_format)
                {
                    let text = request
                        .messages
                        .iter()
                        .flat_map(|message| &message.content)
                        .filter_map(|part| {
                            if let ContentPart::Text { text, .. } = part {
                                Some(text.as_str())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    if framed_tokens("", &text, schema)? > window {
                        return Err(invalid_consolidation(
                            "arc opening does not fit its verdict model",
                        ));
                    }
                }
                Ok(request)
            };
            let mut spent = Vec::new();
            let decided = Decider {
                decisions,
                actor: self.actor,
                guard: self.guard,
            }
            .decide_scoped(
                ScopedRead {
                    step,
                    pass: ctx.deadline,
                    call: &call,
                    shell,
                    seal: &seal,
                    versions: &versions,
                    to: &to,
                    correlation,
                    evidence: &rows,
                    state: &pack.state,
                    ceiling: DecisionRung::Big,
                    sources: None,
                },
                std::slice::from_ref(&pack.question),
                &labels,
                &mut spent,
            )
            .await;
            let fresh = backend.fresh.load(Ordering::Relaxed);
            if fresh {
                *calls = calls.saturating_add(1);
            }
            for (hash, usage, ..) in &spent {
                if let Err(error) =
                    charges.record_terminal(ctx.vault, step.attempt_id, *hash, usage)
                {
                    if fresh {
                        charges.record_usage(usage);
                    }
                    return Ok(ControlFlow::Break(charges.park_on_error(&error)));
                }
            }
            match decided {
                Ok(Some(kept)) => {
                    if kept.iter().any(|kept| {
                        kept.decision.receipt.question == pack.question.id
                            && kept.answer() == Some(&DecisionAnswer::Noul(true))
                    }) {
                        opens.push(pack.turn);
                    }
                }
                Ok(None) => {
                    return Ok(ControlFlow::Break(charges.park_for(
                        "durable step trapped for resume",
                        DreamerParkCause::Signal,
                    )));
                }
                Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                    charges.record_usage(&usage);
                    return Ok(ControlFlow::Break(charges.checkpoint()));
                }
                Err(DurableStepError::FinalizeRefused | DurableStepError::DeadlineHardCut) => {
                    return Ok(ControlFlow::Break(charges.checkpoint()));
                }
                Err(
                    DurableStepError::SpentSchemaValidation { usage, .. }
                    | DurableStepError::SpentLlm { usage, .. }
                    | DurableStepError::SpentFallback { usage, .. },
                ) => charges.record_usage(&usage),
                // An auxiliary read never becomes a new refusal of the narrative path.
                Err(_) => {}
            }
        }
        Ok(ControlFlow::Continue(opens))
    }
}
