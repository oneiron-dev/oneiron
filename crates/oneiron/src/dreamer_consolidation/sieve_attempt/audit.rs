//! The sieve audit of an unflagged window (OF-498f, FIX 486): the expensive
//! path reads a source range the cheap rules flagged nothing in and names
//! every date or name it finds there, zero or more. Each one cites the
//! window by its call label and a quote, and the call's quote binder binds
//! its exact bytes (FIX 7506); an empty list is a negative label, a full
//! answer. A quote the window holds nowhere or more than once keeps its
//! discovery as an unlocated one, with no offsets (FIX 7901); the reply's
//! other discoveries land as they bind. A flagged span's audit runs as
//! before, in the rung loop.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::super::call_labels::{CallLabelMap, CallSources, LabelKind, SourceShown};
use super::super::executor::ConsolidationExecutor;
use super::super::executor::extraction::{QuoteBinding, bind_quote};
use super::super::roles::{DREAMER_EXTRACTION_ROLE, RoleCall};
use super::super::step_charge::{StepChargeTally, reply_text, retry_fallback};
use super::{SIEVE_FALLBACK, label_text};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::sieve::{self, WindowAuditInput, WindowOutcome, WindowRead};
use crate::dreamer_wake::{
    DreamerAttemptExecution, SieveAuditDiscovery, SieveAuditWindow, SieveUnlocatedCause,
    SieveUnlocatedDiscovery, SpanKind, WakeAttemptContext,
};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext, DurableStepError,
    LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, ModelTierRef, ResponseFormat, StepOutcome,
    TierPrecedence, call_as_step_checked,
};
use crate::{EntityId, Result};

/// A finding as the model writes it: each span it found, by the window's
/// label and words copied from it, never an id or an offset.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFinding {
    discovered: Vec<WireDiscovery>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDiscovery {
    source: String,
    quote: String,
    kind: SpanKind,
    confidence: u8,
}

/// What one window audit's call showed: its labels, and the window's words
/// as the one source a quote binds against.
struct WindowShown<'a> {
    labels: &'a CallLabelMap,
    source: EntityId,
    text: &'a str,
}

impl CallSources for WindowShown<'_> {
    fn labels(&self) -> &CallLabelMap {
        self.labels
    }

    fn shown(&self, id: EntityId) -> Option<SourceShown<'_>> {
        (id == self.source).then_some(SourceShown {
            text: Some(self.text),
            project: None,
        })
    }
}

impl ConsolidationExecutor<'_> {
    pub(super) async fn run_sieve_window_audit(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        input: WindowAuditInput,
    ) -> Result<DreamerAttemptExecution> {
        if let Some((completed_units, step_hashes)) =
            sieve::rung_result_units(ctx.vault, attempt.status.attempt.id)?
        {
            return Ok(DreamerAttemptExecution::Completed {
                completed_units,
                step_hashes,
            });
        }
        let retry_at = ctx
            .now_ms
            .div_ceil(1_000)
            .saturating_add(input.policy.rung_retry_secs);
        let evidence = match sieve::window_read(ctx.vault, &input)? {
            WindowRead::Ready(evidence) => evidence,
            WindowRead::Superseded => {
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units: 0,
                    step_hashes: Vec::new(),
                });
            }
            // The source may be withheld for now: the audit waits for it.
            WindowRead::Withheld => {
                return Ok(DreamerAttemptExecution::Deferred {
                    completed_units: 0,
                    retry_at,
                    step_hashes: Vec::new(),
                });
            }
        };
        let window = input.window;
        let mut charges = StepChargeTally::default();
        let call = RoleCall::resolve(
            &self.roles,
            DREAMER_EXTRACTION_ROLE,
            self.backend,
            &self.model,
            &self.inference.binding,
            self.inference.extraction_egress,
        );
        let Some(locality) = call.inference.selected_locality() else {
            return Ok(
                charges.park_for("sieve host binding needs locality", DreamerParkCause::Retry)
            );
        };
        let labels = window_labels(&window);
        let source = labels
            .label(LabelKind::Source, window.source)
            .or_else(|| labels.label(LabelKind::Turn, window.source));
        let data = serde_json::json!({
            "window": {
                "turn": labels.label(LabelKind::Turn, window.turn).map(label_text),
                "source": source.map(label_text),
                "text": evidence.text,
            },
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
                host_keyless: false,
            }
            .with_purpose_defaults(),
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: input.policy.audit_window_instruction.clone(),
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
            host_segments: None,
        };
        labels.bind_request(&mut request, None);
        request =
            match ctx
                .vault
                .authorize_model_role(DREAMER_EXTRACTION_ROLE, request, &call.inference)
            {
                Ok(request) => request.into_request(),
                Err(error) => return Ok(charges.park_on_error(&error)),
            };
        if let Err(error) =
            super::super::roles::bind_reasoning(ctx.vault, call.backend, &mut request)
        {
            return Ok(charges.park_on_error(&error));
        }
        let Ok(step_hash) = request.canonical_hash() else {
            return Ok(charges.park_for("sieve request did not hash", DreamerParkCause::Retry));
        };
        let step = DurableStepContext {
            vault: ctx.vault,
            attempt_id: attempt.status.attempt.id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject: window.turn,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let check_labels = labels.clone();
        let check_text = evidence.text.clone();
        // A fallback whose park would resume as a Retry is refused inside the
        // step, never memoized, so the Retry asks again (FIX 7431); so is a
        // finding outside its contract. A quote that binds no one place is
        // inside it (FIX 7901).
        let check = move |response: &LlmResponse| {
            if retry_fallback(response) {
                return Err(SIEVE_FALLBACK.to_owned());
            }
            let shown = WindowShown {
                labels: &check_labels,
                source: window.source,
                text: &check_text,
            };
            decode_finding(response, &shown, &window).map(|_| ())
        };
        let response = match call_as_step_checked(&step, call.backend, self.guard, request, &check)
            .await
        {
            Ok(StepOutcome::Finished {
                response,
                memoized,
                failure_policy,
                ..
            }) => {
                if let Err(error) = charges.record_terminal(
                    ctx.vault,
                    attempt.status.attempt.id,
                    step_hash,
                    &response.usage,
                ) {
                    if !memoized {
                        charges.record_usage(&response.usage);
                    }
                    return super::super::residency::spent_or_deferred(error, ctx, &charges);
                }
                if failure_policy.is_some() {
                    return match charges.park_on_fallback(
                        ctx.vault,
                        attempt.status.attempt.id,
                        step_hash,
                        SIEVE_FALLBACK,
                        &response,
                    ) {
                        Ok(parked) => Ok(parked),
                        Err(error) => {
                            super::super::residency::spent_or_deferred(error, ctx, &charges)
                        }
                    };
                }
                response
            }
            Ok(StepOutcome::Trapped { .. }) => {
                return Ok(
                    charges.park_for("durable step trapped for resume", DreamerParkCause::Signal)
                );
            }
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                return Ok(charges.checkpoint());
            }
            // A refused finding asks again after its retry delay, as a
            // refused reading does (FIX 7218).
            Err(DurableStepError::SpentSchemaValidation { usage, .. }) => {
                charges.record_usage(&usage);
                return Ok(charges.park_for(
                    "sieve window finding schema refused",
                    DreamerParkCause::Retry,
                ));
            }
            Err(DurableStepError::Engine(error)) if charges.units == 0 => return Err(error),
            Err(error) => {
                return Ok(charges.park_for(&error.to_string(), DreamerParkCause::of_step(&error)));
            }
        };
        if ctx.deadline.expired() {
            return Ok(charges.checkpoint());
        }
        let shown = WindowShown {
            labels: &labels,
            source: window.source,
            text: &evidence.text,
        };
        let (discovered, unlocated) = match decode_finding(&response, &shown, &window) {
            Ok(found) => found,
            Err(reason) => return Ok(charges.park_for(&reason, DreamerParkCause::Retry)),
        };
        let outcome = WindowOutcome {
            discovered,
            unlocated,
            completed_units: charges.units,
            step_hashes: charges.step_hashes.clone(),
            at: ctx.now_ms / 1_000,
        };
        match sieve::finish_window_audit(
            ctx.vault,
            attempt.status.attempt.id,
            &input,
            &evidence,
            outcome,
        ) {
            Ok(true) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
                step_hashes: charges.step_hashes.clone(),
            }),
            Ok(false) => Ok(DreamerAttemptExecution::Deferred {
                completed_units: charges.units,
                retry_at,
                step_hashes: charges.step_hashes.clone(),
            }),
            Err(error) => Ok(charges.park_on_error(&error)),
        }
    }
}

/// The labels a window's call names its turn `T1` and the MESSAGE its
/// offsets index `S1` by (none when that is the turn itself).
fn window_labels(window: &SieveAuditWindow) -> CallLabelMap {
    let mut labels = CallLabelMap::default();
    labels.assign(LabelKind::Turn, window.turn);
    if window.source != window.turn {
        labels.assign(LabelKind::Source, window.source);
    }
    labels
}

/// A window finding as the engine keeps it: the spans it located, and the
/// ones its quotes locate no one place (FIX 7901).
type Found = (Vec<SieveAuditDiscovery>, Vec<SieveUnlocatedDiscovery>);

/// `response`'s finding, each span bound through the call's quote binder to
/// its exact bytes of the window's source. A quote the window holds nowhere
/// or more than once keeps its span unlocated, with no offsets. A label the
/// call did not show, an empty quote or a confidence past 100 is outside
/// the contract; an empty list is a finding.
fn decode_finding(
    response: &LlmResponse,
    shown: &WindowShown<'_>,
    window: &SieveAuditWindow,
) -> std::result::Result<Found, String> {
    let finding: WireFinding = serde_json::from_str(reply_text(response).trim())
        .map_err(|_| "invalid sieve window finding JSON".to_owned())?;
    let mut located = Vec::new();
    let mut unlocated = Vec::new();
    for found in &finding.discovered {
        if found.confidence > 100 {
            return Err("sieve window finding confidence outside contract".to_owned());
        }
        let cause = match bind_quote(shown.named(&found.source), &found.quote) {
            QuoteBinding::Bound { start, end, .. } => {
                located.push(SieveAuditDiscovery {
                    start: window.start.saturating_add(start as u64),
                    end: window.start.saturating_add(end as u64),
                    kind: found.kind,
                    confidence: found.confidence,
                });
                continue;
            }
            QuoteBinding::QuoteNotFound => SieveUnlocatedCause::QuoteNotFound,
            QuoteBinding::QuoteAmbiguous => SieveUnlocatedCause::QuoteAmbiguous,
            fault @ (QuoteBinding::EmptyQuote | QuoteBinding::UnknownSourceLabel) => {
                return Err(fault.name().to_owned());
            }
        };
        unlocated.push(SieveUnlocatedDiscovery {
            kind: found.kind,
            confidence: found.confidence,
            cause,
            quote: found.quote.clone(),
        });
    }
    Ok((located, unlocated))
}
