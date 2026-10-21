//! An Arc's composition (FIX 7509 P8, SUMMARY-SOURCE = A). The call reads
//! its sittings' summary lines, the TURNs read again in place of a line,
//! and the claims and open conflicts of the subjects its TURNs name; its
//! reply is `{lines: [{text, turn_refs}], keep, open_turns}`, each line
//! citing the TURNs it came from by their `T` labels (P7a's checked lines).
//!
//! The model decides where a line and the claims disagree: a reply naming
//! `open_turns` writes nothing. The engine opens those turns through their
//! handles ([`super::arc_turns`]) and composes again with their words, and
//! again while a reply names turns not yet open: each round opens more, so
//! the rounds end. Only a reply asking for none lands.
//!
//! Rule 5 until exhaustive Arc splitting (PR3): an input that fits one call
//! on its model's window is composed; a larger one stays owed as
//! `arc_needs_split`, never written smaller. A sitting's owed summary or a
//! TURN that does not open leaves it owed too, each typed on its row.

use super::super::call_labels::{CallLabelMap, LabelKind};
use super::super::residency::{residency_deferral, waits_on_residency};
use super::super::step_charge::StepChargeTally;
use super::super::support::invalid_consolidation;
use super::arc_evidence::ArcView;
use super::arc_turns::{Opened, open_turns};
use super::chunks::framed_tokens;
use super::output::reply_text;
use super::{ScopeSummaryEvidence, ScopeSummaryExecutor, compose_again};
use crate::EntityId;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::{Error, Result};
use crate::llm::{
    DurableStepContext, DurableStepError, LlmResponse, StepOutcome, call_as_step_checked,
};
use crate::scope_summary::{
    ArcPendingCause, ComposedSummary, ScopeSummaryPlan, SummaryLineSources,
};
use serde::Deserialize;
use std::collections::BTreeSet;

/// The identity an Arc's composition is known by.
const ARC_DOMAIN: &str = "oneiron:arc-summary-composition:v1";

impl<E> ScopeSummaryExecutor<'_, E> {
    /// Composes the Arc `plan` declares over `evidence`, under the host's
    /// `instruction`, landing it through the landing fence.
    pub(super) async fn compose_arc(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        plan: &ScopeSummaryPlan,
        evidence: &ScopeSummaryEvidence,
        instruction: &str,
    ) -> Result<DreamerAttemptExecution> {
        let attempt_id = attempt.status.attempt.id;
        let (Some(arc), Some(view), Some(scope)) = (&plan.arc, &evidence.arc, &plan.scope) else {
            return Err(invalid_consolidation("an arc composes from its sittings"));
        };
        let none = StepChargeTally::default();
        if let Some(session) = arc.owed.first() {
            let cause = ArcPendingCause::LowerPending {
                session: session.to_hex(),
            };
            return owe(ctx, plan, cause, &none);
        }
        if let Some(turn) = view.unavailable {
            let cause = ArcPendingCause::SourceUnavailable {
                handle: turn.to_hex(),
            };
            return owe(ctx, plan, cause, &none);
        }
        // Sittings with no line in the Arc's scope leave nothing to write.
        let Some(first) = evidence.covers.first().copied() else {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        };
        let schema = arc_schema();
        let params = serde_json::to_vec(&(instruction, self.model.as_str(), &schema, ARC_DOMAIN))
            .map_err(|_| invalid_consolidation("summary policy did not encode"))?;
        let params_hash = *blake3::hash(&params).as_bytes();
        let memo = plan.composition_memo(evidence, &params_hash)?;
        // The same composition already stands: no call, no second SUMMARY.
        match ctx.vault.reuse_composed_scope_summary(
            attempt_id,
            plan,
            evidence,
            &first,
            &memo,
            &params_hash,
        ) {
            Ok(true) => return Ok(DreamerAttemptExecution::Completed { completed_units: 0 }),
            Ok(false) => {}
            Err(error) if waits_on_residency(&error) => {
                return Ok(residency_deferral(ctx.now_ms, 0));
            }
            Err(error) => return Err(error),
        }
        let step_ctx = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject: scope.conversation,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let covers: BTreeSet<EntityId> = evidence.covers.iter().copied().collect();
        let mut charges = StepChargeTally::default();
        let mut opened = view.opened.clone();
        let mut opened_text = String::new();
        let lines = loop {
            let user = arc_input(plan, view, &opened_text)?;
            if let Some(window) = self.session_window(ctx.vault) {
                let tokens = framed_tokens(instruction, &user, &schema)?;
                if tokens > window {
                    let cause = ArcPendingCause::NeedsSplit { tokens, window };
                    return owe(ctx, plan, cause, &charges);
                }
            }
            if ctx.deadline.expired() {
                return Ok(charges.checkpoint());
            }
            let mut request =
                self.summary_request(ctx.vault, evidence, schema.clone(), instruction, user)?;
            view.labels.bind_request(&mut request, None);
            let step_hash = request
                .canonical_hash()
                .map_err(|_| invalid_consolidation("summary request did not hash"))?;
            let check_labels = view.labels.clone();
            let check_opened = opened.clone();
            let check_covers = covers.clone();
            let check = move |response: &LlmResponse| {
                arc_output(response, &check_labels, &check_opened, &check_covers)
                    .map(drop)
                    .map_err(str::to_owned)
            };
            let outcome =
                call_as_step_checked(&step_ctx, self.backend, self.guard, request, &check).await;
            let response = match outcome {
                Ok(StepOutcome::Finished { response, .. }) => {
                    if let Err(error) =
                        charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)
                    {
                        return Ok(charges.park_on_error(&error));
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
                Err(DurableStepError::DeadlineHardCut) => return Ok(charges.checkpoint()),
                Err(DurableStepError::FinalizeRefused) => {
                    return Ok(
                        charges.park_for("wake pass finalize window", DreamerParkCause::Checkpoint)
                    );
                }
                Err(DurableStepError::Engine(error)) => return Ok(charges.park_on_error(&error)),
                Err(other @ DurableStepError::SpentSchemaValidation { .. }) => {
                    if let DurableStepError::SpentSchemaValidation { usage, .. } = &other {
                        charges.record_usage(usage);
                    }
                    return Ok(charges.park_for(&other.to_string(), DreamerParkCause::Retry));
                }
                Err(other) => {
                    return Ok(
                        charges.park_for(&other.to_string(), DreamerParkCause::of_step(&other))
                    );
                }
            };
            let ask = match arc_output(&response, &view.labels, &opened, &covers) {
                Ok(ArcReply::Lines(lines)) => break lines,
                Ok(ArcReply::Open(ask)) => ask,
                Err(reason) => return Ok(charges.park_for(reason, DreamerParkCause::Retry)),
            };
            match open_turns(ctx.vault, evidence, view, &ask) {
                Ok(Opened::Text(text)) => {
                    opened_text.push_str(&text);
                    opened.extend(ask);
                }
                Ok(Opened::Unavailable(turn)) => {
                    let cause = ArcPendingCause::SourceUnavailable {
                        handle: turn.to_hex(),
                    };
                    return owe(ctx, plan, cause, &charges);
                }
                Err(Error::ConcurrentWrite(_)) => return Ok(compose_again(&charges, ctx.now_ms)),
                Err(error) if waits_on_residency(&error) => {
                    return Ok(residency_deferral(ctx.now_ms, charges.units));
                }
                Err(error) => return Ok(charges.park_on_error(&error)),
            }
        };
        if ctx.deadline.expired() {
            return Ok(charges.checkpoint());
        }
        let composed = ComposedSummary {
            text: &lines.text,
            keep: &lines.keep,
            params_hash,
            instruction,
            model: self.model.as_str(),
            covers: evidence.covers.clone(),
            messages: evidence.messages.clone(),
            memo,
            line_sources: Some(lines.line_sources),
        };
        // The landing fence reads every sitting's summary, TURN, MESSAGE and
        // claim pin again, with the source set and policy.
        match ctx
            .vault
            .land_composed_scope_summary(attempt_id, plan, evidence, &composed, self.actor)
        {
            Ok(_) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
            }),
            Err(Error::ConcurrentWrite(_)) => Ok(compose_again(&charges, ctx.now_ms)),
            Err(error) if waits_on_residency(&error) => {
                Ok(residency_deferral(ctx.now_ms, charges.units))
            }
            Err(error) => Ok(charges.park(&format!("summary landing refused: {error}"))),
        }
    }
}

/// The Arc stays owed for `cause`, on its row, retried at the next
/// backstop: its attempt ends having written nothing.
fn owe(
    ctx: &WakeAttemptContext<'_>,
    plan: &ScopeSummaryPlan,
    cause: ArcPendingCause,
    charges: &StepChargeTally,
) -> Result<DreamerAttemptExecution> {
    ctx.vault.record_arc_pending(&plan.input, cause)?;
    Ok(DreamerAttemptExecution::Completed {
        completed_units: charges.units,
    })
}

/// The input one Arc call reads: its purpose and `keep`, no editor text,
/// the sittings' lines, the TURNs read again in place of a line, the claims,
/// and the words of every turn opened so far.
fn arc_input(plan: &ScopeSummaryPlan, view: &ArcView, opened: &str) -> Result<String> {
    serde_json::to_string(&serde_json::json!({
        "purpose": plan.purpose,
        "keep": plan.keep,
        "editor_text": null,
        "sittings": view.lines,
        "turns": view.turns,
        "claims": view.claims,
        "opened": opened,
    }))
    .map_err(|_| invalid_consolidation("summary input encoding"))
}

/// The typed output contract of an Arc's call.
fn arc_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["lines", "keep", "open_turns"],
        "properties": {
            "lines": {"type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["text", "turn_refs"],
                "properties": {
                    "text": {"type": "string"},
                    "turn_refs": {"type": "array", "items": {"type": "string"}}
                }
            }},
            "keep": {"type": "string"},
            "open_turns": {"type": "array", "items": {"type": "string"}}
        }
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArcWire {
    lines: Vec<ArcWireLine>,
    keep: String,
    open_turns: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArcWireLine {
    text: String,
    turn_refs: Vec<String>,
}

/// An Arc's lines as composed: its text, rendered once from its lines, and
/// each line's range in that text with the TURNs it came from.
struct ArcLines {
    text: String,
    keep: String,
    line_sources: Vec<SummaryLineSources>,
}

/// What a checked reply asks.
enum ArcReply {
    /// Open these turns first, each one the call showed by label and not
    /// yet open; write nothing.
    Open(Vec<EntityId>),
    Lines(ArcLines),
}

/// The reply, or the static reason it is none. Each turn it names to open
/// is a `T` label its call showed; naming only turns already open asks for
/// none. Otherwise each line is one line of words that are not blank,
/// citing at least one TURN, each once, by a `T` label of a TURN whose
/// words the Arc covers; the lines join with a newline, each range counted
/// in Unicode scalars. The step's check and the landing read the reply
/// through this one parse.
fn arc_output(
    response: &LlmResponse,
    labels: &CallLabelMap,
    opened: &BTreeSet<EntityId>,
    covers: &BTreeSet<EntityId>,
) -> std::result::Result<ArcReply, &'static str> {
    let reply: ArcWire = serde_json::from_str(reply_text(response).trim())
        .map_err(|_| "the model wrote an invalid arc summary result")?;
    let mut ask = Vec::new();
    for label in &reply.open_turns {
        let turn = labels
            .resolve_as(LabelKind::Turn, label)
            .ok_or("an arc reply opens a turn its call did not show")?;
        if !opened.contains(&turn) && !ask.contains(&turn) {
            ask.push(turn);
        }
    }
    if !ask.is_empty() {
        return Ok(ArcReply::Open(ask));
    }
    let mut text = String::new();
    let mut scalars = 0_usize;
    let mut line_sources = Vec::with_capacity(reply.lines.len());
    for line in &reply.lines {
        let words = line.text.trim();
        if words.is_empty() {
            return Err("the model wrote a blank arc line");
        }
        if words.chars().any(|c| {
            matches!(
                c,
                '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
            )
        }) {
            return Err("the model wrote an arc line that breaks");
        }
        if line.turn_refs.is_empty() {
            return Err("an arc line cites no turn");
        }
        let mut seen = BTreeSet::new();
        let mut turn_refs = Vec::with_capacity(line.turn_refs.len());
        for label in &line.turn_refs {
            let turn = labels
                .resolve_as(LabelKind::Turn, label)
                .filter(|turn| covers.contains(turn))
                .ok_or("an arc line cites a turn its call did not show")?;
            if !seen.insert(turn) {
                return Err("an arc line cites a turn twice");
            }
            turn_refs.push(turn.to_hex());
        }
        if !text.is_empty() {
            text.push('\n');
            scalars += 1;
        }
        let output_start = scalars;
        text.push_str(words);
        scalars += words.chars().count();
        line_sources.push(SummaryLineSources {
            output_start,
            output_end: scalars,
            turn_refs,
            source_spans: Vec::new(),
        });
    }
    if text.is_empty() {
        return Err("the model wrote an empty arc");
    }
    Ok(ArcReply::Lines(ArcLines {
        text,
        keep: reply.keep,
        line_sources,
    }))
}
