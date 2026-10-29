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
//! Rule 5 (PR3): an input that fits one call on its model's window, or
//! whose window is unknown, is this one call; a larger one composes in
//! parts ([`super::arc_children`]), never written smaller. A sitting's owed
//! summary or a TURN that does not open leaves it owed, typed on its row.

use super::super::residency::{residency_deferral, spent_or_deferred, waits_on_residency};
use super::super::step_charge::StepChargeTally;
use super::super::support::invalid_consolidation;
use super::arc_evidence::ArcView;
use super::arc_output::{ArcReply, arc_output, arc_schema};
use super::arc_turns::{Opened, open_turns, opened_text};
use super::window::framed_tokens;
use super::{ScopeSummaryEvidence, ScopeSummaryExecutor, compose_again};
use crate::EntityId;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::{Error, Result};
use crate::llm::{
    DurableStepContext, DurableStepError, LlmResponse, StepOutcome, call_as_step_checked,
};
use crate::scope_summary::{ArcPendingCause, ComposedSummary, ScopeSummaryPlan};
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
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            });
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
            Ok(true) => {
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units: 0,
                    step_hashes: Vec::new(),
                });
            }
            Ok(false) => {}
            Err(error) if waits_on_residency(&error) => {
                return Ok(residency_deferral(ctx.now_ms, 0, Vec::new()));
            }
            Err(error) => return Err(error),
        }
        // An Arc already composing in parts goes on where it stopped.
        if let Some(window) = self.session_window(ctx.vault)
            && self.arc_work_open(ctx, plan, evidence, instruction, window)?
        {
            return self
                .compose_arc_work(attempt, ctx, plan, evidence, instruction, (window, none))
                .await;
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
        let mut words = String::new();
        let lines = loop {
            let user = match arc_input(plan, view, &words) {
                Ok(user) => user,
                Err(error) => return spent_or_deferred(error, ctx, &charges),
            };
            if let Some(window) = self.session_window(ctx.vault) {
                let framed = match framed_tokens(instruction, &user, &schema) {
                    Ok(framed) => framed,
                    Err(error) => return spent_or_deferred(error, ctx, &charges),
                };
                if framed > window {
                    return self
                        .compose_arc_work(
                            attempt,
                            ctx,
                            plan,
                            evidence,
                            instruction,
                            (window, charges),
                        )
                        .await;
                }
            }
            if ctx.deadline.expired() {
                return Ok(charges.checkpoint());
            }
            let mut request = match self.summary_request(
                ctx.vault,
                evidence,
                schema.clone(),
                instruction,
                user,
            ) {
                Ok(request) => request,
                Err(error) => return spent_or_deferred(error, ctx, &charges),
            };
            view.labels.bind_request(&mut request, None);
            let Ok(step_hash) = request.canonical_hash() else {
                return spent_or_deferred(
                    invalid_consolidation("summary request did not hash"),
                    ctx,
                    &charges,
                );
            };
            let check_labels = view.labels.clone();
            let check_opened = opened.clone();
            let check_inherited = view.inherited.clone();
            let check_covers = covers.clone();
            let check = move |response: &LlmResponse| {
                let shown = (&check_opened, &check_inherited);
                arc_output(response, &check_labels, shown, &check_covers)
                    .map(drop)
                    .map_err(str::to_owned)
            };
            let outcome =
                call_as_step_checked(&step_ctx, self.backend, self.guard, request, &check).await;
            let response = match outcome {
                Ok(StepOutcome::Finished {
                    response, memoized, ..
                }) => {
                    if let Err(error) =
                        charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)
                    {
                        if !memoized {
                            charges.record_usage(&response.usage);
                        }
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
            let ask = match arc_output(&response, &view.labels, (&opened, &view.inherited), &covers)
            {
                Ok(ArcReply::Lines(lines)) => break lines,
                Ok(ArcReply::Open(ask)) => ask,
                Err(reason) => return Ok(charges.park_for(reason, DreamerParkCause::Retry)),
            };
            match open_turns(ctx.vault, evidence, view, &ask) {
                Ok(Opened::Turns(turns)) => {
                    words.push_str(&opened_text(&turns));
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
                    return Ok(residency_deferral(
                        ctx.now_ms,
                        charges.units,
                        charges.step_hashes.clone(),
                    ));
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
            arc_work: None,
        };
        // The landing fence reads every sitting's summary, TURN, MESSAGE and
        // claim pin again, with the source set and policy.
        match ctx
            .vault
            .land_composed_scope_summary(attempt_id, plan, evidence, &composed, self.actor)
        {
            Ok(_) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
                step_hashes: charges.step_hashes.clone(),
            }),
            Err(Error::ConcurrentWrite(_)) => Ok(compose_again(&charges, ctx.now_ms)),
            Err(error) if waits_on_residency(&error) => Ok(residency_deferral(
                ctx.now_ms,
                charges.units,
                charges.step_hashes.clone(),
            )),
            Err(error) => Ok(charges.park(&format!("summary landing refused: {error}"))),
        }
    }
}

/// The Arc stays owed for `cause`, on its row, retried at the next
/// backstop: its attempt ends having written nothing.
pub(super) fn owe(
    ctx: &WakeAttemptContext<'_>,
    plan: &ScopeSummaryPlan,
    cause: ArcPendingCause,
    charges: &StepChargeTally,
) -> Result<DreamerAttemptExecution> {
    match owe_bare(ctx, plan, cause, charges) {
        Ok(owed) => Ok(owed),
        Err(error) => spent_or_deferred(error, ctx, charges),
    }
}

/// [`owe`] without the spend handover, for the errors an outer wrap
/// already hands over: [`super::arc_children`] hands its whole run over
/// where its child returns, so a handover here would charge the same
/// spend twice (FIX 11560).
pub(super) fn owe_bare(
    ctx: &WakeAttemptContext<'_>,
    plan: &ScopeSummaryPlan,
    cause: ArcPendingCause,
    charges: &StepChargeTally,
) -> Result<DreamerAttemptExecution> {
    ctx.vault.record_arc_pending(&plan.input, cause)?;
    Ok(DreamerAttemptExecution::Completed {
        completed_units: charges.units,
        step_hashes: charges.step_hashes.clone(),
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
