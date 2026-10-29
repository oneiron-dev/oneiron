//! The sieve's owed novelty/typing rungs and its sampled expensive-path audit.
//! Each rung asks its registered questions as one typed pack through the
//! host's ladder, by the executor's sieve port (OF-498a): by default on the
//! host's existing extraction and verdict roles. Receipts and wake charges
//! use the same durable step layer as consolidation.

mod audit;

use super::call_labels::{CallLabel, CallLabelMap, LabelKind};
use super::executor::ConsolidationExecutor;
use super::provenance::KeptDecision;
use super::roles::{DREAMER_EXTRACTION_ROLE, DREAMER_VERDICT_ROLE};
use super::sieve_decisions::{SieveReading, SieveTypingQuestion};
use super::sieve_ports::{SieveRungCall, SieveRungOutcome};
use super::step_charge::StepChargeTally;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::sieve::{self, RungInput};
use crate::dreamer_wake::{
    DreamerAttemptExecution, SieveRung, SieveSpan, SpanOrigin, WakeAttemptContext,
};
use crate::llm::decision::HumanAskReason;
use crate::llm::{DurableStepContext, DurableStepError};
use crate::{EntityId, Error, Result};

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
            return Ok(DreamerAttemptExecution::Completed {
                completed_units,
                step_hashes: Vec::new(),
            });
        }
        if sieve::rung_superseded(ctx.vault, &input)?
            || (!input.audit && input.span.owed.is_empty())
        {
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            });
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
                step_hashes: Vec::new(),
            });
        };
        let mut charges = StepChargeTally::default();
        let mut reading = SieveReading {
            kind: input.span.kind,
            novel: input.span.novel.unwrap_or(true),
            confidence: input.span.confidence,
            entity: input.span.entity,
        };
        let mut kept: Vec<KeptDecision> = Vec::new();
        let rungs = if input.audit {
            vec![SieveRung::Novelty, SieveRung::Typing]
        } else {
            input.span.owed.clone()
        };
        let attempt_id = attempt.status.attempt.id;
        // The rung's asks name its attempt, and its decisions every source
        // its read pinned: the TURN, its source and each candidate.
        let correlation = EntityId::from_bytes(*attempt_id.as_bytes())?;
        let sources: Vec<EntityId> = evidence.versions.iter().map(|pin| pin.id).collect();
        let step = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject: input.span.turn,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        // Every rung's call names the span's turn, source and entities by
        // its own labels (FIX 7506), built before any renders.
        let span_labels = rung_labels(&input.span, &evidence.entities);
        for rung in rungs {
            let role = match rung {
                SieveRung::Novelty => DREAMER_EXTRACTION_ROLE,
                SieveRung::Typing => DREAMER_VERDICT_ROLE,
            };
            let instruction = match rung {
                SieveRung::Novelty => &input.policy.novelty_instruction,
                SieveRung::Typing => &input.policy.typing_instruction,
            };
            // The rung's pack labels its questions and candidate options in
            // its own call's map, before its state renders.
            let mut labels = span_labels.clone();
            let pack = match SieveTypingQuestion::pack(
                rung,
                &self.decisions,
                &evidence.entities,
                &mut labels,
            ) {
                Ok(pack) => pack,
                Err(error) => return Ok(charges.park_on_error(&error)),
            };
            self.label_questions(&mut labels, pack.questions());
            let candidates: Vec<String> = evidence
                .entities
                .iter()
                .filter_map(|id| labels.label(LabelKind::Entity, *id))
                .map(label_text)
                .collect();
            let state = serde_json::json!({
                "span": span_view(&input.span, &evidence.text, &labels),
                "context": evidence.text,
                "entity_candidates": candidates,
                "previous": reading_view(&reading, &labels),
            });
            let read = self
                .roles
                .extraction_ports()
                .sieve_novelty()
                .read(SieveRungCall {
                    decider: self.decider(),
                    role,
                    call: self.role(role),
                    step: &step,
                    pass: ctx.deadline,
                    instruction,
                    scope: &evidence.scope,
                    versions: &evidence.versions,
                    evidence: &sources,
                    correlation,
                    questions: pack.questions(),
                    state: &state,
                    labels: &labels,
                })
                .await;
            // Every generation that finished is spent, whatever the rung's
            // outcome.
            for (hash, usage) in &read.steps {
                charges.record_terminal(ctx.vault, attempt_id, *hash, usage)?;
            }
            let decisions = match read.outcome {
                Ok(SieveRungOutcome::Decided(decisions)) => decisions,
                Ok(SieveRungOutcome::Trapped) => {
                    return Ok(charges
                        .park_for("durable step trapped for resume", DreamerParkCause::Signal));
                }
                // A missing locality, a request that did not seal and an
                // unreadable reading wait on no owner act: each resumes after
                // its retry delay (OF-193a).
                Ok(SieveRungOutcome::NoLocality) => {
                    return Ok(charges
                        .park_for("sieve host binding needs locality", DreamerParkCause::Retry));
                }
                Ok(SieveRungOutcome::Refused(error)) => return Ok(charges.park_on_error(&error)),
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
            // A question the decision clock cut keeps its memo: the attempt
            // checkpoints and its resume reads the reply again.
            if ctx.deadline.expired()
                || decisions
                    .iter()
                    .any(|kept| kept.decision.human_ask == Some(HumanAskReason::Deadline))
            {
                return Ok(charges.checkpoint());
            }
            reading = match pack.reading(&decisions) {
                Some(reading) => reading,
                // A question left unanswered, or a confidence outside the
                // integer percent, is a refused reading: its memos go, so the
                // retry asks the model again (FIX 7218, 7431); the paid
                // receipts stay.
                None => {
                    for (hash, _) in &read.steps {
                        crate::llm::forget_step_memo(ctx.vault, attempt_id, hash)?;
                    }
                    return Ok(charges.park_for(SIEVE_UNREAD, DreamerParkCause::Retry));
                }
            };
            kept.extend(decisions);
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
                        attempt, ctx, &input, &evidence, reading, kept, &charges, true,
                    );
                }
            }
        }
        self.save_sieve_reading(
            attempt, ctx, &input, &evidence, reading, kept, &charges, false,
        )
    }

    fn save_sieve_reading(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        input: &RungInput,
        evidence: &sieve::RungEvidence,
        reading: SieveReading,
        decisions: Vec<KeptDecision>,
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
            decisions,
            ctx.now_ms / 1_000,
        ) {
            Ok(true) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
                step_hashes: charges.step_hashes.clone(),
            }),
            Ok(false) => Ok(DreamerAttemptExecution::Deferred {
                completed_units: charges.units,
                retry_at: ctx
                    .now_ms
                    .div_ceil(1_000)
                    .saturating_add(input.policy.rung_retry_secs),
                step_hashes: charges.step_hashes.clone(),
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
/// Why a rung parks on a pack whose answers give no reading.
const SIEVE_UNREAD: &str = "sieve reading unread";

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
fn reading_view(reading: &SieveReading, labels: &CallLabelMap) -> serde_json::Value {
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
