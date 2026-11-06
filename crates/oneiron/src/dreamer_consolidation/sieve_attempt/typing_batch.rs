//! A TURN's typing-only spans, read in packs (FIX 14711). The carrier reads
//! its TURN's queued spans that owe only typing, highest score first, and
//! asks as many of them in one verdict call as the questions-per-call row
//! takes: each span's own questions, keyed by its span, over its own
//! candidates, with every span's words beside the others'. Each span's
//! answers read back as its reading and land on their own, exactly as a
//! single typing rung's do; a span the reply leaves unread, or whose source
//! moved, waits for the carrier's retry while the rest land.

use std::collections::BTreeSet;

use oneiron_model::llm::Scope;

use super::super::call_labels::{CallLabelMap, LabelKind};
use super::super::executor::ConsolidationExecutor;
use super::super::provenance::KeptDecision;
use super::super::roles::DREAMER_VERDICT_ROLE;
use super::super::sieve_decisions::{SieveReading, SieveTypingQuestion};
use super::super::sieve_ports::{SieveRungCall, SieveRungOutcome};
use super::super::step_charge::{StepChargeTally, usage_units};
use super::{SIEVE_UNREAD, label_text, reading_view, span_view};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::sieve::{self, TypingMember};
use crate::dreamer_wake::{DreamerAttemptExecution, SieveRung, SieveSpan, WakeAttemptContext};
use crate::model_decision::{DecisionQuestion, EvidenceVersion, HumanAskReason};
use crate::model_step_context::DurableStepContext;
use crate::model_step_error::DurableStepError;
use crate::{EntityId, Error, Result};

impl ConsolidationExecutor<'_> {
    /// A rung job a partition window runs whole, by its shape: a TURN's
    /// typing carrier, or a span's own rungs or a window's audit.
    pub(in crate::dreamer_consolidation) async fn run_rung_job(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if attempt.status.payload.attempt_type == sieve::TYPING_BATCH_ATTEMPT {
            return self.run_typing_batch(attempt, ctx).await;
        }
        self.run_sieve_rungs(attempt, ctx).await
    }

    pub(in crate::dreamer_consolidation) async fn run_typing_batch(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if self.scope.is_some() {
            return Err(Error::InvalidConfig(
                "a sieve typing batch does not accept a branch scope".into(),
            ));
        }
        let turn = sieve::typing_batch_turn(&attempt.status.payload.input)?;
        // An excluded conversation's spans wait, as a single rung's do, and
        // are read once it is un-excluded.
        if ctx.vault.dreamer_turn_excluded(&turn)? {
            return Ok(DreamerAttemptExecution::Park {
                reason: "conversation excluded from Dreamer passes".to_owned(),
                cause: DreamerParkCause::Retry,
            });
        }
        let attempt_id = attempt.status.attempt.id;
        // The batch's asks name its carrier, and each call's subject is the
        // TURN that owns every span it reads.
        let correlation = EntityId::from_bytes(*attempt_id.as_bytes())?;
        let step = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject: turn,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let per_call = self.decisions.bands.questions_per_call();
        let mut charges = StepChargeTally::default();
        // The spans this run set aside: a withheld source, a reading the
        // reply left unread, a commit its recheck refused. None is asked
        // twice in one run; each waits for the carrier's retry.
        let mut held: BTreeSet<[u8; 32]> = BTreeSet::new();
        let (mut withheld, mut unread) = (false, false);
        let retry_secs = loop {
            if ctx.deadline.expired() {
                return Ok(charges.checkpoint());
            }
            let policy = match ctx.vault.dreamer_recipe_policy() {
                Ok(policy) => policy,
                Err(error) => return Ok(charges.park_on_error(&error)),
            };
            let members = match sieve::typing_members(ctx.vault, &turn, &held, &policy) {
                Ok(members) => members,
                Err(error) => return Ok(charges.park_on_error(&error)),
            };
            withheld |= !members.withheld.is_empty();
            held.extend(members.withheld);
            let batch = take_batch(members.ready, per_call);
            if batch.is_empty() {
                break policy.rung_retry_secs;
            }
            let mut labels = batch_labels(turn, &batch);
            let mut packs = Vec::with_capacity(batch.len());
            for member in &batch {
                match SieveTypingQuestion::pack_for_span(
                    SieveRung::Typing,
                    &self.decisions,
                    &member.evidence.entities,
                    &mut labels,
                    &member.input.span.id,
                ) {
                    Ok(pack) => packs.push(pack),
                    Err(error) => return Ok(charges.park_on_error(&error)),
                }
            }
            let questions: Vec<DecisionQuestion> = packs
                .iter()
                .flat_map(|pack| pack.questions().iter().cloned())
                .collect();
            self.label_questions(&mut labels, &questions);
            let state = batch_state(&batch, &packs, &labels);
            let (scope, versions) = batch_evidence(&batch);
            let sources: Vec<EntityId> = versions.iter().map(|pin| pin.id).collect();
            let read = self
                .roles
                .extraction_ports()
                .sieve_novelty()
                .read(SieveRungCall {
                    decider: self.decider(),
                    role: DREAMER_VERDICT_ROLE,
                    call: self.role(DREAMER_VERDICT_ROLE),
                    step: &step,
                    pass: ctx.deadline,
                    instruction: &policy.typing_instruction,
                    scope: &scope,
                    versions: &versions,
                    evidence: &sources,
                    correlation,
                    questions: &questions,
                    state: &state,
                    labels: &labels,
                })
                .await;
            // Every generation that finished is spent, whatever the batch's
            // outcome (FIX 11554).
            for (index, (hash, usage, _)) in read.steps.iter().enumerate() {
                if let Err(error) = charges.record_terminal(ctx.vault, attempt_id, *hash, usage) {
                    for (_, usage, memoized) in &read.steps[index..] {
                        if !*memoized {
                            charges.record_usage(usage);
                        }
                    }
                    return super::super::residency::spent_or_deferred(error, ctx, &charges);
                }
            }
            let decisions = match read.outcome {
                Ok(SieveRungOutcome::Decided(decisions)) => decisions,
                Ok(SieveRungOutcome::Trapped) => {
                    return Ok(charges
                        .park_for("durable step trapped for resume", DreamerParkCause::Signal));
                }
                Ok(SieveRungOutcome::NoLocality) => {
                    return Ok(charges
                        .park_for("sieve host binding needs locality", DreamerParkCause::Retry));
                }
                Ok(SieveRungOutcome::Refused(error)) => return Ok(charges.park_on_error(&error)),
                Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.checkpoint());
                }
                Err(DurableStepError::SpentSchemaValidation { usage, .. }) => {
                    charges.record_usage(&usage);
                    return Ok(
                        charges.park_for("sieve reading schema refused", DreamerParkCause::Retry)
                    );
                }
                Err(DurableStepError::Engine(error)) if charges.units == 0 => return Err(error),
                Err(error) => {
                    if let DurableStepError::SpentLlm { usage, .. }
                    | DurableStepError::SpentFallback { usage, .. } = &error
                    {
                        charges.record_usage(usage);
                    }
                    return Ok(
                        charges.park_for(&error.to_string(), DreamerParkCause::of_step(&error))
                    );
                }
            };
            // A question the decision clock cut keeps its memo: the carrier
            // checkpoints and its resume reads the reply again.
            if ctx.deadline.expired()
                || decisions
                    .iter()
                    .any(|kept| kept.decision.human_ask == Some(HumanAskReason::Deadline))
            {
                return Ok(charges.checkpoint());
            }
            // Each span keeps the call's receipts and an equal share of what
            // it actually spent: shared cost, not a per-span measure.
            let hashes: Vec<[u8; 32]> = read.steps.iter().map(|(hash, _, _)| *hash).collect();
            let spent: u64 = read
                .steps
                .iter()
                .map(|(_, usage, _)| usage_units(usage))
                .sum();
            let shares = equal_shares(spent, batch.len());
            let mut decisions = decisions.into_iter();
            let mut refused_reading = false;
            for ((member, pack), share) in batch.iter().zip(&packs).zip(shares) {
                let kept: Vec<KeptDecision> =
                    decisions.by_ref().take(pack.questions().len()).collect();
                let Some(reading) = pack.reading(&kept) else {
                    refused_reading = true;
                    held.insert(member.input.span.id);
                    continue;
                };
                let key = sieve::typing_member_key(attempt_id, &member.input.span)?;
                match sieve::finish_rungs(
                    ctx.vault,
                    key,
                    &member.input,
                    &member.evidence,
                    reading.kind,
                    reading.entity,
                    reading.novel,
                    reading.confidence,
                    false,
                    share,
                    hashes.clone(),
                    kept,
                    ctx.now_ms / 1_000,
                ) {
                    Ok(true) => {}
                    // Its span or source moved since the read: it waits out
                    // its retry delay, as a single rung's recheck does.
                    Ok(false) => {
                        withheld = true;
                        held.insert(member.input.span.id);
                    }
                    Err(error) => return Ok(charges.park_on_error(&error)),
                }
            }
            // A reading the reply left unread forgets the call's memos and
            // charge marks in one write, so its retry asks again and is
            // tallied fresh (FIX 7218, 7431, 7489); the spans that read land
            // now, and the call's units stay in this run's spend.
            if refused_reading {
                unread = true;
                let store = crate::dreamer_runner::DreamerRunnerStore::new(ctx.vault);
                if let Err(error) = ctx.vault.with_write_txn_grouped(|wtxn| {
                    for hash in &hashes {
                        store.forget_step_charge_in_txn(wtxn, attempt_id, hash)?;
                        crate::llm::forget_step_memo_in_txn(ctx.vault, wtxn, attempt_id, hash)?;
                    }
                    Ok(())
                }) {
                    return super::super::residency::spent_or_deferred(error, ctx, &charges);
                }
                charges.step_hashes.retain(|kept| !hashes.contains(kept));
            }
        };
        if unread {
            return Ok(charges.park_for(SIEVE_UNREAD, DreamerParkCause::Retry));
        }
        if withheld {
            return Ok(DreamerAttemptExecution::Deferred {
                completed_units: charges.units,
                retry_at: ctx.now_ms.div_ceil(1_000).saturating_add(retry_secs),
                step_hashes: charges.step_hashes.clone(),
            });
        }
        Ok(DreamerAttemptExecution::Completed {
            completed_units: charges.units,
            step_hashes: charges.step_hashes.clone(),
        })
    }
}

/// The spans one call reads: the first ready span, then each next one while
/// the call's questions stay within `per_call`, in queue order. A span whose
/// own pack is larger than the row still goes alone, its questions split
/// over several requests as any pack's are; a span left out is read by the
/// next call.
fn take_batch(ready: Vec<TypingMember>, per_call: usize) -> Vec<TypingMember> {
    let mut batch = Vec::new();
    let mut asked = 0;
    for member in ready {
        let questions = SieveTypingQuestion::question_count(member.evidence.entities.len());
        if !batch.is_empty() && asked + questions > per_call {
            break;
        }
        asked += questions;
        batch.push(member);
    }
    batch
}

/// The call's labels: its TURN `T1`, each span's source MESSAGE `S<n>`, and
/// each span's candidates and its own entity `P<n>`, span by span.
fn batch_labels(turn: EntityId, batch: &[TypingMember]) -> CallLabelMap {
    let mut labels = CallLabelMap::default();
    labels.assign(LabelKind::Turn, turn);
    for member in batch {
        let span = &member.input.span;
        if span.source != span.turn {
            labels.assign(LabelKind::Source, span.source);
        }
        for id in member.evidence.entities.iter().copied().chain(span.entity) {
            labels.assign(LabelKind::Entity, id);
        }
    }
    labels
}

/// What the model reads: each source's words once, then each span as a
/// single rung shows it, with the labels of the questions that ask about it.
fn batch_state(
    batch: &[TypingMember],
    packs: &[SieveTypingQuestion],
    labels: &CallLabelMap,
) -> serde_json::Value {
    let mut shown = BTreeSet::new();
    let mut contexts = Vec::new();
    let mut spans = Vec::with_capacity(batch.len());
    for (member, pack) in batch.iter().zip(packs) {
        let span = &member.input.span;
        if shown.insert(span.source) {
            let source = labels
                .label(LabelKind::Source, span.source)
                .or_else(|| labels.label(LabelKind::Turn, span.source));
            contexts.push(serde_json::json!({
                "source": source.map(label_text),
                "text": &member.evidence.text,
            }));
        }
        let candidates: Vec<String> = member
            .evidence
            .entities
            .iter()
            .filter_map(|id| labels.label(LabelKind::Entity, *id))
            .map(label_text)
            .collect();
        let questions: Vec<String> = pack
            .questions()
            .iter()
            .filter_map(|question| labels.label(LabelKind::Question, question.id))
            .map(label_text)
            .collect();
        spans.push(serde_json::json!({
            "span": span_view(span, &member.evidence.text, labels),
            "questions": questions,
            "entity_candidates": candidates,
            "previous": reading_view(&queued_reading(span), labels),
        }));
    }
    serde_json::json!({
        "contexts": contexts,
        "spans": spans,
    })
}

/// The reading a span carries in the queue, as its own rung starts from.
fn queued_reading(span: &SieveSpan) -> SieveReading {
    SieveReading {
        kind: span.kind,
        novel: span.novel.unwrap_or(true),
        confidence: span.confidence,
        entity: span.entity,
    }
}

/// The call's grants and pins: every span's, each source once. Each span's
/// decisions name all of them, since the call read all of them.
fn batch_evidence(batch: &[TypingMember]) -> (Scope, Vec<EvidenceVersion>) {
    let mut scope = Scope::default();
    let mut versions: Vec<EvidenceVersion> = Vec::new();
    for member in batch {
        scope
            .readable
            .extend(member.evidence.scope.readable.iter().cloned());
        scope
            .writable
            .extend(member.evidence.scope.writable.iter().cloned());
        for pin in &member.evidence.versions {
            if !versions.contains(pin) {
                versions.push(pin.clone());
            }
        }
    }
    (scope, versions)
}

/// `units` split over `count` spans: equal parts, the remainder one each to
/// the first spans, so the parts sum to `units`.
fn equal_shares(units: u64, count: usize) -> Vec<u64> {
    let count_u64 = u64::try_from(count).unwrap_or(u64::MAX).max(1);
    let (part, rest) = (units / count_u64, units % count_u64);
    (0..count)
        .map(|index| part + u64::from(u64::try_from(index).unwrap_or(u64::MAX) < rest))
        .collect()
}
