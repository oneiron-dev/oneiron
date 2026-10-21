//! The scoped typed read every Dreamer pack shares (OF-498a): questions over a state through
//! the host's ladder, the caller's role generation the dial's first read, under the exact
//! scope its request shell carries and the evidence versions its caller pinned. A branch's
//! verdicts read through `ConsolidationExecutor::decide`, its adapter; a sieve rung reads
//! its span's own evidence, never a branch's write rights.

use std::time::{Duration, Instant};

use super::{VERDICT_CEILING, holds, went_up};
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelledRungs};
use crate::dreamer_consolidation::executor::{ConsolidationDecisions, ConsolidationExecutor};
use crate::dreamer_consolidation::provenance::{KeptAsk, KeptDecision};
use crate::dreamer_consolidation::roles::RoleCall;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_wake::WakePassDeadline;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::{
    AskTo, DecisionQuestion, DecisionRung, DecisionWireLabels, EvidenceVersion, GeneratedDecisions,
    GeneratedRung, GeneratedStep, HumanAskReason, ProviderPin, Reversibility,
};
use crate::llm::{BudgetGuard, DurableStepContext, DurableStepResult, LlmRequest, LlmUsage};
use crate::retrieval_depth::RetrievalDeadline;
use crate::write_envelope::WriteActor;

/// What a typed read decides with: the host's ladder, dial, bands and wording, the Dreamer
/// actor it reads as, and the guard its steps spend on.
#[derive(Clone, Copy)]
pub(in crate::dreamer_consolidation) struct Decider<'a> {
    pub(in crate::dreamer_consolidation) decisions: &'a ConsolidationDecisions,
    pub(in crate::dreamer_consolidation) actor: WriteActor,
    pub(in crate::dreamer_consolidation) guard: &'a BudgetGuard,
}

/// One typed read's call: its step and pass clock, the role generation that reads it first,
/// what that generation's requests carry, and where an ask goes.
pub(in crate::dreamer_consolidation) struct ScopedRead<'a> {
    pub(in crate::dreamer_consolidation) step: &'a DurableStepContext<'a>,
    pub(in crate::dreamer_consolidation) pass: &'a WakePassDeadline,
    /// The role whose generation is the dial's first read, as the caller resolved it.
    pub(in crate::dreamer_consolidation) call: &'a RoleCall<'a>,
    /// That role's request, its own prompt included and no turn of the read yet; its
    /// envelope is the read's exact scope.
    pub(in crate::dreamer_consolidation) shell: LlmRequest,
    /// The role's last word on each built request: its authorization and reasoning binding.
    pub(in crate::dreamer_consolidation) seal:
        &'a (dyn Fn(LlmRequest) -> Result<LlmRequest> + Sync),
    /// The body version of each evidence source the caller pinned; every decision's
    /// receipt names them.
    pub(in crate::dreamer_consolidation) versions: &'a [EvidenceVersion],
    pub(in crate::dreamer_consolidation) to: &'a AskTo,
    pub(in crate::dreamer_consolidation) correlation: EntityId,
    pub(in crate::dreamer_consolidation) evidence: &'a [EntityId],
    pub(in crate::dreamer_consolidation) state: &'a serde_json::Value,
    /// The highest rung the read may climb to; the host's dial may stop lower.
    pub(in crate::dreamer_consolidation) ceiling: DecisionRung,
}

impl ConsolidationExecutor<'_> {
    /// This executor's ladder, actor and guard, as a typed read decides with them.
    pub(in crate::dreamer_consolidation) fn decider(&self) -> Decider<'_> {
        Decider {
            decisions: &self.decisions,
            actor: self.actor,
            guard: self.guard,
        }
    }
}

impl Decider<'_> {
    /// `questions` over `read`'s state through the host's ladder, `read`'s role generation
    /// the dial's first read, on the time the pass has left, any ask going to `read.to` for
    /// the work `read.correlation` names. Each generation that finished is pushed onto
    /// `spent` (its request hash and usage) as it finishes, whatever the pack's outcome. None
    /// when the step trapped: the attempt is parked.
    ///
    /// Every read shows the pack through `labels` (FIX 7506): the generation's questions by
    /// their labels and its choices as registered, every rung past it the same choices, and
    /// each answer reads back canonical. The map binds into each generation's identity.
    ///
    /// A question already put to `read.to` for this work is not put again: an open ask still
    /// holds its work, and an answered one is the answer, so the read stops below the person
    /// rung. Each decision keeps its ask, and its receipt names `read.versions`.
    pub(in crate::dreamer_consolidation) async fn decide_scoped(
        &self,
        read: ScopedRead<'_>,
        questions: &[DecisionQuestion],
        labels: &CallLabelMap,
        spent: &mut Vec<([u8; 32], LlmUsage)>,
    ) -> DurableStepResult<Option<Vec<KeptDecision>>> {
        let vault = read.step.vault;
        let principal = self.actor.entity_ref();
        let asked = questions
            .iter()
            .map(|question| {
                Ok(vault
                    .decision_ask_for(
                        question,
                        principal,
                        read.evidence,
                        read.to,
                        Some(read.correlation),
                    )?
                    .filter(holds))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut dial = self.decisions.dial;
        if dial.ceiling == DecisionRung::Human
            && asked.iter().flatten().any(|ask| ask.answer.is_some())
        {
            dial.ceiling = DecisionRung::Big;
        }
        dial.ceiling = dial.ceiling.min(read.ceiling).min(VERDICT_CEILING);
        dial.first = dial.first.min(dial.ceiling);
        let rung = GeneratedRung {
            pin: ProviderPin {
                rung: self.decisions.dial.first,
                model: read.call.model.to_string(),
                version: read.call.model.to_string(),
            },
            backend: read.call.backend,
            step: GeneratedStep::Durable {
                step: read.step,
                guard: self.guard,
            },
            request: read.shell,
            seal: read.seal,
        };
        let pack: Vec<&DecisionQuestion> = questions.iter().collect();
        let mut held = self.decisions.ladder.ladder();
        held.ask_to = Some(read.to);
        held.correlation = Some(read.correlation);
        let wire: &dyn DecisionWireLabels = labels;
        // Each rung past the generated read shows the pack's choices alike.
        let rungs = LabelledRungs::of(&held, wire);
        let ladder = rungs.ladder(&held);
        let decided = ladder
            .run_pack_generated_spent(
                &rung,
                &pack,
                principal,
                read.evidence,
                read.state,
                dial,
                &self.decisions.bands,
                Reversibility::ReversibleRead,
                &RetrievalDeadline::hard(
                    Instant::now(),
                    Duration::from_millis(read.pass.remaining_ms()),
                ),
                spent,
                Some(wire),
            )
            .await;
        let decisions = match decided? {
            GeneratedDecisions::Decided { decisions, .. } => decisions,
            GeneratedDecisions::Trapped => return Ok(None),
            GeneratedDecisions::Unread(_) => {
                return Err(
                    invalid_consolidation("a durable decision read came back unread").into(),
                );
            }
        };
        let mut kept = Vec::with_capacity(decisions.len());
        for ((question, mut decision), asked) in questions.iter().zip(decisions).zip(asked) {
            decision
                .receipt
                .evidence_versions
                .extend(read.versions.iter().cloned());
            let ask = match asked {
                Some(ask) => Some(ask),
                None if went_up(&decision)
                    && decision.human_ask != Some(HumanAskReason::Deadline) =>
                {
                    vault.decision_ask_for(
                        question,
                        principal,
                        read.evidence,
                        read.to,
                        Some(read.correlation),
                    )?
                }
                None => None,
            };
            kept.push(KeptDecision {
                decision,
                ask: ask.as_ref().map(KeptAsk::of),
            });
        }
        Ok(Some(kept))
    }
}
