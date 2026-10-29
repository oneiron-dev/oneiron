//! Done verdicts and report escalation.
//! Entry: `Memory::report_done`.
//! Shared report vocabulary stays in `highway_report`.

use super::*;
use crate::task_verb::settlement_anchor::{SETTLEMENT_ANCHOR_WORLD_PROOF, anchor_fields};

impl Memory<'_> {
    /// Done: the verdict, then the one write it calls for. Held with a brief
    /// that names no question opens the owner's ask (R3), so a parked result
    /// has an exit.
    #[expect(
        clippy::too_many_arguments,
        reason = "one Done's door, identity, fence handle, result, TASK, decisions and receipt"
    )]
    pub(super) fn report_done(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        attempt: Option<AttemptHandle>,
        (result_ref, confession): (EntityId, Option<String>),
        current: &TaskVerbBody,
        decisions: Option<&TaskDecisions<'_>>,
        mut lifecycle: TaskLifecycleRecord,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        self.report_resolved(rt, result_ref)?;
        lifecycle
            .fields
            .insert("result_ref".to_owned(), result_ref.to_hex());
        if let Some(confession) = confession {
            lifecycle.fields.insert("confession".to_owned(), confession);
        }
        let continuation = block_continuation(
            via,
            task_ref,
            attempt.as_ref(),
            BlockPurpose::Done {
                result_ref,
                brief_rev: current.brief.as_ref().map_or(0, |brief| brief.rev),
            },
        );
        let verdict = self.done_verdict(
            rt,
            task_ref,
            key,
            current,
            result_ref,
            decisions,
            &continuation,
        )?;
        // Reading a settled ask may already have landed this result.
        if matches!(verdict, DoneVerdict::Met)
            && let Some(settled) = self.settled_by(rt, task_ref, result_ref)?
        {
            return Ok(Self::replayed_done(task_ref, &settled, lifecycle));
        }
        let mut related = Vec::new();
        match verdict {
            DoneVerdict::Met => {
                lifecycle
                    .fields
                    .insert("criteria_verdict".to_owned(), "met".to_owned());
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    related,
                    None,
                    now,
                    |queue, wtxn, body, held| {
                        land_done_in(queue, wtxn, body, held_try(held), result_ref, now)?;
                        Ok(true)
                    },
                )
            }
            DoneVerdict::Unmet => {
                lifecycle
                    .fields
                    .insert("criteria_verdict".to_owned(), "unmet".to_owned());
                if let Escalation::Asked(handle) = self.escalate(
                    rt,
                    EscalationTrigger::CriteriaUnmet,
                    task_ref,
                    key,
                    current.brief.as_ref(),
                    decisions,
                    &[result_ref],
                    None,
                )? {
                    related.push(TaskHandle::Ask {
                        group_ref: handle.group_ref,
                    });
                }
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    related,
                    None,
                    now,
                    |queue, wtxn, body, held| {
                        fail_unmet_in(queue, wtxn, body, held_try(held), now)?;
                        Ok(false)
                    },
                )
            }
            DoneVerdict::AskedUp(handle) => {
                lifecycle
                    .fields
                    .insert("criteria_verdict".to_owned(), "asked_up".to_owned());
                self.commit_asked_up(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    result_ref,
                    handle,
                    now,
                )
            }
            DoneVerdict::Held => {
                lifecycle
                    .fields
                    .insert("criteria_verdict".to_owned(), "held".to_owned());
                let asked = match current.brief.as_ref() {
                    Some(brief) if brief.brief.escalation.question_ref.is_none() => self
                        .owner_block_ask(
                            rt,
                            &mut lifecycle,
                            task_ref,
                            brief,
                            &continuation,
                            key,
                            None,
                        )?,
                    _ => None,
                };
                match asked {
                    Some(handle) => self.commit_asked_up(
                        rt,
                        via,
                        task_ref,
                        attempt.as_ref(),
                        lifecycle,
                        result_ref,
                        handle,
                        now,
                    ),
                    None => self.commit_report(
                        rt,
                        via,
                        task_ref,
                        attempt.as_ref(),
                        lifecycle,
                        related,
                        None,
                        now,
                        |_, _, body, _| {
                            block(body, &[result_ref], now);
                            Ok(false)
                        },
                    ),
                }
            }
        }
    }

    /// Done means met? A parked Done whose ask settled answers from the ask;
    /// otherwise the surface question is asked, and asking up opens the
    /// escalation ask, or takes the rule's default when no ask can be opened.
    #[expect(
        clippy::too_many_arguments,
        reason = "the report's door, the TASK and its result, the surface's decisions and the block's continuation"
    )]
    pub(super) fn done_verdict(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        task_ref: EntityId,
        key: &str,
        current: &TaskVerbBody,
        result_ref: EntityId,
        decisions: Option<&TaskDecisions<'_>>,
        continuation: &BlockContinuation,
    ) -> MemoryResult<DoneVerdict> {
        let strict = highway_block::strict_done_reuse(current.brief.as_ref());
        for wait in blocked_on(current) {
            // Whether the ask was opened for this very Done is recorded
            // either way (FIX 10183); under strict reuse an ask bound to
            // anything else is passed over for the TASK's own question.
            let binding = self
                .report_read(rt, |txn| {
                    Ok(highway_block::done_ask_binding_in(
                        self.vault(),
                        txn,
                        wait,
                        continuation,
                    )?)
                })
                .unwrap_or(highway_block::DoneAskBinding::Unbound);
            rt.note_decision(
                &format!("done_ask_binding.{}", wait.to_hex()),
                binding.as_str().to_owned(),
            );
            if strict && binding == highway_block::DoneAskBinding::Unbound {
                continue;
            }
            let Ok(status) = self.report_ask_status(rt, wait) else {
                continue;
            };
            return Ok(match status {
                TaskAskStatus::Settled(result) => match selected_task_ask_option(&result) {
                    Some(option) if option.as_str() == DONE_MET_OPTION => DoneVerdict::Met,
                    Some(_) => DoneVerdict::Unmet,
                    None if matches!(result.decision, TaskAskDecision::No) => DoneVerdict::Unmet,
                    None => DoneVerdict::Held,
                },
                TaskAskStatus::Pending { .. } | TaskAskStatus::Changed { .. } => {
                    DoneVerdict::AskedUp(TaskAskHandle { group_ref: wait })
                }
                // An ask's status is never a world-privacy request's (FIX 4706).
                TaskAskStatus::WorldPrivacy(_) => DoneVerdict::Held,
            });
        }
        let Some(brief) = current.brief.as_ref() else {
            return Ok(DoneVerdict::Met);
        };
        let (evidence, state) = done_question_inputs(task_ref, result_ref, brief);
        let principal = self
            .report_read(rt, |txn| {
                Ok(self.vault().task_authority_state_in(txn, task_ref)?)
            })?
            .map_or(self.actor(), |state| state.owner_ref);
        // A runner's answer, given for exactly this report, stands for the
        // question it cannot ask inside its write.
        let judged = rt
            .judged
            .as_ref()
            .and_then(|judged| judged.for_report(task_ref, result_ref, brief, principal));
        // The model whose answer it is becomes the run's judge, in the
        // report's own write (FIX 1877); a join that fails leaves it unknown.
        if judged.is_some()
            && let Some(answer) = rt.judged.as_ref()
            && let Some(wtxn) = rt.txn.as_deref_mut()
        {
            answer.record_judge_in_txn(self.vault(), wtxn);
        }
        // A bound try's typed Done is a world proof: the settled row names
        // its pin's NOTE as the settlement's anchor.
        if judged.is_some()
            && let Some(note) = rt.judged.as_ref().and_then(RunnerDoneAnswer::world_proof)
        {
            for (field, value) in anchor_fields(SETTLEMENT_ANCHOR_WORLD_PROOF, &note.to_hex()) {
                rt.note_decision(&field, value);
            }
        }
        let decision = judged.unwrap_or_else(|| {
            ask(
                decisions,
                TaskQuestion::DoneMet,
                principal,
                &evidence,
                &state,
                brief.brief.escalation.reversibility,
            )
        });
        // The ladder's receipt rides with the verdict it decided (FIX 10179).
        if let Some(receipt) = decision.receipt_field() {
            rt.note_decision("done_decision_receipt", receipt);
        }
        match decision.answer {
            PortAnswer::Yes => Ok(DoneVerdict::Met),
            PortAnswer::No => Ok(DoneVerdict::Unmet),
            PortAnswer::AskUp => {
                match self.open_escalation_ask(
                    rt,
                    task_ref,
                    key,
                    brief,
                    EscalationTrigger::CriteriaUnmet,
                    true,
                    Some(continuation),
                )? {
                    Some(handle) => Ok(DoneVerdict::AskedUp(handle)),
                    None => Ok(match brief.brief.escalation.default {
                        // The default branch is the agent's own act, never
                        // anyone's answer.
                        TaskAskDefault::Proceed => DoneVerdict::Met,
                        TaskAskDefault::Hold | TaskAskDefault::AskMe => DoneVerdict::Held,
                    }),
                }
            }
        }
    }

    /// Ask up now? On a trigger the brief lists, the surface question is
    /// asked; a yes (or no ladder) opens the escalation ask.
    #[expect(
        clippy::too_many_arguments,
        reason = "the report's door, the trigger, the task and its brief, the surface's decisions and the block's continuation"
    )]
    pub(super) fn escalate(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        trigger: EscalationTrigger,
        task_ref: EntityId,
        key: &str,
        brief: Option<&StoredBrief>,
        decisions: Option<&TaskDecisions<'_>>,
        evidence: &[EntityId],
        continuation: Option<&BlockContinuation>,
    ) -> MemoryResult<Escalation> {
        let Some(brief) = brief else {
            return Ok(Escalation::NotListed);
        };
        if !brief.brief.escalation.triggers.contains(&trigger) {
            return Ok(Escalation::NotListed);
        }
        let mut cited = vec![task_ref];
        cited.extend_from_slice(evidence);
        let state = serde_json::json!({
            "trigger": trigger.as_str(),
            "objective": brief.brief.objective,
            "need": brief.brief.intent.need,
        });
        let decision = ask(
            decisions,
            TaskQuestion::AskUp,
            self.actor(),
            &cited,
            &state,
            brief.brief.escalation.reversibility,
        );
        // The ladder's receipt rides with the escalation it decided (FIX
        // 10179).
        if let Some(receipt) = decision.receipt_field() {
            rt.note_decision("ask_up_decision_receipt", receipt);
        }
        match decision.answer {
            PortAnswer::No => Ok(Escalation::Declined),
            PortAnswer::Yes | PortAnswer::AskUp => Ok(
                match self.open_escalation_ask(
                    rt,
                    task_ref,
                    key,
                    brief,
                    trigger,
                    false,
                    continuation,
                )? {
                    Some(handle) => Escalation::Asked(handle),
                    None => Escalation::Default(brief.brief.escalation.default),
                },
            ),
        }
    }

    /// Opens the escalation ask to the rule's target, keyed by the task, the
    /// trigger and the report key, so a re-issued report finds the same ask.
    /// An ask that holds a block carries its continuation beside it.
    /// `None` when the brief names no question to ask with.
    #[expect(
        clippy::too_many_arguments,
        reason = "the report's door, the task and its brief, the trigger and the block's continuation"
    )]
    pub(super) fn open_escalation_ask(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        task_ref: EntityId,
        key: &str,
        brief: &StoredBrief,
        trigger: EscalationTrigger,
        done: bool,
        continuation: Option<&BlockContinuation>,
    ) -> MemoryResult<Option<TaskAskHandle>> {
        let rule = &brief.brief.escalation;
        let Some(reference) = rule.question_ref else {
            return Ok(None);
        };
        let mut question = TaskAskQuestion::new(reference);
        let (yes, no) = if done {
            (
                (DONE_MET_OPTION, "Done means met"),
                (DONE_UNMET_OPTION, "Done means not met"),
            )
        } else {
            (("proceed", "Proceed"), ("hold", "Hold"))
        };
        for (option, text) in [yes, no] {
            question
                .options
                .insert(TaskAskOptionId::new(option)?, text.to_owned());
        }
        if done {
            question.outcome_binding = brief.brief.success.outcome_binding.clone();
        }
        let mut spec =
            TaskAskSpec::shorthand(Some(rule.to.clone()), question, rule.until, rule.default);
        spec.intent_key = format!(
            "tasks.escalate/{}/{}/{}",
            task_ref.to_hex(),
            trigger.as_str(),
            short_digest(key)
        );
        spec.task_ref = Some(task_ref);
        let label = continuation.map(|continuation| {
            super::highway_block::block_question_label(brief, &continuation.purpose, None)
        });
        self.report_ask(rt, &spec, continuation.zip(label.as_deref()))
    }
}
