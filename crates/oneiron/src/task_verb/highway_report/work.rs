//! Work reports and their atomic commits.
//! Entry: `Memory::report_work`.
//! Shared report vocabulary stays in `highway_report`.

use super::*;

impl Memory<'_> {
    /// The five work reports, each: fence, any question or ask outside the
    /// write, then one write transaction that re-checks the fence and moves
    /// the try and the TASK together.
    #[expect(
        clippy::too_many_arguments,
        reason = "one report's door, identity, fence handle, body, decisions and receipt"
    )]
    pub(super) fn report_work(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        attempt: Option<AttemptHandle>,
        body: TaskReportBody,
        decisions: Option<&TaskDecisions<'_>>,
        mut lifecycle: TaskLifecycleRecord,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        // The same report again answers its journaled receipt, before any
        // fence, question or ask.
        if let Some(identity) = rt.journal.as_ref()
            && let Some(receipt) = self.report_read(rt, |txn| {
                report_journal::replay_in(self.vault(), txn, identity)
            })?
        {
            return Ok(receipt);
        }
        let late_result = match &body {
            TaskReportBody::Done { result_ref, .. } => Some(*result_ref),
            _ => None,
        };
        // A replayed Done answers the first terminal; a new key never
        // overwrites one. Checked before the fence, which refuses a
        // terminal task.
        if let Some(result_ref) = late_result
            && let Some(settled) = self.settled_by(rt, task_ref, result_ref)?
        {
            return Ok(Self::replayed_done(task_ref, &settled, lifecycle));
        }
        let (current, fence) = self.fence_now(rt, via, task_ref, attempt.as_ref())?;
        stamp_fields(&mut lifecycle.fields, current.brief.as_ref());
        // OF-540: the realizing attempt's frozen team run, never the
        // project's current pattern.
        if let Fence::Held {
            team: Some(team), ..
        } = &fence
        {
            crate::receipt::append_team_receipt_fields(&mut lifecycle.fields, team);
        }
        if let Some(outcome) = fence.outcome() {
            return Ok(Self::fenced_out(task_ref, outcome, lifecycle, late_result));
        }
        match body {
            TaskReportBody::Progress {
                evidence_refs,
                renew_lease,
            } => {
                for evidence in &evidence_refs {
                    self.report_resolved(rt, *evidence)?;
                }
                lifecycle.fields.insert(
                    "evidence".to_owned(),
                    evidence_refs
                        .iter()
                        .map(EntityId::to_hex)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                lifecycle
                    .fields
                    .insert("renewed".to_owned(), renew_lease.to_string());
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    Vec::new(),
                    None,
                    now,
                    |queue, wtxn, body, held| {
                        if renew_lease {
                            let Some((record, lease_owner)) = held_try(held) else {
                                return Err(MemoryError::bad_request(
                                    "only an external try's lease renews through a report",
                                ));
                            };
                            queue.renew_lease_in_txn(
                                wtxn,
                                record.id,
                                lease_owner,
                                record.attempt_count,
                                now,
                            )?;
                        }
                        if matches!(
                            body.state,
                            None | Some(
                                TaskExecutionState::Queued | TaskExecutionState::Blocked { .. }
                            )
                        ) {
                            body.state = Some(TaskExecutionState::Working { started_at: now });
                        }
                        Ok(false)
                    },
                )
            }
            TaskReportBody::Blocked {
                on,
                note,
                ask: wanted,
            } => {
                let mut waits: Vec<EntityId> = on.iter().map(handle_entity).collect();
                let mut related = Vec::new();
                let continuation =
                    block_continuation(via, task_ref, attempt.as_ref(), BlockPurpose::Blocked);
                let opened = match wanted {
                    // The agent's own ask: its Progress is its exit.
                    Some(spec) => {
                        let mut spec = *spec;
                        spec.task_ref = Some(task_ref);
                        self.report_ask(rt, &spec, None)?
                    }
                    None => match self.escalate(
                        rt,
                        EscalationTrigger::Blocked,
                        task_ref,
                        key,
                        current.brief.as_ref(),
                        decisions,
                        &waits,
                        Some(&continuation),
                    )? {
                        Escalation::Asked(handle) => Some(handle),
                        Escalation::Default(default) => {
                            // No question to ask with: the rule's default is
                            // the agent's own act, never anyone's answer.
                            lifecycle
                                .fields
                                .insert("default_taken".to_owned(), format!("{default:?}"));
                            // AskMe with no question to ask with: the engine
                            // asks the owner, so the block has an exit.
                            match current.brief.as_ref() {
                                Some(brief)
                                    if default == TaskAskDefault::AskMe
                                        && brief.brief.escalation.question_ref.is_none() =>
                                {
                                    self.owner_block_ask(
                                        rt,
                                        &mut lifecycle,
                                        task_ref,
                                        brief,
                                        &continuation,
                                        key,
                                        note.as_deref(),
                                    )?
                                }
                                _ => None,
                            }
                        }
                        Escalation::NotListed | Escalation::Declined => None,
                    },
                };
                if let Some(note) = note {
                    lifecycle.fields.insert("note".to_owned(), note);
                }
                if let Some(handle) = opened {
                    waits.push(handle.group_ref);
                    related.push(TaskHandle::Ask {
                        group_ref: handle.group_ref,
                    });
                    lifecycle
                        .fields
                        .insert("ask".to_owned(), handle.group_ref.to_hex());
                }
                lifecycle.fields.insert(
                    "on".to_owned(),
                    waits
                        .iter()
                        .map(EntityId::to_hex)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    related,
                    None,
                    now,
                    |_, _, body, _| {
                        block(body, &waits, now);
                        Ok(false)
                    },
                )
            }
            TaskReportBody::Done {
                result_ref,
                confession,
            } => self.report_done(
                rt,
                via,
                task_ref,
                key,
                attempt,
                (result_ref, confession),
                &current,
                decisions,
                lifecycle,
                now,
            ),
            TaskReportBody::Failed {
                error,
                retryable,
                result_ref,
            } => {
                if error.trim().is_empty() {
                    return Err(MemoryError::bad_request("a failure names its error"));
                }
                if let Some(result_ref) = result_ref {
                    self.report_resolved(rt, result_ref)?;
                    lifecycle
                        .fields
                        .insert("result_ref".to_owned(), result_ref.to_hex());
                }
                lifecycle.fields.insert("error".to_owned(), error.clone());
                lifecycle
                    .fields
                    .insert("retry".to_owned(), retryable.to_string());
                let mut related = Vec::new();
                if retryable
                    && let Escalation::Asked(handle) = self.escalate(
                        rt,
                        EscalationTrigger::RetryRequested,
                        task_ref,
                        key,
                        current.brief.as_ref(),
                        decisions,
                        &[],
                        None,
                    )?
                {
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
                        if retryable {
                            if let Some((record, lease_owner)) = held_try(held) {
                                queue.retry_in_txn(
                                    wtxn,
                                    RetryAttempt {
                                        id: record.id,
                                        lease_owner: lease_owner.to_owned(),
                                        attempt_count: record.attempt_count,
                                        backoff_until: now,
                                        last_error: Some(error.clone()),
                                        now,
                                    },
                                )?;
                            }
                            requeue(body);
                            Ok(false)
                        } else {
                            fail_final_in(
                                queue,
                                wtxn,
                                body,
                                held_try(held),
                                &error,
                                result_ref,
                                now,
                            )?;
                            Ok(true)
                        }
                    },
                )
            }
            TaskReportBody::Release { reason } => {
                if reason.trim().is_empty() {
                    return Err(MemoryError::bad_request("a release names its reason"));
                }
                lifecycle.fields.insert("reason".to_owned(), reason.clone());
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    Vec::new(),
                    None,
                    now,
                    |queue, wtxn, body, held| {
                        if let Some((record, lease_owner)) = held_try(held) {
                            // The same try goes back to the queue as a fresh one,
                            // ready at once: a release is not a failure to back
                            // off from.
                            queue.retry_in_txn(
                                wtxn,
                                RetryAttempt {
                                    id: record.id,
                                    lease_owner: lease_owner.to_owned(),
                                    attempt_count: record.attempt_count,
                                    backoff_until: now,
                                    last_error: Some(reason.clone()),
                                    now,
                                },
                            )?;
                        }
                        requeue(body);
                        Ok(false)
                    },
                )
            }
            TaskReportBody::Ack | TaskReportBody::Brief(_) | TaskReportBody::Edit { .. } => {
                Err(MemoryError::bad_request(
                    "an acknowledgement, brief revision or title edit is not a work report",
                ))
            }
        }
    }

    /// A Done parked on an ask: the TASK blocks on its result and the ask,
    /// and the receipt hands the ask back.
    #[expect(
        clippy::too_many_arguments,
        reason = "one Done's door, identity, fence handle, receipt, result and ask"
    )]
    pub(super) fn commit_asked_up(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        attempt: Option<&AttemptHandle>,
        mut lifecycle: TaskLifecycleRecord,
        result_ref: EntityId,
        handle: TaskAskHandle,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        lifecycle
            .fields
            .insert("ask".to_owned(), handle.group_ref.to_hex());
        let waits = [result_ref, handle.group_ref];
        self.commit_report(
            rt,
            via,
            task_ref,
            attempt,
            lifecycle,
            vec![TaskHandle::Ask {
                group_ref: handle.group_ref,
            }],
            Some(handle),
            now,
            |_, _, body, _| {
                block(body, &waits, now);
                Ok(false)
            },
        )
    }

    /// One report's write: re-check the fence in the committing
    /// transaction, apply `apply` to the try and the TASK, write the TASK,
    /// and, when the TASK settled on a call of its own, signal its waiters
    /// after commit. In a runner's write the caller's commit announces it.
    /// `asked_up` names the ask a parked Done answers with.
    #[expect(
        clippy::too_many_arguments,
        reason = "one report's door, identity, fence handle, receipt and its one write"
    )]
    pub(super) fn commit_report(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        attempt: Option<&AttemptHandle>,
        mut lifecycle: TaskLifecycleRecord,
        related: Vec<TaskHandle>,
        asked_up: Option<TaskAskHandle>,
        now: u64,
        apply: impl FnOnce(
            &AttemptQueue<'_>,
            &mut heed::RwTxn<'_>,
            &mut TaskVerbBody,
            &(Lane, Option<AttemptRecord>, Option<String>),
        ) -> MemoryResult<bool>,
    ) -> MemoryResult<TaskCallReceipt> {
        if !rt.refused.is_empty() {
            lifecycle
                .fields
                .insert("ask_refused".to_owned(), rt.refused.join("; "));
        }
        lifecycle.fields.extend(rt.decisions.drain(..));
        let own = rt.txn.is_none();
        let staged = StagedReport {
            via,
            task_ref,
            attempt,
            journal: rt.journal.as_ref(),
            receipt_id: rt.receipt_id.clone(),
            lifecycle,
            related,
            asked_up,
            now,
        };
        let committed = match rt.txn.as_deref_mut() {
            None => self.with_verified_actor_write_txn(|wtxn| {
                self.commit_report_in_txn(wtxn, staged, apply)
            })?,
            Some(wtxn) => self.commit_report_in_txn(wtxn, staged, apply)?,
        };
        if own && committed.applied {
            self.vault().store.notify_attempt_observers();
            self.vault().store.notify_task_updates([task_ref]);
            if committed.settled {
                // The terminal record committed before the signal goes out; a
                // crash in this gap is replayed from the local binding index.
                crate::llm::send_peer_result_signal(self.vault(), task_ref, now)?;
                crate::llm::reconcile_peer_result_signals(self.vault(), now)?;
            }
        }
        Ok(committed.receipt)
    }

    /// The body of one report's write, in `wtxn`: the journal first, so the
    /// same report again answers its first receipt and moves nothing; then
    /// the fence again, the try and the TASK moved together, the TASK
    /// written, and the receipt journaled beside it. A fence that refuses
    /// writes nothing and journals nothing.
    pub(super) fn commit_report_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        staged: StagedReport<'_>,
        apply: impl FnOnce(
            &AttemptQueue<'_>,
            &mut heed::RwTxn<'_>,
            &mut TaskVerbBody,
            &(Lane, Option<AttemptRecord>, Option<String>),
        ) -> MemoryResult<bool>,
    ) -> MemoryResult<ReportCommit> {
        let StagedReport {
            via,
            task_ref,
            attempt,
            journal,
            receipt_id,
            mut lifecycle,
            related,
            asked_up,
            now,
        } = staged;
        if let Some(identity) = journal
            && let Some(receipt) = report_journal::replay_in(self.vault(), &*wtxn, identity)?
        {
            return Ok(ReportCommit {
                receipt,
                settled: false,
                applied: false,
            });
        }
        let queue = AttemptQueue::new(self.vault());
        let mut body = task_body_in_txn(self.vault(), &*wtxn, task_ref)?;
        let fence = self.report_fence_in(&*wtxn, via, task_ref, &body, attempt)?;
        let Some(held) = fence.held() else {
            let outcome = fence.outcome().unwrap_or(TaskOutcome::StaleFence);
            let late = lifecycle
                .fields
                .get("result_ref")
                .and_then(|hex| EntityId::from_hex(hex).ok());
            return Ok(ReportCommit {
                receipt: Self::fenced_out(task_ref, outcome, lifecycle, late),
                settled: false,
                applied: false,
            });
        };
        let settled = apply(&queue, wtxn, &mut body, &held)?;
        let phase = phase_of(&body);
        self.rewrite_task_in_txn(wtxn, task_ref, body, now)?;
        lifecycle.outcome = match &phase {
            TaskPhase::Terminal { disposition } => disposition.as_str(),
            TaskPhase::Blocked { .. } => "blocked",
            TaskPhase::Queued => "queued",
            TaskPhase::Working { .. } => "working",
            TaskPhase::Proposed { .. }
            | TaskPhase::Rejected
            | TaskPhase::Interrupted
            | TaskPhase::Asked { .. } => "reported",
        }
        .to_owned();
        let mut receipt = TaskCallReceipt {
            handle: attempt.map_or(TaskHandle::Task { task_ref }, |attempt| {
                TaskHandle::Attempt(*attempt)
            }),
            related,
            outcome: match asked_up {
                Some(ask) => TaskOutcome::AskedUp { ask },
                None => TaskOutcome::Reported { phase },
            },
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        };
        // The lifecycle lands with the move, and the journal keeps the
        // receipt naming it, so a replay answers the same reference.
        if let Some(id) = receipt_id {
            lifecycle_receipt::stamp_in(self.vault(), wtxn, &mut receipt, id, None)?;
        }
        // A write that settled the TASK marks its receipt, so a replayed
        // Done under another key names it (FIX 3272).
        if settled && let Some(id) = &receipt.receipt_ref {
            lifecycle_receipt::mark_settled_in(self.vault(), wtxn, id)?;
        }
        if let Some(identity) = journal {
            report_journal::put_in(self.vault(), wtxn, identity, &receipt)?;
        }
        Ok(ReportCommit {
            receipt,
            settled,
            applied: true,
        })
    }
}
