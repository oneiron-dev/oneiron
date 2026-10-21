//! Highway report receipts and fence reads.
//! Entry: `Memory::report_fence_in`.
//! Shared report vocabulary stays in `highway_report`.

use super::*;

impl Memory<'_> {
    /// The id one work report keeps its lifecycle receipt under, `None`
    /// when this surface keeps no record. A journaled report's replay answers
    /// the receipt it journaled, so the id needs only to be its own.
    pub(super) fn report_receipt_id(
        &self,
        task_ref: EntityId,
        key: &str,
        now: u64,
    ) -> MemoryResult<Option<String>> {
        if !self.keeps_lifecycle() {
            return Ok(None);
        }
        lifecycle_receipt::receipt_id(
            "report",
            &[
                task_ref.as_bytes(),
                self.actor().as_bytes(),
                key.as_bytes(),
                &now.to_be_bytes(),
            ],
        )
        .map(Some)
    }

    /// The receipt skeleton of one work report.
    pub(super) fn work_lifecycle(
        &self,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        attempt: Option<&AttemptHandle>,
        body: &TaskReportBody,
        now: u64,
    ) -> TaskLifecycleRecord {
        let mut lifecycle = self.lifecycle_record(
            via,
            "report",
            body.as_str(),
            Some(task_ref),
            attempt.map(|attempt| attempt.attempt_ref),
            now,
        );
        lifecycle
            .fields
            .insert("report_key".to_owned(), key.to_owned());
        lifecycle
            .fields
            .insert("body".to_owned(), body.as_str().to_owned());
        lifecycle
    }

    /// `Ack`: the owner's dismissal of a failed task, today's `tasks.update`.
    pub(super) fn report_ack(
        &self,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        let mut lifecycle =
            self.lifecycle_record(via, "report", "acked", Some(task_ref), None, now);
        lifecycle
            .fields
            .insert("report_key".to_owned(), key.to_owned());
        lifecycle.fields.insert("body".to_owned(), "ack".to_owned());
        // An acknowledgement that dismisses a failure keeps its lifecycle in
        // the dismissal's transaction; one that changes nothing keeps none.
        let receipt_id = self.report_receipt_id(task_ref, key, now)?;
        let mut receipt_ref = None;
        let acked = self.tasks_ack_core(task_ref, |wtxn| {
            if let Some(id) = receipt_id {
                let mut dismissed = lifecycle.clone();
                dismissed
                    .fields
                    .insert("acked".to_owned(), true.to_string());
                receipt_ref = Some(lifecycle_receipt::stamp_record_in(
                    self.vault(),
                    wtxn,
                    &dismissed,
                    id,
                    None,
                )?);
            }
            Ok(())
        })?;
        lifecycle
            .fields
            .insert("acked".to_owned(), acked.acked.to_string());
        let phase = task_verb_body(self.vault(), task_ref)?
            .as_ref()
            .map_or(TaskPhase::Queued, phase_of);
        Ok(TaskCallReceipt {
            handle: TaskHandle::Task { task_ref },
            related: Vec::new(),
            outcome: TaskOutcome::Reported { phase },
            receipt_ref,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        })
    }

    /// The fence one report runs, in `txn`: L02's rule proves the reporter
    /// over the immutable facts (a runner by its lease), the TASK is a live
    /// standard task, and the reporter still holds the work its lane holds
    /// work by.
    pub(super) fn report_fence_in(
        &self,
        txn: &heed::RoTxn<'_>,
        via: &TaskVia,
        task_ref: EntityId,
        body: &TaskVerbBody,
        attempt: Option<&AttemptHandle>,
    ) -> MemoryResult<Fence> {
        let lane = lane_of(body.assignee);
        let (standing, runner) = match (lane, via) {
            (Lane::Runner, TaskVia::Host(binding)) => {
                let (standing, fence) = self.runner_standing_in(txn, binding, task_ref)?;
                (standing, Some(fence))
            }
            // Refused below: the runner's lane never reports over the wire.
            (Lane::Runner, TaskVia::Wire) => (
                self.vault()
                    .task_standing_in(txn, task_ref)?
                    .ok_or_else(not_found)?,
                None,
            ),
            (Lane::External | Lane::Human, _) => (
                self.highway_task_actor_in(
                    txn,
                    task_ref,
                    TaskActorVerb::Report,
                    "The assignee or taker reports; the owner reads its status.",
                )?,
                None,
            ),
        };
        require_live_standard(body, &standing)?;
        let generation = self
            .vault()
            .actor_binding_generation_in_txn(txn, self.actor())?;
        let task_hex = task_ref.to_hex();
        match (lane, runner) {
            (Lane::Runner, None) => Err(invalid_state(
                "the engine's runner reports this task through its host binding",
                "Report from the attempt that realizes the task.",
            )),
            (Lane::Runner, Some(fence)) => Ok(match fence {
                // The runner settles its own try; the report moves the TASK
                // alone.
                HostFence::Held(record) => Fence::Held {
                    lane,
                    attempt: None,
                    lease_owner: None,
                    team: crate::agent_dispatch::attempt_team_stamp(&record)?,
                },
                HostFence::Stale => Fence::Stale,
                HostFence::Missing => Fence::WrongNode,
            }),
            (Lane::Human, _) => Ok(
                if standing.taker.as_ref().is_some_and(|taker| {
                    taker.actor == self.actor() && taker.generation == generation
                }) {
                    Fence::Held {
                        lane,
                        attempt: None,
                        lease_owner: None,
                        team: None,
                    }
                } else {
                    Fence::Stale
                },
            ),
            (Lane::External, _) => {
                let handle = attempt.ok_or_else(|| {
                    MemoryError::bad_request(
                        "an external report names the attempt handle its accept returned",
                    )
                })?;
                if handle.task_ref != task_ref {
                    return Err(MemoryError::bad_request(
                        "the attempt handle names another task",
                    ));
                }
                if let (Some(named), Some(local)) =
                    (handle.node_ref, local_node_in(self.vault(), txn)?)
                    && named != local
                {
                    return Ok(Fence::WrongNode);
                }
                let Some(record) =
                    AttemptQueue::new(self.vault()).get_in_txn(txn, handle.attempt_ref)?
                else {
                    return Ok(Fence::WrongNode);
                };
                if record.task_ref.as_deref() != Some(task_hex.as_str())
                    || record.kind != TASK_EXTERNAL_ATTEMPT_KIND
                {
                    return Err(MemoryError::bad_request(
                        "the attempt handle names another task's try",
                    ));
                }
                let lease_owner = lease_owner_for(self.actor(), generation.as_ref());
                let same_try = record.attempt_count == handle.attempt_count;
                Ok(match record.state {
                    AttemptState::Leased | AttemptState::Landing
                        if same_try
                            && record.lease_owner.as_deref() == Some(lease_owner.as_str()) =>
                    {
                        // OF-540: the team run the try froze at its accept.
                        let team = crate::agent_dispatch::attempt_team_stamp(&record)?;
                        Fence::Held {
                            lane,
                            attempt: Some(record),
                            lease_owner: Some(lease_owner),
                            team,
                        }
                    }
                    AttemptState::Completed | AttemptState::Failed
                        if same_try
                            && standing
                                .taker
                                .as_ref()
                                .is_some_and(|taker| taker.actor == self.actor()) =>
                    {
                        Fence::Settled
                    }
                    _ => Fence::Stale,
                })
            }
        }
    }

    /// One read a report makes: in its own read transaction, or in the
    /// runner's write.
    pub(super) fn report_read<T>(
        &self,
        rt: &ReportTxn<'_, '_>,
        read: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        match rt.txn.as_deref() {
            Some(txn) => read(&**txn),
            None => {
                let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
                read(&txn)
            }
        }
    }

    /// A report's typed ref must still name a live entity.
    pub(super) fn report_resolved(
        &self,
        rt: &ReportTxn<'_, '_>,
        entity_ref: EntityId,
    ) -> MemoryResult<()> {
        self.report_read(rt, |txn| {
            if self
                .vault()
                .get_entity_type_in_txn(txn, &entity_ref)?
                .is_some()
            {
                Ok(())
            } else {
                Err(MemoryError::from(Error::EntityNotFound))
            }
        })
    }

    /// Opens one ask a report raises. On a wire or host call it runs in its
    /// own transaction and a refusal fails the report, as it always has. In
    /// a runner's write, admission's read-only rules run first: a refusal
    /// there opens no ask and is kept for the receipt. `continuation`, when
    /// the ask holds a block, is written beside a first admission, or, when
    /// the approval mode holds the ask, as the owner's approval releases it.
    pub(super) fn report_ask(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        spec: &TaskAskSpec,
        continuation: Option<(&BlockContinuation, &str)>,
    ) -> MemoryResult<Option<TaskAskHandle>> {
        let effect = continuation.map(|(continuation, label)| AskEffect::Block {
            continuation: *continuation,
            label: label.to_owned(),
        });
        match rt.txn.as_deref_mut() {
            None => Ok(Some(self.tasks_ask_composed(spec, effect)?.handle)),
            Some(txn) => {
                if let Err(refusal) = self.ask_admits_in(txn, spec) {
                    rt.refused.push(refusal.message);
                    return Ok(None);
                }
                Ok(Some(
                    self.tasks_ask_composed_in_txn(txn, spec, effect)?.handle,
                ))
            }
        }
    }

    /// An ask's status, settling it when due: in its own transactions, or
    /// in the runner's write.
    pub(super) fn report_ask_status(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        group_ref: EntityId,
    ) -> MemoryResult<TaskAskStatus> {
        let handle = TaskAskHandle { group_ref };
        match rt.txn.as_deref_mut() {
            None => self.tasks_ask_status(handle),
            Some(txn) => self.tasks_ask_status_in_txn(txn, handle),
        }
    }

    /// The owner ask an engine block owes when it would otherwise leave
    /// nobody to ask (R3). On a wire or host call it opens in a transaction
    /// of its own, so any refusal leaves nothing behind; in a runner's
    /// write, admission's read-only rules refuse first. A refusal opens no
    /// ask and is named in the receipt; the TASK still blocks as it did.
    #[expect(
        clippy::too_many_arguments,
        reason = "the report's door and receipt, the TASK and its brief, and the block's continuation"
    )]
    pub(super) fn owner_block_ask(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        lifecycle: &mut TaskLifecycleRecord,
        task_ref: EntityId,
        brief: &StoredBrief,
        continuation: &BlockContinuation,
        key: &str,
        note: Option<&str>,
    ) -> MemoryResult<Option<TaskAskHandle>> {
        let opened = match rt.txn.as_deref_mut() {
            None => self
                .with_verified_actor_write_txn(|txn| {
                    self.open_block_ask_in_txn(txn, task_ref, brief, continuation, key, note)
                })
                .and_then(|opened| opened),
            Some(txn) => {
                self.open_block_ask_in_txn(txn, task_ref, brief, continuation, key, note)?
            }
        };
        Ok(match opened {
            Ok(handle) => {
                lifecycle
                    .fields
                    .insert("owner_ask".to_owned(), handle.group_ref.to_hex());
                Some(handle)
            }
            Err(refusal) => {
                lifecycle
                    .fields
                    .insert("owner_ask_refused".to_owned(), refusal.message);
                None
            }
        })
    }

    /// The TASK, when it already completed with `result_ref` and this actor
    /// is the one it was addressed to (or its owner, on a runner lane), with
    /// the lifecycle receipt of the write that completed it (FIX 3272), when
    /// that write kept one.
    pub(super) fn settled_by(
        &self,
        rt: &ReportTxn<'_, '_>,
        task_ref: EntityId,
        result_ref: EntityId,
    ) -> MemoryResult<Option<(TaskVerbBody, Option<String>)>> {
        self.report_read(rt, |txn| {
            let body = task_body_in_txn(self.vault(), txn, task_ref)?;
            let Some(finished_at) = body
                .terminal()
                .filter(|terminal| {
                    terminal.disposition == TaskTerminalDisposition::Completed
                        && terminal.result_ref == Some(result_ref)
                })
                .map(|terminal| terminal.finished_at)
            else {
                return Ok(None);
            };
            let standing = self.highway_task_actor_in(
                txn,
                task_ref,
                TaskActorVerb::Status,
                "Replay a settled report as the task's owner or assignee.",
            )?;
            if standing.assignee != Some(self.actor()) && standing.owner != self.actor() {
                return Err(not_found());
            }
            let settled = lifecycle_receipt::settled_in(self.vault(), txn, task_ref, finished_at)?;
            Ok(Some((body, settled)))
        })
    }

    /// The fence, read before any ask or question.
    pub(super) fn fence_now(
        &self,
        rt: &ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        attempt: Option<&AttemptHandle>,
    ) -> MemoryResult<(TaskVerbBody, Fence)> {
        self.report_read(rt, |txn| {
            let body = task_body_in_txn(self.vault(), txn, task_ref)?;
            let fence = self.report_fence_in(txn, via, task_ref, &body, attempt)?;
            Ok((body, fence))
        })
    }

    /// A receipt for a report the fence refused.
    pub(super) fn fenced_out(
        task_ref: EntityId,
        outcome: TaskOutcome,
        mut lifecycle: TaskLifecycleRecord,
        late_result: Option<EntityId>,
    ) -> TaskCallReceipt {
        lifecycle.outcome = match outcome {
            TaskOutcome::WrongNode => "wrong_node",
            _ => "stale_fence",
        }
        .to_owned();
        if let Some(result_ref) = late_result {
            lifecycle
                .fields
                .insert("late_result".to_owned(), result_ref.to_hex());
        }
        TaskCallReceipt {
            handle: TaskHandle::Task { task_ref },
            related: Vec::new(),
            outcome,
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        }
    }

    /// A replayed Done: the first terminal answers it, and names the receipt
    /// the write that landed it kept (FIX 3272). A replay keeps none of its
    /// own, so no replay ever stands in for that one.
    pub(super) fn replayed_done(
        task_ref: EntityId,
        (settled, receipt_ref): &(TaskVerbBody, Option<String>),
        mut lifecycle: TaskLifecycleRecord,
    ) -> TaskCallReceipt {
        stamp_fields(&mut lifecycle.fields, settled.brief.as_ref());
        lifecycle.outcome = "replayed".to_owned();
        TaskCallReceipt {
            handle: TaskHandle::Task { task_ref },
            related: Vec::new(),
            outcome: TaskOutcome::Reported {
                phase: phase_of(settled),
            },
            receipt_ref: receipt_ref.clone(),
            lifecycle: Some(lifecycle),
            idempotent_replay: true,
        }
    }
}
