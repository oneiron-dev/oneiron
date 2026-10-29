//! Ask status, waiting and evidence views.
//! Entry: `Memory::tasks_ask_status`.
//! Ask records belong to `ask_record`; wait rows belong to `wait`.

use super::*;

impl Memory<'_> {
    /// Owner and admitted responders see the same winner, including its actor.
    /// An ask held for launch approval reads, to its asker, as pending on
    /// that approval.
    pub fn tasks_ask_status(&self, handle: TaskAskHandle) -> MemoryResult<TaskAskStatus> {
        if !self.has_task_work_turn() {
            return self.task_work_memory().tasks_ask_status(handle);
        }
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if let Some(status) = self.vault().verb_hook_state.session.status_ask(
            self.vault(),
            handle.group_ref,
            self.actor(),
        ) {
            return status;
        }
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let Some(group) = self.ask_group_named_in(&txn, handle.group_ref)? else {
            return self.held_ask_status_in(&txn, handle);
        };
        require_ask_audience(&group, self.actor())?;
        drop(txn);
        self.with_verified_actor_write_txn(|txn| self.tasks_ask_status_in_txn(txn, handle))
    }

    /// The status of an ask still held for launch approval, for its asker;
    /// any other handle with no group is unknown.
    pub(super) fn held_ask_status_in(
        &self,
        txn: &heed::RoTxn<'_>,
        handle: TaskAskHandle,
    ) -> MemoryResult<TaskAskStatus> {
        match super::fanout_launch::held_ask_owner_in(self.vault(), txn, handle.group_ref)? {
            Some(owner) if owner == self.actor() => Ok(TaskAskStatus::Pending {
                hold: Some(TaskAskHoldReason::ApprovalRequired),
            }),
            Some(_) => Err(consult_refusal(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "ask handle is not addressed to this actor",
                "Read an ask you own or answer.",
            )),
            None => Err(MemoryError::bad_request("unknown ask handle")),
        }
    }

    /// [`Self::tasks_ask_status`] inside a write transaction the caller
    /// holds and verified: the same audience check, cut and status read.
    pub(in crate::task_verb) fn tasks_ask_status_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        handle: TaskAskHandle,
    ) -> MemoryResult<TaskAskStatus> {
        let Some(group) = self.ask_group_named_in(txn, handle.group_ref)? else {
            return self.held_ask_status_in(txn, handle);
        };
        require_ask_audience(&group, self.actor())?;
        super::ask_settlement::settle_in(
            self.vault(),
            txn,
            handle.group_ref,
            self.vault().store.clock.now_recorded_at(),
        )?;
        Ok(ask_record::status_in(
            self.vault(),
            txn,
            handle.group_ref,
            &group,
        )?)
    }

    /// Projects a sibling's group winner without replacing that sibling's
    /// terminal evidence. An arbitrary matching correlation is not membership.
    pub fn tasks_ask_status_for_task(
        &self,
        task_ref: EntityId,
    ) -> MemoryResult<Option<TaskAskStatus>> {
        if !self.has_task_work_turn() {
            return self.task_work_memory().tasks_ask_status_for_task(task_ref);
        }
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let body = super::create_validation::task_body_in_txn(self.vault(), &txn, task_ref)?;
        let Some(consult) = body.consult else {
            return Ok(None);
        };
        let Some(group) = self.ask_group_in(&txn, consult.correlation_ref)? else {
            return Ok(None);
        };
        if !group
            .members
            .iter()
            .any(|member| member.task == task_ref.to_hex())
        {
            return Ok(None);
        }
        if group.owner != self.actor().to_hex()
            && !group
                .members
                .iter()
                .any(|member| member.actor == self.actor().to_hex())
        {
            return Err(consult_refusal(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "ask handle is not addressed to this actor",
                "Read an ask you own or answer.",
            ));
        }
        drop(txn);
        self.with_verified_actor_write_txn(|txn| {
            super::ask_settlement::settle_in(
                self.vault(),
                txn,
                consult.correlation_ref,
                self.vault().store.clock.now_recorded_at(),
            )?;
            Ok(Some(ask_record::status_in(
                self.vault(),
                txn,
                consult.correlation_ref,
                &group,
            )?))
        })
    }

    /// Call only when this step has no other work. A host without an engine
    /// step supplies its stable key; code mode consumes the returned C9 park.
    pub fn tasks_wait(
        &self,
        handle: TaskAskHandle,
        step_key: Option<&str>,
    ) -> MemoryResult<TaskAskWait> {
        self.tasks_wait_observing(handle, step_key, 0)
    }

    /// Code mode supplies only a generation proved by its durable bridge
    /// replay. An unrecorded Changed result cannot suppress a future wake.
    pub(crate) fn tasks_wait_observing(
        &self,
        handle: TaskAskHandle,
        step_key: Option<&str>,
        observed_generation: u64,
    ) -> MemoryResult<TaskAskWait> {
        if !self.has_task_work_turn() {
            return self.task_work_memory().tasks_wait_observing(
                handle,
                step_key,
                observed_generation,
            );
        }
        if step_key.is_some_and(str::is_empty) {
            return Err(MemoryError::bad_request("invalid wait step key"));
        }
        self.with_verified_actor_write_txn(|txn| {
            // A world-privacy request waits by its own id (FIX 4706).
            if let Some(wait) = self.world_privacy_wait_in(txn, handle, step_key)? {
                return Ok(wait);
            }
            let Some(group) = self.ask_group_named_in(txn, handle.group_ref)? else {
                // A held ask waits on its approval like any pending ask: the
                // park or the bound wait wakes once it goes out and settles.
                let status = self.held_ask_status_in(txn, handle).map_err(|error| {
                    if error.code == crate::memory::MEMORY_CODE_FORBIDDEN {
                        MemoryError::bad_request("only the asking actor may wait")
                    } else {
                        error
                    }
                })?;
                return match step_key {
                    None => {
                        let mut wait = peer_result_wait(handle.group_ref);
                        wait.effect = crate::code_run::SelfEffect::TasksWait;
                        Ok(TaskAskWait::Park(wait))
                    }
                    Some(step_key) => self.bind_external_wait(txn, handle, step_key, status),
                };
            };
            if group.owner != self.actor().to_hex() {
                return Err(MemoryError::bad_request("only the asking actor may wait"));
            }
            super::ask_settlement::settle_in(
                self.vault(),
                txn,
                handle.group_ref,
                self.vault().store.clock.now_recorded_at(),
            )?;
            let status = ask_record::status_in(self.vault(), txn, handle.group_ref, &group)?;
            let Some(step_key) = step_key else {
                return Ok(match status {
                    TaskAskStatus::Pending { .. } => {
                        let voided = super::ask_option_link::voided_friends_in_txn(
                            self.vault(),
                            txn,
                            handle.group_ref,
                            &group,
                        )?;
                        let generation = super::ask_option_link::option_void_generation_in(
                            self.vault(),
                            txn,
                            handle.group_ref,
                        )?;
                        if generation > observed_generation && !voided.is_empty() {
                            TaskAskWait::Changed { voided, generation }
                        } else {
                            let mut wait = peer_result_wait(handle.group_ref);
                            wait.effect = crate::code_run::SelfEffect::TasksWait;
                            TaskAskWait::Park(wait)
                        }
                    }
                    TaskAskStatus::Settled(result) => TaskAskWait::Ready(result),
                    TaskAskStatus::Changed { voided, generation } => {
                        TaskAskWait::Changed { voided, generation }
                    }
                    TaskAskStatus::WorldPrivacy(request) => TaskAskWait::WorldPrivacyReady(request),
                });
            };
            self.bind_external_wait(txn, handle, step_key, status)
        })
    }
}

impl Memory<'_> {
    /// Owner-scoped calibration pairs. The outcome reader rechecks current
    /// fact fields, lifecycle and privacy; the ask id is never a read grant.
    pub fn tasks_ask_outcomes(
        &self,
        handle: &TaskAskHandle,
    ) -> MemoryResult<Vec<crate::llm::decision::questions::CalibrationPair>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = self
            .ask_group_named_in(&txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        if group.owner != self.actor().to_hex() {
            return Err(MemoryError::bad_request(
                "only the asking actor may read outcomes",
            ));
        }
        drop(txn);
        Ok(crate::llm::decision::questions::calibration_pairs(
            self.vault(),
            self.actor(),
            handle.group_ref,
            self.destination(),
        )?)
    }
}

impl Memory<'_> {
    /// `peek(ask)`: attributed partial words, then explicit unknowns at cutoff.
    /// Reading this view never mints a TASK or settles an ask.
    pub fn tasks_ask_peek(
        &self,
        handle: TaskAskHandle,
    ) -> MemoryResult<Vec<TaskAskPersonEvidence>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = self
            .ask_group_named_in(&txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        if group.owner != self.actor().to_hex()
            && !group
                .members
                .iter()
                .any(|member| member.actor == self.actor().to_hex())
        {
            return Err(consult_refusal(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "ask handle is not addressed to this actor",
                "Read an ask you own or answer.",
            ));
        }
        Ok(ask_record::person_evidence_in(
            self.vault(),
            &txn,
            handle.group_ref,
            &group,
            self.vault().store.clock.now_recorded_at(),
        )?)
    }

    /// Live evidence includes late words, without rewriting the cutoff receipt.
    pub fn tasks_ask_evidence(&self, handle: TaskAskHandle) -> MemoryResult<Vec<TaskAskEvidence>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = self
            .ask_group_named_in(&txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        if group.owner != self.actor().to_hex()
            && !group
                .members
                .iter()
                .any(|member| member.actor == self.actor().to_hex())
        {
            return Err(MemoryError::bad_request(
                "ask evidence is not addressed to this actor",
            ));
        }
        Ok(super::ask_settlement::evidence(
            self.vault(),
            &txn,
            handle.group_ref,
            &group,
        )?)
    }
}
