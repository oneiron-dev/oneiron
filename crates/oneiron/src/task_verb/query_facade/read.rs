//! Task descriptions, updates and acknowledgement.
//! Entry: `Memory::describe`.
//! Public task DTOs stay at their existing `task_verb` paths.

use super::*;

impl Memory<'_> {
    /// Describes one TASK, or the whole TASKS section when no task is named.
    ///
    /// The section renders through the existing board renderer. The TASK
    /// type-index walk is bounded and paged, so a vault past the 100k-row
    /// `entities_by_type` cliff still renders a live board (ARCH-0067 §2: the
    /// board is the dynamic tail, re-rendered every turn). What the scan or
    /// the render cap left out is stated in the section's additive overflow
    /// footer, never silently dropped.
    ///
    /// A named task's card is read direct by id: a row the collapsed board
    /// leaves out is hidden, never gone, so the card never inherits the
    /// section's render cap.
    ///
    /// A handle bound to a read credential describes only the TASKs that
    /// credential reads: a task it does not read has no card, as an absent
    /// one has none.
    pub fn describe(&self, task_ref: Option<EntityId>) -> MemoryResult<TaskDescription> {
        let _provenance = facade_provenance(task_verb_contract(AgentVerb::Describe));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let Some(task_ref) = task_ref else {
            let rows = self.credential_rows(self.section_rows()?)?;
            return Ok(TaskDescription::Section(rows.render()));
        };
        // The credential is judged before the card is read, so a task it
        // does not read names no failure of its own, and again after, so a
        // card read past a revocation is never served.
        if self.credential_withholds(task_ref)? {
            return Err(MemoryError::from(Error::EntityNotFound));
        }
        let Some(intent) = task_presence_for_id(self.vault(), task_ref)? else {
            return Err(MemoryError::from(Error::EntityNotFound));
        };
        if self.credential_withholds(task_ref)? {
            return Err(MemoryError::from(Error::EntityNotFound));
        }
        // An acked failure has left the TASKS surface (the renderer drops it);
        // the typed read verbs must agree, so it has no card by id either.
        if intent.is_acked_failure() {
            return Err(MemoryError::from(Error::EntityNotFound));
        }
        let mut lines = expand_task(&intent);
        // OF-389: a wrapper stays one checkbox; its card names the subproject
        // it holds.
        if let Some(subproject) = self.vault().task_subproject(task_ref)? {
            lines.push(format!("  subproject={}", subproject.to_hex()));
        }
        Ok(TaskDescription::Card { lines })
    }

    /// The rows `describe` renders its TASKS section from, before the render
    /// cap and before any reader's cut: the actor's whole board, even on a
    /// handle bound to a read credential. A host whose reader is narrower
    /// than this facade's actor keeps the rows that reader may see and
    /// renders only those ([`TasksSectionRows::render`]), so it can count
    /// what it withheld. An acknowledged failure, which the section never
    /// renders, is not among them.
    pub fn describe_rows(&self) -> MemoryResult<TasksSectionRows> {
        let _provenance = facade_provenance(task_verb_contract(AgentVerb::Describe));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        self.section_rows()
    }

    pub(super) fn section_rows(&self) -> MemoryResult<TasksSectionRows> {
        let snapshot = task_presence_at(self.vault(), self.destination())?;
        for failure in &snapshot.read_failures {
            tracing::warn!(
                task_ref = %failure.task_ref.to_hex(),
                stage = ?failure.stage,
                kind = ?failure.kind,
                "task presence skipped unreadable row"
            );
        }
        let mut intents = snapshot.intents;
        intents.retain(|intent| !intent.is_acked_failure());
        Ok(TasksSectionRows {
            intents,
            bare_jobs: snapshot.bare_jobs,
            source_exhausted: snapshot.source_exhausted,
        })
    }

    /// Whether this handle's read credential withholds `task_ref`. An unbound
    /// handle withholds nothing.
    pub(in crate::task_verb) fn credential_withholds(
        &self,
        task_ref: EntityId,
    ) -> MemoryResult<bool> {
        Ok(self
            .credential_readable_ids(&[task_ref])?
            .is_some_and(|readable| readable.is_empty()))
    }

    /// `rows` cut to what a handle bound to a read credential reads: each
    /// TASK by the credential's point read. A bare job is an attempt, not an
    /// entity, so no entity read proves it, and the cut drops it. An unbound
    /// handle keeps them all.
    pub(super) fn credential_rows(
        &self,
        mut rows: TasksSectionRows,
    ) -> MemoryResult<TasksSectionRows> {
        let ids: Vec<EntityId> = rows
            .intents
            .iter()
            .filter_map(|intent| EntityId::from_hex(&intent.id).ok())
            .collect();
        if let Some(readable) = self.credential_readable_ids(&ids)? {
            rows.intents.retain(|intent| {
                EntityId::from_hex(&intent.id).is_ok_and(|id| readable.contains(&id))
            });
            rows.bare_jobs.clear();
        }
        Ok(rows)
    }

    /// Updates one TASK with the owner's acknowledgement of its failure: a
    /// thin wrapper over the task highway's `Ack` report (OF-220), whose
    /// richer reports (progress, blocked, done, failed, release, brief) ride
    /// the same verb through [`Memory::tasks_highway`].
    pub fn tasks_update(&self, task_ref: EntityId) -> MemoryResult<TaskUpdateReceipt> {
        if !self.has_task_work_turn() {
            return self.task_work_memory().tasks_update(task_ref);
        }
        self.tasks_highway(
            super::TaskVia::Wire,
            super::TaskCall::Report(super::TaskReport {
                task_ref,
                attempt: None,
                report_key: "ack".to_owned(),
                body: super::TaskReportBody::Ack,
            }),
        )?;
        Ok(TaskUpdateReceipt {
            task_ref,
            acked: task_is_acked(self.vault(), task_ref)?,
            report: None,
        })
    }

    /// `tasks.update` at a host door. Without a report it is the owner's
    /// acknowledgement, as [`Self::tasks_update`]; a report is one task
    /// highway call under the caller's key and attempt, its surface questions
    /// asked through the decision path a host bound, and its answer returned
    /// unchanged. A `resultRef` names a code run's result, which only that
    /// run resolves, so a host door refuses it.
    pub fn tasks_update_request(
        &self,
        input: &super::sdk::TaskUpdateRequest,
    ) -> MemoryResult<TaskUpdateReceipt> {
        if !self.has_task_work_turn() {
            return self.task_work_memory().tasks_update_request(input);
        }
        if input.result_ref.is_some() {
            return Err(MemoryError::bad_request("task_update_result_needs_run"));
        }
        let task_ref = EntityId::from_hex(&input.task_ref)?;
        let Some(body) = input.report.clone() else {
            if input.report_key.is_some() || input.attempt.is_some() {
                return Err(MemoryError::bad_request("task_update_report_required"));
            }
            return self.tasks_update(task_ref);
        };
        let report_key = input
            .report_key
            .clone()
            .ok_or_else(|| MemoryError::bad_request("task_update_report_key_required"))?;
        let via = match self.task_host() {
            Some(binding) => super::TaskVia::Host(binding.clone()),
            None => super::TaskVia::Wire,
        };
        let report = self.tasks_highway(
            via,
            super::TaskCall::Report(super::TaskReport {
                task_ref,
                attempt: input.attempt,
                report_key,
                body,
            }),
        )?;
        Ok(TaskUpdateReceipt {
            task_ref,
            acked: task_is_acked(self.vault(), task_ref)?,
            report: Some(report),
        })
    }

    /// The free render-tier acknowledgement bit of a failed task, as the
    /// highway's `Ack` report runs it.
    ///
    /// Only the task's owner dismisses its failure: the bit takes the row off
    /// every board, so another actor's dismissal is a typed refusal. A task
    /// this handle's credential does not read is absent, as in `describe`.
    /// `witness` writes beside a dismissal, in its transaction, and runs only
    /// when there is one (the highway's lifecycle receipt, OF-220).
    pub(in crate::task_verb) fn tasks_ack_core(
        &self,
        task_ref: EntityId,
        witness: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<TaskUpdateReceipt> {
        let _provenance = facade_provenance(task_verb_contract(AgentVerb::TasksUpdate));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if self.credential_withholds(task_ref)? {
            return Err(MemoryError::from(Error::EntityNotFound));
        }
        // The acknowledgement applies only to a currently-FAILED task: failed
        // rows stay surfaced until acknowledged (08b §3). Acknowledging a
        // queued/running task would pre-set the bit so the later failure is
        // dropped from render and never surfaced — so updating a non-failed
        // task is a no-op that leaves the bit unset.
        //
        // Direct by id, like a `describe` card: a failed row past the board
        // scan prefix must stay acknowledgeable.
        let Some(intent) = task_presence_for_dismissal(self.vault(), task_ref)? else {
            return Err(MemoryError::from(Error::EntityNotFound));
        };
        match task_owned_by(self.vault(), self.actor(), task_ref)? {
            Some(true) => {}
            Some(false) => return Err(not_the_task_owner()),
            None => return Err(MemoryError::from(Error::EntityNotFound)),
        }
        if intent.status != TaskBoardStatus::Failed {
            return Ok(TaskUpdateReceipt {
                task_ref,
                acked: intent.acked,
                report: None,
            });
        }
        // The acknowledgement is a FACT about a real failed row, stamped with
        // who acknowledged it and when, and it commits inside the verified
        // actor's write transaction like every other engine-authored fact.
        let now = self.vault().store.clock.now_recorded_at();
        self.with_verified_actor_write_txn(|wtxn| {
            // Ownership is re-read in the transaction that commits the
            // dismissal, so a TASK rewritten since the check above is judged
            // as it stands now.
            match task_owned_in(self.vault(), &*wtxn, self.actor(), task_ref)? {
                Some(true) => {}
                Some(false) => return Err(not_the_task_owner()),
                None => return Err(MemoryError::from(Error::EntityNotFound)),
            }
            ack_task_in_txn(self.vault(), wtxn, task_ref, self.actor(), now)
                .map_err(MemoryError::from)?;
            witness(wtxn)
        })?;
        Ok(TaskUpdateReceipt {
            task_ref,
            acked: task_is_acked(self.vault(), task_ref)?,
            report: None,
        })
    }
}
