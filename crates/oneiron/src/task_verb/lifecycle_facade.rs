use crate::Vault;
use crate::code_run::{SelfDurableWait, peer_result_wait};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::llm::send_peer_result_signal;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    verify_actor_binding,
};

use super::consult_result::{ConsultResultInput, TaskResultReceipt, TaskVerbBody};
use super::create_spec::TaskCreateSpec;
use super::create_validation::{
    consult_body_in_txn, consult_refusal, require_resolved_entity, require_resolved_payload_ref,
    standard_body_in_txn, task_body_in_txn,
};
use super::route_receipts::{TaskCreateReceipt, TaskResultInput, TaskStartedReceipt};
use super::terminal_state::{TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord};
use super::verb_kind::TaskAssignee;
use super::wire_encode::encode_task_verb_body;

impl Memory<'_> {
    // ── authoritative execution facts (ONE-1700) ────────────────────────

    /// Stamps the authoritative `started_at` fact once an executor begins. It
    /// is a synced FACT — every device sees who is working on what — and is
    /// engine-owned, outside the five agent-visible `TASKS_VERBS` names.
    ///
    /// Replaying it on an already-started task reports the FIRST `started_at`
    /// and mutates nothing: a re-delivered start is not a restart.
    pub fn mark_task_started(
        &self,
        task_ref: EntityId,
        started_at: u64,
    ) -> MemoryResult<TaskStartedReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let (started_at, idempotent_replay) = self.with_verified_actor_write_txn(|wtxn| {
            let mut body = task_body_in_txn(self.vault(), &*wtxn, task_ref)?;
            self.require_execution_writer(&body)?;
            match body.state {
                Some(TaskExecutionState::Working {
                    started_at: already,
                }) => return Ok((already, true)),
                Some(TaskExecutionState::Terminal(_)) => {
                    return Err(consult_refusal(
                        MEMORY_CODE_INVALID_STATE,
                        "task is already terminal",
                        "A settled task cannot start; read its terminal record.",
                    ));
                }
                Some(TaskExecutionState::Interrupted { .. }) => {
                    return Err(consult_refusal(
                        MEMORY_CODE_INVALID_STATE,
                        "an interrupted task resumes through its ladder, not through start",
                        "Settle the interrupting decision before starting the task.",
                    ));
                }
                None | Some(TaskExecutionState::Queued) => {}
            }
            body.state = Some(TaskExecutionState::Working { started_at });
            let encoded = encode_task_verb_body(body);
            self.put_task_body_in_txn(wtxn, task_ref, &encoded, started_at)?;
            Ok((started_at, false))
        })?;

        Ok(TaskStartedReceipt {
            task_ref,
            started_at,
            idempotent_replay,
        })
    }

    /// Lands the terminal record for ANY executor lane: the local Dreamer or
    /// agent-definition child projecting through its TASK backlink, or a peer
    /// whose exhaust was captured as a durable artifact first and whose ref
    /// lands here.
    ///
    /// `Abandoned` is as first-class as `Completed` — both carry `result_ref`,
    /// because the durable outputs of a run nobody finished are exactly what
    /// makes it reviewable.
    pub fn land_task_result(
        &self,
        task_ref: EntityId,
        input: &TaskResultInput,
    ) -> MemoryResult<TaskResultReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        require_resolved_entity(self.vault(), input.result_ref)?;
        let landed = TaskTerminalRecord {
            disposition: input.disposition,
            result_ref: Some(input.result_ref),
            summary: None,
            finished_at: input.finished_at,
            ladder: None,
            counter_task_ref: None,
        };
        self.settle_task_terminal(task_ref, &landed, input.finished_at, standard_body_in_txn)
    }

    /// Hands one peer-assigned TASK to its executor and returns the durable
    /// wait the C9 host parks on. The TASK ref IS the wait id, so the trap, the
    /// local binding, and the peer's eventual result all key on one entity.
    pub fn delegate_task_and_wait(
        &self,
        spec: &TaskCreateSpec,
    ) -> MemoryResult<(TaskCreateReceipt, SelfDurableWait)> {
        if !matches!(spec.assignee, Some(TaskAssignee::Peer { .. })) {
            return Err(MemoryError::bad_request(
                "delegation requires a peer-actor assignee",
            ));
        }
        let receipt = self.tasks_create(spec)?;
        let Some(task_ref) = receipt.task_ref else {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "delegation parked as a proposal and has nothing to wait on",
                "Approve the parked create, then delegate against the minted task.",
            ));
        };
        Ok((receipt, peer_result_wait(task_ref)))
    }

    // ── consult delegation (ONE-1699) ───────────────────────────────────

    /// Lands one peer answer or abstention on the consult TASK it was addressed
    /// to. Engine-owned and outside the five agent-visible `tasks.*` verbs: the
    /// synced TASK is the single coordination object, so the result settles ON
    /// it rather than being cloned into a second synthetic task.
    pub fn land_consult_result(
        &self,
        task_ref: EntityId,
        input: &ConsultResultInput,
    ) -> MemoryResult<TaskResultReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        input.kind.validate()?;
        // Refs bind to resolved entities HERE, before the write transaction
        // opens — a read transaction cannot be nested inside a write one, and
        // a refusal must leave no partial state behind.
        require_resolved_entity(self.vault(), input.kind.result_ref())?;
        for carried_ref in input.kind.carried_refs() {
            require_resolved_payload_ref(self.vault(), carried_ref)?;
        }
        let landed = TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Completed,
            result_ref: Some(input.kind.result_ref()),
            summary: Some(input.kind.summary()),
            finished_at: input.completed_at,
            ladder: None,
            counter_task_ref: None,
        };
        // The consult keeps its own reader: a non-consult task is refused
        // before the shared terminal writer ever sees it, and the evidence /
        // abstention contract above is unchanged.
        self.settle_task_terminal(task_ref, &landed, input.completed_at, consult_body_in_txn)
    }

    /// The one terminal-write path: assignee actor check, local compare-and-set
    /// against the existing terminal register, one body write, then the C9
    /// peer-result signal. Both the consult and general result doors run it, so
    /// there is exactly one place a task settles.
    ///
    /// The compare-and-set asks about BOTH settled halves of the register: the
    /// terminal record, and the deferring ladder terminal that settles on a row
    /// the TASK axis deliberately keeps live. Either one already settled means
    /// this write is late.
    fn settle_task_terminal(
        &self,
        task_ref: EntityId,
        landed: &TaskTerminalRecord,
        at: u64,
        read_body: impl FnOnce(&Vault, &heed::RoTxn<'_>, EntityId) -> MemoryResult<TaskVerbBody>,
    ) -> MemoryResult<TaskResultReceipt> {
        let (terminal, idempotent_replay) = self.with_verified_actor_write_txn(|wtxn| {
            let mut body = read_body(self.vault(), &*wtxn, task_ref)?;
            self.require_execution_writer(&body)?;
            // Local compare-and-set: one replica settles a task once. A
            // byte-identical replay is the network retrying rather than a
            // second result, so it reports the winner and mutates nothing.
            if let Some(existing) = body.terminal() {
                if existing == landed {
                    return Ok((existing.clone(), true));
                }
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "task is already terminal",
                    "Read the settled terminal record; a converged terminal task is immutable.",
                ));
            }
            // The OTHER settled half. A deferring ladder terminal handed the
            // case to a follow-on and left this row live on purpose, so the
            // check above reads `None` while the ladder is already immutable.
            // Landing a terminal record here would overwrite it with one whose
            // `ladder`, `counter_task_ref` and result linkage are all absent —
            // the escalation's disposition erased by a late result. Nothing
            // reopens a settled ladder, so this is refused rather than merged.
            if body.settled_ladder_disposition().is_some() {
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "this task's ladder already settled and handed the case to a follow-on",
                    "Read the settled ladder record; a settled ladder is immutable, and the follow-on task carries the case.",
                ));
            }
            body.state = Some(TaskExecutionState::Terminal(landed.clone()));
            let encoded = encode_task_verb_body(body);
            self.put_task_body_in_txn(wtxn, task_ref, &encoded, at)?;
            // ONE-1702 SEAM (own-task settlement → WAKE/CARRIER): this is the
            // producer call site for `mint_own_task_event` → `route_event`.
            // ONE-1702 has not landed on this base and owns both signatures and
            // every `context_board/stream.rs` edit, so the call is added on its
            // rebase; no oracle-only event injection substitutes for it.
            Ok((landed.clone(), false))
        })?;

        // The terminal record is committed before the signal goes out, so a
        // crash in this gap loses nothing: `reconcile_peer_result_signals`
        // replays the edge from the local binding index.
        send_peer_result_signal(self.vault(), task_ref, at)?;

        Ok(TaskResultReceipt {
            task_ref,
            terminal,
            idempotent_replay,
        })
    }

    /// The one actor allowed to write execution facts on this TASK: the
    /// addressed executor, or the owner when the assignee is the local Dreamer,
    /// which has no actor row of its own.
    fn require_execution_writer(&self, body: &TaskVerbBody) -> MemoryResult<()> {
        let expected = match body.assignee.and_then(TaskAssignee::entity_ref) {
            Some(entity_ref) => entity_ref,
            None => EntityId::from_hex(&body.owner_ref)
                .map_err(|_| MemoryError::from(Error::InvalidTaskBody("tasks.body.owner_ref")))?,
        };
        if expected == self.actor() {
            Ok(())
        } else {
            // The task is ADDRESSED. A write from anyone else is not a late
            // result, it is an unaddressed write.
            Err(consult_refusal(
                MEMORY_CODE_FORBIDDEN,
                "only the addressed assignee may write this task's execution facts",
                "Write as the actor the task is addressed to.",
            ))
        }
    }
}
