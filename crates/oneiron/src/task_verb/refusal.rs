//! The agent's own refusal of a TASK, applied through her dial (OF-533).
//!
//! An agent who will not do what a TASK asks says so here, naming what her
//! refusal concerns and pointing at a durable reason. Her dial, read live from
//! her AGENT_DEF and the vault's kind, decides what the refusal becomes:
//! nothing; one objection on the TASK, after which she does the work; or a
//! decline that settles the TASK `Rejected` with her reason.
//!
//! Only this door is a self-refusal. A `Failed` result is inability, a
//! provider's content filter is a provider error, a consult abstention is a
//! lack of evidence, and an owner's or magistrate's "no" is a ladder verdict;
//! none of them is read as a refusal or routed through the dial, and the
//! general result door keeps every disposition it had.

use crate::agent_def::{RefusalDomain, RefusalLevel, RefusalOutcome, resolve_refusal};
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    verify_actor_binding,
};
use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};
use crate::registry::ENTITY_TYPE_AGENT_DEF;

use super::consult_payload::ConsultPayloadRef;
use super::consult_result::ConsultResultKind;
use super::create_validation::{consult_refusal, require_resolved_payload_ref, task_body_in_txn};
use super::terminal_state::{TaskTerminalDisposition, TaskTerminalRecord};
use super::verb_kind::TaskKind;
use super::wire_encode::encode_task_verb_body;

/// One agent's tagged refusal of the TASK addressed to her.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfRefusalInput {
    /// What her refusal concerns; her dial may sit differently per domain.
    pub domain: RefusalDomain,
    /// Her durable reason: a claim or turn she can be read back on.
    pub reason_ref: ConsultPayloadRef,
    /// The caller's clock. One later than the engine's is refused.
    pub at: u64,
}

/// The one refusal a TASK carries: who refused, where her dial sat, and why.
/// Written once; a later dial edit never rewrites it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRefusalRecord {
    pub by: EntityId,
    pub domain: RefusalDomain,
    pub level: RefusalLevel,
    pub reason_ref: ConsultPayloadRef,
    pub at: u64,
}

/// Receipt for one self-refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfRefusalReceipt {
    pub task_ref: EntityId,
    /// Where her dial sat for the domain when the refusal was first applied.
    pub level: RefusalLevel,
    pub outcome: RefusalOutcome,
    /// The TASK's refusal record; `None` when the dial sat at `None`.
    pub record: Option<TaskRefusalRecord>,
    /// The terminal record a decline settled.
    pub terminal: Option<TaskTerminalRecord>,
    pub idempotent_replay: bool,
}

impl Memory<'_> {
    /// Applies the bound agent's refusal of `task_ref` through her dial.
    ///
    /// `None` proceeds and writes nothing. `Voice` records her one objection
    /// on the TASK and leaves it live: she does the work and lands its result
    /// through the ordinary door. `Veto` and `Full` settle the TASK `Rejected`
    /// through the shared terminal writer, with her reason as the result; a
    /// consult also keeps it as its abstention reason. Engine-owned, beside
    /// [`Self::land_task_result`] and [`Self::land_consult_result`].
    ///
    /// A TASK carries one refusal. A byte-identical retry replays the first
    /// decision, even after a dial edit; any other second refusal is refused.
    /// Each recorded refusal also notes in her diary where the dial sat. The
    /// TASK write commits first, so a diary failure surfaces as an error and
    /// the retry is a replay.
    pub fn land_task_refusal(
        &self,
        task_ref: EntityId,
        input: &SelfRefusalInput,
    ) -> MemoryResult<SelfRefusalReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if self.actor_class() != crate::EdgeActorClass::Agent {
            return Err(consult_refusal(
                MEMORY_CODE_FORBIDDEN,
                "only an agent's own refusal reaches the refusal dial",
                "A person's no is a rejection through the task's ladder, not a self-refusal.",
            ));
        }
        // Resolved before the write transaction opens, as the result doors do.
        require_resolved_payload_ref(self.vault(), input.reason_ref)?;
        if input.at > self.vault().store.clock.now_recorded_at() {
            return Err(MemoryError::bad_request(
                "refusal time is later than the engine clock",
            ));
        }
        let receipt = self.with_verified_actor_write_txn(|wtxn| {
            let mut body = task_body_in_txn(self.vault(), &*wtxn, task_ref)?;
            self.require_execution_writer(&*wtxn, task_ref, &body)?;
            if let Some(existing) = &body.refusal {
                if existing.by == self.actor()
                    && existing.domain == input.domain
                    && existing.reason_ref == input.reason_ref
                    && existing.at == input.at
                {
                    return Ok(SelfRefusalReceipt {
                        task_ref,
                        level: existing.level,
                        outcome: existing.level.outcome(),
                        record: Some(existing.clone()),
                        terminal: body.terminal().cloned(),
                        idempotent_replay: true,
                    });
                }
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "this task already carries its one refusal",
                    "Read the refusal on the task; a second objection is not recorded.",
                ));
            }
            if body.terminal().is_some() || body.settled_ladder_disposition().is_some() {
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "task is already settled",
                    "A settled task cannot be refused; read its terminal record.",
                ));
            }
            // Her dial, read live: the stored definition at her actor id and
            // this vault's kind.
            if self.vault().get_entity_type_in_txn(&*wtxn, &self.actor())?
                != Some(ENTITY_TYPE_AGENT_DEF)
            {
                return Err(consult_refusal(
                    MEMORY_CODE_FORBIDDEN,
                    "only an agent with a stored definition carries a refusal dial",
                    "Refuse as the agent the task is addressed to.",
                ));
            }
            let definition = self
                .vault()
                .read_agent_definition_in_txn(&*wtxn, &self.actor())?;
            let level = resolve_refusal(
                &definition,
                self.vault().vault_kind_in_txn(&*wtxn)?,
                input.domain,
            );
            let outcome = level.outcome();
            let record = TaskRefusalRecord {
                by: self.actor(),
                domain: input.domain,
                level,
                reason_ref: input.reason_ref,
                at: input.at,
            };
            let mut receipt = SelfRefusalReceipt {
                task_ref,
                level,
                outcome,
                record: None,
                terminal: None,
                idempotent_replay: false,
            };
            match outcome {
                RefusalOutcome::Proceed => {}
                RefusalOutcome::Object => {
                    body.refusal = Some(record.clone());
                    let encoded = encode_task_verb_body(body);
                    self.put_task_body_in_txn(wtxn, task_ref, &encoded, input.at)?;
                    receipt.record = Some(record);
                }
                RefusalOutcome::Decline => {
                    let consult = (body.task_kind() == TaskKind::Consult).then_some(
                        ConsultResultKind::Abstain {
                            result_ref: input.reason_ref.entity_ref(),
                            reason_ref: input.reason_ref,
                        },
                    );
                    let landed = TaskTerminalRecord {
                        disposition: TaskTerminalDisposition::Rejected,
                        result_ref: Some(input.reason_ref.entity_ref()),
                        summary: consult.as_ref().map(ConsultResultKind::summary),
                        finished_at: input.at,
                        ladder: None,
                        counter_task_ref: None,
                    };
                    body.refusal = Some(record.clone());
                    let (terminal, _) = self.settle_task_terminal_in_txn(
                        wtxn,
                        task_ref,
                        body,
                        &landed,
                        input.at,
                        consult.as_ref(),
                    )?;
                    receipt.record = Some(record);
                    receipt.terminal = Some(terminal);
                }
            }
            Ok(receipt)
        })?;

        if receipt.terminal.is_some() {
            self.signal_task_settled(task_ref, input.at)?;
        }
        if !receipt.idempotent_replay
            && let Some(record) = &receipt.record
        {
            self.note_refusal_in_diary(task_ref, record, receipt.outcome)?;
        }
        Ok(receipt)
    }

    /// Her diary records where the dial sat when she refused: one private
    /// NOTE, written as her, through the diary door.
    fn note_refusal_in_diary(
        &self,
        task_ref: EntityId,
        record: &TaskRefusalRecord,
        outcome: RefusalOutcome,
    ) -> MemoryResult<()> {
        let act = match outcome {
            RefusalOutcome::Proceed => return Ok(()),
            RefusalOutcome::Object => "objected to, then did,",
            RefusalOutcome::Decline => "declined",
        };
        self.author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate {
                owner_ref: self.actor(),
            },
            markdown: format!(
                "My refusal dial sat at {} on {} when I {act} task {}.",
                record.level.as_str(),
                record.domain.as_str(),
                task_ref.to_hex(),
            ),
            source_revision_ref: *self.vault().store.clock.entity_id()?.as_bytes(),
            mask: None,
        })?;
        Ok(())
    }
}
