//! The doors of two verb-table rows an agent calls on itself and its own
//! children: `self.memory.diary`, one private diary entry (ARCH-0032
//! `#diary-acl`), and `steer`, the spawner's nudge to its own child, taken
//! at the child's next safe breakpoint (ARCH-0079 channels: `say` is talk,
//! `steer` is control). The vault's owner steers any live run too, at the
//! owner route, on their own authenticated session ([`steer_child_as_owner`]).
use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::consent::AuthenticatedOwner;
use crate::memory::{
    EntityRefReceipt, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError,
    MemoryResult,
};
use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};
use crate::run_tree::{RunSignalInput, RunSignalKind, RunSignalState, RunTreeAdapter};
use crate::task_verb::superseded_attempt_ids;
use crate::task_verb::task_create_owner_in;
use crate::{EdgeActorClass, EntityId};

/// `self.memory.diary`'s input: one private entry, and the kind of entry it
/// is (`reflection`, `daily`), when the agent names one.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiaryEntryRequest {
    pub content: String,
    #[serde(default)]
    pub kind: Option<String>,
}

/// `self.memory.diary`'s answer: the NOTE the entry was written as.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiaryEntryReceipt {
    pub entry_id: String,
    pub entry_ref: String,
    pub receipt_ref: String,
    /// The entry's NOTE as a typed record ref (OF-063), as the writing door
    /// named it, with no read.
    #[serde(default)]
    pub record: Option<crate::lens::RecordRef>,
}

impl From<EntityRefReceipt> for DiaryEntryReceipt {
    fn from(receipt: EntityRefReceipt) -> Self {
        Self {
            entry_id: receipt.id_hex,
            entry_ref: receipt.entity_ref,
            receipt_ref: receipt.receipt_ref,
            record: receipt.record,
        }
    }
}

/// `self.memory.diary`: one entry in the bound actor's own diary. The NOTE
/// is actor-private: its owner is the handle's actor, never a field the
/// caller names. A named kind heads the entry's text.
pub fn self_memory_diary_write(
    memory: &Memory<'_>,
    input: DiaryEntryRequest,
) -> MemoryResult<DiaryEntryReceipt> {
    let markdown = match input.kind.as_deref().map(str::trim) {
        Some(kind) if !kind.is_empty() => {
            if kind.contains(['\n', '\r']) {
                return Err(MemoryError::bad_request("a diary kind is one line"));
            }
            format!("---\nkind: {kind}\n---\n{}", input.content)
        }
        _ => input.content,
    };
    let source = memory
        .vault()
        .store
        .clock
        .entity_id()
        .map_err(MemoryError::from)?;
    let receipt = memory.author_note(&NoteWriteEnvelope {
        kind: NoteKind::Diary,
        scope: NoteScope::ActorPrivate {
            owner_ref: memory.actor(),
        },
        markdown,
        source_revision_ref: *source.as_bytes(),
        mask: None,
    })?;
    Ok(receipt.into())
}

/// `steer`'s input: the child TASK, the nudge, and the caller's retry key.
/// A resend with the same key and instruction answers the first receipt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SteerRequest {
    pub task_ref: String,
    pub instruction: String,
    pub key: String,
}

/// `steer`'s answer: the live attempt whose inbox holds the signal, and the
/// signal's state (pending until the child's breakpoint takes it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteerReceipt {
    pub task_ref: String,
    pub branch: String,
    pub run_id: String,
    pub key: String,
    pub state: RunSignalState,
}

/// `steer`: the TASK's spawner nudges its live run. Anyone else's steer is
/// refused, not proposed: a nudge carries no effect a review could approve.
pub fn steer_child(memory: &Memory<'_>, input: SteerRequest) -> MemoryResult<SteerReceipt> {
    crate::memory::verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    steer_live_run(memory, input, |txn, task| spawner_admits(memory, txn, task))
}

/// The owner's `steer` (FIX 783, Engine ruling 10-18): the vault's owner
/// nudges any live run in the vault, whoever spawned it. The proof is the
/// owner's own authenticated session, rechecked in the transaction that
/// reads the run, and it must name the bound human caller. Every other
/// actor stays spawner-bound ([`steer_child`]).
pub fn steer_child_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: SteerRequest,
) -> MemoryResult<SteerReceipt> {
    steer_live_run(memory, input, |txn, _task| owner_admits(memory, owner, txn))
}

/// [`steer_child`] at one exact run of the TASK (FIX 8534): `attempt`, as a
/// concern card recorded it, never the TASK's later try. Its signal lands in
/// that attempt's own inbox, and a resend with the same key answers the
/// first receipt, after the run has ended too.
pub fn steer_child_at(
    memory: &Memory<'_>,
    input: SteerRequest,
    attempt: AttemptId,
) -> MemoryResult<SteerReceipt> {
    crate::memory::verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    steer_run(
        memory,
        input,
        |txn, task| spawner_admits(memory, txn, task),
        |txn, task| attempt_run_in(memory, txn, task, attempt),
    )
}

/// [`steer_child_as_owner`] at one exact run of the TASK (FIX 8534), as
/// [`steer_child_at`] reaches it.
pub fn steer_child_at_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: SteerRequest,
    attempt: AttemptId,
) -> MemoryResult<SteerReceipt> {
    steer_run(
        memory,
        input,
        |txn, _task| owner_admits(memory, owner, txn),
        |txn, task| attempt_run_in(memory, txn, task, attempt),
    )
}

/// A steer whose caller commits its own record with the signal (FIX 8533).
/// Who may steer and which run are read as the four `steer_child*` doors
/// read them: the owner's proof when `owner` is set, else the spawner's
/// binding; `attempt` when set, else the TASK's live run. Then one writer
/// runs `check`, lands the signal (a resend under the same key answers the
/// receipt it holds) and runs `record` with that receipt, and commits them
/// together: an error from either rolls the signal back.
pub(crate) fn steer_linked(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: SteerRequest,
    attempt: Option<AttemptId>,
    check: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    record: impl FnOnce(&mut heed::RwTxn<'_>, &SteerReceipt) -> MemoryResult<()>,
) -> MemoryResult<SteerReceipt> {
    if owner.is_none() {
        crate::memory::verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    }
    let task = EntityId::from_hex(&input.task_ref)
        .map_err(|_| MemoryError::bad_request("task_ref is not an entity id"))?;
    let (branch, run_id) = {
        let txn = memory
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        match owner {
            Some(owner) => owner_admits(memory, owner, &txn)?,
            None => spawner_admits(memory, &txn, task)?,
        }
        match attempt {
            Some(attempt) => attempt_run_in(memory, &txn, task, attempt)?,
            None => live_run_in(memory, &txn, task)?,
        }
    };
    let vault = memory.vault();
    let adapter = RunTreeAdapter::new(vault);
    let (receipt, landed) = vault.try_with_write_txn_grouped(|txn| -> MemoryResult<_> {
        check(txn)?;
        let (signal, landed) = adapter.signal_in_txn(
            txn,
            RunSignalInput {
                branch,
                run_id: run_id.clone(),
                key: input.key,
                actor: memory.actor().to_hex(),
                kind: RunSignalKind::Steer {
                    instruction: input.instruction,
                },
            },
        )?;
        let receipt = SteerReceipt {
            task_ref: input.task_ref,
            branch: branch
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            run_id,
            key: signal.key,
            state: signal.state,
        };
        record(txn, &receipt)?;
        Ok((receipt, landed))
    })?;
    if landed {
        vault.store.notify_attempt_observers();
    }
    Ok(receipt)
}

/// The spawner's admission: only the TASK's creator steers it.
fn spawner_admits(memory: &Memory<'_>, txn: &heed::RoTxn<'_>, task: EntityId) -> MemoryResult<()> {
    if task_create_owner_in(memory.vault(), txn, task)? != Some(memory.actor()) {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "only the task's spawner steers it",
            &["Steer a task you created; say(...) reaches any other agent."],
        ));
    }
    Ok(())
}

/// The owner's admission: the owner proof, rechecked in `txn`, names the
/// bound human caller.
fn owner_admits(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<()> {
    if owner.revalidate_in_txn(memory.vault(), txn)? != memory.actor()
        || memory.actor_class() != EdgeActorClass::Human
    {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the owner proof must name the bound caller",
            &["Steer as the vault owner on your own session."],
        ));
    }
    Ok(())
}

/// Both TASK-current steers: `admit` decides who may steer `task` inside the
/// read transaction, then the signal lands in the task's live attempt's
/// inbox.
fn steer_live_run(
    memory: &Memory<'_>,
    input: SteerRequest,
    admit: impl FnOnce(&heed::RoTxn<'_>, EntityId) -> MemoryResult<()>,
) -> MemoryResult<SteerReceipt> {
    steer_run(memory, input, admit, |txn, task| {
        live_run_in(memory, txn, task)
    })
}

/// The task's live attempt and its run: the newest try no retry superseded
/// and no terminal state ended.
fn live_run_in(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> MemoryResult<(AttemptId, String)> {
    let task_key = task.to_hex();
    let records: Vec<_> = AttemptQueue::new(memory.vault())
        .list_in_txn(txn)?
        .into_iter()
        .filter(|record| record.task_ref.as_deref() == Some(task_key.as_str()))
        .collect();
    let superseded = superseded_attempt_ids(&records);
    let live = records
        .iter()
        .rev()
        .filter(|record| !superseded.contains(&record.id) && !record.state.is_terminal())
        .find_map(|record| record.run_id.clone().map(|run_id| (record.id, run_id)));
    live.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the task has no live run to steer",
            &["Steer a task while its run is live."],
        )
    })
}

/// `attempt` and its run, when it is a run of `task`: that attempt alone,
/// never a retry tip. Whether it is still live is the signal's own check,
/// after a resend's replay.
fn attempt_run_in(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    attempt: AttemptId,
) -> MemoryResult<(AttemptId, String)> {
    let task_key = task.to_hex();
    AttemptQueue::new(memory.vault())
        .get_in_txn(txn, attempt)?
        .filter(|record| record.task_ref.as_deref() == Some(task_key.as_str()))
        .and_then(|record| record.run_id.map(|run_id| (record.id, run_id)))
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the attempt is no run of this task",
                &["Steer an attempt the task ran."],
            )
        })
}

/// Every steer: `admit` decides who may steer `task` and `run` names the
/// attempt and run, both inside one read transaction; then the signal lands
/// in that attempt's inbox.
fn steer_run(
    memory: &Memory<'_>,
    input: SteerRequest,
    admit: impl FnOnce(&heed::RoTxn<'_>, EntityId) -> MemoryResult<()>,
    run: impl FnOnce(&heed::RoTxn<'_>, EntityId) -> MemoryResult<(AttemptId, String)>,
) -> MemoryResult<SteerReceipt> {
    let task = EntityId::from_hex(&input.task_ref)
        .map_err(|_| MemoryError::bad_request("task_ref is not an entity id"))?;
    let (branch, run_id) = {
        let txn = memory
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        admit(&txn, task)?;
        run(&txn, task)?
    };
    let signal = RunTreeAdapter::new(memory.vault()).signal(RunSignalInput {
        branch,
        run_id: run_id.clone(),
        key: input.key,
        actor: memory.actor().to_hex(),
        kind: RunSignalKind::Steer {
            instruction: input.instruction,
        },
    })?;
    Ok(SteerReceipt {
        task_ref: input.task_ref,
        branch: branch
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        run_id,
        key: signal.key,
        state: signal.state,
    })
}
