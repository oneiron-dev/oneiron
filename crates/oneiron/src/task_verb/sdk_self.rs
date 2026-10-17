//! The doors of two verb-table rows an agent calls on itself and its own
//! children: `self.memory.diary`, one private diary entry (ARCH-0032
//! `#diary-acl`), and `steer`, the spawner's nudge to its own child, taken
//! at the child's next safe breakpoint (ARCH-0079 channels: `say` is talk,
//! `steer` is control).
use serde::{Deserialize, Serialize};

use super::presence_scan::superseded_attempt_ids;
use super::rate_limit::task_create_owner_in;
use crate::EntityId;
use crate::attempt_queue::AttemptQueue;
use crate::memory::{
    EntityRefReceipt, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError,
    MemoryResult,
};
use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};
use crate::run_tree::{RunSignalInput, RunSignalKind, RunSignalState, RunTreeAdapter};

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
    let task = EntityId::from_hex(&input.task_ref)
        .map_err(|_| MemoryError::bad_request("task_ref is not an entity id"))?;
    let (branch, run_id) = {
        let txn = memory
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        if task_create_owner_in(memory.vault(), &txn, task)? != Some(memory.actor()) {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only the task's spawner steers it",
                &["Steer a task you created; say(...) reaches any other agent."],
            ));
        }
        let task_key = task.to_hex();
        let records: Vec<_> = AttemptQueue::new(memory.vault())
            .list_in_txn(&txn)?
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
        })?
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
