//! The doors of two verb-table rows an agent calls on itself and its own
//! children: `self.memory.diary`, one private diary entry (ARCH-0032
//! `#diary-acl`), and `steer`, the spawner's nudge to its own child, taken
//! at the child's next safe breakpoint (ARCH-0079 channels: `say` is talk,
//! `steer` is control). The vault's owner steers any live run too, at the
//! owner route, on their own authenticated session ([`steer_child_as_owner`]).
use serde::{Deserialize, Serialize};

use crate::memory::{EntityRefReceipt, Memory, MemoryError, MemoryResult};
use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};

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

pub(crate) use crate::dreamer_runner::maintenance::agent_health::steer::steer_linked;
pub use crate::dreamer_runner::maintenance::agent_health::steer::{
    SteerReceipt, SteerRequest, steer_child, steer_child_as_owner, steer_child_at,
    steer_child_at_as_owner,
};
