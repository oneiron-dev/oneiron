//! Typed owner actions over NOTE history. No grant or caller-supplied purge
//! floor reaches these doors; the engine chooses the retained pin boundary.

use super::owner_confirm;
use crate::consent::AuthenticatedOwner;
use crate::entity_doc::{PurgeReceipt, TextHistoryErase};
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::note_history::{
    NoteHistoryPurgeExecuteRequest, NoteHistoryPurgeOutcome, NoteHistoryPurgeReceipt,
    NoteHistoryPurgeRequest,
};

impl From<PurgeReceipt> for NoteHistoryPurgeReceipt {
    fn from(receipt: PurgeReceipt) -> Self {
        Self {
            receipt: receipt.receipt,
            entity: receipt.entity,
            document: receipt.document,
            actor: receipt.actor.id().map(|actor| actor.to_hex()),
            requested: receipt.requested,
            applied: receipt.applied,
            at: receipt.at,
            live_text_hash: receipt.live_text_hash,
        }
    }
}

fn note_id(vault: &Vault, note_ref: &str) -> MemoryResult<EntityId> {
    let note = crate::memory::resolve_entity_ref(vault, note_ref)?;
    if vault.get_entity_type(&note)? != Some(crate::registry::ENTITY_TYPE_NOTE) {
        return Err(MemoryError::bad_request("entity is not a NOTE"));
    }
    Ok(note)
}

/// Start the engine's owner-only erase without inventing a caller's floor.
/// Where the purge erases at once (no veto vault, so one Owner) it takes
/// the shared confirm; a purge that opens a veto window is not yet one-way,
/// so its start takes none and its `_execute` keeps erase and its confirm
/// (PURGE-START, Engine 11:34).
pub fn purge_note_history_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: NoteHistoryPurgeRequest,
) -> MemoryResult<NoteHistoryPurgeOutcome> {
    owner.revalidate(vault)?;
    let note = note_id(vault, &input.note_ref)?;
    let outcome = vault.start_text_history_erase_with(owner, &note, None, || {
        let ask = owner_confirm::asked("vault.notes.history_purge", &input)?;
        owner_confirm::admit(vault, owner, ask, &())
    })?;
    Ok(match outcome {
        TextHistoryErase::Erased(receipt) => NoteHistoryPurgeOutcome::Erased {
            receipt: receipt.into(),
        },
        TextHistoryErase::Waiting(act) => NoteHistoryPurgeOutcome::Waiting {
            note_ref: note.to_hex(),
            act_id: act.id,
        },
    })
}

/// The engine checks the act's starter, target, veto window and execution
/// receipt in its own transaction; a retry returns that same receipt. The
/// call takes the shared confirm of its act first.
pub fn execute_note_history_purge_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: NoteHistoryPurgeExecuteRequest,
) -> MemoryResult<NoteHistoryPurgeReceipt> {
    let ask = owner_confirm::asked("vault.notes.history_purge_execute", &input)?;
    owner_confirm::admit(vault, owner, ask, &())?;
    Ok(vault
        .execute_completed_text_history_erase(owner, &input.act_id)?
        .into())
}

pub fn note_history_purge_receipts_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: NoteHistoryPurgeRequest,
) -> MemoryResult<Vec<NoteHistoryPurgeReceipt>> {
    owner.revalidate(vault)?;
    let note = note_id(vault, &input.note_ref)?;
    Ok(vault
        .entity_text_purge_receipts(&note)?
        .into_iter()
        .map(Into::into)
        .collect())
}
