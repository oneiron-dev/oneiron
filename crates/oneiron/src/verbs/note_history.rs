//! Typed owner actions over NOTE history. No grant or caller-supplied purge
//! floor reaches these doors; the engine chooses the retained pin boundary.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::entity_doc::{PurgeReceipt, TextHistoryErase};
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Vault};

/// `vault.notes.history_purge`'s input: the NOTE whose history the owner
/// erases.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteHistoryPurgeRequest {
    pub note_ref: String,
    /// An asker's approved check-in for this erase, 32 hex
    /// (`text_history_erase_effect_digest` over the note, with no frontier):
    /// the Owner applies it on their own proof, and the outcome names its
    /// asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

/// `vault.notes.history_purge_receipts`'s input: the NOTE whose purge
/// receipts the owner reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteHistoryPurgeReceiptsRequest {
    pub note_ref: String,
}

/// The shared-vault act returned by an owner's explicit history purge.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteHistoryPurgeExecuteRequest {
    pub act_id: String,
}

/// The engine's durable receipt, with encoded causal frontiers rather than
/// a scalar floor. `applied` identifies the boundary the engine retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteHistoryPurgeReceipt {
    pub receipt: String,
    pub entity: String,
    pub document: String,
    /// No actor identity remains after that actor is erased.
    pub actor: Option<String>,
    pub requested: Vec<u8>,
    pub applied: Vec<u8>,
    pub at: u64,
    /// The engine's BLAKE3 hash, not a citation quote's SHA-256.
    pub live_text_hash: [u8; 32],
}

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

/// A waiting act has erased nothing. Its starter executes it after the
/// shared-vault veto window closes without an objection. Each names the
/// check-in decision the erase runs on (2k2): the Owner on their own proof,
/// and the approved check-in of another asker it applied, with its
/// requester; a waiting act records it too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NoteHistoryPurgeOutcome {
    Erased {
        receipt: NoteHistoryPurgeReceipt,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        check_in: Option<crate::check_in::CheckInDecision>,
    },
    Waiting {
        note_ref: String,
        act_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        check_in: Option<crate::check_in::CheckInDecision>,
    },
}

fn note_id(vault: &Vault, note_ref: &str) -> MemoryResult<EntityId> {
    let note = crate::memory::resolve_entity_ref(vault, note_ref)?;
    if vault.get_entity_type(&note)? != Some(crate::registry::ENTITY_TYPE_NOTE) {
        return Err(MemoryError::bad_request("entity is not a NOTE"));
    }
    Ok(note)
}

/// Start the engine's owner-only erase without inventing a caller's floor.
/// With `input.check_in_ref` the Owner applies an asker's approved check-in
/// for this erase (2k2).
pub fn purge_note_history_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: NoteHistoryPurgeRequest,
) -> MemoryResult<NoteHistoryPurgeOutcome> {
    owner.revalidate(vault)?;
    let note = note_id(vault, &input.note_ref)?;
    let check_in_ref = super::shared::check_in_ref(input.check_in_ref.as_deref())?;
    let (erase, decision) =
        vault.start_text_history_erase_with_check_in(owner, &note, None, check_in_ref)?;
    Ok(match erase {
        TextHistoryErase::Erased(receipt) => NoteHistoryPurgeOutcome::Erased {
            receipt: receipt.into(),
            check_in: Some(decision),
        },
        TextHistoryErase::Waiting(act) => NoteHistoryPurgeOutcome::Waiting {
            note_ref: note.to_hex(),
            act_id: act.id,
            check_in: Some(decision),
        },
    })
}

/// The engine checks the act's starter, target, veto window and execution
/// receipt in its own transaction; a retry returns that same receipt.
pub fn execute_note_history_purge_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: NoteHistoryPurgeExecuteRequest,
) -> MemoryResult<NoteHistoryPurgeReceipt> {
    Ok(vault
        .execute_completed_text_history_erase(owner, &input.act_id)?
        .into())
}

pub fn note_history_purge_receipts_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: NoteHistoryPurgeReceiptsRequest,
) -> MemoryResult<Vec<NoteHistoryPurgeReceipt>> {
    owner.revalidate(vault)?;
    let note = note_id(vault, &input.note_ref)?;
    Ok(vault
        .entity_text_purge_receipts(&note)?
        .into_iter()
        .map(Into::into)
        .collect())
}
