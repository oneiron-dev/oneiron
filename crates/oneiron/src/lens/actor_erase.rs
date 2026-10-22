//! An erased actor out of the lens proposals it made and the slot selections
//! it decided (FIX 3520).

use super::intent::INTENTS;
use super::proposal::{PROPOSALS, SLOTS, slot_key};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::{EntityId, Error, Result, Vault};

/// What an actor's erase does with a lens proposal it made that no slot
/// selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnselectedLensProposalErase {
    /// The proposal goes, with its intent.
    Delete,
    /// The proposal stays and names no one, as a selected one does.
    Keep,
}

/// A proposal no slot selects is still work the owner's selection could
/// mount, so an erase of the actor who made it deletes it (FIX 3520). Its
/// row cannot tell one never selected from one whose selection was cleared,
/// so both go.
pub const ACTOR_ERASE_UNSELECTED_LENS_PROPOSAL: UnselectedLensProposalErase =
    UnselectedLensProposalErase::Delete;

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the lens rows.
use crate::deletion::names_no_actor;

/// Erasing `actor` from the lens proposals it made (FIX 3520): one its slot
/// selects keeps its tree, slot, hashes and time and names no one; one no
/// slot selects goes with its intent, when
/// [`ACTOR_ERASE_UNSELECTED_LENS_PROPOSAL`] says so. The pack and its skill
/// stay. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a proposal or slot row that cannot be read.
pub(crate) fn erase_proposal_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let hex = actor.to_hex();
    let mut proposals = Vec::new();
    for (lens_ref, record) in PROPOSALS.scan(&vault.store, wtxn)? {
        if record.proposed_by == hex {
            proposals.push((lens_ref, record));
        }
    }
    for (lens_ref, mut record) in proposals {
        let skill_id = EntityId::from_hex(&record.skill_id)
            .map_err(|_| Error::CorruptedIndex("lens proposal record"))?;
        let selected = SLOTS
            .get(&vault.store, wtxn, &slot_key(&record.pack_name, &skill_id))?
            .is_some_and(|slot| slot.lens_ref == lens_ref.to_hex());
        if !selected && ACTOR_ERASE_UNSELECTED_LENS_PROPOSAL == UnselectedLensProposalErase::Delete
        {
            PROPOSALS.delete(&vault.store, wtxn, &lens_ref)?;
            INTENTS.delete(&vault.store, wtxn, &lens_ref)?;
        } else {
            record.proposed_by = ERASED_CALL_IDENTITY.to_owned();
            PROPOSALS.put(&vault.store, wtxn, &lens_ref, &record)?;
        }
    }
    Ok(())
}

/// Erasing `actor` from the slot selections it decided (FIX 3520): each
/// keeps its lens, hashes, decision refs and time, and its decider reads
/// [`ERASED_CALL_IDENTITY`]. The selected lens stays mounted: no read of a
/// slot asks who decided it, and a later change takes the live owner's
/// proof. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a slot row that cannot be read.
pub(crate) fn erase_slot_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let hex = actor.to_hex();
    let mut slots = Vec::new();
    for (key, mut slot) in SLOTS.scan(&vault.store, wtxn)? {
        if slot.decided_by == hex {
            slot.decided_by = ERASED_CALL_IDENTITY.to_owned();
            slots.push((key, slot));
        }
    }
    for (key, slot) in slots {
        SLOTS.put(&vault.store, wtxn, &key, &slot)?;
    }
    Ok(())
}
