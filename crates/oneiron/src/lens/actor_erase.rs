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
    /// The proposal goes, with its intent, its CODE kind=lens row and its
    /// `lens/intent` NOTE (FIX 11259).
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
/// slot selects goes with its intent and its two vault rows (FIX 11259),
/// when [`ACTOR_ERASE_UNSELECTED_LENS_PROPOSAL`] says so. The pack and its
/// skill stay. One-way, in the erase's own transaction. An id whose entity
/// is no actor scans nothing.
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
            tear_lens_rows_in_txn(vault, wtxn, &lens_ref, &record.prompt_ref)?;
        } else {
            record.proposed_by = ERASED_CALL_IDENTITY.to_owned();
            PROPOSALS.put(&vault.store, wtxn, &lens_ref, &record)?;
        }
    }
    Ok(())
}

/// Tears an erased proposal's CODE kind=lens row `lens_ref` and its
/// `lens/intent` NOTE `prompt_ref` in the erase's own transaction (FIX
/// 11259), as a cascade tears a row: its indexes, edges and side rows go,
/// and its replicas get its tombstone. A row a legal hold keeps stays, as
/// every tear keeps it; a prompt ref that is no id names nothing to tear.
fn tear_lens_rows_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    lens_ref: &EntityId,
    prompt_ref: &str,
) -> Result<()> {
    let prompt = EntityId::from_hex(prompt_ref).ok();
    for id in std::iter::once(*lens_ref).chain(prompt) {
        if crate::store::legal_hold::held_in_txn(&vault.store, wtxn, id.as_bytes())? {
            continue;
        }
        if Some(id) == prompt {
            crate::note::delete_document_in_txn(&vault.store, wtxn, &id)?;
        }
        crate::provenance::erase_row_provenance_in_txn(&vault.store, wtxn, &id, true)?;
        let (existed, vector, graph, neighbors) =
            crate::batch::deindex_entity(&vault.store, wtxn, &id)?;
        if !existed {
            continue;
        }
        crate::batch::stage_cascade_tombstone_in_txn(&vault.store, wtxn, &id)?;
        crate::ppr::invalidate_ppr_for_delete(&vault.store, wtxn, &id, &neighbors)?;
        if graph {
            crate::ppr::increment_graph_version(&vault.store, wtxn)?;
        }
        if vector {
            crate::hnsw::increment_vector_version(&vault.store, wtxn)?;
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
