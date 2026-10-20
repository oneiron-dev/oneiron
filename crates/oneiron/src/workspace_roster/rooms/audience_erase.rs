//! A privacy erase of a thread audience edit (FIX 5639). Engine ruling
//! 2026-10-19: "Erasing a remove edit must keep the edit's op and order as a
//! content-free tombstone, so the removed person stays out."
//!
//! The edit's TURN stays a live TURN under its own id, so its place in the
//! fold's order and its header times hold, and the fold applies it as it
//! did. Its body is rewritten as its erased form
//! ([`super::audience_events`]): the thread binding, and the edit's root,
//! person, op and history, made by no one, with no other byte. The put is
//! the one change the DAG admits on an edit, and the edit's retained
//! revisions start over from it, so none keeps who made it. No tombstone,
//! deletion mark, stale mark or withdrawn pin is written: each would drop
//! the edit from the fold as a delete does.
//!
//! # Erased people
//!
//! An actor's erase and a room's erase of one of its people rewrite every
//! edit that names them the same way (FIX 5640): it names them as no one,
//! and anyone else it names stays named. The owner's confirmed erase of an
//! edit is a privacy erase of it (FIX 5906, Engine ruling 2026-10-20), both
//! at the confirm and once a host order that kept it lifts; no edit bound
//! applies to it.

use super::audience_edit_guard::kept_root_in;
use super::audience_events::{AudienceEvent, erased_here_in, event_body, live_edit_in};
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::deletion::{DeleteEntityOutcome, DeleteReason, LegalHoldActorKind};
use crate::memory::{DeleteReceipt, SafeDeleteReason};
use crate::registry::ENTITY_TYPE_TURN;
use crate::store::legal_hold::{HoldActor, pending_erase_by_in_txn};

/// Erases the audience edit `id` its live root keeps, for a privacy erase
/// by `actor` that `reverify` re-proves: in one write, a legal hold naming
/// the edit refuses it, and the edit's body becomes its erased form, a
/// person this vault erased named as no one too. `None` when `id` is no
/// such edit, for the erase to run as any other does.
pub(crate) fn erase_audience_edit(
    vault: &Vault,
    id: &EntityId,
    actor: HoldActor,
    reverify: impl Fn(&heed::RoTxn<'_>) -> Result<()>,
) -> Result<Option<DeleteEntityOutcome>> {
    erase_edit_as(vault, id, |txn| reverify(txn).map(|()| actor.clone()))
}

/// [`erase_audience_edit`] with the actor a hold's refusal names read in
/// the write itself, by `reverify` as it re-proves the erase there.
fn erase_edit_as(
    vault: &Vault,
    id: &EntityId,
    reverify: impl Fn(&heed::RoTxn<'_>) -> Result<HoldActor>,
) -> Result<Option<DeleteEntityOutcome>> {
    vault.with_write_txn_grouped(|txn| {
        if kept_root_in(&vault.store, txn, id)?.is_none() {
            return Ok(None);
        }
        let actor = reverify(txn)?;
        vault
            .store
            .reject_legal_holds_in_txn(txn, &[*id], &actor.privacy(true))?;
        let (_, held) = live_edit_in(vault, txn, id)?
            .ok_or(Error::CorruptedIndex("thread audience edit body"))?;
        let erased = erased_here_in(vault, txn, held.erased())?;
        rewrite_audience_edit_in_txn(vault, txn, id, &erased)?;
        Ok(Some(DeleteEntityOutcome {
            existed: true,
            receipt_id: None,
            sweep_key: None,
        }))
    })
}

/// Rewrites the stored audience edit `id` as recording `event`, in place:
/// its header times kept, its thread binding and no other byte, and its
/// retained revisions started over from the rewritten row, so none keeps
/// whom it named before. An edit already in that form is left as it is.
pub(super) fn rewrite_audience_edit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    event: &AudienceEvent,
) -> Result<()> {
    let row = crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, id)?
        .ok_or(Error::EntityNotFound)?;
    let binding = super::audience::thread_binding(&row.body)?
        .ok_or(Error::CorruptedIndex("thread audience edit body"))?;
    let erased = event_body(&binding, event)?;
    if erased != row.body {
        vault
            .batch_in()
            .put(id, ENTITY_TYPE_TURN, row.occurred, row.learned_at, &erased)
            .apply(txn)?;
        crate::vault::entity_revision::remove_entity_revisions(&vault.store, txn, id)?;
        let raw = vault.get_raw_in(txn, id)?.ok_or(Error::EntityNotFound)?;
        crate::vault::entity_revision::capture_entity_revision(&vault.store, txn, id, &raw)?;
    }
    Ok(())
}

/// The live edit `id`, with `actor` erased where it names them
/// ([`AudienceEvent::erased_for`]), when it does and it is an edit of a
/// thread of `room` where one is named. Only a TURN whose stored bytes
/// spell the actor's id is decoded: an edit names an id by its hex.
fn edit_erased_for(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: Option<EntityId>,
    actor: EntityId,
    id: &EntityId,
) -> Result<Option<AudienceEvent>> {
    let hex = actor.to_hex();
    let spells =
        crate::ports::EntityStoreRead::port_entity_with_raw(&vault.store, txn, id, |raw| {
            Ok(raw.first() == Some(&ENTITY_TYPE_TURN)
                && raw
                    .windows(hex.len())
                    .any(|window| window.eq_ignore_ascii_case(hex.as_bytes())))
        })?;
    if spells != Some(true) {
        return Ok(None);
    }
    Ok(live_edit_in(vault, txn, id)?
        .filter(|(binding, _)| room.is_none_or(|room| binding.room == room))
        .and_then(|(_, event)| event.erased_for(actor)))
}

/// Erasing `actor` from the thread audience edits (FIX 5640): each live
/// edit TURN that names it, as its editor or as the person it adds or
/// removes, is rewritten naming it as no one, anyone else it names kept.
/// Runs in the erase's own transaction, from the actor sweep, over every
/// TURN, however many (rule 5). An id whose entity is no actor scans
/// nothing.
pub(crate) fn erase_audience_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::workspace_roster::join_receipt::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut rewrites = Vec::new();
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        wtxn,
        ENTITY_TYPE_TURN,
        None,
    )? {
        let id = id?;
        if let Some(event) = edit_erased_for(vault, wtxn, None, *actor, &id)? {
            rewrites.push((id, event));
        }
    }
    for (id, event) in &rewrites {
        rewrite_audience_edit_in_txn(vault, wtxn, id, event)?;
    }
    Ok(())
}

/// Erasing `person` from the audience edits of `room`'s threads, as the
/// room's erase of them runs (FIX 5640): each edit the room carries that
/// names them is rewritten naming them as no one, anyone else it names
/// kept. `reauthorize` re-proves the erase in its read and its write;
/// `unheld` is the erase's own legal-hold split, so a held edit stays as it
/// is and is counted once, and one a hold names since stays too. Every
/// edit is read, however many (rule 5).
pub(crate) fn scrub_room_audience(
    vault: &Vault,
    room: EntityId,
    person: EntityId,
    reauthorize: &impl Fn(&heed::RoTxn<'_>) -> Result<()>,
    unheld: impl FnOnce(&[EntityId]) -> Result<Vec<EntityId>>,
) -> Result<()> {
    let named = {
        let txn = vault.store.env.read_txn()?;
        reauthorize(&txn)?;
        let mut named = Vec::new();
        for edge in crate::ports::EdgeStoreRead::port_edges(
            &vault.store,
            &txn,
            &room,
            crate::ports::EdgeDirection::In,
            Some(crate::edge::EdgeKind::ChildOf),
            None,
        )? {
            let id = edge?.target;
            if edit_erased_for(vault, &txn, Some(room), person, &id)?.is_some() {
                named.push(id);
            }
        }
        named
    };
    if named.is_empty() {
        return Ok(());
    }
    let edits = unheld(&named)?;
    vault.with_write_txn_grouped(|txn| {
        reauthorize(txn)?;
        for id in &edits {
            if crate::store::legal_hold::held_in_txn(&vault.store, txn, id.as_bytes())? {
                continue;
            }
            if let Some(event) = edit_erased_for(vault, txn, Some(room), person, id)? {
                rewrite_audience_edit_in_txn(vault, txn, id, &event)?;
            }
        }
        Ok(())
    })
}

impl Memory<'_> {
    /// The owner's confirmed erase of `record` (FIX 5906): an audience edit
    /// its live root keeps is erased as a privacy erase leaves it
    /// ([`erase_audience_edit`]), the owner's proof re-proved in its write
    /// and a hold placed since refusing it, with no receipt; any other
    /// record goes through the owner delete rail as before.
    pub(crate) fn owner_confirmed_erase(
        &self,
        owner: &AuthenticatedOwner,
        record: EntityId,
        reason: SafeDeleteReason,
    ) -> MemoryResult<DeleteReceipt> {
        let vault = self.vault();
        let erased = erase_audience_edit(vault, &record, HoldActor::owner(self.actor()), |txn| {
            owner.revalidate_in_txn(vault, txn).map(drop)
        })?;
        match erased {
            Some(outcome) => Ok(DeleteReceipt {
                existed: outcome.existed,
                reason: reason.as_str().to_owned(),
                receipt_ref: None,
            }),
            None => self.safe_delete(&record.to_hex(), reason),
        }
    }
}

impl Vault {
    /// An owner-confirmed erase of `record` come due, nothing holding it
    /// now (FIX 5906): an audience edit its live root keeps is erased as
    /// [`Memory::owner_confirmed_erase`] erases it, a hold placed since
    /// refusing it; any other record is hard-deleted as before. The edit's
    /// write re-proves that the erase still waits, and a hold's refusal there
    /// names the owner its row records as confirming it (FIX 6099).
    pub(crate) fn due_confirmed_erase(&self, record: &EntityId) -> Result<DeleteEntityOutcome> {
        let erased = erase_edit_as(self, record, |txn| {
            let by = pending_erase_by_in_txn(&self.store, txn, record)?.ok_or_else(|| {
                Error::InvalidConfig("no confirmed erase of this record waits".into())
            })?;
            Ok(by.map_or(HoldActor::UNATTRIBUTED, |by| {
                HoldActor::new(LegalHoldActorKind::Owner, Some(by))
            }))
        })?;
        match erased {
            Some(outcome) => Ok(outcome),
            None => self.delete_entity_with_reason(record, DeleteReason::UserHardDelete),
        }
    }
}
