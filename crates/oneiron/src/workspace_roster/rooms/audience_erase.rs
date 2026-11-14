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
//! # Receipt
//!
//! A privacy erase of an edit writes, in its write, a content-free erase
//! receipt naming the edit, and owes the erasure sweep the compaction of the
//! window carrying its earlier revisions; the receipt completes once that
//! settles (FIX 10234). No hard erase runs for the live edit.
//!
//! # Erased people
//!
//! An actor's erase and a room's erase of one of its people rewrite every
//! edit that names them the same way (FIX 5640): it names them as no one,
//! and anyone else it names stays named.

use super::audience_edit_guard::kept_root_in;
use super::audience_events::{AudienceEvent, erased_here_in, event_body, live_edit_in};
use super::*;
use crate::deletion::{ConfirmedEraseOutcome, DeleteEntityOutcome};
use crate::registry::ENTITY_TYPE_TURN;
use crate::store::legal_hold::HoldActor;

/// Erases the audience edit `id` its live root keeps, for a privacy erase
/// by `actor` that `reverify` re-proves: in one write, a cooperative
/// restriction naming the edit refuses it, and the edit's body becomes its
/// erased form, a person this vault erased named as no one too. `None` when
/// `id` is no such edit, for the erase to run as any other does.
pub(crate) fn erase_audience_edit(
    vault: &Vault,
    id: &EntityId,
    actor: HoldActor,
    reason: crate::deletion::DeleteReason,
    reverify: impl Fn(&heed::RoTxn<'_>) -> Result<()>,
) -> Result<Option<DeleteEntityOutcome>> {
    let erased = erase_edit_as(vault, id, reason, |txn| {
        reverify(txn)?;
        Ok(Some(actor.clone()))
    })?;
    match erased {
        Some(ConfirmedEraseOutcome::Completed(outcome)) => Ok(Some(outcome)),
        // Its proof always names an actor, so it never cancels; were it to,
        // the erase fails rather than running as an ordinary delete.
        Some(ConfirmedEraseOutcome::Cancelled) => Err(Error::InvariantViolation(
            "an ordinary audience edit erase cancelled",
        )),
        None => Ok(None),
    }
}

/// [`erase_audience_edit`] with the actor its receipt names read in
/// the write itself, by `reverify` as it re-proves the erase there. `None`
/// from it cancels the erase, the edit left as it is (FIX 6337); `None`
/// from this, when `id` is no such edit, is never a cancelled one. The
/// erase's receipt lands in the same write (FIX 10234), signed by this
/// device's key, loaded first (P6c); with no key to sign, the edit is
/// erased as before, with no receipt.
fn erase_edit_as(
    vault: &Vault,
    id: &EntityId,
    reason: crate::deletion::DeleteReason,
    reverify: impl Fn(&heed::RoTxn<'_>) -> Result<Option<HoldActor>>,
) -> Result<Option<ConfirmedEraseOutcome>> {
    let edit = {
        let txn = vault.store.env.read_txn()?;
        kept_root_in(&vault.store, &txn, id)?.is_some()
    };
    let signs = edit && vault.prepare_install_signing_logged();
    let outcome = vault.with_write_txn_grouped(|txn| {
        if kept_root_in(&vault.store, txn, id)?.is_none() {
            return Ok(None);
        }
        let Some(actor) = reverify(txn)? else {
            return Ok(Some(ConfirmedEraseOutcome::Cancelled));
        };
        let principal = actor
            .id
            .as_deref()
            .and_then(|id| EntityId::from_hex(id).ok());
        vault.store.reject_restricted_records_in_txn(txn, &[*id])?;
        let (binding, held) = live_edit_in(vault, txn, id)?
            .ok_or(Error::CorruptedIndex("thread audience edit body"))?;
        let erased = erased_here_in(vault, txn, binding.room, held.erased())?;
        rewrite_audience_edit_in_txn(vault, txn, id, &erased)?;
        if matches!(
            reason,
            crate::deletion::DeleteReason::OwnerErase | crate::deletion::DeleteReason::GdprDelete
        ) {
            vault
                .store
                .roll_checkpoint_payload_for_purge_in_txn(txn, id)?;
        } else {
            crate::deletion::settle_checkpoint_payloads_for_reason_in_txn(
                &vault.store,
                txn,
                id,
                Some(reason.into()),
            )?;
        }
        let outcome = if signs {
            let requested_at = vault.store.clock.now_recorded_at();
            vault.record_audience_edit_erase_in_txn(txn, id, principal, reason, requested_at)?
        } else {
            DeleteEntityOutcome {
                existed: true,
                receipt_id: None,
                sweep_key: None,
                turn_program_details: Vec::new(),
            }
        };
        Ok(Some(ConfirmedEraseOutcome::Completed(outcome)))
    })?;
    if matches!(&outcome, Some(ConfirmedEraseOutcome::Completed(_))) {
        vault
            .store
            .finish_checkpoint_payload_retirements_after_commit();
    }
    Ok(outcome)
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
/// `unheld` is the erase's own restriction split, so a held edit stays as
/// it is and is counted once, and one a restriction names since stays
/// too. Every edit is read, however many (rule 5).
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
