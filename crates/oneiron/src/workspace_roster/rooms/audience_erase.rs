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

use super::audience_edit_guard::kept_root_in;
use super::audience_events::erased_audience_edit;
use super::*;
use crate::deletion::DeleteEntityOutcome;
use crate::registry::ENTITY_TYPE_TURN;
use crate::store::legal_hold::HoldActor;

/// Erases the audience edit `id` its live root keeps, for a privacy erase
/// by `actor` that `reverify` re-proves: in one write, a legal hold naming
/// the edit refuses it, and the edit's body becomes its erased form. `None`
/// when `id` is no such edit, for the erase to run as any other does.
pub(crate) fn erase_audience_edit(
    vault: &Vault,
    id: &EntityId,
    actor: HoldActor,
    reverify: impl Fn(&heed::RoTxn<'_>) -> Result<()>,
) -> Result<Option<DeleteEntityOutcome>> {
    vault.with_write_txn_grouped(|txn| {
        if kept_root_in(&vault.store, txn, id)?.is_none() {
            return Ok(None);
        }
        reverify(txn)?;
        vault
            .store
            .reject_legal_holds_in_txn(txn, &[*id], &actor.privacy(true))?;
        let row = crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let erased = erased_audience_edit(&row.body)?
            .ok_or(Error::CorruptedIndex("thread audience edit body"))?;
        if erased != row.body {
            vault
                .batch_in()
                .put(id, ENTITY_TYPE_TURN, row.occurred, row.learned_at, &erased)
                .apply(txn)?;
            crate::vault::entity_revision::remove_entity_revisions(&vault.store, txn, id)?;
            let raw = vault.get_raw_in(txn, id)?.ok_or(Error::EntityNotFound)?;
            crate::vault::entity_revision::capture_entity_revision(&vault.store, txn, id, &raw)?;
        }
        Ok(Some(DeleteEntityOutcome {
            existed: true,
            receipt_id: None,
            sweep_key: None,
        }))
    })
}
