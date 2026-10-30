//! The owner-answer obligation: a critical claim's durable hold, which only
//! its owner's answer closes (ARCH-0026 §G3).
//!
//! A critical confirm that attaches from any door (the claim door, the replica
//! hook, policy re-staging, a parked destructive action) opens one per claim:
//! the tray's own put records it. Only an owner answer closes it: a Clear or a
//! Decline the authority log folded for the item's confirm, an approval under
//! an owner-tier proof revalidated in the answering transaction that names the
//! claim at the revision its item showed, or a revision the owner wrote in
//! person. A let-go, a replacement, a timeout, a demotion, a replica overwrite
//! and a deletion close nothing. The obligation is this device's own state: it
//! never replicates, and it is restored with the tray it holds.
//!
//! The obligation is the hold, and every reader asks it, never the tray
//! ([`super::claim_critical_confirm_settled_in_txn`]). The tray row is only the
//! item the owner answers. A door that removes that item without an answer, or
//! a revision that outdates it, leaves the obligation open, and the owner is
//! shown a fresh item for the claim's current revision.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::consent::OwnerAuthoredWrite;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::{PendingGateConsentRecord, Store, TrayRemoval, owner_answer_item_hash};

use super::confirm::{
    GATE_REASON_PENDING_CRITICAL_CONFIRM_REOPENED, pending_row_holds_critical_confirm,
};
use super::doors::GateConsentBinding;
use super::replicated_confirm::put_critical_confirm_item_in_txn;
use super::resolution::resolve_policy_manifest;

/// An owner's answer to the item a claim's obligation names. Only the doors
/// that hold one build it: settlement from the owner's signed authority-log
/// entry, and the doors that revalidated an owner-tier proof in the answering
/// transaction.
pub(crate) struct OwnerAnswer(());

impl OwnerAnswer {
    /// A Clear or a Decline the authority log folded for the item's confirm.
    pub(super) const fn authority_log() -> Self {
        Self(())
    }

    /// An approval under an owner-tier proof revalidated in this transaction
    /// ([`crate::consent::AuthenticatedOwner::owner_answer_in_txn`]). A
    /// person-tier proof, an agent and a delegate never hold one.
    pub(crate) const fn owner(_proof: &OwnerAuthoredWrite) -> Self {
        Self(())
    }
}

/// Closes `claim_id`'s obligation with its owner's answer to the item whose
/// content binding is `answered`, and says how the door removes that item. An
/// answer to an item the obligation no longer names closes nothing: an earlier
/// revision's, or a parked action's over an assertion its owner has not
/// answered. A confirm parked before obligations were recorded is answered as
/// its own item.
pub(crate) fn close_owner_answer_obligation_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    answered: &[u8],
    _answer: OwnerAnswer,
) -> Result<TrayRemoval> {
    let names_answered = match store.owner_answer_obligation_in_txn(wtxn, claim_id)? {
        Some(obligation) => obligation.item == owner_answer_item_hash(answered),
        None => store
            .pending_gate_consent_in_txn(wtxn, claim_id)?
            .is_some_and(|row| {
                pending_row_holds_critical_confirm(&row) && row.diff_handle == answered
            }),
    };
    if !names_answered {
        return Ok(TrayRemoval::Unanswered);
    }
    store.delete_owner_answer_obligation_in_txn(wtxn, claim_id)?;
    Ok(TrayRemoval::Answered)
}

/// Closes `claim_id`'s obligation for a revision its owner wrote in person:
/// owner-authored writes carry their own confirmation.
pub(super) fn close_owner_answer_obligation_by_owner_revision_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    _proof: &OwnerAuthoredWrite,
) -> Result<()> {
    store.delete_owner_answer_obligation_in_txn(wtxn, claim_id)
}

/// A fresh local confirm on the claim's current revision is the item its
/// owner answers now.
pub(super) fn rebind_owner_answer_obligation_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    item: &PendingGateConsentRecord,
) -> Result<()> {
    store.open_owner_answer_obligation_in_txn(
        wtxn,
        claim_id,
        item.decision_id,
        &item.diff_handle,
    )?;
    let mut obligation = store
        .owner_answer_obligation_in_txn(wtxn, claim_id)?
        .ok_or(Error::InvariantViolation(
            "owner answer obligation not opened",
        ))?;
    obligation.item = owner_answer_item_hash(&item.diff_handle);
    store.put_owner_answer_obligation_in_txn(wtxn, &obligation)
}

/// Shows the owner an item for `claim_id`'s open obligation, bound to the
/// claim's current revision: `written` is the revision a put is landing, and
/// `None` reads the stored one.
///
/// A tray row that reviews the current revision is that item: an owner-tier
/// approval of it answers the obligation. A parked destructive action the
/// obligation names is answered first. Otherwise the owner is shown a fresh
/// confirm with no deadline, since a timeout's demotion would rewrite bytes
/// the owner has not answered for. A deleted or closed claim reaches no
/// reader and is shown nothing; its obligation stays open.
pub(crate) fn show_owner_answer_item_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    written: Option<&ClaimBody>,
) -> Result<()> {
    let Some(mut obligation) = store.owner_answer_obligation_in_txn(wtxn, claim_id)? else {
        return Ok(());
    };
    let stored;
    let body = match written {
        Some(body) => body,
        None => {
            let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, claim_id)?
            else {
                return Ok(());
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Ok(());
            }
            stored = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            &stored
        }
    };
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Ok(());
    }
    let policy = resolve_policy_manifest(store, &*wtxn)?;
    let binding = GateConsentBinding::for_claim(body, &policy)?;
    if let Some(row) = store.pending_gate_consent_in_txn(wtxn, claim_id)? {
        if row.diff_handle == binding.diff_handle {
            let item = owner_answer_item_hash(&row.diff_handle);
            if obligation.item != item {
                obligation.item = item;
                store.put_owner_answer_obligation_in_txn(wtxn, &obligation)?;
            }
            return Ok(());
        }
        if owner_answer_item_hash(&row.diff_handle) == obligation.item
            && crate::claim::claim_has_deferred_action_in_txn(store, wtxn, claim_id)?
        {
            return Ok(());
        }
    }
    let item = put_critical_confirm_item_in_txn(
        store,
        wtxn,
        claim_id,
        body,
        binding,
        GATE_REASON_PENDING_CRITICAL_CONFIRM_REOPENED,
    )?;
    obligation.item = owner_answer_item_hash(&item.diff_handle);
    store.put_owner_answer_obligation_in_txn(wtxn, &obligation)
}
