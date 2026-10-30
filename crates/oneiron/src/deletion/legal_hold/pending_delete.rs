//! The owner's plain delete of a record only secret orders keep (OF-470
//! C2, C4, FIX 1465): "erase confirmed; completion pending". The owner's
//! act is accepted and recorded, in one writer: the request with its own
//! reason, its link to the orders that keep the record, and the hold log's
//! `erase_confirmed` event. Nothing is lifted, no bytes go, and nothing
//! about the orders is said. The erase runs from the legal-hold pass under
//! that same reason once nothing holds the record.
//!
//! Only a proven owner's own delete is accepted so. A customer hold, an
//! order the owner may see, a member, an agent, a timer or a raw delete
//! meets the hold's refusal as before. A record the due run's delete rail
//! would refuse for any other reason is not accepted either: the ordinary
//! delete runs, and refuses it as it does today.

use super::{LegalHoldEventKind, LegalHoldReason, LegalHoldTarget};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::deletion::DeleteReason;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::legal_hold::{self as hold_store, HoldActor, PendingErase, PendingEraseKind};

impl Vault {
    /// The owner's own delete of `id` under `reason`, accepted as erase
    /// confirmed, completion pending, while only host orders the owner may
    /// not be told of hold it (FIX 1465). True when it was: the request
    /// waits, under its own reason, and runs once nothing holds the record.
    /// False when it was not so: no such record is stored, nothing holds
    /// it, or a customer hold or an order the owner may see does; the
    /// ordinary delete then runs, and refuses as it does. A user delete
    /// stays a shell-keeping delete and a privacy erasure stays one, its
    /// record use-limited where Oneiron hosts the bytes (C6). The same
    /// request again keeps the one waiting; another one replaces it.
    ///
    /// # Errors
    /// The owner proof no longer holds, or the caller's deletion authority
    /// does not.
    pub fn owner_pending_delete(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        reason: DeleteReason,
    ) -> Result<bool> {
        self.owner_pending_delete_checked(owner, id, reason, &|_| Ok(()))
    }

    /// [`Self::owner_pending_delete`] with the caller's own deletion
    /// `authority` re-proved in its writer too, as the delete rail re-proves
    /// it.
    pub(crate) fn owner_pending_delete_checked(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        reason: DeleteReason,
        authority: &dyn Fn(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<bool> {
        if !matches!(
            reason,
            DeleteReason::UserDelete | DeleteReason::UserHardDelete | DeleteReason::GdprDelete
        ) {
            return Ok(false);
        }
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            authority(txn)?;
            if !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, id)? {
                return Ok(false);
            }
            let now = self.store.clock.now_recorded_at();
            let target = LegalHoldTarget::Record(*id);
            let holds = hold_store::holds_on_in_txn(&self.store, txn, &target)?;
            if holds.is_empty() || !holds.iter().all(|hold| hold.secret_at(now)) {
                return Ok(false);
            }
            // A pad its world's holds keep goes the ordinary way (OF-470).
            if crate::world_keys::reject_held_pad_world_in_txn(&self.store, txn, &[*id]).is_err() {
                return Ok(false);
            }
            // What the due run will refuse is never accepted: the ordinary
            // delete runs instead, and refuses as it does today. The due run
            // is this owner's gated delete (FIX 10402).
            if self.delete_admission_in_txn(txn, id, reason, true).is_err() {
                return Ok(false);
            }
            let generation = self.store.clock.entity_id()?;
            let request = PendingErase {
                confirmed_by: Some(actor.to_hex()),
                confirmed_at: now,
                kind: PendingEraseKind::OwnerDelete,
                reason,
                generation,
                veto_act: None,
                withdrawn: None,
            };
            let stored = hold_store::put_pending_erase_in_txn(&self.store, txn, id, request)?;
            if stored.generation != generation {
                // The same request already waits: it is logged once.
                return Ok(true);
            }
            let who = HoldActor::owner(actor).privacy(reason == DeleteReason::GdprDelete);
            for hold in &holds {
                hold_store::link_erase_in_txn(&self.store, txn, id, hold)?;
                hold_store::log_in_txn(
                    &self.store,
                    txn,
                    hold,
                    LegalHoldEventKind::EraseConfirmed,
                    LegalHoldReason::CompletionPending,
                    vec![target],
                    &who,
                    now,
                    None,
                )?;
            }
            if reason == DeleteReason::GdprDelete {
                hold_store::use_limit_pending_privacy_in_txn(&self.store, txn, *id, now)?;
            }
            Ok(true)
        })
    }
}
