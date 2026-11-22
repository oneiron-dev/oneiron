//! Owner checks for the ordinary booking publication claim write/read seam.

use super::support::{verify_actor_binding_in_txn, verify_owner_actor_binding_in_txn};
use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::edge::EdgeActorClass;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

/// Marks an id as inside the owner-authorized booking-publication write
/// transaction. Staged and removed inside that one transaction only, never
/// committed or accepted from replay. A home move's adopting transaction
/// stages it for each publication claim the old home carried, as that
/// node's owner write stored it ([`land_carried_publication_in_txn`]).
/// Key: id16; value: the literal marker `b"owner"` (presence is all any
/// reader checks). Generic byte and candidate
/// doors cannot mint a publication by copying write-envelope evidence:
/// `crate::booking::publication::write_index` checks this row's presence.
pub(crate) const STAGE: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::BOOKING_PUBLICATION_WRITE_STAGE);

pub(super) fn stage_publication_write(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> crate::Result<()> {
    STAGE.put(&vault.store, txn, &id, &b"owner".to_vec())?;
    Ok(())
}

pub(super) fn finish_publication_write(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> crate::Result<()> {
    STAGE.delete(&vault.store, txn, &id)?;
    Ok(())
}

/// FIX [BK-HOME-MOVE-PUBLIC-PAGE-INDEX-NOT-CARRIED]: runs `put`, the landing
/// of publication claim `id` as a home move carried it from the old home,
/// inside the owner write's staging for that one id: the claim is the owner's
/// write as that node stored it, and the move lands it unchanged, never a new
/// one. No generic, candidate or replay door reaches this staging.
///
/// # Errors
///
/// Storage errors, and `put`'s own.
#[cfg(feature = "sync")]
pub(crate) fn land_carried_publication_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    put: impl FnOnce(&mut heed::RwTxn<'_>) -> crate::Result<()>,
) -> crate::Result<()> {
    stage_publication_write(vault, txn, id)?;
    put(txn)?;
    finish_publication_write(vault, txn, id)
}

pub(crate) fn verify_public_booking_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> MemoryResult<()> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &owner)?.is_live() {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "booking publication requires a live owner actor",
            &["Bind the live owner actor through the normal authority interface."],
        ));
    }
    verify_actor_binding_in_txn(vault, txn, owner, EdgeActorClass::Human)?;
    verify_owner_actor_binding_in_txn(vault, txn, owner)
}

impl Memory<'_> {
    /// Confirms a staged booking revision through the same deferred closure gate.
    /// The live owner is checked before either publication slot is writable.
    pub fn confirm_booking_publication(
        &self,
        claim_ref: &str,
        now: u64,
    ) -> MemoryResult<crate::inbox::InboxAmendedApproval> {
        let id = self.resolve_ref(claim_ref)?;
        let (approval, vad) = self
            .vault
            .with_write_txn_grouped(|txn| {
                self.verify_public_booking_writer_in_txn(txn).map_err(|_| {
                    crate::Error::InvalidClaimBody("booking publication owner authority refused")
                })?;
                let body = self
                    .vault
                    .get_claim_in_txn(txn, &id)?
                    .ok_or(crate::Error::EntityNotFound)?;
                if body.predicate != crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE {
                    return Err(crate::Error::InvalidClaimBody("not a booking publication"));
                }
                let old = self
                    .vault
                    .pending_claim_supersession_in_txn(txn, &id)?
                    .ok_or(crate::Error::EntityNotFound)?;
                stage_publication_write(self.vault, txn, id)?;
                stage_publication_write(self.vault, txn, old)?;
                let result = self.vault.approve_inbox_member_with_edit_in_txn(
                    txn,
                    &id,
                    &crate::claim::encode_claim_body(&body)?,
                    now,
                    None,
                )?;
                finish_publication_write(self.vault, txn, id)?;
                finish_publication_write(self.vault, txn, old)?;
                Ok(result)
            })
            .map_err(MemoryError::from)?;
        if let Some(id) = vad {
            self.vault
                .consolidate_claim_vad_now(&id, now)
                .map_err(MemoryError::from)?;
        }
        Ok(approval)
    }

    pub(super) fn verify_public_booking_writer_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<()> {
        if self.actor_class != EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "booking publication is an owner write",
                &["Use the owner-authorized memory claim write interface."],
            ));
        }
        verify_public_booking_owner_in_txn(self.vault, txn, self.actor)
    }
}
