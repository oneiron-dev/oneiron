//! Owner checks for the ordinary booking publication claim write/read seam.

use super::support::{verify_actor_binding_in_txn, verify_owner_actor_binding_in_txn};
use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::edge::EdgeActorClass;
use crate::{EntityId, Vault};

// These keys are staged and removed inside the owner transaction. They are
// never committed or accepted from replay. Generic byte and candidate doors
// cannot mint a publication by copying write-envelope evidence.
pub(crate) fn publication_write_key(id: EntityId) -> Vec<u8> {
    let mut key = b"booking.public_write.in_txn/".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

pub(super) fn stage_publication_write(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> crate::Result<()> {
    vault
        .store
        .vault_meta
        .put(txn, &publication_write_key(id), b"owner")?;
    Ok(())
}

pub(super) fn finish_publication_write(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> crate::Result<()> {
    vault
        .store
        .vault_meta
        .delete(txn, &publication_write_key(id))?;
    Ok(())
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
            .with_write_txn(|txn| {
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
