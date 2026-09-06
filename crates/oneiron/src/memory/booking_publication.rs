//! Owner checks for the ordinary booking publication claim write/read seam.

use super::support::{verify_actor_binding_in_txn, verify_owner_actor_binding_in_txn};
use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::edge::EdgeActorClass;
use crate::{EntityId, Vault};

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
