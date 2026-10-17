//! The owner's NOTE tombstone doors (OF-073, FIX 2419): the tombstones the
//! monthly NOTE review proposed, and accepting or declining one. The review
//! only asks; a tombstone is the owner's act, through the deletion rail's
//! `user_delete`, and is never reverted.

use super::support::verify_deletion_authority_in_txn;
use super::{
    DeleteReceipt, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult, SafeDeleteReason,
};
use crate::entity_id::EntityId;
use crate::note::NoteTombstoneProposal;

impl Memory<'_> {
    /// The NOTE tombstones the monthly review proposed that the owner has
    /// not decided, oldest first. Owner only.
    pub fn note_tombstone_proposals(&self) -> MemoryResult<Vec<NoteTombstoneProposal>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        Ok(crate::note::open_tombstone_proposals_in_txn(
            self.vault, &txn,
        )?)
    }

    /// Tombstones a proposed NOTE as the owner: the deletion rail's
    /// `user_delete`, whose write rechecks the owner, that the proposal is
    /// open, and that the NOTE still qualifies in the archive it was
    /// proposed in. A tombstone is not reverted.
    pub fn accept_note_tombstone(&self, note: &EntityId) -> MemoryResult<DeleteReceipt> {
        let receipt =
            self.safe_delete_checked(&note.to_hex(), SafeDeleteReason::UserDelete, |txn| {
                if crate::note::tombstone_still_proposed_in_txn(self.vault, txn, *note)? {
                    Ok(())
                } else {
                    Err(not_proposed())
                }
            })?;
        crate::note::tombstone_accepted(self.vault, *note)?;
        Ok(receipt)
    }

    /// Declines a proposed NOTE tombstone as the owner. The NOTE stays
    /// archived, and the review does not ask again while it stays in that
    /// archive.
    pub fn decline_note_tombstone(&self, note: &EntityId) -> MemoryResult<()> {
        {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        }
        if crate::note::decline_tombstone(self.vault, *note)? {
            Ok(())
        } else {
            Err(not_proposed())
        }
    }
}

fn not_proposed() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "no open tombstone proposal names this NOTE, or it no longer qualifies",
        &["List the NOTE tombstone proposals again before deciding one."],
    )
}
