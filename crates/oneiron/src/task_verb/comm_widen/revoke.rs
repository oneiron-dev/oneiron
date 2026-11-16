//! The owner's revocation of a recorded stop-asking choice (FIX 10695).
//! Entry: `Memory::revoke_comm_widen_standing`.
//!
//! An owner's approve-and-stop-asking answers the asking run's descendants'
//! widen asks up to its reach for as long as that run's row lives (FIX
//! 10178). The owner ends that standing here, in one writer that proves the
//! owner again: the recorded choice stays as it was answered, with the time
//! it was revoked beside it, and the asking run keeps the reach it was
//! approved once. Its descendants, born or not, inherit nothing from it and
//! ask again.

use super::*;
use crate::consent::AuthenticatedOwner;
use crate::memory::MEMORY_CODE_FORBIDDEN;

#[doc(hidden)]
pub use oneiron_verb_wire::task_verb::comm_widen::revoke::CommWidenRevokeReceipt;

impl Memory<'_> {
    /// Ends the standing of the stop-asking choice the run `attempt`'s
    /// widen ask recorded, as the vault owner `owner` proves, rechecked in
    /// the writer that ends it. A second revocation answers the first.
    ///
    /// # Errors
    ///
    /// `FORBIDDEN` when the proof does not name this surface's human caller;
    /// `NOT_FOUND` when the run recorded no stop-asking choice; storage
    /// errors.
    pub fn revoke_comm_widen_standing(
        &self,
        owner: &AuthenticatedOwner,
        attempt: AttemptId,
    ) -> MemoryResult<CommWidenRevokeReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            if owner.revalidate_in_txn(self.vault(), &*txn)? != self.actor()
                || self.actor_class() != EdgeActorClass::Human
            {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "the owner proof must name the bound caller",
                    &["Revoke a stop-asking choice as the vault owner on your own session."],
                ));
            }
            let now = self.vault().store.clock.now_recorded_at();
            let mut record = comm_widen_in(self.vault(), &*txn, attempt)?
                .ok_or_else(crate::task_verb::highway::not_found)?;
            let (approval, revoked) = record
                .revoke_standing(now)
                .ok_or_else(crate::task_verb::highway::not_found)?;
            if revoked {
                put_comm_widen_in(self.vault(), txn, attempt, &record)?;
            }
            Ok(CommWidenRevokeReceipt {
                attempt: crate::entity_id::bytes_to_hex_lower(attempt.as_bytes()),
                reach: approval.reach,
                revoked_at: approval.standing_revoked_at.unwrap_or(now),
                revoked,
            })
        })
    }
}
