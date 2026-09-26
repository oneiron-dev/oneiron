//! Owner-bound preview and one-call unshare-before-delete confirmation.

use super::support::verify_deletion_authority_in_txn;
use super::{DeleteReceipt, Memory, MemoryResult, SafeDeleteReason};
use crate::deletion::{DeleteEntityOptions, DeleteEntityPreview};
use crate::entity_id::EntityId;
use crate::write_envelope::WriteActor;

impl Memory<'_> {
    /// Preview the exact record and live, directly attributed brief recipients.
    /// This read is owner-checked; it reveals no body or unverifiable peer list.
    pub fn preview_entity_delete(&self, id: &EntityId) -> MemoryResult<DeleteEntityPreview> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        drop(txn);
        Ok(self.vault.preview_entity_delete(id)?)
    }

    /// A single owner action revokes the previewed brief grants, publishes a
    /// CRDT tombstone (hard purge retracts incident edges with it), then erases
    /// the active body only when `purge` is set. The named delete gate rechecks
    /// owner authority and the preview in its linearizing write transactions.
    /// If a later step fails, already-revoked grants stay revoked; retry with
    /// a fresh preview. Remote recipients may still retain delivered copies.
    pub fn confirm_entity_delete(
        &self,
        preview: &DeleteEntityPreview,
        options: DeleteEntityOptions,
    ) -> MemoryResult<DeleteReceipt> {
        {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
            preview.check_before_unshare(self.vault, &txn)?;
        }
        let actor = WriteActor::new(self.actor, self.actor_class);
        for (share_id, _) in preview.shared_with() {
            self.vault
                .revoke_share(share_id, &actor, self.vault.store.clock.now_recorded_at())?;
        }
        let reason = if options.purge {
            SafeDeleteReason::UserHardDelete
        } else {
            SafeDeleteReason::UserDelete
        };
        self.safe_delete_checked(&preview.entity().to_hex(), reason, |txn| {
            preview
                .check_after_unshare(self.vault, txn)
                .map_err(Into::into)
        })
    }
}
