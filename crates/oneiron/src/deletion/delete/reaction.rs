//! Atomic reaction revocation using the existing replicated user-delete tombstone.
use super::super::tombstone::window_label_from_timestamp;
use super::super::{DeleteReason, TombstoneValueV2};
use crate::{EntityId, Result, Vault};

impl Vault {
    pub(crate) fn stage_reaction_revocation(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        tombstone: &TombstoneValueV2,
    ) -> Result<()> {
        self.put_pending_tombstone_in_txn(
            txn,
            &window_label_from_timestamp(learned_at),
            id,
            tombstone,
        )?;
        crate::conversation::reaction::stage_revoked(&self.store, txn, id, tombstone.deleted_at)
    }

    pub(crate) fn publish_reaction_revocation(
        &self,
        id: &EntityId,
        learned_at: u64,
        tombstone: &TombstoneValueV2,
    ) -> Result<()> {
        debug_assert_eq!(tombstone.reason, DeleteReason::UserDelete.into());
        if self.write_crdt_tombstone(id, learned_at, tombstone, None, None)? {
            self.clear_pending_tombstone(&window_label_from_timestamp(learned_at), id)?;
        }
        Ok(())
    }
}
