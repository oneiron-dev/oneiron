//! One-transaction reaction toggle revocation, then the usual sync publication.
use crate::batch::EntityMetadataHeader;
use crate::deletion::{DeleteReason, TombstoneValueV2, window_label_from_timestamp};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_REACTION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use uuid::Uuid;

pub(crate) struct ReactionRevocation {
    pub(crate) id: EntityId,
    learned_at: u64,
    tombstone: TombstoneValueV2,
    window_label: String,
}

impl Vault {
    /// The caller already holds the writer lock and checked reactor binding.
    /// The shell scrub, signal, outbound intent and pending sync tombstone all
    /// share the SAME transaction as the live-triple selection.
    pub(crate) fn revoke_reaction_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        queue_outbound: bool,
    ) -> Result<Option<ReactionRevocation>> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_REACTION,
            ..
        } = live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(None);
        };
        let raw = self
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("reaction revoke header"))?;
        let learned_at = header.learned_at;
        let tombstone = TombstoneValueV2 {
            reason: DeleteReason::UserDelete.into(),
            deleted_at: self.store.clock.now_recorded_at(),
            request_id: *Uuid::from_bytes(self.store.clock.ulid()?).as_bytes(),
        };
        let window_label = window_label_from_timestamp(learned_at);
        crate::reaction::record_revoke(self, txn, id, queue_outbound)?;
        let (existed, had_vector) = self.soft_erase_active_store_in_txn(txn, &id)?;
        if !existed {
            return Err(Error::CorruptedIndex("reaction vanished during revoke"));
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, txn)?;
        }
        self.put_pending_tombstone_in_txn(txn, &window_label, &id, &tombstone)?;
        Ok(Some(ReactionRevocation {
            id,
            learned_at,
            tombstone,
            window_label,
        }))
    }

    /// Called only AFTER the scrub txn commits. On a transient failure the
    /// pending marker remains for restart replay, as on `user_delete`.
    pub(crate) fn publish_reaction_revocation(&self, commit: &ReactionRevocation) -> Result<()> {
        if self.write_crdt_tombstone(
            &commit.id,
            commit.learned_at,
            &commit.tombstone,
            None,
            None,
        )? {
            self.clear_pending_tombstone(&commit.window_label, &commit.id)?;
        }
        Ok(())
    }
}
