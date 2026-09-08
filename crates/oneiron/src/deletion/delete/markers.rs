//! pt:/ac: marker and gate-decision commit helpers plus the cleanup-archive door.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY};
use crate::store::GateDecisionRecord;

use super::super::rendezvous::maybe_fail_first_txn_pending_tombstone;
use super::super::tombstone::{
    DecodedTombstoneValue, TombstoneReason, TombstoneValueV2, archive_tombstone_key,
    decode_tombstone_value, pending_tombstone_key,
};

impl Vault {
    /// Archives a checked PERSON/SUMMARY in the cleanup decision transaction.
    /// No headerless fallback, publication, sweep, or per-entity receipt.
    pub(crate) fn archive_cleanup_candidate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        tombstone: &TombstoneValueV2,
    ) -> Result<bool> {
        let Some(raw) = self.store.entities.get(wtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity metadata"))?;
        let eligible = matches!(header.entity_type, ENTITY_TYPE_PERSON | ENTITY_TYPE_SUMMARY);
        if !eligible || tombstone.reason != TombstoneReason::ArchivedByCleanup {
            return Ok(false);
        }
        // Re-prove eligibility at the archive door itself. Archive is a local
        // visibility marker, not erasure: retain the complete body and indexes.
        if crate::vault_cleanup::zero_live_members_in_txn(self, wtxn, id)?.is_none() {
            return Ok(false);
        }
        self.put_archive_tombstone_in_txn(wtxn, id, tombstone)?;
        Ok(true)
    }

    /// Completes the deletion authority record in the same TXN3 write as the
    /// active-store purge and REDACTION_AUDIT receipt. Sync-enabled deletes
    /// stage recovery data before the tombstone commit; sync-disabled deletes
    /// append the evaluated record directly on their first durable purge.
    pub(super) fn append_deletion_gate_decision_in_purge_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        crdt_persisted: bool,
        decision: Option<&GateDecisionRecord>,
        id: &EntityId,
        tombstone_reason: TombstoneReason,
    ) -> Result<()> {
        let Some(decision) = decision else {
            return Ok(());
        };
        if crdt_persisted {
            if self
                .store
                .append_pending_deletion_gate_decision_in_txn(
                    wtxn,
                    decision.decision_id,
                    id.as_bytes(),
                    tombstone_reason.wire_byte(),
                )?
                .is_none()
            {
                return Err(Error::CorruptedIndex("pending deletion gate decision"));
            }
        } else {
            self.store.append_gate_decision_in_txn(wtxn, decision)?;
        }
        Ok(())
    }

    /// Writes the CRDT-independent `pt:{window}:{entity_hex}` marker in the
    /// caller's purge / shell-scrub transaction (ONE-1132 OWNER-DECISION:
    /// deletion durability must not depend on the `sync` cargo feature).
    /// Value = the v2 tombstone wire value, so a sync-enabled boot can
    /// replay it verbatim.
    pub(super) fn put_pending_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        let key = pending_tombstone_key(window_label, id);
        self.store.sync_state.put(wtxn, &key, &value.encode())?;
        Ok(())
    }

    /// Writes the `pt:` marker in a transaction that is ITSELF this delete's
    /// linearization point (fix-leg 9), carrying the crash surrogate that proves
    /// the write is atomic with everything else that transaction did.
    ///
    /// Separate from [`Self::put_pending_tombstone_in_txn`] only so the failure
    /// injection has an exact anchor: the regression arms it, this call fails,
    /// and the caller's `?` drops the whole `RwTxn` un-committed — body and
    /// vector intact, no `pt:`. A future edit that moves the marker back out of
    /// the scrub transaction loses that anchor and the regression goes red.
    pub(super) fn put_linearizing_pending_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        self.put_pending_tombstone_in_txn(wtxn, window_label, id, value)?;
        #[cfg(all(test, not(feature = "sync")))]
        maybe_fail_first_txn_pending_tombstone()?;
        #[cfg(not(all(test, not(feature = "sync"))))]
        maybe_fail_first_txn_pending_tombstone();
        Ok(())
    }

    /// Clears the pending-tombstone marker. Only called once the CRDT
    /// commit + snapshot persistence have succeeded — never before.
    pub(super) fn clear_pending_tombstone(&self, window_label: &str, id: &EntityId) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let key = pending_tombstone_key(window_label, id);
            self.store.sync_state.delete(wtxn, &key)?;
            Ok(())
        })
    }

    /// Writes the GLOBAL `ac:{entity_hex}` cleanup-archive marker in the
    /// caller's shell-scrub transaction (ONE-1931).
    ///
    /// The archive twin of [`Self::put_pending_tombstone_in_txn`], and
    /// deliberately NOT that function: an archive carries no propagation
    /// intent, so its record must live under a prefix no sync replay reads.
    pub(super) fn put_archive_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        let key = archive_tombstone_key(id);
        self.store.sync_state.put(wtxn, &key, &value.encode())?;
        Ok(())
    }

    /// Reads the `ac:` cleanup-archive marker for `id` through the caller's
    /// transaction, decoded (ONE-1931).
    ///
    /// `None` when there is no marker. A marker whose bytes do not decode to
    /// the archive reason is returned VERBATIM rather than swallowed — the
    /// restore door refuses on the decoded reason, so a corrupt or
    /// wrong-reason row must reach it as itself.
    pub(crate) fn archive_tombstone_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<DecodedTombstoneValue>> {
        let key = archive_tombstone_key(id);
        Ok(self
            .store
            .sync_state
            .get(txn, &key)?
            .map(|raw| decode_tombstone_value(&raw)))
    }

    /// Deletes the `ac:` cleanup-archive marker in the caller's transaction,
    /// returning whether a row was there to delete (ONE-1931).
    ///
    /// This IS the restore: the shell the archive kept becomes live again the
    /// moment the marker is gone, and because the archive published nothing,
    /// nothing is withdrawn from any peer.
    pub(crate) fn clear_archive_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let key = archive_tombstone_key(id);
        self.store.sync_state.delete(wtxn, &key)
    }
}
