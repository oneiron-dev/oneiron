//! pt:/ac: marker and gate-decision commit helpers plus the cleanup-archive door.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK};
use crate::side_table::HexId;
use crate::store::GateDecisionRecord;

use super::super::erase::PiercedCarrier;
use super::super::receipt::RedactionScope;
use super::super::rendezvous::maybe_fail_first_txn_pending_tombstone;
#[cfg(feature = "sync")]
use super::super::tombstone::TOMBSTONE_VALUE_V2_LEN;
use super::super::tombstone::{
    ARCHIVE_MARKER, DecodedTombstoneValue, PENDING_TOMBSTONE, PendingTombstoneKey, TombstoneReason,
    TombstoneValueV2, decode_tombstone_value,
};
use super::super::topology_delete_intent::{
    clear_own_topology_delete_in_txn, reserve_pierced_carrier_in_txn,
};

/// The carriers a walk tombstoned inside a sync ingest transaction, which cannot publish there:
/// [`Vault::publish_late_pierced_tombstones`] publishes them once it committed. Local, never
/// replicated. Key: id16; value: `[learned_at:8 LE][tombstone value:25][window label]`.
#[cfg(any(feature = "sync", test))]
const LATE_PIERCED: crate::side_table::SideTable<EntityId, Vec<u8>, crate::side_table::Raw> =
    crate::side_table::SideTable::new(&crate::side_table::BLOB_ARTIFACT_LATE_PIERCED);

impl Vault {
    /// Archives a checked PERSON/SUMMARY in the cleanup decision transaction.
    /// No headerless fallback, publication, sweep, or per-entity receipt.
    pub(crate) fn archive_cleanup_candidate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        tombstone: &TombstoneValueV2,
    ) -> Result<bool> {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, id)?
        else {
            return Ok(false);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity metadata"))?;
        let eligible = matches!(
            header.entity_type,
            ENTITY_TYPE_PERSON | ENTITY_TYPE_SUMMARY | ENTITY_TYPE_TASK
        );
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
        let key = PendingTombstoneKey {
            window: window_label.to_owned(),
            id: *id,
        };
        PENDING_TOMBSTONE.put(&self.store, wtxn, &key, &value.encode().to_vec())?;
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

    /// The GDPR/policy scrub's walk (ARCH-0005a, ARCH-0038 carrier 13): HardErase pierces
    /// refcounting BEFORE the scrub drops the version chain and claim pairs the walk reads; the
    /// purge walks again for anything that came since. What it took is kept for the purge's
    /// receipt and sweep row, which a crash before the purge leaves to the replay that completes
    /// it. Returns the carriers to tombstone once the scrub released the bytes.
    pub(in crate::deletion) fn pierce_for_scrub_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        tombstone: &TombstoneValueV2,
        changed: &mut Vec<EntityId>,
    ) -> Result<Vec<PiercedCarrier>> {
        let pierced =
            self.cascade_hard_erase_to_blob_references_in_txn(wtxn, id, &tombstone.encode(), true)?;
        changed.extend(pierced.changed);
        crate::blob_artifact::record_erase_scope_in_txn(&self.store, wtxn, id, &pierced.carriers)?;
        Ok(pierced.tombstoned)
    }

    /// The purge's walk: BEFORE the purge drops the version chain and claim pairs the walk reads,
    /// and in its transaction, the bytes and every reference to them go with the record. The
    /// receipt scope gets one line per carrier, the scrub's included. Returns the carriers to
    /// tombstone once the purge released the bytes.
    pub(in crate::deletion) fn pierce_for_purge_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        tombstone: &TombstoneValueV2,
        affected: &mut Vec<EntityId>,
        scope: &mut RedactionScope,
    ) -> Result<Vec<PiercedCarrier>> {
        let pierced =
            self.cascade_hard_erase_to_blob_references_in_txn(wtxn, id, &tombstone.encode(), true)?;
        affected.extend(pierced.changed);
        let mut carriers = crate::blob_artifact::take_erase_scope_in_txn(&self.store, wtxn, id)?;
        carriers.extend(pierced.carriers);
        carriers.sort_unstable();
        carriers.dedup();
        scope
            .entity_ids
            .extend(carriers.iter().map(EntityId::to_hex));
        Ok(pierced.tombstoned)
    }

    /// Stages the tombstone of each carrier a hard erase pierced (ARCH-0005a) under the erase's
    /// own request, in the transaction that pierced it: its reservation and `pt:` marker, as
    /// the erase's own destructive commit stages them. A carrier another hard request owns keeps
    /// that request's. Returns what it staged, for [`Self::publish_pierced_tombstones`].
    pub(in crate::deletion) fn stage_pierced_tombstones_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        tombstoned: Vec<PiercedCarrier>,
        value: &TombstoneValueV2,
    ) -> Result<Vec<PiercedCarrier>> {
        let mut staged = Vec::new();
        for carrier in tombstoned {
            if !reserve_pierced_carrier_in_txn(
                &self.store,
                wtxn,
                &carrier.id,
                value,
                carrier.learned_at,
            )? {
                continue;
            }
            self.put_pending_tombstone_in_txn(wtxn, &carrier.window_label, &carrier.id, value)?;
            if carrier.window_label.contains('@') {
                super::super::tombstone::DELETION_WINDOW_LABEL.put(
                    &self.store,
                    wtxn,
                    &HexId(carrier.id),
                    &carrier.window_label.as_bytes().to_vec(),
                )?;
            }
            staged.push(carrier);
        }
        Ok(staged)
    }

    /// Publishes the tombstones [`Self::stage_pierced_tombstones_in_txn`] staged, once their
    /// transaction committed: settled, as the erase's tear already committed, and one
    /// publication per window. A crash first leaves each `pt:` marker to the window's replay.
    pub(in crate::deletion) fn publish_pierced_tombstones(
        &self,
        staged: &[PiercedCarrier],
        value: &TombstoneValueV2,
    ) -> Result<()> {
        let mut windows: std::collections::BTreeMap<&str, Vec<(EntityId, u64)>> =
            std::collections::BTreeMap::new();
        for carrier in staged {
            windows
                .entry(carrier.window_label.as_str())
                .or_default()
                .push((carrier.id, carrier.learned_at));
        }
        for (window_label, carriers) in windows {
            let published = self.write_settled_crdt_tombstones(window_label, &carriers, value)?;
            if published.is_empty() {
                continue;
            }
            self.with_write_txn_grouped(|wtxn| {
                for id in &published {
                    self.finish_published_topology_delete_in_txn(wtxn, window_label, id, value)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Stages the tombstones of what a walk pierced inside a sync ingest transaction, as
    /// [`Self::stage_pierced_tombstones_in_txn`] does, and keeps each for
    /// [`Self::publish_late_pierced_tombstones`]: that transaction cannot publish.
    #[cfg(any(feature = "sync", test))]
    pub(in crate::deletion) fn stage_late_pierced_tombstones_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        tombstoned: Vec<PiercedCarrier>,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        for carrier in self.stage_pierced_tombstones_in_txn(wtxn, tombstoned, value)? {
            let mut row = carrier.learned_at.to_le_bytes().to_vec();
            row.extend_from_slice(&value.encode());
            row.extend_from_slice(carrier.window_label.as_bytes());
            LATE_PIERCED.put(&self.store, wtxn, &carrier.id, &row)?;
        }
        Ok(())
    }

    /// ARCH-0005a: publishes the tombstones a walk staged during sync ingest, grouped by window
    /// and request, and forgets each. One whose `pt:` marker is gone was published by its
    /// window's replay. The sync entry points call this once their ingest committed, and the
    /// host's lifecycle tick calls it as a backstop; a crash first leaves the `pt:` markers to
    /// each window's replay. Returns how many it published.
    #[cfg(feature = "sync")]
    pub fn publish_late_pierced_tombstones(&self) -> Result<usize> {
        type Group = (String, [u8; TOMBSTONE_VALUE_V2_LEN]);
        let mut groups: std::collections::BTreeMap<Group, Vec<PiercedCarrier>> =
            std::collections::BTreeMap::new();
        let mut gone = Vec::new();
        {
            let rtxn = self.store.env.read_txn()?;
            for row in LATE_PIERCED.iter_from(&self.store, &rtxn, &[])? {
                let (id, row) = row?;
                let (Some(learned_at), Some(value), Ok(window_label)) = (
                    row.get(..8)
                        .and_then(|raw| raw.try_into().ok())
                        .map(u64::from_le_bytes),
                    row.get(8..8 + TOMBSTONE_VALUE_V2_LEN)
                        .and_then(|raw| <[u8; TOMBSTONE_VALUE_V2_LEN]>::try_from(raw).ok()),
                    std::str::from_utf8(row.get(8 + TOMBSTONE_VALUE_V2_LEN..).unwrap_or_default()),
                ) else {
                    return Err(Error::CorruptedIndex("late pierced tombstone"));
                };
                let key = PendingTombstoneKey {
                    window: window_label.to_owned(),
                    id,
                };
                if PENDING_TOMBSTONE
                    .get_bytes(&self.store, &rtxn, &key)?
                    .is_none_or(|raw| raw != value)
                {
                    gone.push(id);
                    continue;
                }
                groups
                    .entry((window_label.to_owned(), value))
                    .or_default()
                    .push(PiercedCarrier {
                        id,
                        learned_at,
                        window_label: window_label.to_owned(),
                    });
            }
        }
        let mut published = 0;
        for ((_, raw), carriers) in groups {
            let decoded = decode_tombstone_value(&raw);
            let (Some(reason), Some(request_id)) = (decoded.reason, decoded.request_id) else {
                return Err(Error::CorruptedIndex("late pierced tombstone"));
            };
            let value = TombstoneValueV2 {
                reason,
                deleted_at: decoded.deleted_at,
                request_id,
            };
            self.publish_pierced_tombstones(&carriers, &value)?;
            published += carriers.len();
            gone.extend(carriers.iter().map(|carrier| carrier.id));
        }
        if !gone.is_empty() {
            self.with_write_txn_grouped(|wtxn| {
                for id in &gone {
                    LATE_PIERCED.delete(&self.store, wtxn, id)?;
                }
                Ok(())
            })?;
        }
        Ok(published)
    }

    /// Retire this request's propagation marker and reservation together,
    /// only after both CRDT publication and local deletion have committed.
    /// Do not consume a later request's `pt:` row at the same window/entity.
    pub(super) fn finish_published_topology_delete(
        &self,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            self.finish_published_topology_delete_in_txn(wtxn, window_label, id, value)
        })
    }

    fn finish_published_topology_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        let key = PendingTombstoneKey {
            window: window_label.to_owned(),
            id: *id,
        };
        if PENDING_TOMBSTONE
            .get_bytes(&self.store, wtxn, &key)?
            .is_some_and(|raw| raw == value.encode())
        {
            PENDING_TOMBSTONE.delete(&self.store, wtxn, &key)?;
        }
        clear_own_topology_delete_in_txn(&self.store, wtxn, id, &value.request_id, false)?;
        Ok(())
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
        ARCHIVE_MARKER.put(&self.store, wtxn, &HexId(*id), &value.encode().to_vec())?;
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
        Ok(ARCHIVE_MARKER
            .get(&self.store, txn, &HexId(*id))?
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
        ARCHIVE_MARKER.delete(&self.store, wtxn, &HexId(*id))
    }
}
