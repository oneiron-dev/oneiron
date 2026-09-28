use super::*;

impl Vault {
    /// Presence-only check for the permanent `dt:{entity_hex}` local
    /// hard-delete marker. Materialization gates OR this with the CRDT
    /// tombstones-map presence so LOCAL delete truth survives hostile
    /// tombstone-map manipulation (a removed tombstone + re-put entity must
    /// not resurrect). The value is NEVER decoded (pinned presence-only
    /// semantics).
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn local_hard_delete_marker_exists_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(self
            .store
            .sync_state
            .get(txn, &local_hard_delete_key(id))?
            .is_some())
    }

    /// Removes a headerless tombstone replay's stale `dt:` poison once a
    /// delete-protected engine row is successfully admitted. This is called
    /// in the SAME transaction as protected-row materialization and tombstone
    /// quarantine; such a marker never represented valid delete authority.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn neutralize_delete_protected_marker_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        entity_type: u8,
    ) -> Result<bool> {
        if !crate::registry::is_delete_protected_engine_record(entity_type) {
            return Err(Error::InvariantViolation(
                "dt: poison neutralization requires a delete-protected engine record",
            ));
        }
        self.store
            .sync_state
            .delete(wtxn, &local_hard_delete_key(id))
    }

    pub(in crate::deletion) fn active_delete_scope_exists_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if crate::note::citation_delete_scope_exists(&self.store, txn, id)?
            || crate::skill_hub::source_custody_exists_in_txn(&self.store, txn, id)?
            || crate::skill_hub::claim_refinement_scope_exists_in_txn(&self.store, txn, id)?
            || crate::skill_hub::refinement_custody_exists_in_txn(&self.store, txn, id)?
            || crate::agent_def::birth_custody_exists_in_txn(&self.store, txn, id)?
            || crate::receipt::receipt_archive_custody_exists(&self.store, txn, id)?
            || self.store.entities.get(txn, id.as_bytes())?.is_some()
            || self.port_retrieval_delete_scope_exists(txn, id)?
            || self.port_short_id_mapping_exists(txn, id)?
        {
            return Ok(true);
        }

        let mut edges_out = self.store.edges_out.prefix_iter(txn, id.as_bytes())?;
        if edges_out.next().transpose()?.is_some() {
            return Ok(true);
        }
        let mut edges_in = self.store.edges_in.prefix_iter(txn, id.as_bytes())?;
        if edges_in.next().transpose()?.is_some() {
            return Ok(true);
        }

        if crate::note::erase::scope_exists(self, txn, id)?
            || !self
                .store
                .verify_claim_erasure_by_scan_in_txn(txn, id.as_bytes())?
                .is_empty()
        {
            return Ok(true);
        }
        vad_annotation_delete_scope_exists_in_txn(&self.store, txn, id)
    }
}
