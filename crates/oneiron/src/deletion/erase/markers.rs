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
        HARD_DELETE_MARKER.contains(&self.store, txn, &HexId(*id))
    }

    /// Removes a headerless tombstone replay's stale `dt:` and row-fence
    /// poison once a delete-protected engine row is successfully admitted.
    /// This is called in the SAME transaction as protected-row
    /// materialization and tombstone quarantine; such a marker never
    /// represented valid delete authority.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn neutralize_delete_protected_marker_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        entity_type: u8,
    ) -> Result<bool> {
        if *id != crate::dreamer_runner::authority::dreamer_actor_id()?
            && !crate::registry::is_delete_protected_engine_record(entity_type)
        {
            return Err(Error::InvariantViolation(
                "dt: poison neutralization requires a delete-protected engine record",
            ));
        }
        let fenced = ROW_DELETION_FENCE.delete(&self.store, wtxn, &HexId(*id))?;
        Ok(HARD_DELETE_MARKER.delete(&self.store, wtxn, &HexId(*id))? | fenced)
    }

    /// Fences the row of a validated peer tombstone this vault accepted but
    /// could not apply. Its body may still be stored, and the window keeping
    /// the tombstone may have no snapshot, so without the fence the row would
    /// read live until the `rm:` retry lands. A delete-protected engine record
    /// is never deleted, so it is never fenced.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn fence_unapplied_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, id)?
            && EntityMetadataHeader::parse(&raw).is_some_and(|header| {
                crate::registry::is_delete_protected_engine_record(header.entity_type)
            })
        {
            return Ok(());
        }
        ROW_DELETION_FENCE.put(&self.store, wtxn, &HexId(*id), &Vec::new())
    }

    /// One-time open backfill of [`ROW_DELETION_FENCE`]. A vault written
    /// before the fence existed records its applied soft deletes only in the
    /// identity marker; each header-only row under that marker is fenced, so
    /// the deletes it records keep reading deleted.
    pub(crate) fn backfill_row_deletion_fences_on_open(&self) -> Result<()> {
        if ROW_DELETION_FENCE_BACKFILLED.contains(&self.store, &self.store.env.read_txn()?, &())? {
            return Ok(());
        }
        self.with_write_txn(|wtxn| {
            if ROW_DELETION_FENCE_BACKFILLED.contains(&self.store, wtxn, &())? {
                return Ok(());
            }
            for HexId(id) in IDENTITY_SOFT_DELETE_MARKER.scan_keys(&self.store, wtxn, &[])? {
                if crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, &id)?
                    .is_some_and(|raw| raw.len() == ENTITY_METADATA_HEADER_LEN)
                {
                    ROW_DELETION_FENCE.put(&self.store, wtxn, &HexId(id), &Vec::new())?;
                }
            }
            ROW_DELETION_FENCE_BACKFILLED.put(&self.store, wtxn, &(), &b"1".to_vec())
        })
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
            || crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, id)?.is_some()
            || self.port_retrieval_delete_scope_exists(txn, id)?
            || self.port_short_id_mapping_exists(txn, id)?
        {
            return Ok(true);
        }

        if crate::ports::EdgeStoreRead::port_edge_has_any(
            &self.store,
            txn,
            id,
            crate::ports::EdgeDirection::Both,
        )? {
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
