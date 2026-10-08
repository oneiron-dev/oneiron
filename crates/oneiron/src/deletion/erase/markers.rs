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
    /// could not apply. Its body may still be stored, so without the fence
    /// the row would read live until the `rm:` retry lands. Only a delete the
    /// replay's protection gates admit is fenced, the gates re-run here
    /// against the state the failed apply saw: a delete they refuse (a custody
    /// guard, the current pack-map carrier, a delete-protected record) never
    /// applies, so the row stays as it was. A gate that fails to read its
    /// state fences, failing closed.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn fence_unapplied_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<()> {
        match self.replayed_tombstone_protection_in_txn(
            wtxn,
            id,
            &decode_tombstone_value(raw_value),
        ) {
            Ok(()) | Err(Error::Storage(_) | Error::Io(_) | Error::MapFull) => {
                ROW_DELETION_FENCE.put(&self.store, wtxn, &HexId(*id), &Vec::new())
            }
            Err(_) => Ok(()),
        }
    }

    /// One-time open backfill of [`ROW_DELETION_FENCE`]. A vault written
    /// before the fence existed records its applied soft deletes only in the
    /// identity marker; each header-only row under that marker is fenced, so
    /// the deletes it records keep reading deleted. Its reads also replayed
    /// each row's window for published tombstones; see
    /// [`Self::backfill_published_delete_fences_in_txn`].
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
            #[cfg(feature = "sync")]
            self.backfill_published_delete_fences_in_txn(wtxn)?;
            ROW_DELETION_FENCE_BACKFILLED.put(&self.store, wtxn, &(), &b"1".to_vec())
        })
    }

    /// Reads used to answer a row's deletion by replaying the row's own window
    /// document for a published tombstone, which a delete accepted here but
    /// never applied (or a hard delete published before its purge) relied on.
    /// Reads now go by markers alone, so each stored row such a tombstone
    /// still deletes, as the replay's protection gates admit it, is fenced
    /// once here and keeps reading deleted.
    #[cfg(feature = "sync")]
    fn backfill_published_delete_fences_in_txn(&self, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
        use crate::sync::loro_support::{
            doc_from_snapshot, import_doc, map_for_each_tombstone_value,
        };

        let mut windows = Vec::new();
        for row in self.store.sync_state.prefix_iter(wtxn, "d:w:")? {
            windows.push(row?.0["d:w:".len()..].to_owned());
        }
        for window in windows {
            let Some(snapshot) = self.store.sync_state.get(wtxn, &format!("d:w:{window}"))? else {
                continue;
            };
            let doc = doc_from_snapshot(&snapshot)?;
            for row in self
                .store
                .sync_state
                .prefix_iter(wtxn, &format!("u:w:{window}:"))?
            {
                let (_, update) = row?;
                import_doc(&doc, &update)?;
            }
            let mut tombstones = Vec::new();
            map_for_each_tombstone_value(&doc.get_map("tombstones"), |key, value| {
                if let Ok(id) = EntityId::from_hex(key) {
                    tombstones.push((id, value.to_vec()));
                }
            });
            for (id, value) in tombstones {
                let Some(raw) =
                    crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, &id)?
                else {
                    continue;
                };
                if crate::deletion::row_deletion_marked(&self.store, wtxn, &id, Some(&raw))?
                    || super::super::timeline::residence_window_for_row(
                        &self.store,
                        wtxn,
                        &id,
                        &raw,
                    )? != window
                {
                    continue;
                }
                self.fence_unapplied_delete_in_txn(wtxn, &id, &value)?;
            }
        }
        Ok(())
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
