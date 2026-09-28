use super::*;

impl Vault {
    /// ARCH-0055 §9 (r6): "HardErase walks redirects. Erasing a canonical
    /// head erases its redirect shells' payloads too — leaving a shell
    /// readable would leak what erasure hid."
    ///
    /// MUST run BEFORE the head's purge, in the SAME transaction: the purge
    /// deletes the head's incident edges, and those edges are the shell
    /// walk's primary witness. Same-transaction is not a convenience —
    /// erasing the head while a shell of it stays readable is the leak, so
    /// the two either commit together or neither does.
    ///
    /// The shells are NOT deleted. Merge-away is not deletion (§10), so
    /// there is no tombstone, no `dt:` marker and no new reason: only the
    /// readable payload goes, through the same shell-preserving SoftErase
    /// `user_delete` uses, leaving the 25 B row and the topology that makes
    /// the projection rebuildable exactly where they were.
    ///
    /// Returns the erased shells so the caller can widen its redaction
    /// scope: a shell's historical carriers must ride the head's `h:` sweep
    /// row, or the bytes this clears from the active store simply survive in
    /// history and nothing has been erased at all.
    pub(in crate::deletion) fn cascade_hard_erase_to_redirect_shells_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        head: &EntityId,
    ) -> Result<BTreeSet<EntityId>> {
        let shells = crate::identity_redirect::inbound_redirect_shells_in_txn(
            &self.store,
            &*wtxn,
            &BTreeSet::from([*head]),
        )?;
        if shells.is_empty() {
            return Ok(shells);
        }
        let mut had_vector = false;
        for shell in &shells {
            // Same pre-scrub capture every SoftErase door pays: the subject
            // EdgeRef is only readable while the body is.
            let captured = self.capture_provenance_delete_in_txn(&*wtxn, shell)?;
            crate::note::erase_citations_in_txn(self, wtxn, shell)?;
            let (existed, shell_had_vector, _ledger_changed) =
                self.soft_erase_active_store_in_txn(wtxn, shell)?;
            had_vector |= shell_had_vector;
            // D16 in the SAME transaction as the scrub, exactly as the local
            // and replayed SoftErase arms do it.
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    wtxn,
                    shell,
                    &captured.subject,
                )?;
            }
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, wtxn)?;
        }
        let mut touched = shells.clone();
        touched.insert(*head);
        self.scrub_identity_op_author_stamps_in_txn(wtxn, &touched)?;
        Ok(shells)
    }

    /// ARCH-0055 §9 author-stamp rider, STRICTLY scoped: drop the deciding
    /// actor's stamp from the type-76 merge/split events whose payloads this
    /// erase walk touched — the records that bound the erased head to the
    /// shells this transaction just emptied. Erasing the subjects of a
    /// decision while the ledger keeps reading "X decided this about them"
    /// leaves the erasure half-done.
    ///
    /// The boundary is the walk's own reach and nothing wider. A general
    /// participant-deletion sweep over the family is a separate obligation
    /// with its own ticket; a rider that grew into it would erase authorship
    /// of decisions this erase never read, on a path with no receipt for
    /// having done so.
    ///
    /// Fail-closed on an undecodable body, like every other reader of this
    /// engine-authored family — and reached only when the head actually had
    /// shells, so an ordinary delete never enumerates the ledger at all.
    fn scrub_identity_op_author_stamps_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        touched: &BTreeSet<EntityId>,
    ) -> Result<()> {
        let mut scrubbed: Vec<(EntityId, Vec<u8>)> = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(&*wtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
        {
            let (key, _) = entry?;
            let event_id = crate::vault::entity_id_from_type_index_key(&key)?;
            let Some(raw) = self.store.entities.get(&*wtxn, event_id.as_bytes())? else {
                continue;
            };
            if raw.len() < ENTITY_METADATA_HEADER_LEN {
                return Err(Error::CorruptedIndex("entity metadata"));
            }
            let event = decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| Error::CorruptedIndex("identity topology event body"))?;
            if !identity_op_event_touches(&event.action, touched) {
                continue;
            }
            let Some(event) = event.without_author_stamp() else {
                continue;
            };
            let mut record = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
            record.extend_from_slice(&encode_identity_topology_event_body(&event)?);
            scrubbed.push((event_id, record));
        }
        for (event_id, record) in &scrubbed {
            // Erasure must remove the old author stamp from retained history too.
            crate::vault::entity_revision::remove_entity_revisions(&self.store, wtxn, event_id)?;
            self.store.entities.put(wtxn, event_id.as_bytes(), record)?;
        }
        Ok(())
    }
}
