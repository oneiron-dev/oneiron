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
            let (existed, shell_had_vector) = self.soft_erase_active_store_in_txn(wtxn, shell)?;
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
}
