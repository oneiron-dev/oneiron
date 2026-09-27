use super::*;

impl Vault {
    /// Reason-aware replay of a CRDT tombstone into the LOCAL active store —
    /// the ONE primitive every sync replay surface routes through (Observer
    /// B's tombstone phase and `forward_rematerialize`'s tombstone pass), so
    /// a remote delete can never diverge from the pinned ARCH-0038 reason
    /// semantics. OWNER-DECISION (M4-06 / ONE-1133, fail-closed): replay
    /// routes through this reason-aware delete primitive, never bare purge.
    ///
    /// * KNOWN-soft value (`reason = user_delete`) → shell-preserving
    ///   SoftErase: payload truncated to the 25 B entity header,
    ///   text/phonetic/vector/hnsw deindexed, and — when the entity was a
    ///   live `edge.provenance` Claim — the D16 subject-edge refresh
    ///   committed in the SAME transaction. No receipt, no sweep row
    ///   (contracts.ts `user_delete`: activeStoreHardPurgeV1 = false,
    ///   receipt = false).
    /// * Hard value (known hard reason, legacy 8-byte, reserved 0, unknown
    ///   byte, malformed) → destructive purge of the payload plus every
    ///   active index entry, the D16 refresh in the SAME transaction, and —
    ///   when local state was actually erased — a LOCAL `h:{seq:8BE}`
    ///   historical-carrier sweep row (`deadline_at` ≤ queued_at + 30 d,
    ///   GDPR Art. 12(3)) and a LOCAL REDACTION_AUDIT receipt whose
    ///   `request_id` comes from the wire value (OWNER-DECISION: Art. 5(2)
    ///   accountability attaches to each replica actually erasing, so N
    ///   devices yield N receipts for one request). Ambiguity resolves to
    ///   MORE deletion, never less.
    /// * Never-downgrade on receive: a soft value for an id this replica
    ///   already hard-purged finds no row to scrub and is a no-op — it
    ///   never recreates a shell.
    /// * Idempotent: after a completed hard apply the delete-scope probe
    ///   finds nothing, so re-application (every-boot forward
    ///   re-materialization, repeated delta delivery) is a receipt-free
    ///   no-op.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn apply_replayed_tombstone(
        &self,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.apply_replayed_tombstone_in_txn(&mut wtxn, id, raw_value)?;
        wtxn.commit()?;
        while self.collect_lfs_garbage(32)? != 0 {}
        Ok(outcome)
    }

    /// [`Self::apply_replayed_tombstone`]'s effect core, against a
    /// caller-owned transaction (ONE-521). Every reason semantic above is
    /// decided here; the wrapper only owns the commit, so a batched replay
    /// (Observer B's tombstone phase) can apply N tombstones — each in its own
    /// nested savepoint — under ONE durable transaction without changing what
    /// any single tombstone does.
    ///
    /// The transaction is the caller's: this function NEVER commits, and an
    /// `Err` return leaves the decision of what to roll back (the whole batch,
    /// or just this item's savepoint) to the caller.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn apply_replayed_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        crate::federation::reject_ruling_delete(&self.store, wtxn, id)?;
        crate::blob_artifact::esign::reject_event_delete(&self.store, wtxn, id)?;
        crate::origin::lfs::reject_direct_lfs_chunk_delete(&self.store, wtxn, id)?;
        let mutation_recorded_at = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        self.store.guard_pack_map_carrier_delete_in_txn(wtxn, id)?;
        let decoded = decode_tombstone_value(raw_value);
        // Cleanup is local visibility, never a replicated deletion intent.
        // Accepting byte 5 here would irreversibly scrub a retained archive
        // (or an unrelated row) without the cleanup predicate or owner decision.
        if decoded.reason == Some(super::tombstone::TombstoneReason::ArchivedByCleanup) {
            return Err(Error::InvariantViolation(
                "cleanup archives cannot be replayed as deletion intent",
            ));
        }
        if let Some(header) = self.read_entity_header_in_txn(wtxn, id)?
            && crate::registry::is_delete_protected_engine_record(header.entity_type)
        {
            return Err(Error::Registry(RegistryError::MaintenanceKindNotWritable(
                header.entity_type,
            )));
        }
        // ARCH-0038 DELETE interplay: an `edge.provenance` Claim's subject
        // EdgeRef and sweep refs are only readable PRE-scrub.
        let captured = self.capture_provenance_delete_in_txn(wtxn, id)?;

        if !decoded.is_hard() {
            let had_sources =
                crate::skill_hub::source_custody_exists_in_txn(&self.store, wtxn, id)?;
            crate::skill_hub::retire_source_holder_in_txn(&self.store, wtxn, id)?;
            let had_receipt_sources =
                crate::receipt::receipt_archive_custody_exists(&self.store, wtxn, id)?;
            let had_birth_sources =
                crate::agent_def::birth_custody_exists_in_txn(&self.store, wtxn, id)?;
            crate::agent_def::retire_birth_sources_for_entity_in_txn(&self.store, wtxn, id)?;
            crate::receipt::retire_receipt_archives_for_erased_id(&self.store, wtxn, id)?;
            let had_body =
                crate::ports::EntityStoreRead::port_entity_raw(&self.store, &*wtxn, &id)?
                    .is_some_and(|raw| raw.len() > ENTITY_METADATA_HEADER_LEN);
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, wtxn)?;
            }
            // D16: SoftErase tombstones the Claim, and "the derived edge
            // flag follows the Claim" — refresh in the SAME transaction.
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(wtxn, id, &captured.subject)?;
            }
            return Ok(ReplayedTombstoneOutcome::SoftErased {
                changed: had_body
                    || had_vector
                    || had_birth_sources
                    || had_sources
                    || had_receipt_sources,
            });
        }

        let marker_key = local_hard_delete_key(id);
        let marker_value = decoded.local_hard_delete_marker_value();
        // Probe the FULL delete scope (entity row, vectors, text, phonetic,
        // short-ids, edges): orphan residue without an entities row still
        // counts as local state to erase, mirroring the local
        // `delete_entity_without_header` semantics.
        if !self.active_delete_scope_exists_in_txn(wtxn, id)? {
            crate::skill_hub::retire_source_holder_in_txn(&self.store, wtxn, id)?;
            crate::agent_def::retire_birth_sources_for_entity_in_txn(&self.store, wtxn, id)?;
            crate::receipt::retire_receipt_archives_for_erased_id(&self.store, wtxn, id)?;
            // Hard-once-seen is durable LOCAL truth even when nothing local
            // was erased (never-materialized id): the permanent `dt:` marker
            // still gates a future re-put after hostile tombstone-map
            // manipulation. The guarded write keeps every-boot replay a
            // read-only no-op once the marker exists.
            if self.store.sync_state.get(&*wtxn, &marker_key)?.is_none() {
                self.store
                    .sync_state
                    .put(wtxn, &marker_key, &marker_value)?;
            }
            if let Some((request_id, tombstone_reason)) =
                decoded.request_id.zip(raw_value.first().copied())
            {
                let discarded_local_authority =
                    self.store.discard_pending_deletion_gate_decision_in_txn(
                        wtxn,
                        GateDecisionId::from_bytes(request_id),
                        id.as_bytes(),
                        tombstone_reason,
                    )?;
                if discarded_local_authority {
                    tracing::debug!(
                        entity = %id.to_hex(),
                        "remote replay found no local state; discarded the matching local deletion authority sidecar"
                    );
                }
            }
            return Ok(ReplayedTombstoneOutcome::HardPurged {
                erased: false,
                receipt_id: None,
                sweep_key: None,
            });
        }
        // ARCH-0055 §9 (r6) on the RECEIVING side: a remote hard erase must
        // leave this replica as unreadable as the origin, so the local shells
        // of the erased head are cascaded here too — before the purge takes
        // the shell edges with it, in the caller's transaction.
        let cascaded_shells = self.cascade_hard_erase_to_redirect_shells_in_txn(wtxn, id)?;
        self.purge_entity_active_store_in_txn(wtxn, id)?;
        // Receiver-side `dt:` local hard-delete marker (pinned: presence-only
        // value, GLOBAL key, permanent, no GC) — written in the SAME txn as
        // the purge so local delete truth survives CRDT-map manipulation.
        self.store
            .sync_state
            .put(wtxn, &marker_key, &marker_value)?;
        // ARCH-0038 DELETE: "The derived edge flag follows the Claim" — the
        // subject edge is refreshed in the SAME transaction as the purge.
        if let Some(captured) = &captured {
            self.refresh_subject_edge_after_claim_delete_in_txn(wtxn, id, &captured.subject)?;
        }
        if let Some((request_id, tombstone_reason)) =
            decoded.request_id.zip(raw_value.first().copied())
        {
            let completed_local_authority =
                self.store.append_pending_deletion_gate_decision_in_txn(
                    wtxn,
                    GateDecisionId::from_bytes(request_id),
                    id.as_bytes(),
                    tombstone_reason,
                )?;
            if completed_local_authority.is_some() {
                tracing::debug!(
                    entity = %id.to_hex(),
                    "remote replay completed a staged local deletion authority record"
                );
            }
        }
        let applied_at = mutation_recorded_at;
        let receipt_id = self.store.clock.entity_id()?;
        let mut scope = RedactionScope::entity(id);
        scope
            .entity_ids
            .extend(cascaded_shells.iter().map(EntityId::to_hex));
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            wtxn,
            &receipt_id,
            RedactionReceiptInput {
                actor_principal: None,
                request_id: decoded.receipt_request_id(),
                scope,
                reason: decoded.receipt_hard_reason(),
                // The origin's request time, straight off the wire (0 for
                // malformed shapes); completion stamps are device-local
                // facts on the replica that erased.
                requested_at: decoded.deleted_at,
                soft_complete_at: applied_at,
                hard_purge_complete_at: applied_at,
                sweep_queued_at: Some(applied_at),
            },
            sweep_extras(captured.as_ref()),
        )?;
        Ok(ReplayedTombstoneOutcome::HardPurged {
            erased: true,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    #[cfg(feature = "sync")]
    pub(crate) fn apply_replayed_tombstone_for_sync(
        &self,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        self.apply_replayed_tombstone(id, raw_value)
    }

    /// [`Vault::read_entity_header`](crate::Vault::read_entity_header) against
    /// a caller-owned snapshot: the delete-protection gate of a batched replay
    /// must read the same state its writes will land in, not a second snapshot
    /// taken outside the caller's transaction.
    fn read_entity_header_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityMetadataHeader>> {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, rtxn, &id)?
        else {
            return Ok(None);
        };
        EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity metadata"))
            .map(Some)
    }
}
