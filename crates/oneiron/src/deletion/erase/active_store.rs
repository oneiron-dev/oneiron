use super::*;

impl Vault {
    /// IDs whose local body or edge projection can change when this hard
    /// deletion commits. Capture before deindex removes incident edges and
    /// before the redirect walk scrubs shells. Callers publish only after
    /// their owning transaction commits; a rolled-back delete publishes none.
    pub(crate) fn hard_delete_affected_ids_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut affected = crate::identity_redirect::inbound_redirect_shells_in_txn(
            &self.store,
            txn,
            &BTreeSet::from([*id]),
        )?;
        affected.insert(*id);
        for row in crate::ports::EdgeStoreRead::port_edges(
            &self.store,
            txn,
            id,
            crate::ports::EdgeDirection::Both,
            None,
            None,
        )? {
            affected.insert(row?.target);
        }
        Ok(affected.into_iter().collect())
    }

    /// Returns whether local state existed, plus the citing NOTE documents
    /// whose pins the erasure rewrote, for the caller's post-commit notice.
    pub(in crate::deletion) fn purge_entity_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        request_id: Option<&[u8; 16]>,
    ) -> Result<(bool, Vec<EntityId>)> {
        // A held record keeps its bytes on every door that purges it, and a
        // held world keeps its pads (OF-470).
        self.store.reject_legal_hold_in_txn(wtxn, id.as_bytes())?;
        crate::world_keys::reject_held_pad_world_in_txn(&self.store, wtxn, &[*id])?;
        crate::dreamer_runner::authority::guard_actor_delete(id)?;
        crate::blob_artifact::esign::reject_event_delete(&self.store, wtxn, id)?;
        crate::workspace_roster::refuse_revision_delete(&self.store, wtxn, id)?;
        crate::task_authority::reject_fact_delete(&self.store, wtxn, id)?;
        // A purged world takes its keys with it (fix 7).
        self.destroy_world_keys_for_delete_in_txn(
            wtxn,
            *id,
            crate::world_keys::WorldKeyDestroyCause::LocalDelete,
            request_id.copied(),
        )?;
        // Capture before tear: a project's signed history outlives its row.
        self.capture_project_before_tear_in_txn(wtxn, *id)?;
        // A purged message's turns stop matching its words: read them while
        // its edges stand, and drop their vectors once it is gone.
        let turns = crate::embed::erased_message_turns_in_txn(self, wtxn, id)?;
        let settled = match request_id {
            Some(request) => settled_topology_delete_in_txn(&self.store, wtxn, id, request)?,
            None => false,
        };
        if !settled {
            self.guard_active_merge_hard_delete_in_txn(wtxn, id)?;
        }
        self.record_invalid_participant_dispositions_for_delete_in_txn(wtxn, id)?;
        crate::workspace_roster::retire_goal_for_delete(self, wtxn, *id)?;
        #[cfg(feature = "sync")]
        crate::entity_doc::erase_in_txn(&self.store, wtxn, id)?;
        crate::provenance::erase_row_provenance_in_txn(&self.store, wtxn, id)?;
        // Saved tags read the turn's messages through their PartOf edges, so
        // they go before the graph is torn down.
        let had_tags = crate::tagging::erase_in_txn(self, wtxn, id)?;
        // The content-hash index row is dropped by `deindex_entity` below;
        // ONE-1741 removed the verdict relocation that this hook also carried.
        //
        // ONE-1447 runs BEFORE the tear: the stale fold reads the skills that
        // CITED this id, not this id's own rows, and both acts belong to the
        // one transaction that destroys the evidence.
        self.mark_dependent_skills_stale_in_txn(wtxn, id)?;
        let citing = crate::note::erase_citations_in_txn(self, wtxn, id)?;
        crate::calendar::origin::invalidate_dependents(self, wtxn, id)?;
        self.moot_identity_proposals_for_participant_in_txn(wtxn, id)?;
        self.scrub_identity_op_actor_in_txn(wtxn, id)?;
        let had_refinement =
            crate::skill_hub::erase_claim_refinement_in_txn(&self.store, wtxn, id)?;
        let had_merge_receipt =
            crate::skill_hub::erase_refinement_custody_in_txn(&self.store, wtxn, id)?;
        crate::conversation_dag::capture_before_erase(self, wtxn, id, true)?;
        // A ChannelIdentity's or contact's own claim heads close while their
        // claim_of edges still stand (OF-272).
        let now = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        crate::counterparty_contact::close_family_claims_for_delete_in_txn(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            id,
            now,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
        )?;
        // A MACHINE claim's signed history controls go with it.
        let (existed, had_vector, had_graph_mutation, neighbors) =
            crate::batch::deindex_entity_with_machine_history(&self.store, wtxn, id)?;
        crate::codebase::delete_codebase_snapshot_in_txn(&self.store, wtxn, id)?;
        crate::note::delete_document_in_txn(&self.store, wtxn, id)?;
        let note_removed = crate::note::erase::purge(self, wtxn, id)?;
        ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &neighbors)?;
        if had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, wtxn)?;
        }
        crate::embed::erase_turn_vectors_in_txn(self, wtxn, turns)?;
        Ok((
            existed || note_removed || had_refinement || had_merge_receipt || had_tags,
            citing,
        ))
    }

    pub(in crate::deletion) fn soft_erase_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(bool, bool, bool)> {
        // A soft erase scrubs the body, so a hold refuses it too.
        self.store.reject_legal_hold_in_txn(wtxn, id.as_bytes())?;
        crate::world_keys::reject_held_pad_world_in_txn(&self.store, wtxn, &[*id])?;
        crate::dreamer_runner::authority::guard_actor_delete(id)?;
        crate::workspace_roster::refuse_revision_delete(&self.store, wtxn, id)?;
        // Capture before the body is scrubbed (see the purge).
        self.capture_project_before_tear_in_txn(wtxn, *id)?;
        // An erased message's turns stop matching its words (see the purge).
        let turns = crate::embed::erased_message_turns_in_txn(self, wtxn, id)?;
        crate::conversation_dag::capture_before_erase(self, wtxn, id, false)?;
        crate::federation::reject_ruling_delete(&self.store, wtxn, id)?;
        crate::blob_artifact::esign::reject_event_delete(&self.store, wtxn, id)?;
        crate::task_authority::reject_fact_delete(&self.store, wtxn, id)?;
        let had_tags = crate::tagging::erase_in_txn(self, wtxn, id)?;
        // A soft erase keeps the graph, so the sieve and projection rows of
        // the same words go here, not at the physical tear.
        crate::dreamer_wake::erase_in_txn(&self.store, wtxn, id)?;
        self.record_invalid_participant_dispositions_for_delete_in_txn(wtxn, id)?;
        self.moot_identity_proposals_for_participant_in_txn(wtxn, id)?;
        crate::workspace_roster::retire_goal_for_delete(self, wtxn, *id)?;
        #[cfg(feature = "sync")]
        crate::entity_doc::erase_in_txn(&self.store, wtxn, id)?;
        crate::provenance::erase_row_provenance_in_txn(&self.store, wtxn, id)?;
        self.store.guard_pack_map_carrier_delete_in_txn(wtxn, id)?;
        let ledger_changed = self.store.redact_gate_decisions_for_claim_in_txn(
            wtxn,
            id.as_bytes(),
            self.store.clock.now_recorded_at(),
        )?;
        let (room_had_vector, room_had_graph, room_neighbors) =
            crate::workspace_roster::deindex_project_room(&self.store, wtxn, id)?;
        if room_had_graph {
            ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &room_neighbors)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        self.store
            .l2_base_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .erase(id, self.store.env.info().last_txn_id);
        let mutation_recorded_at = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        crate::ports::invalidate_source_in_txn(
            &self.store,
            wtxn,
            id,
            crate::ports::DependentWalkDoor::SoftErase,
        )?;
        crate::ports::keep_deleted_worlds_in_txn(&self.store, wtxn, id)?;
        crate::calendar::origin::invalidate_dependents(self, wtxn, id)?;
        let (hint_had_vector, hint_had_graph_mutation, _hint_neighbors) =
            deindex_lexical_query_hints_for_target(&self.store, wtxn, id)?;
        if hint_had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        crate::note::erase::purge(self, wtxn, id)?;
        self.port_retrieval_clear_text_for_soft_erase(wtxn, id)?;
        crate::vault::entity_revision::remove_entity_revisions(&self.store, wtxn, id)?;
        self.port_retrieval_clear_phonetic_for_soft_erase(wtxn, id)?;
        crate::code_revision::delete_code_revision_lifecycle_in_txn(&self.store, wtxn, id)?;
        crate::codebase::delete_codebase_snapshot_in_txn(&self.store, wtxn, id)?;
        crate::origin::lfs::delete_lfs_lifecycle_in_txn(&self.store, wtxn, id)?;
        crate::note::delete_document_in_txn(&self.store, wtxn, id)?;
        let blob_cleanup =
            crate::blob_artifact::delete_blob_artifact_lifecycle_in_txn(&self.store, wtxn, id)?;
        if blob_cleanup.had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        self.store.clear_pending_embedding(wtxn, id)?;
        let entity_had_vector = self.port_retrieval_clear_vector_for_soft_erase(wtxn, id)?;
        let mut had_vector =
            hint_had_vector | entity_had_vector | blob_cleanup.had_vector | room_had_vector;

        crate::skill_hub::remove_hub_package_in_txn(&self.store, wtxn, id)?;
        let had_refinement =
            crate::skill_hub::erase_claim_refinement_in_txn(&self.store, wtxn, id)?;
        let had_merge_receipt =
            crate::skill_hub::erase_refinement_custody_in_txn(&self.store, wtxn, id)?;
        crate::skill_hub::remove_refinement_carrier_in_txn(&self.store, wtxn, id)?;
        crate::skill_hub::retire_refinement_holder_in_txn(&self.store, wtxn, id)?;
        crate::agent_def::remove_birth_custody_in_txn(&self.store, wtxn, id)?;
        crate::comm::clear_pending_stop_for_delete(&self.store, wtxn, id)?;
        let Some(entity_record) =
            crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, id)?
        else {
            let cleanup = delete_vad_annotation_metadata_in_txn(&self.store, wtxn, id)?;
            had_vector |= cleanup.had_vector;
            if cleanup.had_graph_mutation {
                ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &cleanup.neighbors)?;
                ppr::increment_graph_version(&self.store, wtxn)?;
            }
            return Ok((
                had_refinement || had_merge_receipt || had_tags,
                had_vector,
                ledger_changed,
            ));
        };
        let header = EntityMetadataHeader::parse(&entity_record)
            .ok_or(Error::CorruptedIndex("entity metadata"))?;
        // Soft erase keeps the reply edges but removes the TURN body. Both
        // local UserDelete and replayed soft tombstones pass through here.
        if header.entity_type == crate::registry::ENTITY_TYPE_TURN {
            crate::conversation_dag::invalidate_thread_meta_for_turn_put(&self.store, wtxn, *id)?;
        }
        // A ChannelIdentity's or contact's own claim heads close before the
        // shell replaces the row (OF-272).
        crate::counterparty_contact::close_family_claims_for_delete_in_txn(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            id,
            mutation_recorded_at,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
        )?;
        crate::channel_identity::clear_assignment_for_delete(
            &self.store,
            wtxn,
            id,
            header.entity_type,
        )?;
        crate::deletion::tear_derived_rows_in_txn(&self.store, wtxn, id, false)?;
        // Soft-erase truncates the body in place, so unlike the hard-purge path it
        // does not route through `deindex_entity`; drop any content-hash index row
        // here before the body is gone (ONE-1741: scan verdicts anchor to the
        // content bytes, so nothing to relocate). The maintenance helper no-ops for
        // kinds that keep no content-hash index, so the generic delete engine needs
        // no entity-kind branch of its own.

        self.maintain_skill_content_hash_index_on_delete_in_txn(wtxn, id)?;
        // ONE-1447, the other half of the same question: this id may be the
        // conversation a SKILL was converted from, and a skill whose evidence
        // this transaction is erasing must stop loading as canon in that same
        // transaction. Visible and reversible — never a silent orphan, never a
        // cascading delete.
        self.mark_dependent_skills_stale_in_txn(wtxn, id)?;
        let mut cleanup = VadAnnotationCleanup::default();
        delete_vad_annotation_metadata_for_type_in_txn(
            &self.store,
            wtxn,
            id,
            header.entity_type,
            &mut cleanup,
        )?;
        had_vector |= cleanup.had_vector;
        if cleanup.had_graph_mutation {
            ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &cleanup.neighbors)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
        }

        crate::claim::remove_claim_projection_index(&self.store, wtxn, *id)?;
        crate::dreamer_runner::deindex_dreamer_milestone_claim(&self.store, wtxn, id)?;
        crate::llm::deindex_dreamer_step_claim(&self.store, wtxn, id)?;
        // An epoch summary keeps its keyframe, so the next mint numbers above it.
        let scrubbed = crate::compaction::erased_form(&entity_record);
        self.store
            .port_entity_scrub(wtxn, id, scrubbed, mutation_recorded_at)?;
        crate::federation::record_scope::retire_stamp(&self.store, wtxn, *id)?;
        IDENTITY_SOFT_DELETE_MARKER.put(&self.store, wtxn, &HexId(*id), &Vec::new())?;
        ROW_DELETION_FENCE.put(&self.store, wtxn, &HexId(*id), &Vec::new())?;
        crate::embed::erase_turn_vectors_in_txn(self, wtxn, turns)?;
        Ok((true, had_vector, ledger_changed))
    }
}
