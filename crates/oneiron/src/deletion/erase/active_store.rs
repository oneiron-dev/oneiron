use super::*;

impl Vault {
    pub(in crate::deletion) fn purge_entity_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        crate::blob_artifact::esign::reject_event_delete(&self.store, wtxn, id)?;
        crate::workspace_roster::retire_goal_for_delete(self, wtxn, *id)?;
        #[cfg(feature = "sync")]
        crate::entity_doc::erase_in_txn(&self.store, wtxn, id)?;
        // The content-hash index row is dropped by `deindex_entity` below;
        // ONE-1741 removed the verdict relocation that this hook also carried.
        //
        // ONE-1447 runs BEFORE the tear: the stale fold reads the skills that
        // CITED this id, not this id's own rows, and both acts belong to the
        // one transaction that destroys the evidence.
        self.mark_dependent_skills_stale_in_txn(wtxn, id)?;
        crate::note::erase_citations_in_txn(self, wtxn, id)?;
        crate::calendar::origin::invalidate_dependents(self, wtxn, id)?;
        let had_refinement =
            crate::skill_hub::erase_claim_refinement_in_txn(&self.store, wtxn, id)?;
        let had_merge_receipt =
            crate::skill_hub::erase_refinement_custody_in_txn(&self.store, wtxn, id)?;
        let (existed, had_vector, had_graph_mutation, neighbors) =
            deindex_entity(&self.store, wtxn, id)?;
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
        Ok(existed || note_removed || had_refinement || had_merge_receipt)
    }

    pub(in crate::deletion) fn soft_erase_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(bool, bool, bool)> {
        crate::federation::reject_ruling_delete(&self.store, wtxn, id)?;
        crate::blob_artifact::esign::reject_event_delete(&self.store, wtxn, id)?;
        crate::workspace_roster::retire_goal_for_delete(self, wtxn, *id)?;
        #[cfg(feature = "sync")]
        crate::entity_doc::erase_in_txn(&self.store, wtxn, id)?;
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
        crate::config::failure_signals::purge_tier2_for_source_in_txn(&self.store, wtxn, id)?;
        crate::ports::invalidate_source_in_txn(&self.store, wtxn, id)?;
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
        let Some(entity_record) = self.store.entities.get(wtxn, id.as_bytes())? else {
            let cleanup = delete_vad_annotation_metadata_in_txn(&self.store, wtxn, id)?;
            had_vector |= cleanup.had_vector;
            if cleanup.had_graph_mutation {
                ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &cleanup.neighbors)?;
                ppr::increment_graph_version(&self.store, wtxn)?;
            }
            return Ok((
                had_refinement || had_merge_receipt,
                had_vector,
                ledger_changed,
            ));
        };
        let header = EntityMetadataHeader::parse(&entity_record)
            .ok_or(Error::CorruptedIndex("entity metadata"))?;
        let payload = entity_record[..ENTITY_METADATA_HEADER_LEN].to_vec();
        let changed = entity_record.len() > ENTITY_METADATA_HEADER_LEN;
        // Soft erase keeps the reply edges but removes the TURN body. Both
        // local UserDelete and replayed soft tombstones pass through here.
        if header.entity_type == crate::registry::ENTITY_TYPE_TURN {
            crate::conversation_dag::invalidate_thread_meta_for_turn_put(&self.store, wtxn, *id)?;
        }
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
        crate::federation::record_scope::retire_stamp(&self.store, wtxn, *id)?;
        self.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        if changed {
            crate::ports::audit_mutation_in_txn(
                &self.store,
                wtxn,
                crate::ports::MutationAudit {
                    entity: *id,
                    op: crate::ports::ChangeOp::Redact,
                    actor_principal: None,
                    occurred_at: mutation_recorded_at,
                    input: id.as_bytes(),
                    reason: None,
                },
            )?;
        }
        Ok((true, had_vector, ledger_changed))
    }
}
