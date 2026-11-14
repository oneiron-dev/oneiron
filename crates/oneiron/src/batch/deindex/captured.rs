//! The physical tear's captured row and original same-writer tail.

use super::*;

pub(super) struct CapturedEntityDeindex {
    pub(super) id: EntityId,
    pub(super) entity_record: Option<Vec<u8>>,
    pub(super) had_vector: bool,
    pub(super) had_graph_mutation: bool,
    pub(super) neighbors: Vec<EntityId>,
}

impl CapturedEntityDeindex {
    pub(super) fn apply(
        self,
        write: &crate::secret_custody::CustodyWrite<'_>,
        wtxn: &mut RwTxn<'_>,
    ) -> Result<(bool, bool, bool, Vec<EntityId>)> {
        let store = write.store;
        let Self {
            id,
            entity_record,
            mut had_vector,
            mut had_graph_mutation,
            mut neighbors,
        } = self;
        let id = &id;
        let Some(entity_record) = entity_record else {
            let cleanup = crate::store::vad_annotation::delete_vad_annotation_metadata_in_txn(
                write, wtxn, id,
            )?;
            had_vector |= cleanup.had_vector;
            had_graph_mutation |= cleanup.had_graph_mutation;
            neighbors.extend(cleanup.neighbors);
            neighbors.sort_unstable();
            neighbors.dedup();
            return Ok((false, had_vector, had_graph_mutation, neighbors));
        };
        had_graph_mutation = true;

        let (entity_type, occurred, learned_at) = parse_entity_metadata(&entity_record)?;
        // A definition that reached the store without a put leaves no pin behind
        // it; its delete pins it first, so the id comes back no wider (H215).
        if entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF {
            crate::agent_def::pin_stored_row_in_txn(store, wtxn, id)?;
        }
        // A purged epoch summary keeps its place in its session's count (OF-013).
        crate::compaction::raise_epoch_floor_in_txn(store, wtxn, &entity_record)?;
        if entity_type == ENTITY_TYPE_SKILL {
            let body = &entity_record[ENTITY_METADATA_HEADER_LEN..];
            if let Some(content_hash) =
                crate::write_envelope::skill_record::decode_skill_record(body)?.content_hash
            {
                crate::store::skill_content_index::maintain_skill_content_hash_index_for_delete(
                    store,
                    wtxn,
                    id,
                    content_hash,
                )?;
            }
        }
        crate::channel_identity::clear_assignment_for_delete(store, wtxn, id, entity_type)?;
        let mut cleanup = crate::write_envelope::vad_annotation::VadAnnotationCleanup::default();
        crate::store::vad_annotation::delete_vad_annotation_metadata_for_type_in_txn(
            write,
            wtxn,
            id,
            entity_type,
            &mut cleanup,
        )?;
        had_vector |= cleanup.had_vector;
        had_graph_mutation |= cleanup.had_graph_mutation;
        neighbors.extend(cleanup.neighbors);
        neighbors.sort_unstable();
        neighbors.dedup();

        delete_entity_index_rows(store, wtxn, id, entity_type, occurred, learned_at)?;

        crate::dreamer_runner::deindex_dreamer_milestone_claim(store, wtxn, id)?;
        crate::llm::deindex_dreamer_step_claim(store, wtxn, id)?;
        crate::store::identity_hints::reindex_identity_hints(store, wtxn, id, None)?;
        crate::ports::reindex_named_entities(store, wtxn, id, None)?;
        crate::store::blob_fingerprint::invalidate_blob_fingerprint(store, wtxn, id)?;
        TRUSTED_MANIFEST_ORIGIN.delete(store, wtxn, &HexId(*id))?;
        SEEDED_MANIFEST_CONFIDENCE.delete(store, wtxn, &HexId(*id))?;
        crate::store::claim_projection::remove_claim_projection_index(store, wtxn, *id)?;
        crate::store::person_party_keys::reindex_person_party_keys(store, wtxn, id, None)?;
        // The change log's delete names no type; a change feed judges the withdrawal by it.
        crate::feeds::remember_withdrawn_type_in_txn(store, wtxn, id, entity_type)?;
        store.port_remove_entity_row(wtxn, id)?;
        crate::ports::audit_mutation_in_txn(
            store,
            wtxn,
            crate::ports::MutationAudit {
                entity: *id,
                op: crate::ports::ChangeOp::Delete,
                actor_principal: None,
                occurred_at: store.clock.now_recorded_at(),
                input: id.as_bytes(),
                reason: None,
            },
        )?;
        neighbors.sort_unstable();
        neighbors.dedup();
        Ok((true, had_vector, had_graph_mutation, neighbors))
    }
}
