use super::*;

use super::authority::observe_authority_put;

/// P6: stage the projections — refinement and proposal observations, SKILL and
/// claim indexes, authority observation, entity indexes, short ids, and
/// embeddings — and report the applied put.
pub(super) fn stage_put_projections(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    data: &[u8],
    fixed: &super::admission::FixedPut<'_>,
    dispatch: &super::admission::Dispatch,
    revision: &super::admission::RevisionSlot,
    body_changed: bool,
    consolidation_dirty: bool,
    stored_before: bool,
    previous_skill_record: &Option<crate::skill::SkillRecord>,
    short_id_plan: Option<crate::batch::short_id::ShortIdPlan>,
    authority_first_seen_key: Option<String>,
    evicted_shell_sources: BTreeSet<EntityId>,
    project_revisions: Vec<(EntityId, Vec<u8>)>,
    portable_agent_source: Option<(EntityId, Vec<u8>)>,
) -> Result<AppliedPut> {
    crate::skill_hub::stage_refinement_origin(
        store,
        wtxn,
        &fixed.id,
        dispatch.decoded_claim_body.as_ref(),
        dispatch.new_skill_record.as_ref(),
        data,
    )?;
    super::super::put_staging::stage_local_proposal_observation(
        store,
        wtxn,
        super::super::put_staging::ProposedClaimObservation {
            id: fixed.id,
            replicated: fixed.replicated,
            body: dispatch.decoded_claim_body.as_ref(),
            envelope: fixed.write_envelope,
            policy: fixed.write_policy,
            body_changed,
        },
    )?;
    super::super::put_staging::stage_task_and_turn(
        store,
        wtxn,
        fixed.id,
        fixed.entity_type,
        data,
        body_changed,
    )?;
    if let Some(record) = dispatch.new_skill_record.as_ref() {
        super::super::put_staging::stage_skill_index_rows(
            store,
            wtxn,
            &fixed.id,
            previous_skill_record.as_ref(),
            record,
        )?;
    }
    if let Some(body) = dispatch.decoded_claim_body.as_ref() {
        super::super::put_staging::stage_claim_projection_indexes(
            store,
            wtxn,
            &fixed.id,
            body,
            fixed.learned_at,
        )?;
    }
    if let Some(key) = authority_first_seen_key {
        let first_stored = observe_authority_put(
            store,
            wtxn,
            &key,
            dispatch.authority_entry_observation.as_ref(),
            dispatch.authority_entry_hash_pin.as_ref(),
            fixed.replicated,
            fixed.mutation_recorded_at,
        )?;
        // OF-469 cutoffs: a row stored here for the first time counts once.
        if first_stored && let Some(hash) = dispatch.authority_entry_hash_pin.as_ref() {
            crate::authority::note_new_authority_row_in_txn(store, wtxn, hash, data.len())?;
        }
        crate::authority::advance_authority_cache_generation(store, wtxn)?;
    }

    let touched_projects = crate::workspace_roster::projects_touched_by_put(
        store,
        wtxn,
        (fixed.id, fixed.entity_type),
        revision.put.as_ref(),
        dispatch.authority_entry_observation.as_ref(),
    )?;

    stage_entity_index_rows(
        store,
        wtxn,
        &fixed.id,
        fixed.entity_type,
        fixed.occurred,
        fixed.learned_at,
    )?;
    if fixed.entity_type == crate::registry::ENTITY_TYPE_TURN && consolidation_dirty {
        crate::dreamer_consolidation::admit_turn_position_in_txn(store, wtxn, &fixed.id)?;
    }
    // A row stored before this put takes no first position from it (FIX 11925).
    let row_put = if fixed.replicated {
        crate::federation::record_scope::RowPut::Replicated
    } else if stored_before {
        crate::federation::record_scope::RowPut::LocalReput
    } else {
        crate::federation::record_scope::RowPut::Birth
    };
    crate::federation::record_scope::stamp_put(
        store,
        wtxn,
        fixed.id,
        fixed.entity_type,
        data,
        row_put,
    )?;
    if fixed.entity_type == crate::registry::ENTITY_TYPE_PERSON {
        super::super::super::person_substrate::ensure_person_substrate(
            store,
            wtxn,
            fixed.id,
            fixed.occurred,
            fixed.learned_at,
        )?;
    }
    crate::agent_def::stage_birth_custody_put(store, wtxn, &fixed.id, fixed.entity_type, data)?;
    crate::receipt::stage_receipt_archive_put(store, wtxn, &fixed.id, fixed.entity_type, data)?;
    crate::receipt::stage_receipt_record_index(store, wtxn, &fixed.id, fixed.entity_type, data)?;

    if let Some(plan) = short_id_plan {
        apply_short_id_plan(store, wtxn, &fixed.id, plan)?;
    } else if dispatch.is_lexical_query_hint_claim {
        delete_short_id_rows_for_id(store, wtxn, &fixed.id)?;
    }
    let embedding = super::super::put_staging::stage_post_put_embeddings(
        store,
        wtxn,
        &fixed.id,
        fixed.entity_type,
        data,
        dispatch.is_lexical_query_hint_claim,
        body_changed,
    )?;
    // A workflow's `[limits]` rows ask only once every fallible step of its
    // put is staged (Rule 5).
    if let Some(definition) = dispatch.new_workflow.as_ref() {
        crate::agent_def::workflow::measure_workflow_limits(&store.limit_watch, definition);
    }
    Ok(AppliedPut {
        portable_agent_source,
        project_revisions,
        touched_projects,
        pending_embedding_token: embedding.pending_embedding_token,
        cleared_pending_embedding: embedding.cleared_pending_embedding,
        had_vector_mutation: embedding.had_vector_mutation,
        is_lexical_query_hint_claim: dispatch.is_lexical_query_hint_claim,
        evicted_shell_sources,
    })
}
