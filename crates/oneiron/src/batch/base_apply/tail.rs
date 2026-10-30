//! Base-apply tail: births, frontiers, rooms and index finalization.

use super::indexes::finalize_batch_indexes;
use super::*;

pub(super) fn apply_tail(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    mut state: BatchApplyState,
    text_index_trusted: bool,
) -> Result<()> {
    require_consumed_claim_bindings(&state.claim_materializations, &state.claim_transitions)?;
    // Rule A: each born row's made_by lands in the transaction that births it.
    for (row, birth) in &state.births {
        crate::provenance::birth::stamp_row_birth_in_txn(store, wtxn, row, birth)?;
    }
    if state
        .preflight_gate_decision_ids
        .values()
        .any(|ids| !ids.is_empty())
    {
        return Err(Error::InvariantViolation(
            "unconsumed preflight gate decision identity",
        ));
    }

    // Each touched project's frontier is folded once over the final batch
    // state, before rooms reconcile against it.
    crate::workspace_roster::refresh_project_frontiers(
        store,
        wtxn,
        config.privacy.posture,
        &state.touched_projects,
    )?;
    crate::workspace_roster::reconcile_project_rooms(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &state.materialized_entity_ids,
    )?;
    state
        .project_edge_endpoints
        .extend(&state.materialized_entity_ids);
    crate::workspace_roster::validate_project_graph(store, wtxn, &state.project_edge_endpoints)?;
    crate::workspace_roster::validate_local_leader_chat_turns(
        store,
        wtxn,
        &state.local_chat_turns,
    )?;

    // STO-03: derived Habit counters, recomputed from the FINAL child state of
    // this transaction — after every op, so an add and a delete of the same
    // edge net out and the batch order cannot be read off the result. Local
    // check-in commits and sync replay both land here because both reach
    // `apply_ops`; there is no second, sync-only streak algorithm.
    recompute_touched_habit_streaks_in_txn(store, wtxn, &state.habit_streak_candidates)?;

    crate::identity_topology::reconcile_identity_topology_for_materialized_entities_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &state.materialized_entity_ids,
    )?;
    crate::identity_topology::reconcile_identity_topology_for_deleted_entities_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &state.deleted_entity_ids,
    )?;
    // ONE-1604-D1 (fix-leg 5): the dominance eviction removed a type-76 event
    // ROW, which both hides the removed event's own participants from the
    // reconciler above (it enumerates SURVIVING rows) and replays the entire
    // fold, so LATER events can flip effective/rejected and strand THEIR
    // sources' edges too. Recompute the union of both families against one
    // final fold. Ordered after the materialization pass so both see the same
    // ledger, and a no-op on every batch without an eviction.
    crate::identity_topology::reconcile_shell_edges_after_eviction_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &state.evicted_shell_sources,
    )?;

    crate::authority::check_materialized_claim_causality(
        store,
        wtxn,
        config.privacy.posture,
        &state.local_materialized_ids,
    )?;

    #[cfg(feature = "sync")]
    for (id, token) in &state.pending_embedding_tokens_written {
        if config.embedding_model.is_some()
            && store.pending_embedding_token_in_txn(wtxn, id)?.as_deref() == Some(token.as_slice())
        {
            let priority = state
                .pending_embedding_enqueue_priorities
                .get(id)
                .copied()
                .unwrap_or(crate::embed::EMBED_PRIORITY_DEVICE);
            crate::sync::queue::push_embed_job_in_txn(store, wtxn, id, priority)?;
        }
    }

    state.masked_files.restrict(store, wtxn)?;
    crate::skill_attribution::note_run_derivations_in_txn(
        store,
        wtxn,
        state.run_derivations.as_ref(),
    );
    // DOOR-101: an owner home pick this batch landed, local or from a peer's
    // log, re-elects this node's MACRO home over the final batch state.
    if crate::authority::authority_cache_generation(store, wtxn)? != state.authority_generation {
        crate::dreamer_runner::reelect_home_in_txn(store, wtxn, config.privacy.posture);
    }

    finalize_batch_indexes(
        store,
        config,
        wtxn,
        &state.materialized_entity_ids,
        state.pending_hnsw_rebuild,
        state.had_graph_mutation,
        state.had_vector_mutation,
    )
}
