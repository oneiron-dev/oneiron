//! Base-apply Delete arm: tears rows and graph state.

use super::*;
use crate::ppr;

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_delete_arm(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    state: &mut BatchApplyState,
    id: EntityId,
    origin: BaseWriteOrigin<'_>,
    text_index_trusted: bool,
) -> Result<()> {
    reject_engine_authored_delete(store, wtxn, &id)?;
    state.deleted_entity_ids.insert(id);
    crate::counterparty_contact::retire_family_claims_for_batch_delete_in_txn(
        store,
        config,
        analyzer,
        wtxn,
        &id,
        state.mutation_recorded_at,
        text_index_trusted,
    )?;
    // A batch delete tears the row, a hard delete (ARCH-0038), so
    // a batch-deleted world takes its keys with it (fix 7). There
    // is no soft batch delete; a soft delete keeps the keys.
    crate::world_keys::destroy_world_keys_in_txn(
        store,
        wtxn,
        id,
        crate::world_keys::WorldKeyDestroyCause::BatchDelete,
        None,
        state.mutation_recorded_at,
    )?;
    // A pad row's key leaves custody with it (KS-5, FIX 7192).
    crate::world_keys::erase_batch_pad_row_in_txn(
        store,
        wtxn,
        &id,
        state.mutation_recorded_at,
    )?;
    // A FEDERATION_GRANT row torn here is withdrawn: marked, and its hard
    // erasure staged for sync, since a batch delete stages none (FIX 11779).
    crate::authority::withdraw_grant_row_in_txn(store, wtxn, id)?;
    // Capture before tear (R2-F4): a PROJECT row's signed chain
    // is kept as revisions before the row goes.
    let captured = crate::workspace_roster::capture_before_tear(store, wtxn, id)?;
    let revisions = super::project_history::revision_puts(store, captured)?;
    if !revisions.is_empty() {
        apply_ops_with_origin(
            store,
            config,
            analyzer,
            wtxn,
            revisions,
            text_index_trusted,
            ApplyOpsGateMode::new(state.record_gate_decisions, state.persist_gate_pending_consent),
            origin,
        )?;
    }
    let (_existed, had_vector, deleted_graph_state, neighbors) =
        deindex_entity_with_machine_history(store, wtxn, &id)?;
    claim_materialization::invalidate_authored_claim(store, wtxn, &id)?;
    if state.persist_gate_pending_consent {
        store.let_go_pending_gate_consent_in_txn(wtxn, &id, state.mutation_recorded_at)?;
    }
    state.pending_embedding_tokens_written.remove(&id);
    #[cfg(feature = "sync")]
    state.pending_embedding_enqueue_priorities.remove(&id);
    ppr::invalidate_ppr_for_delete(store, wtxn, &id, &neighbors)?;
    state.had_graph_mutation |= deleted_graph_state;
    state.had_vector_mutation |= had_vector;
    Ok(())
}
