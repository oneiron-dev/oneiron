//! Base-apply claim arms: candidates and lexical-hint reconciliation.

use super::*;
use super::validation::consume_preflight_decisions;
use crate::ppr;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteEnvelope;

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_claim_candidate_arm(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    state: &mut BatchApplyState,
    gate_mode: &ApplyOpsGateMode,
    id: EntityId,
    candidate: Box<ClaimCandidate>,
    envelope: WriteEnvelope,
    occurred: TimeRange,
    learned_at: u64,
    internal_lexical_query_hint: bool,
    mut put_options: PutOptions,
    text_index_trusted: bool,
) -> Result<()> {
    let preflight_decision_id = if !internal_lexical_query_hint {
        state.preflight_gate_decision_ids
            .get_mut(&id)
            .and_then(VecDeque::pop_front)
            .flatten()
    } else {
        None
    };
    put_options.consent.can_resolve_pending =
        state.pending_gate_consent_at_batch_start.contains(&id);
    put_options.decision.preflight = preflight_decision_id;
    let pre_mask = state.masked_claims.get_mut(&id).and_then(VecDeque::pop_front);
    let applied = apply_claim_candidate(
        store,
        config,
        (analyzer, text_index_trusted),
        wtxn,
        ClaimCandidateRequest {
            id,
            candidate: *candidate,
            envelope: &envelope,
            occurred,
            learned_at,
            decision: put_options.decision,
            consent: put_options.consent,
            indexing: put_options.indexing,
            write_policy: state.write_policy.as_ref(),
            owner_authored: gate_mode.owner_authored.as_ref(),
        },
        pre_mask,
    )?;
    consume_preflight_decisions(store, wtxn, [preflight_decision_id])?;
    if !internal_lexical_query_hint {
        claim_materialization::record_committed_claim(store, wtxn, &id, true)?;
    }
    state.had_graph_mutation |= applied.had_graph_mutation;
    state.had_vector_mutation |= applied.had_vector_mutation;
    if let Some(token) = applied.pending_embedding_token {
        state.pending_embedding_tokens_written.insert(id, token);
        #[cfg(feature = "sync")]
        state.pending_embedding_enqueue_priorities
            .entry(id)
            .and_modify(|priority| {
                *priority = (*priority).min(crate::embed::EMBED_PRIORITY_DEVICE);
            })
            .or_insert(crate::embed::EMBED_PRIORITY_DEVICE);
    }
    if applied.cleared_pending_embedding {
        state.pending_embedding_tokens_written.remove(&id);
        #[cfg(feature = "sync")]
        state.pending_embedding_enqueue_priorities.remove(&id);
    }
    state.materialized_entity_ids.insert(id);
    state.local_materialized_ids.insert(id);
    Ok(())
}

pub(super) fn apply_reconcile_lexical_arm(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    state: &mut BatchApplyState,
    source: EntityId,
    keep: Vec<EntityId>,
) -> Result<()> {
    let keep: HashSet<EntityId> = keep.into_iter().collect();
    let deleted =
        delete_lexical_query_hint_claims_for_target(store, wtxn, &source, &keep)?;
    for (deleted_id, neighbors) in &deleted.deleted {
        state.pending_embedding_tokens_written.remove(deleted_id);
        #[cfg(feature = "sync")]
        state.pending_embedding_enqueue_priorities.remove(deleted_id);
        ppr::invalidate_ppr_for_delete(store, wtxn, deleted_id, neighbors)?;
    }
    state.had_graph_mutation |= deleted.had_graph_mutation;
    state.had_vector_mutation |= deleted.had_vector;
    Ok(())
}
