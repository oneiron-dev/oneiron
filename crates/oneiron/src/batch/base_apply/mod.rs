use super::claim_materialization::consume_claim_materialization;
use super::verified_claim_transition::consume_next;
use super::*;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use heed::RwTxn;
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, RegistryError, Result};
use crate::ppr;
use crate::store::Store;

mod edge;
mod indexes;
mod validation;

use self::edge::{apply_edge_op, edge_op_endpoints};
use self::indexes::{apply_text_index_update, finalize_batch_indexes};
use self::validation::{
    birth_stamp_target, consume_preflight_decisions, mark_unapplied_preflight_decisions,
    take_lapse_decisions, validate_put_type,
};

// Holds promotion's independent journal clone until apply completes. The
// iterator retains every unconsumed op on early return; per-op payloads that
// move into match arms get a Zeroizing owner at the point of consumption.
struct ReplayOps {
    ops: Vec<BatchOp>,
    replay: bool,
}

impl Drop for ReplayOps {
    fn drop(&mut self) {
        if self.replay {
            for op in &mut self.ops {
                crate::session_overlay::zeroize_batch_op_payload(op);
            }
        }
    }
}

impl std::ops::Deref for ReplayOps {
    type Target = Vec<BatchOp>;
    fn deref(&self) -> &Self::Target {
        &self.ops
    }
}

struct ReplayIter {
    remaining: std::vec::IntoIter<BatchOp>,
    replay: bool,
}

impl Iterator for ReplayIter {
    type Item = BatchOp;
    fn next(&mut self) -> Option<Self::Item> {
        self.remaining.next()
    }
}

impl Drop for ReplayIter {
    fn drop(&mut self) {
        if self.replay {
            for op in self.remaining.as_mut_slice() {
                crate::session_overlay::zeroize_batch_op_payload(op);
            }
        }
    }
}

/// Check the decode point while this replay op still owns its buffers. On
/// pre-match errors no match arm takes ownership, so scrub here before return.
fn prepare_replay_op(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    bindings: &mut VecDeque<ClaimMaterialization>,
    op: &mut BatchOp,
    origin: BaseWriteOrigin<'_>,
) -> Result<Option<ClaimMaterialization>> {
    let result = check_decode_point_taint_guard(store, op, origin)
        .and_then(|()| consume_claim_materialization(store, txn, bindings, op, origin));
    if result.is_err() && matches!(origin, BaseWriteOrigin::PromoteReplay(_)) {
        crate::session_overlay::zeroize_batch_op_payload(op);
    }
    result
}

fn require_gated_claim_materializations(
    claim_gate_prechecked: bool,
    materializations: &VecDeque<ClaimMaterialization>,
) -> Result<()> {
    if claim_gate_prechecked && !materializations.is_empty() {
        return Err(Error::InvariantViolation(
            "owner-bound materialization cannot skip the gate",
        ));
    }
    Ok(())
}

fn require_consumed_claim_bindings(
    materializations: &VecDeque<ClaimMaterialization>,
    transitions: &VecDeque<super::VerifiedClaimTransition>,
) -> Result<()> {
    if !materializations.is_empty() {
        return Err(Error::InvariantViolation(
            "unconsumed claim materialization envelope",
        ));
    }
    super::verified_claim_transition::require_consumed(transitions)
}

/// Materializes the already-authorized CLAIM puts from a session-bundle merge.
///
/// The narrow operation-shape check prevents the prechecked mode from being
/// reused as a general batch gate bypass. The caller must have evaluated every
/// body with `check_claim_policy_for_write_with_record` in this same `wtxn`.
pub(crate) fn apply_session_bundle_claim_puts(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
) -> Result<()> {
    apply_session_bundle_claim_puts_with_transitions(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        Vec::new(),
        text_index_trusted,
    )
}

pub(crate) fn apply_session_bundle_claim_puts_with_transitions(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    transitions: Vec<super::VerifiedClaimTransition>,
    text_index_trusted: bool,
) -> Result<()> {
    if ops.iter().any(|op| {
        !matches!(
            op,
            BatchOp::Put {
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                ..
            }
        )
    }) {
        return Err(Error::InvariantViolation(
            "session bundle claim batch contains a non-claim put",
        ));
    }
    apply_ops_with_gate_mode(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        text_index_trusted,
        ApplyOpsGateMode::new(false, false)
            .with_prechecked_claim_gate()
            .with_verified_claim_transitions(transitions),
    )
}

/// Applies a batch under an explicit [`BaseWriteOrigin`].
///
/// The K4 taint guard runs INSIDE this transaction, at the point where each op
/// is decoded — there is no preflight pass and no membership-epoch publication
/// protocol. The membership state the guard reads inside the applying `wtxn`
/// is the state the transaction applies against, which removes the TOCTOU
/// class outright.
#[expect(
    clippy::too_many_arguments,
    reason = "batch write plumbing keeps gate persistence modes and the write origin explicit at call sites"
)]
pub(super) fn apply_ops_with_origin(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
    origin: BaseWriteOrigin<'_>,
) -> Result<()> {
    let replay = matches!(origin, BaseWriteOrigin::PromoteReplay(_));
    let mut ops = ReplayOps { ops, replay };
    let hub_admission = gate_mode.hub_admission;
    let refinement_admission = gate_mode.refinement_admission;
    let birth_mask = gate_mode.birth_mask;
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    let record_gate_decisions = gate_mode.record_decisions;
    let persist_gate_pending_consent = gate_mode.persist_pending_consent;
    let include_source_in_gate_input = gate_mode.include_source_in_gate_input;
    let claim_gate_prechecked = gate_mode.claim_gate_prechecked;
    let mut claim_materializations = gate_mode.claim_materializations;
    let mut claim_transitions = gate_mode.claim_transitions;
    require_gated_claim_materializations(claim_gate_prechecked, &claim_materializations)?;
    let mut preflight_gate_decision_ids = gate_mode.preflight_gate_decision_ids;

    secret_scan::scan_batch_ops(&ops)?;
    // ONE-1871 (F5): LWW-resolve a replicated reparent of one child's single
    // parent slot BEFORE the overlay is built, so the winner add and the stored
    // losers' deletes are one atomic strict batch — cardinality is already one
    // when `validate_child_of_batch` runs, and no bytes stage in between.
    // Promotion contains only public attribution edges; it cannot carry the
    // replicated ChildOf arm that this resolver rewrites. Keep its owned
    // buffers in the scrub guard even on an error before the op loop.
    if !replay {
        ops.ops = resolve_replicated_child_of_slots(store, &*wtxn, std::mem::take(&mut ops.ops))?;
    }
    let child_of_overlay = ChildOfBatchOverlay::from_ops(&ops);
    let habit_streak_candidates =
        habit_streak_recompute_candidates(store, &*wtxn, &ops, &child_of_overlay)?;
    validate_child_of_batch(store, &*wtxn, &child_of_overlay)?;
    let mut had_graph_mutation = false;
    let mut had_vector_mutation = false;
    let mut materialized_entity_ids = BTreeSet::new();
    let mut project_edge_endpoints = BTreeSet::new();
    // ONE-1604-D1: shell-edge sources orphaned by a dominance eviction. Their
    // inducing type-76 rows are gone, so the full reconciler's
    // surviving-events derivation can no longer reach them. Non-empty here
    // also SIGNALS that a row left the ledger, which is what forces the
    // wider post-eviction union pass at the end of the batch.
    let mut evicted_shell_sources = BTreeSet::new();
    let mut text_manifest_checked = false;
    let later_text_coverage_by_op = text_coverage_after_op(&ops);
    let write_policy = if contains_local_claim_put(&ops) && !claim_gate_prechecked {
        Some(crate::gate::resolve_policy_manifest(store, &*wtxn)?)
    } else {
        None
    };
    let pending_gate_consent_at_batch_start = if persist_gate_pending_consent {
        pending_gate_consent_ids_at_batch_start(store, &*wtxn, &ops)?
    } else {
        HashSet::new()
    };
    // Legacy (pre-symmetric-migration) graphs answer a vector refresh with a
    // full snapshot rebuild. Batched vector updates coalesce that into at
    // most ONE rebuild per transaction: once pending, per-op graph mutations
    // are skipped (the end-of-batch rebuild re-derives the graph from the
    // `vectors` DB) and the rebuild runs after the op loop (ONE-324 AC11).
    let mut pending_hnsw_rebuild = false;
    let mut pending_embedding_tokens_written = HashMap::<EntityId, Vec<u8>>::new();
    #[cfg(feature = "sync")]
    let mut pending_embedding_enqueue_priorities = HashMap::<EntityId, u8>::new();
    // Preflight precedes every operation. Protect only future receipts from
    // earlier deletes; successful nested applies consume their own markers.
    mark_unapplied_preflight_decisions(store, wtxn, &preflight_gate_decision_ids)?;
    let mut iter = ReplayIter {
        remaining: std::mem::take(&mut ops.ops).into_iter(),
        replay,
    };
    let mut op_index = 0;
    while let Some(mut op) = iter.next() {
        // K4: the op-decode point, inside the applying transaction. Every arm
        // below decodes an op that may carry overlay ids, so this is where
        // membership is judged — before the arm can stage a byte.
        let materialization =
            prepare_replay_op(store, &*wtxn, &mut claim_materializations, &mut op, origin)?;
        let transition = consume_next(&mut claim_transitions, &op, iter.remaining.as_slice())?;
        match op {
            BatchOp::Put {
                id,
                mut entity_type,
                occurred,
                learned_at,
                data,
                allow_maintenance,
                allow_reserved_predicate,
                hub_sync_imported,
            } => {
                let mut data = Zeroizing::new(data);
                entity_type = validate_put_type(
                    store,
                    wtxn,
                    &id,
                    (entity_type, &mut data),
                    allow_maintenance,
                    allow_reserved_predicate,
                    hub_sync_imported,
                )?;
                let replicated = allow_maintenance && allow_reserved_predicate;
                if let Some(facet) =
                    birth_stamp_target(store, wtxn, id, entity_type, replicated, birth_mask)?
                {
                    let owner = crate::vault::embedded_owner_actor_id()?;
                    if birth_mask.is_none()
                        && facet == crate::claim::substrate_facet_id(owner)
                        && stored_entity_type(store, wtxn, &owner)?.is_none()
                    {
                        apply_ops_with_origin(
                            store,
                            config,
                            analyzer,
                            wtxn,
                            vec![BatchOp::Put {
                                id: owner,
                                entity_type: crate::registry::ENTITY_TYPE_PERSON,
                                occurred,
                                learned_at,
                                data: crate::vault::encode_embedded_owner_actor_body()?,
                                allow_maintenance: false,
                                allow_reserved_predicate: false,
                                hub_sync_imported: false,
                            }],
                            text_index_trusted,
                            ApplyOpsGateMode::new(
                                record_gate_decisions,
                                persist_gate_pending_consent,
                            ),
                            origin,
                        )?;
                    }
                    let found = stored_entity_type(store, wtxn, &facet)?;
                    if found != Some(crate::registry::ENTITY_TYPE_FACET) {
                        return Err(Error::Registry(RegistryError::InvalidFacet {
                            facet,
                            found,
                        }));
                    }
                    apply_edge_with_created_at(
                        store,
                        wtxn,
                        id,
                        crate::edge::EdgeKind::FacetOf,
                        facet,
                        1.0,
                        learned_at,
                        crate::affect::Vad::NEUTRAL,
                        None,
                    )?;
                    ppr::invalidate_ppr_for_edge(store, wtxn, &id, &facet)?;
                    had_graph_mutation = true;
                }
                let preflight_decision_id = if entity_type == crate::registry::ENTITY_TYPE_CLAIM
                    && !allow_reserved_predicate
                {
                    preflight_gate_decision_ids
                        .get_mut(&id)
                        .and_then(VecDeque::pop_front)
                        .flatten()
                } else {
                    None
                };
                let applied = apply_put(
                    store,
                    wtxn,
                    id,
                    entity_type,
                    occurred,
                    learned_at,
                    &data,
                    allow_reserved_predicate,
                    // ONE-1141: `replicated_put_op` is the SINGLE constructor
                    // that opens BOTH admit bands at once (see its doc), so
                    // both-flags-set identifies the sync replay doors
                    // (`put_replicated` → here). The replicated arm of
                    // `apply_put` deindexes the loser's BM25F postings on a
                    // body-changing overwrite, same-txn (ARCH-0031 amendment).
                    replicated,
                    hub_sync_imported,
                    hub_admission.as_ref(),
                    refinement_admission.as_ref(),
                    later_text_coverage_by_op[op_index],
                    write_policy.as_ref(),
                    materialization
                        .as_ref()
                        .and_then(ClaimMaterialization::gate_envelope),
                    false,
                    record_gate_decisions,
                    persist_gate_pending_consent,
                    pending_gate_consent_at_batch_start.contains(&id),
                    include_source_in_gate_input,
                    claim_gate_prechecked,
                    preflight_decision_id,
                    transition.as_ref(),
                    origin,
                )?;
                consume_preflight_decisions(store, wtxn, [preflight_decision_id])?;
                if let Some((source_id, source_bytes)) = applied.portable_agent_source {
                    apply_ops_with_origin(
                        store,
                        config,
                        analyzer,
                        wtxn,
                        vec![BatchOp::Put {
                            id: source_id,
                            entity_type: crate::registry::ENTITY_TYPE_ASSET,
                            occurred,
                            learned_at,
                            data: source_bytes,
                            allow_maintenance: false,
                            allow_reserved_predicate: false,
                            hub_sync_imported: false,
                        }],
                        text_index_trusted,
                        ApplyOpsGateMode::new(record_gate_decisions, persist_gate_pending_consent),
                        origin,
                    )?;
                }
                if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                    let authored = materialization.is_some() && !allow_reserved_predicate;
                    claim_materialization::record_committed_claim(store, wtxn, &id, authored)?;
                }
                evicted_shell_sources.extend(applied.evicted_shell_sources);
                #[cfg(feature = "sync")]
                let pending_embedding_priority = if allow_maintenance && allow_reserved_predicate {
                    crate::embed::EMBED_PRIORITY_SERVER
                } else {
                    crate::embed::EMBED_PRIORITY_DEVICE
                };
                if let Some(token) = applied.pending_embedding_token {
                    pending_embedding_tokens_written.insert(id, token);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities
                        .entry(id)
                        .and_modify(|priority| {
                            *priority = (*priority).min(pending_embedding_priority);
                        })
                        .or_insert(pending_embedding_priority);
                }
                if applied.cleared_pending_embedding {
                    pending_embedding_tokens_written.remove(&id);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities.remove(&id);
                }
                had_vector_mutation |= applied.had_vector_mutation;
                if entity_type == crate::registry::ENTITY_TYPE_CLAIM
                    && !(allow_maintenance && allow_reserved_predicate)
                    && !applied.is_lexical_query_hint_claim
                {
                    let deleted = delete_lexical_query_hint_claims_for_target(
                        store,
                        wtxn,
                        &id,
                        &HashSet::new(),
                    )?;
                    for (deleted_id, neighbors) in &deleted.deleted {
                        pending_embedding_tokens_written.remove(deleted_id);
                        #[cfg(feature = "sync")]
                        pending_embedding_enqueue_priorities.remove(deleted_id);
                        ppr::invalidate_ppr_for_delete(store, wtxn, deleted_id, neighbors)?;
                    }
                    had_graph_mutation |= deleted.had_graph_mutation;
                    had_vector_mutation |= deleted.had_vector;
                }
                if let Some((target, query_hint)) = lexical_query_hint_for_replayed_put(
                    &id,
                    entity_type,
                    allow_maintenance && allow_reserved_predicate,
                    &data,
                )? {
                    let mut text_indexing = LexicalHintTextIndexing {
                        analyzer,
                        manifest_checked: &mut text_manifest_checked,
                        trusted: text_index_trusted,
                    };
                    let materialized = materialize_lexical_query_hint_text_if_target_ready(
                        store,
                        wtxn,
                        &mut text_indexing,
                        id,
                        &target,
                        query_hint,
                    )?;
                    had_graph_mutation |= materialized;
                }
                if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                    let mut text_indexing = LexicalHintTextIndexing {
                        analyzer,
                        manifest_checked: &mut text_manifest_checked,
                        trusted: text_index_trusted,
                    };
                    let materialized = materialize_lexical_query_hints_for_target(
                        store,
                        wtxn,
                        &mut text_indexing,
                        &id,
                    )?;
                    had_graph_mutation |= materialized;
                }
                // Type-76 rows are never legal participants/actors. Their
                // dedicated ingest door reconciles after the seq join, so
                // feeding event ids into the generic participant hook would
                // enumerate the append-only family once per appended event.
                if entity_type != crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
                    materialized_entity_ids.insert(id);
                }
            }
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                occurred,
                learned_at,
                internal_lexical_query_hint,
            } => {
                let preflight_decision_id = if !internal_lexical_query_hint {
                    preflight_gate_decision_ids
                        .get_mut(&id)
                        .and_then(VecDeque::pop_front)
                        .flatten()
                } else {
                    None
                };
                let applied = apply_claim_candidate(
                    store,
                    wtxn,
                    id,
                    *candidate,
                    &envelope,
                    occurred,
                    learned_at,
                    later_text_coverage_by_op[op_index],
                    write_policy.as_ref(),
                    internal_lexical_query_hint,
                    record_gate_decisions,
                    persist_gate_pending_consent,
                    pending_gate_consent_at_batch_start.contains(&id),
                    include_source_in_gate_input,
                    claim_gate_prechecked,
                    preflight_decision_id,
                )?;
                consume_preflight_decisions(store, wtxn, [preflight_decision_id])?;
                if !internal_lexical_query_hint {
                    claim_materialization::record_committed_claim(store, wtxn, &id, true)?;
                }
                had_graph_mutation |= applied.had_graph_mutation;
                had_vector_mutation |= applied.had_vector_mutation;
                if let Some(token) = applied.pending_embedding_token {
                    pending_embedding_tokens_written.insert(id, token);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities
                        .entry(id)
                        .and_modify(|priority| {
                            *priority = (*priority).min(crate::embed::EMBED_PRIORITY_DEVICE);
                        })
                        .or_insert(crate::embed::EMBED_PRIORITY_DEVICE);
                }
                if applied.cleared_pending_embedding {
                    pending_embedding_tokens_written.remove(&id);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities.remove(&id);
                }
                materialized_entity_ids.insert(id);
            }
            BatchOp::ReconcileLexicalQueryHints { source, keep } => {
                let keep: HashSet<EntityId> = keep.into_iter().collect();
                let deleted =
                    delete_lexical_query_hint_claims_for_target(store, wtxn, &source, &keep)?;
                for (deleted_id, neighbors) in &deleted.deleted {
                    pending_embedding_tokens_written.remove(deleted_id);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities.remove(deleted_id);
                    ppr::invalidate_ppr_for_delete(store, wtxn, deleted_id, neighbors)?;
                }
                had_graph_mutation |= deleted.had_graph_mutation;
                had_vector_mutation |= deleted.had_vector;
            }
            BatchOp::Vector {
                id,
                vector,
                pending_embedding_token,
            } => {
                let vector = Zeroizing::new(vector);
                let pending_embedding_token = Zeroizing::new(pending_embedding_token);
                let same_batch_token = pending_embedding_token
                    .as_deref()
                    .or_else(|| pending_embedding_tokens_written.get(&id).map(Vec::as_slice));
                let applied = apply_vector(store, config, wtxn, id, &vector, same_batch_token)?;
                if applied.wrote_vector {
                    crate::hnsw::hnsw_insert_batched(
                        store,
                        config,
                        wtxn,
                        &id,
                        &vector,
                        &mut pending_hnsw_rebuild,
                    )?;
                    had_vector_mutation = true;
                }
                if applied.cleared_pending_embedding {
                    pending_embedding_tokens_written.remove(&id);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities.remove(&id);
                }
            }
            op @ (BatchOp::Edge { .. }
            | BatchOp::PublicEdgeWithCreatedAt { .. }
            | BatchOp::EdgeWithCreatedAt { .. }
            | BatchOp::SetEdgeWeight { .. }
            | BatchOp::SetEdgeVad { .. }
            | BatchOp::DeleteEdge { .. }) => {
                project_edge_endpoints.extend(edge_op_endpoints(&op));
                had_graph_mutation |= apply_edge_op(store, wtxn, op)?;
            }
            BatchOp::Text { id, fields } => {
                let fields = Zeroizing::new(fields);
                apply_text_index_update(
                    store,
                    wtxn,
                    analyzer,
                    &id,
                    &fields,
                    text_index_trusted,
                    &mut text_manifest_checked,
                )?;
            }
            BatchOp::Phonetic { id, codes } => {
                if !crate::vault::entity_revision::defer_phonetic(store, wtxn, &id, &codes)? {
                    apply_phonetic(store, wtxn, id, &codes)?;
                }
            }
            BatchOp::Delete { id } => {
                reject_engine_authored_delete(store, wtxn, &id)?;
                let (_existed, had_vector, deleted_graph_state, neighbors) =
                    deindex_entity(store, wtxn, &id)?;
                claim_materialization::invalidate_authored_claim(store, wtxn, &id)?;
                if persist_gate_pending_consent {
                    store.let_go_pending_gate_consent_in_txn(wtxn, &id, mutation_recorded_at)?;
                }
                pending_embedding_tokens_written.remove(&id);
                #[cfg(feature = "sync")]
                pending_embedding_enqueue_priorities.remove(&id);
                ppr::invalidate_ppr_for_delete(store, wtxn, &id, &neighbors)?;
                had_graph_mutation |= deleted_graph_state;
                had_vector_mutation |= had_vector;
            }
            // CMT-4 (ONE-1541). All-or-nothing by construction: the helper
            // grounds every selected instance before staging a single op and
            // never commits, so one stale, closed or gate-refused member takes
            // the whole selection down with the caller's transaction.
            BatchOp::CommitmentGapDecay {
                ids,
                envelope,
                learned_at,
            } => {
                // Hand each id its preflight identity in recorded order. The
                // nested ClaimCandidate applies consume its marker, not this
                // outer arm; consuming here a second time aborts the lapse.
                let lapse_decision_ids =
                    take_lapse_decisions(&mut preflight_gate_decision_ids, &ids);
                crate::commitment::lapse_commitments_in_txn(
                    store,
                    config,
                    analyzer,
                    wtxn,
                    &ids,
                    &envelope,
                    learned_at,
                    text_index_trusted,
                    write_policy.as_ref(),
                    lapse_decision_ids,
                )?;
            }
        }
        op_index += 1;
    }

    require_consumed_claim_bindings(&claim_materializations, &claim_transitions)?;
    if preflight_gate_decision_ids
        .values()
        .any(|ids| !ids.is_empty())
    {
        return Err(Error::InvariantViolation(
            "unconsumed preflight gate decision identity",
        ));
    }

    crate::workspace_roster::reconcile_project_rooms(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &materialized_entity_ids,
    )?;
    project_edge_endpoints.extend(&materialized_entity_ids);
    crate::workspace_roster::validate_project_graph(store, wtxn, &project_edge_endpoints)?;

    // STO-03: derived Habit counters, recomputed from the FINAL child state of
    // this transaction — after every op, so an add and a delete of the same
    // edge net out and the batch order cannot be read off the result. Local
    // check-in commits and sync replay both land here because both reach
    // `apply_ops`; there is no second, sync-only streak algorithm.
    recompute_touched_habit_streaks_in_txn(store, wtxn, &habit_streak_candidates)?;

    crate::identity_topology::reconcile_identity_topology_for_materialized_entities_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &materialized_entity_ids,
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
        &evicted_shell_sources,
    )?;

    crate::authority::check_materialized_claim_causality(
        store,
        wtxn,
        config.privacy.posture,
        &materialized_entity_ids,
    )?;

    #[cfg(feature = "sync")]
    for (id, token) in &pending_embedding_tokens_written {
        if config.embedding_model.is_some()
            && store.pending_embedding_token_in_txn(wtxn, id)?.as_deref() == Some(token.as_slice())
        {
            let priority = pending_embedding_enqueue_priorities
                .get(id)
                .copied()
                .unwrap_or(crate::embed::EMBED_PRIORITY_DEVICE);
            crate::sync::queue::push_embed_job_in_txn(store, wtxn, id, priority)?;
        }
    }

    finalize_batch_indexes(
        store,
        config,
        wtxn,
        &materialized_entity_ids,
        pending_hnsw_rebuild,
        had_graph_mutation,
        had_vector_mutation,
    )
}
