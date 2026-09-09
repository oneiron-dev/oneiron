use super::claim_materialization::consume_claim_materialization;
use super::*;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ppr;
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_SKILL};
use crate::store::Store;

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
        ApplyOpsGateMode::new(false, false).with_prechecked_claim_gate(),
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
    let record_gate_decisions = gate_mode.record_decisions;
    let persist_gate_pending_consent = gate_mode.persist_pending_consent;
    let include_source_in_gate_input = gate_mode.include_source_in_gate_input;
    let claim_gate_prechecked = gate_mode.claim_gate_prechecked;
    let mut claim_materializations = gate_mode.claim_materializations;
    if claim_gate_prechecked && !claim_materializations.is_empty() {
        return Err(Error::InvariantViolation(
            "owner-bound materialization cannot skip the gate",
        ));
    }
    let mut preflight_gate_decision_ids = gate_mode.preflight_gate_decision_ids;
    let staged_claim_gate = gate_mode.staged_claim_gate;

    secret_scan::scan_batch_ops(&ops)?;
    // ONE-1871 (F5): LWW-resolve a replicated reparent of one child's single
    // parent slot BEFORE the overlay is built, so the winner add and the stored
    // losers' deletes are one atomic strict batch — cardinality is already one
    // when `validate_child_of_batch` runs, and no bytes stage in between.
    let ops = resolve_replicated_child_of_slots(store, &*wtxn, ops)?;
    let child_of_overlay = ChildOfBatchOverlay::from_ops(&ops);
    let habit_streak_candidates =
        habit_streak_recompute_candidates(store, &*wtxn, &ops, &child_of_overlay)?;
    validate_child_of_batch(store, &*wtxn, &child_of_overlay)?;
    let mut had_graph_mutation = false;
    let mut had_vector_mutation = false;
    let mut materialized_entity_ids = BTreeSet::new();
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
    let companion_retired_histories = companion_retired_histories_in_batch(&ops)?;

    for (op_index, op) in ops.into_iter().enumerate() {
        // K4: the op-decode point, inside the applying transaction. Every arm
        // below decodes an op that may carry overlay ids, so this is where
        // membership is judged — before the arm can stage a byte.
        check_decode_point_taint_guard(store, &op, origin)?;
        let materialization =
            consume_claim_materialization(store, &*wtxn, &mut claim_materializations, &op, origin)?;
        match op {
            BatchOp::Put {
                id,
                entity_type,
                occurred,
                learned_at,
                data,
                allow_maintenance,
                allow_reserved_predicate,
                hub_sync_imported,
            } => {
                if hub_sync_imported
                    && (entity_type != ENTITY_TYPE_SKILL
                        || allow_maintenance
                        || allow_reserved_predicate)
                {
                    return Err(Error::InvariantViolation(
                        "hub-sync imported flag is only valid for a local SKILL Put",
                    ));
                }
                // Public writes reject engine-authored system kinds via
                // the public entity-type gate; the sync rematerialization path
                // sets `allow_maintenance` so REDACTION_AUDIT receipts
                // survive CRDT→LMDB replay (registry-only entity-type validation
                // still rejects genuinely unknown type bytes).
                if allow_maintenance
                    && allow_reserved_predicate
                    && matches!(
                        entity_type,
                        crate::registry::ENTITY_TYPE_POLICY_MANIFEST
                            | ENTITY_TYPE_ACCESS_GRANT
                            | ENTITY_TYPE_OUTBOUND_GRANT
                    )
                {
                    return Err(Error::MaintenanceKindNotWritable(entity_type));
                }
                // ONE-1865 arm-pending seal (SECRET-01, ONE-1919): the custody
                // record is the secret VALUE's home, so a replicated carry of
                // byte 77 would materialize a peer-supplied plaintext
                // `value_bytes` straight into LMDB. `Vault::register_secret`
                // is the ONE write path and it uses the engine-internal shape
                // (`allow_maintenance` WITHOUT `allow_reserved_predicate`);
                // the both-flags shape here is exclusively the CRDT replay
                // door (`window::forward_rematerialize` → `put_replicated`),
                // which must never admit the byte. The custody module owns the
                // rejection constructor so one grep audits the whole seal.
                if allow_maintenance
                    && allow_reserved_predicate
                    && entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                {
                    return Err(crate::secret_custody::reject_secret_custody_byte());
                }
                if allow_maintenance {
                    store.validate_entity_type(entity_type)?;
                } else {
                    store.validate_public_entity_type(entity_type)?;
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
                    allow_maintenance && allow_reserved_predicate,
                    hub_sync_imported,
                    later_text_coverage_by_op[op_index],
                    write_policy.as_ref(),
                    materialization.as_ref().map(ClaimMaterialization::envelope),
                    false,
                    record_gate_decisions,
                    persist_gate_pending_consent,
                    pending_gate_consent_at_batch_start.contains(&id),
                    include_source_in_gate_input,
                    claim_gate_prechecked,
                    preflight_decision_id,
                    preflight_decision_id
                        .and_then(|decision_id| staged_claim_gate.as_ref()?.get(&decision_id)),
                    Some(&companion_retired_histories),
                    origin,
                )?;
                if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                    if materialization.is_some() && !allow_reserved_predicate {
                        claim_materialization::bind_committed_claim(store, wtxn, &id)?;
                    } else {
                        claim_materialization::invalidate_authored_claim(store, wtxn, &id)?;
                    }
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
                    preflight_decision_id
                        .and_then(|decision_id| staged_claim_gate.as_ref()?.get(&decision_id)),
                )?;
                if !internal_lexical_query_hint {
                    claim_materialization::bind_committed_claim(store, wtxn, &id)?;
                }
                if applied.had_graph_mutation {
                    had_graph_mutation = true;
                }
                if applied.had_vector_mutation {
                    had_vector_mutation = true;
                }
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
            BatchOp::Edge {
                src,
                kind,
                tgt,
                weight,
                vad,
            } => {
                validate_facet_of_edge(store, wtxn, src, kind, tgt)?;
                apply_edge(store, wtxn, src, kind, tgt, weight, vad)?;
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::PublicEdgeWithCreatedAt {
                src,
                kind,
                tgt,
                weight,
                created_at,
                vad,
            } => {
                validate_facet_of_edge(store, wtxn, src, kind, tgt)?;
                apply_public_edge_with_created_at(
                    store, wtxn, src, kind, tgt, weight, created_at, vad,
                )?;
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            // UNGATED by design — this is the replicated/replay shape. A
            // bare-over-provenanced LWW edge is a legitimate remote winner;
            // gating here would turn a legitimate remote merge into a
            // permanent local sync-wedging abort (H2). The public timestamped
            // builders route through the gated `PublicEdgeWithCreatedAt` arm
            // instead.
            //
            // Ungated is not unvalidated: the ONE-1645 `FacetOf` type table
            // runs on every path INTO this arm instead, as a
            // quarantine-and-continue rejection rather than an abort —
            // `sync::window`'s forward-remat edge write and
            // `sync::bridge`'s Observer-B edge batch both call
            // `validate_facet_of_edge` after endpoint readiness, and
            // `sync::selector`'s federation admission door drops a provably
            // off-table row before it ever enters the admitted document. A
            // federation peer therefore cannot replay a facet stamp local
            // writers may not write.
            BatchOp::EdgeWithCreatedAt {
                src,
                kind,
                tgt,
                weight,
                created_at,
                vad,
                provenance,
            } => {
                apply_edge_with_created_at(
                    store, wtxn, src, kind, tgt, weight, created_at, vad, provenance,
                )?;
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::SetEdgeWeight {
                src,
                kind,
                tgt,
                weight,
            } => {
                apply_set_edge_weight(store, wtxn, src, kind, tgt, weight)?;
                // The weight at offset 0 is the PPR edge weight — invalidate
                // and bump exactly like the plain edge-write arms.
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::SetEdgeVad {
                src,
                kind,
                tgt,
                vad,
            } => {
                apply_set_edge_vad(store, wtxn, src, kind, tgt, vad)?;
                // Mirror the existing edge-write behavior: every edge value
                // rewrite invalidates the endpoint PPR caches.
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::Text { id, fields } => {
                if !text_index_trusted {
                    return Err(Error::CorruptedIndex(
                        "text index handshake bypassed on populated index",
                    ));
                }
                if !text_manifest_checked {
                    crate::vault::ensure_text_index_manifest_matches_wtxn(store, wtxn, analyzer)?;
                    text_manifest_checked = true;
                }
                crate::bm25::index_text(store, wtxn, analyzer, &id, &fields)?;
            }
            BatchOp::Phonetic { id, codes } => {
                apply_phonetic(store, wtxn, id, &codes)?;
            }
            BatchOp::Delete { id } => {
                reject_engine_authored_delete(store, wtxn, &id)?;
                let (_existed, had_vector, deleted_graph_state, neighbors) =
                    deindex_entity(store, wtxn, &id)?;
                claim_materialization::invalidate_authored_claim(store, wtxn, &id)?;
                if persist_gate_pending_consent {
                    store.let_go_pending_gate_consent_in_txn(
                        wtxn,
                        &id,
                        crate::unix_seconds_now(),
                    )?;
                }
                pending_embedding_tokens_written.remove(&id);
                #[cfg(feature = "sync")]
                pending_embedding_enqueue_priorities.remove(&id);
                ppr::invalidate_ppr_for_delete(store, wtxn, &id, &neighbors)?;
                had_graph_mutation |= deleted_graph_state;
                had_vector_mutation |= had_vector;
            }
            BatchOp::DeleteEdge { src, kind, tgt } => {
                if apply_delete_edge(store, wtxn, src, kind, tgt)? {
                    ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                    had_graph_mutation = true;
                }
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
                // Hand each id its own preflight receipt identity, in the
                // order the preflight recorded them, so the unconsumed-identity
                // invariant below stays exact.
                let mut lapse_decision_ids: HashMap<
                    EntityId,
                    VecDeque<Option<crate::store::GateDecisionId>>,
                > = HashMap::new();
                for id in &ids {
                    let decision_id = preflight_gate_decision_ids
                        .get_mut(id)
                        .and_then(VecDeque::pop_front)
                        .flatten();
                    lapse_decision_ids
                        .entry(*id)
                        .or_default()
                        .push_back(decision_id);
                }
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
    }

    if !claim_materializations.is_empty() {
        return Err(Error::InvariantViolation(
            "unconsumed claim materialization envelope",
        ));
    }
    if preflight_gate_decision_ids
        .values()
        .any(|ids| !ids.is_empty())
    {
        return Err(Error::InvariantViolation(
            "unconsumed preflight gate decision identity",
        ));
    }

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

    #[cfg(feature = "sync")]
    for (id, token) in &pending_embedding_tokens_written {
        if store.pending_embedding_token_in_txn(wtxn, id)?.as_deref() == Some(token.as_slice()) {
            let priority = pending_embedding_enqueue_priorities
                .get(id)
                .copied()
                .unwrap_or(crate::embed::EMBED_PRIORITY_DEVICE);
            crate::sync::queue::push_embed_job_in_txn(store, wtxn, id, priority)?;
        }
    }

    crate::hnsw::run_pending_legacy_rebuild(store, config, wtxn, pending_hnsw_rebuild)?;

    if had_graph_mutation {
        ppr::increment_graph_version(store, wtxn)?;
    }
    if had_vector_mutation {
        crate::hnsw::increment_vector_version(store, wtxn)?;
    }

    Ok(())
}
