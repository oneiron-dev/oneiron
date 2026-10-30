//! Batch base apply: `apply_ops_with_origin` and its per-op arms.
//! The loop dispatches each `BatchOp` to its phase child; the tail folds
//! frontiers, rooms, streaks and indexes once over the final batch state.

use super::claim_materialization::consume_claim_materialization;
use super::verified_claim_transition::consume_next;
use super::*;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::write_envelope::ClaimCandidate;

mod edge;
mod indexes;
mod ops_claim;
mod ops_delete;
mod ops_misc;
mod ops_put;
mod ops_text;
mod ops_vector;
mod project_history;
mod replay;
mod tail;
mod validation;

use self::replay::{ReplayIter, ReplayOps};
use self::validation::mark_unapplied_preflight_decisions;

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

/// Batch-level mutable state threaded through per-op arms and the tail.
struct BatchApplyState {
    replay: bool,
    run_derivations: Option<crate::skill_attribution::RunDerivations>,
    hub_admission: Option<crate::skill_hub::HubAdmissionProof>,
    refinement_admission: Option<crate::skill_hub::RefinementAdmissionProof>,
    birth_mask: Option<EntityId>,
    text_births: HashMap<EntityId, Vec<EntityId>>,
    births: Vec<(EntityId, crate::provenance::birth::RowBirth)>,
    asset_files: HashMap<EntityId, crate::store::AssetBodyFacts>,
    replicated_puts: BTreeSet<EntityId>,
    mutation_recorded_at: u64,
    authority_generation: u64,
    record_gate_decisions: bool,
    persist_gate_pending_consent: bool,
    claim_materializations: VecDeque<ClaimMaterialization>,
    claim_transitions: VecDeque<super::VerifiedClaimTransition>,
    preflight_gate_decision_ids: HashMap<EntityId, VecDeque<Option<crate::store::GateDecisionId>>>,
    pre_analyzed_text: HashMap<EntityId, VecDeque<Option<crate::bm25::AnalyzedText>>>,
    nsw_plans: HashMap<EntityId, VecDeque<crate::hnsw::InsertPlan>>,
    masked_files: super::secret_scan::MaskedFiles,
    masked_claims: HashMap<EntityId, VecDeque<ClaimCandidate>>,
    habit_streak_candidates: BTreeSet<EntityId>,
    had_graph_mutation: bool,
    had_vector_mutation: bool,
    materialized_entity_ids: BTreeSet<EntityId>,
    local_materialized_ids: BTreeSet<EntityId>,
    deleted_entity_ids: BTreeSet<EntityId>,
    project_edge_endpoints: BTreeSet<EntityId>,
    touched_projects: BTreeSet<EntityId>,
    local_chat_turns: BTreeSet<EntityId>,
    evicted_shell_sources: BTreeSet<EntityId>,
    text_manifest_checked: bool,
    later_text_coverage_by_op: Vec<bool>,
    write_policy: Option<crate::gate::PolicyManifestResolution>,
    pending_gate_consent_at_batch_start: HashSet<EntityId>,
    pending_hnsw_rebuild: bool,
    pending_embedding_tokens_written: HashMap<EntityId, Vec<u8>>,
    #[cfg(feature = "sync")]
    pending_embedding_enqueue_priorities: HashMap<EntityId, u8>,
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
// One transaction applies every op and then its whole-batch validators in order.
#[allow(clippy::too_many_lines)]
pub(super) fn apply_ops_with_origin(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    mut gate_mode: ApplyOpsGateMode,
    origin: BaseWriteOrigin<'_>,
) -> Result<()> {
    let replay = matches!(origin, BaseWriteOrigin::PromoteReplay(_));
    let mut ops = ReplayOps { ops, replay };
    let run_derivations = crate::skill_attribution::run_derivations(&ops.ops, replay);
    let hub_admission = gate_mode.hub_admission.take();
    let refinement_admission = gate_mode.refinement_admission.take();
    let birth_mask = gate_mode.birth_mask;
    let text_births = std::mem::take(&mut gate_mode.text_births);
    let births = std::mem::take(&mut gate_mode.births);
    let mut asset_files = std::mem::take(&mut gate_mode.asset_files);
    let replicated_puts = std::mem::take(&mut gate_mode.replicated_puts);
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    let authority_generation = crate::authority::authority_cache_generation(store, wtxn)?;
    let record_gate_decisions = gate_mode.record_decisions;
    let persist_gate_pending_consent = gate_mode.persist_pending_consent;
    let claim_gate_prechecked = gate_mode.claim_gate_prechecked;
    let mut claim_materializations = std::mem::take(&mut gate_mode.claim_materializations);
    let mut claim_transitions = std::mem::take(&mut gate_mode.claim_transitions);
    require_gated_claim_materializations(claim_gate_prechecked, &claim_materializations)?;
    let mut preflight_gate_decision_ids =
        std::mem::take(&mut gate_mode.preflight_gate_decision_ids);
    let mut pre_analyzed_text = std::mem::take(&mut gate_mode.pre_analyzed_text);
    let mut nsw_plans = std::mem::take(&mut gate_mode.nsw_plans);

    // The owner's `secrets` switch is read in this transaction, so a batch
    // and the mode it was admitted under are one snapshot. A secret the door
    // places goes to custody and leaves its handle (OF-560); a file keeps
    // its bytes and is marked.
    let (masked_files, masked_claim_pre) = secret_scan::mask_batch_ops(
        store,
        config,
        analyzer,
        wtxn,
        &mut ops.ops,
        text_index_trusted,
        !replay,
        mutation_recorded_at,
    )?;
    // The pre-mask body of each MACHINE candidate the mask rewrote in this
    // transaction (FIX 11356), in op order per id: the candidate apply
    // renews a proof only over its verified pre-mask body. A replayed batch
    // reports none, so its proofs stay byte for byte.
    let mut masked_claims: HashMap<EntityId, VecDeque<ClaimCandidate>> = HashMap::new();
    for (id, pre) in masked_claim_pre {
        masked_claims.entry(id).or_default().push_back(pre);
    }
    // FIX 5507: a body file a mark names bands its record as a marked row does.
    let masked_files =
        masked_files.with_marked_body_files(store, &*wtxn, &ops.ops, &asset_files)?;
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
    // FIX 7925: this batch's own writes; replay keeps its bytes for read quarantine.
    let mut local_materialized_ids = BTreeSet::new();
    // FIX 4652: rows this batch deleted, for the seal standing rerun.
    let mut deleted_entity_ids = BTreeSet::new();
    let mut project_edge_endpoints = BTreeSet::new();
    let mut touched_projects = BTreeSet::new();
    let local_chat_turns = super::leader_chat_admission::local_turns(&ops);
    // ONE-1604-D1: shell-edge sources orphaned by a dominance eviction. Their
    // inducing type-76 rows are gone, so the full reconciler's
    // surviving-events derivation can no longer reach them. Non-empty here
    // also SIGNALS that a row left the ledger, which is what forces the
    // wider post-eviction union pass at the end of the batch.
    let mut evicted_shell_sources = BTreeSet::new();
    let mut text_manifest_checked = false;
    let later_text_coverage_by_op = text_coverage_after_op(&ops);
    let write_policy = (contains_local_claim_put(&ops) && !claim_gate_prechecked)
        .then(|| crate::gate::resolve_policy_manifest(store, &*wtxn))
        .transpose()?;
    let pending_gate_consent_at_batch_start = persist_gate_pending_consent
        .then(|| pending_gate_consent_ids_at_batch_start(store, &*wtxn, &ops))
        .transpose()?
        .unwrap_or_default();
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
    let mut state = BatchApplyState {
        replay,
        run_derivations,
        hub_admission,
        refinement_admission,
        birth_mask,
        text_births,
        births,
        asset_files,
        replicated_puts,
        mutation_recorded_at,
        authority_generation,
        record_gate_decisions,
        persist_gate_pending_consent,
        claim_materializations,
        claim_transitions,
        preflight_gate_decision_ids,
        pre_analyzed_text,
        nsw_plans,
        masked_files,
        masked_claims,
        habit_streak_candidates,
        had_graph_mutation,
        had_vector_mutation,
        materialized_entity_ids,
        local_materialized_ids,
        deleted_entity_ids,
        project_edge_endpoints,
        touched_projects,
        local_chat_turns,
        evicted_shell_sources,
        text_manifest_checked,
        later_text_coverage_by_op,
        write_policy,
        pending_gate_consent_at_batch_start,
        pending_hnsw_rebuild,
        pending_embedding_tokens_written,
        #[cfg(feature = "sync")]
        pending_embedding_enqueue_priorities,
    };
    let mut op_index = 0;
    while let Some(mut op) = iter.next() {
        // K4: the op-decode point, inside the applying transaction. Every arm
        // below decodes an op that may carry overlay ids, so this is where
        // membership is judged — before the arm can stage a byte.
        let materialization = prepare_replay_op(
            store,
            &*wtxn,
            &mut state.claim_materializations,
            &mut op,
            origin,
        )?;
        let transition =
            consume_next(&mut state.claim_transitions, &op, iter.remaining.as_slice())?;
        let mut put_options = PutOptions::for_batch_op(&op, &gate_mode);
        put_options.indexing.later_text_op_covers = state.later_text_coverage_by_op[op_index];

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
                ops_put::apply_put_arm(
                    store,
                    config,
                    analyzer,
                    &mut *wtxn,
                    &mut state,
                    &gate_mode,
                    id,
                    entity_type,
                    occurred,
                    learned_at,
                    data,
                    allow_maintenance,
                    allow_reserved_predicate,
                    hub_sync_imported,
                    &materialization,
                    &transition,
                    put_options,
                    origin,
                    text_index_trusted,
                )?;
            }
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                occurred,
                learned_at,
                internal_lexical_query_hint,
            } => {
                ops_claim::apply_claim_candidate_arm(
                    store,
                    config,
                    analyzer,
                    &mut *wtxn,
                    &mut state,
                    &gate_mode,
                    id,
                    candidate,
                    envelope,
                    occurred,
                    learned_at,
                    internal_lexical_query_hint,
                    put_options,
                    text_index_trusted,
                )?;
            }
            BatchOp::ReconcileLexicalQueryHints { source, keep } => {
                ops_claim::apply_reconcile_lexical_arm(
                    store, &mut *wtxn, &mut state, source, keep,
                )?;
            }
            BatchOp::Vector {
                id,
                vector,
                pending_embedding_token,
                provenance,
            } => {
                ops_vector::apply_vector_arm(
                    store,
                    config,
                    &mut *wtxn,
                    &mut state,
                    id,
                    vector,
                    pending_embedding_token,
                    provenance,
                )?;
            }
            op @ (BatchOp::Edge { .. }
            | BatchOp::PublicEdgeWithCreatedAt { .. }
            | BatchOp::EdgeWithCreatedAt { .. }
            | BatchOp::SetEdgeWeight { .. }
            | BatchOp::SetEdgeVad { .. }
            | BatchOp::DeleteEdge { .. }) => {
                ops_misc::apply_edge_arm(store, &mut *wtxn, &mut state, op)?;
            }
            BatchOp::Text { id, fields } => {
                ops_text::apply_text_arm(
                    store,
                    &mut *wtxn,
                    &mut state,
                    analyzer,
                    id,
                    fields,
                    text_index_trusted,
                )?;
            }
            BatchOp::MediaVector {
                space,
                id,
                kind,
                text_hash,
                vector,
                provenance,
            } => {
                ops_vector::apply_media_vector_arm(
                    store, &mut *wtxn, space, id, kind, text_hash, vector, provenance,
                )?;
            }
            BatchOp::Phonetic { id, codes } => {
                ops_vector::apply_phonetic_arm(store, &mut *wtxn, id, codes)?;
            }
            BatchOp::Delete { id } => {
                ops_delete::apply_delete_arm(
                    store,
                    config,
                    analyzer,
                    &mut *wtxn,
                    &mut state,
                    id,
                    origin,
                    text_index_trusted,
                )?;
            }
            BatchOp::CommitmentGapDecay {
                ids,
                envelope,
                learned_at,
            } => {
                ops_misc::apply_commitment_gap_decay_arm(
                    store,
                    config,
                    analyzer,
                    &mut *wtxn,
                    &mut state,
                    ids,
                    envelope,
                    learned_at,
                    text_index_trusted,
                )?;
            }
        }
        op_index += 1;
    }

    tail::apply_tail(store, config, analyzer, wtxn, state, text_index_trusted)
}
