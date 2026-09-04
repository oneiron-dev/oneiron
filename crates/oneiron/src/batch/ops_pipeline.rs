use super::*;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use heed::RwTxn;

use crate::claim::ClaimLifecycleStatus;
use crate::companion::{ENTITY_TYPE_COMPANION_REGISTER, decode_companion_record_body};
use crate::edge::{encode_edge_value, validate_edge_weight};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::off_record::PromoteReplayGrant;
use crate::ppr;
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_SKILL};
use crate::session_overlay::{JournalEntry, RouteTarget, SessionWriteRoute};
use crate::store::Store;

#[derive(Debug, Clone)]
pub(crate) struct ApplyOpsGateMode {
    record_decisions: bool,
    persist_pending_consent: bool,
    include_source_in_gate_input: bool,
    claim_gate_prechecked: bool,
    preflight_gate_decision_ids: HashMap<EntityId, VecDeque<Option<crate::store::GateDecisionId>>>,
}

impl ApplyOpsGateMode {
    pub(crate) fn new(record_decisions: bool, persist_pending_consent: bool) -> Self {
        Self {
            record_decisions,
            persist_pending_consent,
            include_source_in_gate_input: false,
            claim_gate_prechecked: false,
            preflight_gate_decision_ids: HashMap::new(),
        }
    }

    pub(crate) fn with_source_in_gate_input(mut self) -> Self {
        self.include_source_in_gate_input = true;
        self
    }

    /// Marks local CLAIM puts as already authorized in this transaction.
    /// Structural validation and materialization still run; only the duplicate
    /// gate evaluation in `apply_put` is skipped.
    fn with_prechecked_claim_gate(mut self) -> Self {
        self.claim_gate_prechecked = true;
        self
    }

    /// Binds the receipt identities a same-transaction gate preflight already
    /// recorded. Reachable crate-wide because `commitment::lapse_commitments_in_txn`
    /// composes the batch apply from inside a `CommitmentGapDecay` op and must
    /// carry its preflight identities forward rather than mint fresh ones.
    pub(crate) fn with_preflight_gate_decision_ids(
        mut self,
        preflight_gate_decision_ids: HashMap<
            EntityId,
            VecDeque<Option<crate::store::GateDecisionId>>,
        >,
    ) -> Self {
        self.preflight_gate_decision_ids = preflight_gate_decision_ids;
        self
    }
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

/// Applies a list of batch operations to an LMDB write transaction.
#[expect(
    clippy::too_many_arguments,
    reason = "batch write plumbing keeps gate persistence modes explicit at call sites"
)]
pub(crate) fn apply_ops(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    record_gate_decisions: bool,
    persist_gate_pending_consent: bool,
) -> Result<()> {
    apply_ops_with_gate_mode(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        text_index_trusted,
        ApplyOpsGateMode::new(record_gate_decisions, persist_gate_pending_consent),
    )
}

/// Why a base write transaction is allowed to touch the ids it touches
/// (ARCH-0052 D2, ONE-1728 K4). Exactly two arms:
///
/// * [`Self::Ordinary`] — every ordinary base write. An op referencing a live
///   session overlay's member is rejected at the decode point.
/// * [`Self::PromoteReplay`] — the promote transaction replaying one session's
///   own closure into base (ONE-1730). It exempts ONLY the ids of the session
///   whose promote this transaction is; every other live session's ids still
///   reject.
///
/// The exemption set RIDES ON THE ORIGIN, as a borrowed
/// [`PromoteReplayGrant`]. That type's field and its only constructor are
/// private to `off_record::promote`, so the exempting arm cannot be built
/// anywhere else in the crate — the capability is the arm, not a predicate a
/// caller supplies alongside it. There is no `Fn` channel to hand-roll and no
/// test-mintable capability anywhere in this design.
#[derive(Clone, Copy)]
pub(crate) enum BaseWriteOrigin<'grant> {
    Ordinary,
    PromoteReplay(&'grant PromoteReplayGrant),
}

impl BaseWriteOrigin<'_> {
    /// Whether this write origin exempts `id` from live-overlay membership
    /// rejection. Both doors that judge membership — the K4 decode-point taint
    /// guard over an op's REFERENCES and
    /// [`reject_overlay_member_base_write`] over the id it MATERIALIZES — ask
    /// exactly this, so an id is exempt at both or at neither.
    pub(crate) fn exempts(self, id: &EntityId) -> bool {
        match self {
            Self::Ordinary => false,
            Self::PromoteReplay(grant) => grant.exempts(id),
        }
    }
}

/// The K4 taint guard, run at the decode point of ONE op inside the applying
/// write transaction (ARCH-0052 D2, ONE-1728).
///
/// **Enumeration IS the decode point.** The overlay-id-bearing op list is not a
/// separate table that could drift: it is this function's own exhaustive match
/// over [`BatchOp`], so a new id-bearing variant fails to compile until it names
/// its refs here. Raw base CLAIM puts hide their subject/world refs inside an
/// opaque body, so they decode through the same landed decoder their apply path
/// uses ([`crate::claim::validate_claim_body_and_decode`]) and an undecodable
/// body fails closed.
///
/// Membership is read from live registry state INSIDE the transaction, at the
/// moment the op is decoded — there is no preflight pass and no membership-epoch
/// publication protocol to keep in sync. The state read here is the state this
/// transaction applies against, which removes the TOCTOU class rather than
/// racing it.
/// The K4 verdict for ONE id: a base row may not be written AT an id that is a
/// live session-overlay member.
///
/// ONE-1731 folded the old off-record entity-put door into this preflight
/// family. That door judged live-overlay membership AND a durable per-entity
/// row; only the first half was ever the taint guard, and the second half went
/// away with the durable state it read. What is left is the same live registry
/// read [`check_decode_point_taint_guard`] makes about an op's REFERENCES,
/// applied to the id the op materializes — so both halves of "this write must
/// not touch a live room" answer with one predicate and one typed error.
pub(crate) fn reject_overlay_member_base_write(
    store: &Store,
    id: &EntityId,
    origin: BaseWriteOrigin<'_>,
) -> Result<()> {
    if store.off_record_sessions.contains_entity(id)? && !origin.exempts(id) {
        return Err(Error::OffRecordTaintedBaseWrite {
            entity_ref: id.to_hex(),
        });
    }
    Ok(())
}

pub(super) fn check_decode_point_taint_guard(
    store: &Store,
    op: &BatchOp,
    origin: BaseWriteOrigin<'_>,
) -> Result<()> {
    // Decode-point membership probe. With zero live overlay entities no id in
    // this op can be a member, so the guard is a no-op and a raw CLAIM body is
    // never decoded twice on the canonical path. This is the same live read the
    // per-id checks below make — read here, inside the applying transaction, at
    // the decode point — not a hoisted preflight: it answers "could any id be
    // tainted right now", and the transaction applies against exactly this
    // state.
    if !store.off_record_sessions.has_overlay_entities()? {
        return Ok(());
    }
    let tainted = |id: &EntityId| Error::OffRecordTaintedBaseWrite {
        entity_ref: id.to_hex(),
    };
    let check = |id: &EntityId| -> Result<()> {
        if !store.off_record_sessions.contains_entity(id)? {
            return Ok(());
        }
        // `PromoteReplay` exempts ONLY the session whose promote this
        // transaction is: its grant is minted inside that promote transaction
        // out of the closure being replayed, so it has no way to answer `true`
        // for another live session's ids — and `Ordinary` carries no grant at
        // all.
        if origin.exempts(id) {
            return Ok(());
        }
        Err(tainted(id))
    };

    match op {
        BatchOp::Put {
            id,
            entity_type,
            data,
            allow_reserved_predicate,
            ..
        } => {
            // The MATERIALIZED id is deliberately not judged here: it reaches
            // `reject_overlay_member_base_write` inside `apply_put`, the landed
            // entity-materialization chokepoint, which is the WIDER door —
            // sync replay reaches `apply_put` without passing through this
            // decode-point pass at all. Both raise the same
            // `OffRecordTaintedBaseWrite`, which `sync/window.rs` and
            // `sync/quarantine.rs` classify to quarantine-and-continue a
            // replicated window. K4 owns the refs the entity door structurally
            // cannot see — the ones below, which materialize nothing and so
            // never reach it.
            if *entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                let Ok(body) =
                    crate::claim::validate_claim_body_and_decode(data, *allow_reserved_predicate)
                else {
                    // Undecodable body: its refs cannot be enumerated, so
                    // membership cannot be disproved. FAIL CLOSED with the
                    // taint error rather than letting an opaque body through to
                    // be judged later. (`apply_put` would reject it too, with
                    // `InvalidClaimBody`; reaching that verdict would mean
                    // deciding an undecodable body is untainted, which is the
                    // open-by-default shape the guard exists to forbid.)
                    return Err(tainted(id));
                };
                check_claim_body_refs(&body, &check)?;
            }
        }
        BatchOp::ClaimCandidate {
            candidate,
            envelope,
            ..
        } => {
            // The candidate's own `id` materializes through `apply_put` and is
            // judged by the entity door there, for the reason above. Its
            // world/subject/actor refs do not materialize, so they are K4's.
            if let Some(world) = candidate.world() {
                check(&world)?;
            }
            check_claim_subject_refs(candidate.subject(), &check)?;
            check(&envelope.actor().entity_ref())?;
        }
        BatchOp::ReconcileLexicalQueryHints { source, keep } => {
            check(source)?;
            for id in keep {
                check(id)?;
            }
        }
        BatchOp::Vector { id, .. }
        | BatchOp::Text { id, .. }
        | BatchOp::Phonetic { id, .. }
        | BatchOp::Delete { id } => check(id)?,
        BatchOp::CommitmentGapDecay { ids, envelope, .. } => {
            // Each id MATERIALIZES its own rewritten claim row and so also
            // reaches the wider entity door inside `apply_put`; the envelope's
            // actor materializes nothing, which makes it K4's.
            for id in ids {
                check(id)?;
            }
            check(&envelope.actor().entity_ref())?;
        }
        BatchOp::Edge { src, tgt, .. }
        | BatchOp::PublicEdgeWithCreatedAt { src, tgt, .. }
        | BatchOp::EdgeWithCreatedAt { src, tgt, .. }
        | BatchOp::SetEdgeWeight { src, tgt, .. }
        | BatchOp::SetEdgeVad { src, tgt, .. }
        | BatchOp::DeleteEdge { src, tgt, .. } => {
            check(src)?;
            check(tgt)?;
        }
    }
    Ok(())
}

/// Entity refs a decoded CLAIM body carries: its subject and its world scope.
pub(super) fn check_claim_body_refs(
    body: &crate::claim::ClaimBody,
    check: &impl Fn(&EntityId) -> Result<()>,
) -> Result<()> {
    check_claim_subject_refs(body.subject, check)?;
    if let Some(world) = body.world {
        check(&world)?;
    }
    Ok(())
}

/// Entity refs a [`crate::claim::ClaimSubject`] carries: the entity itself, or
/// BOTH endpoints of an edge subject.
pub(super) fn check_claim_subject_refs(
    subject: crate::claim::ClaimSubject,
    check: &impl Fn(&EntityId) -> Result<()>,
) -> Result<()> {
    match subject {
        crate::claim::ClaimSubject::Entity(id) => check(&id),
        crate::claim::ClaimSubject::Edge { source, target, .. } => {
            check(&source)?;
            check(&target)
        }
    }
}

/// Applies a batch under [`BaseWriteOrigin::Ordinary`] — the shape every
/// existing caller uses, unchanged.
pub(crate) fn apply_ops_with_gate_mode(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
) -> Result<()> {
    apply_ops_with_origin(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        text_index_trusted,
        gate_mode,
        BaseWriteOrigin::Ordinary,
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
pub(crate) fn apply_ops_with_origin(
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
    let mut preflight_gate_decision_ids = gate_mode.preflight_gate_decision_ids;

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
                    None,
                    false,
                    record_gate_decisions,
                    persist_gate_pending_consent,
                    pending_gate_consent_at_batch_start.contains(&id),
                    include_source_in_gate_input,
                    claim_gate_prechecked,
                    if entity_type == crate::registry::ENTITY_TYPE_CLAIM
                        && !allow_reserved_predicate
                    {
                        preflight_gate_decision_ids
                            .get_mut(&id)
                            .and_then(VecDeque::pop_front)
                            .flatten()
                    } else {
                        None
                    },
                    Some(&companion_retired_histories),
                    origin,
                )?;
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
                    if !internal_lexical_query_hint {
                        preflight_gate_decision_ids
                            .get_mut(&id)
                            .and_then(VecDeque::pop_front)
                            .flatten()
                    } else {
                        None
                    },
                )?;
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

/// The session apply entry (ONE-1728 K4/K11): stages one witness program into
/// the session overlay and NEVER enters the base apply.
///
/// # Why this is a sibling of `apply_ops_with_origin`, not a mode flag on it
///
/// The base apply's body is base-shaped in ways a session has no answer for:
/// it publishes gate decisions to the durable ledger, enqueues `pe:` embed
/// jobs, reconciles the identity-topology fold across the whole ledger, and
/// schedules legacy HNSW rebuilds off the base `vectors` DB. Threading a
/// target through it would put a live `if session { skip }` in front of each —
/// four chances for a later edit to leak a room into base. Here the leak is
/// structurally impossible instead: this function has no access to a `Store`,
/// so there is no base row it *could* write.
///
/// What it shares with base is exactly what must not drift — the row STAGING
/// (`stage_entity_body_row`, `stage_entity_index_rows`, `stage_edge_rows`,
/// `stage_vector_row`, `index_text`, `hnsw_insert_batched`) — reached through
/// the same [`ManifestDbs`](crate::store::ManifestDbs) accessors base uses.
/// That is what makes promote a replay of bytes rather than a re-derivation of
/// them.
///
/// # What the session path deliberately does NOT do
///
/// * **No `pe:` markers or embed jobs** (K6): session content embeds inline at
///   witness time or has no vectors until promote. No overlay `pe:` keyspace
///   exists, so this is skip, not redirect.
/// * **No base entity door** (`reject_overlay_member_base_write`): that door
///   REJECTS live-overlay membership, so running it here would refuse the
///   room's own witness writes. The separation is structural — the session
///   path never enters the base apply — not an added exemption.
/// * **No graph/vector version bump**: those counters gate the BASE PPR and
///   HNSW caches. A room's writes must not invalidate the base's caches, and
///   the session's own reads compose over the snapshot, not the cache.
/// * **No legacy HNSW rebuild**: `hnsw_insert_batched` takes `&impl
///   ManifestDbs` while the rebuild arm takes `&Store`, so a session target
///   cannot reach a rebuild — it does not typecheck.
///
/// Every op is journaled with its [`JournalRole`] and the witnessing write's
/// own `occurred`/`learned_at`, because the typed journal is promote's ONLY
/// legal closure source (ARCH-0052 D4); ownership must never be inferable from
/// index keys.
///
/// [`JournalRole`]: crate::session_overlay::JournalRole
/// # The op list IS the journal
///
/// This entry takes [`JournalEntry`] values, not bare [`BatchOp`]s: staging a
/// row and journaling it are one act, so an op cannot reach the overlay
/// without its role tag and preserved timestamps. A `Vec<BatchOp>` parameter
/// would have made "tag every op" a discipline someone can forget; this makes
/// it a thing you cannot express.
pub(crate) fn apply_ops_session(
    view: &crate::store::SessionStoreView<'_>,
    route: &SessionWriteRoute,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    entries: Vec<JournalEntry>,
) -> Result<()> {
    // A route minted before the most recent mode publication names a mode
    // epoch that no longer authorizes overlay writes. Refuse BEFORE staging a
    // byte, so a flip landing mid-call cannot leave half a turn in a room the
    // caller no longer believes it is in. `batch.rs` never reads route fields;
    // the route revalidates itself.
    route.revalidate()?;
    if route.target() != RouteTarget::Overlay {
        return Err(Error::InvariantViolation(
            "session apply needs an Overlay route; a Base route witnesses through the ordinary apply",
        ));
    }
    let overlay = route.overlay();

    for entry in entries {
        match &entry.op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                allow_reserved_predicate,
                ..
            } => {
                // Same registry discipline as base: a room is not a place
                // where unknown or engine-authored type bytes become writable.
                // Promote replays these rows into base, so a byte that would
                // be rejected there is rejected here.
                crate::registry::validate_public_entity_type(*entity_type)?;
                // D18, on the same terms: a CLAIM body is structurally
                // validated before a byte of it is staged. The type-byte gate
                // above is not enough — it admits the byte, not the shape.
                //
                // The op's OWN `allow_reserved_predicate` is what promote will
                // replay this body under (`apply_put` reads the same field off
                // the same op), so validating under it makes in-room admission
                // byte-exactly promote's admission. Hardcoding `false` here
                // would instead refuse in-room a body promote would accept —
                // trading a claim that cannot land for one that cannot be
                // written, which is the same divergence facing the other way.
                if *entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                    crate::claim::validate_claim_body_and_decode(data, *allow_reserved_predicate)?;
                }
                if *entity_type == crate::registry::ENTITY_TYPE_MESSAGE {
                    // The overlay is a write target, not a weaker MESSAGE
                    // store. Keep the same canonical-body and stable-id
                    // immutability rules as base: exact executor retries are
                    // idempotent, while a same-id divergent retry is refused
                    // before any overlay mutation or journal entry stages.
                    crate::gate::validate_canonical_witness_message_body(data)?;
                    if let Some(raw) = view.entities.get(&*wtxn, id.as_bytes())? {
                        let header = EntityMetadataHeader::parse(&raw)
                            .ok_or(Error::CorruptedIndex("entity header"))?;
                        if header.entity_type != *entity_type {
                            return Err(Error::EntityTypeImmutable {
                                id: *id,
                                existing: header.entity_type,
                                attempted: *entity_type,
                            });
                        }
                        if &raw[ENTITY_METADATA_HEADER_LEN..] != data.as_slice() {
                            return Err(Error::InvalidWitnessMessageBody(
                                "an existing MESSAGE id is bound to its original canonical body",
                            ));
                        }
                    }
                }
                // The ENTRY's stamps, not the op's: they are the witnessing
                // write's own and are what promote replays into the right
                // month window (ARCH-0052 D4).
                stage_entity_body_row(
                    view,
                    wtxn,
                    id,
                    *entity_type,
                    entry.occurred,
                    entry.learned_at,
                    data,
                )?;
                stage_entity_index_rows(
                    view,
                    wtxn,
                    id,
                    *entity_type,
                    entry.occurred,
                    entry.learned_at,
                )?;
            }
            BatchOp::Edge {
                src,
                kind,
                tgt,
                weight,
                vad,
            } => {
                validate_edge_weight(*weight)?;
                if let Some((component, value)) = vad.invalid_component() {
                    return Err(Error::InvalidVad { component, value });
                }
                // `created_at` is the witness's `learned_at`, never
                // `unix_seconds_now()` — a promoted edge must carry the time
                // the turn happened, not the time it was promoted.
                let value = encode_edge_value(*kind, *weight, entry.learned_at, *vad, None)?;
                stage_edge_rows(view, wtxn, src, *kind, tgt, &value)?;
            }
            BatchOp::Text { id, fields } => {
                crate::bm25::index_text(view, wtxn, analyzer, id, fields)?;
            }
            BatchOp::Vector { id, vector, .. } => {
                stage_vector_row(view, config, wtxn, id, vector)?;
                // `pending_rebuild` can only come back false: the legacy arm
                // that would set it needs a base `&Store` this call does not
                // have. Passing a local sink states that and keeps the shared
                // staging body byte-identical with base.
                let mut pending_rebuild = false;
                crate::hnsw::hnsw_insert_batched(
                    view,
                    config,
                    wtxn,
                    id,
                    vector,
                    &mut pending_rebuild,
                )?;
                debug_assert!(
                    !pending_rebuild,
                    "a session target cannot schedule a base graph rebuild"
                );
            }
            _ => {
                return Err(Error::InvariantViolation(
                    "session witness stages only put, edge, text, and vector ops",
                ));
            }
        }
        overlay.stage_journal_entry(entry)?;
    }
    Ok(())
}

pub(super) fn contains_text_op(ops: &[BatchOp]) -> bool {
    ops.iter().any(|op| match op {
        BatchOp::Text { .. } => true,
        BatchOp::Put {
            id,
            entity_type,
            data,
            allow_maintenance,
            allow_reserved_predicate,
            ..
        } => {
            *entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && *allow_maintenance
                && *allow_reserved_predicate
                && id
                    .as_bytes()
                    .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
                && crate::claim::decode_claim_body(data, true)
                    .ok()
                    .is_some_and(|body| {
                        body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT
                    })
        }
        _ => false,
    })
}

pub(super) fn contains_local_claim_put(ops: &[BatchOp]) -> bool {
    ops.iter().any(|op| {
        matches!(op, BatchOp::ClaimCandidate { .. })
            // CMT-4 (ONE-1541): a gap-decay lapse rewrites a local
            // `commitment.record` CLAIM, so the policy snapshot must be
            // resolved before the write transaction reaches the arm.
            || matches!(op, BatchOp::CommitmentGapDecay { .. })
            || matches!(
                op,
                BatchOp::Put {
                    entity_type,
                    allow_maintenance,
                    allow_reserved_predicate,
                    ..
                } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
                    && !(*allow_maintenance && *allow_reserved_predicate)
            )
    })
}

pub(super) fn companion_retired_histories_in_batch(
    ops: &[BatchOp],
) -> Result<CompanionRetiredHistoryOverlay> {
    let mut histories = CompanionRetiredHistoryOverlay::new();
    for op in ops {
        let BatchOp::Put {
            entity_type, data, ..
        } = op
        else {
            continue;
        };
        if *entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            continue;
        }
        let record = decode_companion_record_body(data)?;
        record.validate_current_schema_lifecycle_events()?;
        if record.lifecycle == ClaimLifecycleStatus::Retracted {
            histories.insert((record.key(), record.lifecycle_events));
        }
    }
    Ok(histories)
}

pub(super) fn pending_gate_consent_ids_at_batch_start(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    ops: &[BatchOp],
) -> Result<HashSet<EntityId>> {
    let mut pending = HashSet::new();
    for op in ops {
        let Some(id) = local_claim_op_id(op) else {
            continue;
        };
        if store.pending_gate_consent_in_txn(txn, &id)?.is_some() {
            pending.insert(id);
        }
    }
    Ok(pending)
}

pub(super) fn local_claim_op_id(op: &BatchOp) -> Option<EntityId> {
    match op {
        BatchOp::ClaimCandidate {
            id,
            internal_lexical_query_hint,
            ..
        } if !*internal_lexical_query_hint => Some(*id),
        BatchOp::Put {
            id,
            entity_type,
            allow_maintenance,
            allow_reserved_predicate,
            ..
        } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
            && !(*allow_maintenance && *allow_reserved_predicate) =>
        {
            Some(*id)
        }
        _ => None,
    }
}

pub(super) fn text_coverage_after_op(ops: &[BatchOp]) -> Vec<bool> {
    let mut text_ids_after = HashSet::new();
    let mut covered = vec![false; ops.len()];

    for (index, op) in ops.iter().enumerate().rev() {
        match op {
            BatchOp::Put { id, .. } | BatchOp::ClaimCandidate { id, .. } => {
                covered[index] = text_ids_after.contains(id);
            }
            BatchOp::Text { id, .. } => {
                text_ids_after.insert(*id);
            }
            _ => {}
        }
    }

    covered
}
