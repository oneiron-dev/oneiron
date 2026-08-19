use super::*;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use heed::RwTxn;

use crate::edge::{EdgeKind, encode_edge_value, parse_strict_edge_record};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::habit::TaskRole;
use crate::limits::{ERR_CHILD_OF_CYCLE_CHECK, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS};
use crate::registry::ENTITY_TYPE_TASK;
use crate::store::Store;
use crate::temporal::TimeRange;

#[derive(Debug, Default)]
pub(super) struct ChildOfBatchOverlay {
    entity_clears: HashMap<EntityId, usize>,
    entity_puts: HashMap<EntityId, BatchEntityPut>,
    edge_ops: HashMap<(EntityId, EntityId), (usize, bool)>,
    edge_candidates: HashMap<EntityId, HashSet<EntityId>>,
}

impl ChildOfBatchOverlay {
    pub(super) fn from_ops(ops: &[BatchOp]) -> Self {
        let mut overlay = Self::default();

        for (index, op) in ops.iter().enumerate() {
            match op {
                BatchOp::Edge { src, kind, tgt, .. }
                | BatchOp::PublicEdgeWithCreatedAt { src, kind, tgt, .. }
                | BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. }
                    if *kind == EdgeKind::ChildOf =>
                {
                    overlay.edge_ops.insert((*src, *tgt), (index, true));
                    overlay
                        .edge_candidates
                        .entry(*src)
                        .or_default()
                        .insert(*tgt);
                }
                BatchOp::DeleteEdge { src, kind, tgt } if *kind == EdgeKind::ChildOf => {
                    overlay.edge_ops.insert((*src, *tgt), (index, false));
                    overlay
                        .edge_candidates
                        .entry(*src)
                        .or_default()
                        .insert(*tgt);
                }
                BatchOp::Delete { id } => {
                    overlay.entity_clears.insert(*id, index);
                }
                BatchOp::Put {
                    id,
                    entity_type,
                    data,
                    ..
                } => {
                    overlay.entity_puts.insert(
                        *id,
                        BatchEntityPut {
                            seq: index,
                            entity_type: *entity_type,
                            task_body: (*entity_type == ENTITY_TYPE_TASK).then(|| data.clone()),
                        },
                    );
                }
                _ => {}
            }
        }

        overlay
    }

    fn final_edge_override(&self, child: &EntityId, parent: &EntityId) -> Option<bool> {
        let clear_seq = self
            .entity_clears
            .get(child)
            .copied()
            .into_iter()
            .chain(self.entity_clears.get(parent).copied())
            .max();
        let edge_seq = self.edge_ops.get(&(*child, *parent)).copied();

        match (clear_seq, edge_seq) {
            (Some(clear_seq), Some((op_seq, present))) if op_seq > clear_seq => Some(present),
            (Some(_), _) => Some(false),
            (None, Some((_, present))) => Some(present),
            (None, None) => None,
        }
    }

    fn effective_parents(
        &self,
        store: &Store,
        rtxn: &heed::RoTxn<'_>,
        child: &EntityId,
    ) -> Result<HashSet<EntityId>> {
        let mut parents = HashSet::new();
        let prefix = child_of_prefix(child);

        for entry in store.edges_out.prefix_iter(rtxn, &prefix)? {
            let (key, value) = entry?;
            let parent = parse_strict_edge_record(&key, &value)?.target;

            if self.final_edge_override(child, &parent).unwrap_or(true) {
                parents.insert(parent);
            }
        }

        if let Some(candidates) = self.edge_candidates.get(child) {
            for parent in candidates {
                if self.final_edge_override(child, parent) == Some(true) {
                    parents.insert(*parent);
                }
            }
        }

        Ok(parents)
    }

    /// Every child whose `ChildOf` pair this batch can invalidate.
    ///
    /// An edge op is only the most VISIBLE way a pair changes: a TASK put
    /// re-judges its pair from BOTH endpoints while naming no edge at all —
    /// the put's own parent (child side) and every child already linked to it
    /// (parent side). Triggering on edge ops alone would let a `Milestone`
    /// flip to `Task` under its `Goal` parent and persist a pair the matrix
    /// forbids.
    ///
    /// Only TASK puts widen the set. `EntityTypeImmutable` pins a stored
    /// row's type byte, so no other put can move an endpoint into or out of
    /// the productivity matrix, and a non-TASK domain is never dragged onto
    /// this scan.
    ///
    /// Ordered, so a batch carrying several violations reports a stable one.
    fn children_to_validate(
        &self,
        store: &Store,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<BTreeSet<EntityId>> {
        let mut children: BTreeSet<EntityId> = self.edge_candidates.keys().copied().collect();
        for (id, put) in &self.entity_puts {
            if put.task_body.is_none() {
                continue;
            }
            children.insert(*id);
            for entry in store.edges_in.prefix_iter(rtxn, &child_of_prefix(id))? {
                let (key, value) = entry?;
                children.insert(parse_strict_edge_record(&key, &value)?.target);
            }
        }
        Ok(children)
    }

    /// Every parent named by a `ChildOf` add or delete in this batch.
    fn child_of_edge_parents(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.edge_ops.keys().map(|(_, parent)| *parent)
    }
}

/// One contender for a child's single `ChildOf` parent slot during
/// replicated-batch normalization (ONE-1871 / F5).
#[derive(Debug, Clone, Copy)]
pub(super) struct ChildOfCandidate {
    parent: EntityId,
    /// The LINK's learned-at clock. `ChildOf` is structural, so its 12 B value
    /// is `weight + created_at` (ARCH-0034) — the persisted `created_at` IS
    /// the clock. No layout change, no versioned `parentId` body field.
    learned_at: u64,
    origin: ChildOfCandidateOrigin,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ChildOfCandidateOrigin {
    /// Already projected into `edges_out` — the local replica's current winner.
    Stored,
    /// Arriving in this batch, at that op index.
    Replicated { op_index: usize },
}

impl ChildOfCandidate {
    /// Deterministic precedence, maximum wins: greater `learned_at` first,
    /// ties broken on the PARENT target's `EntityId` bytes.
    ///
    /// The tiebreak is deliberately the parent id — never the shared child id
    /// (identical across candidates, so it decides nothing) and never arrival
    /// order (the very thing that made the projection replica-dependent).
    fn precedence_key(&self) -> (u64, [u8; ENTITY_ID_LEN]) {
        (self.learned_at, *self.parent.as_bytes())
    }
}

/// LWW-resolves the single `ChildOf` parent slot of every child a REPLICATED
/// batch reparents (ONE-1871, audit finding F5; ARCH-0016 **I6** "concurrent
/// reparent (CRDT) = LWW" — the ticket's I7 citation is off by one, I7 is
/// derived-state repair).
///
/// Two replicas that reparent the same child offline converge in the CRDT edge
/// map — both candidate links survive there — but the LMDB projection did not:
/// the already-STORED parent wins by being on disk, the incoming valid edge
/// hits `validate_child_of_batch` as a second parent, and quarantine-and-
/// continue (ONE-1124) leaves each replica holding the parent IT authored. The
/// repair belongs HERE, at the batch-validation entry, because this is the only
/// point where the stored winner and every incoming candidate are visible at
/// once — no ordering of the incoming ops alone can see the stored one.
///
/// Scope is pinned by the `BatchOp::EdgeWithCreatedAt` variant, which is the
/// replicated/replay shape: Observer B, forward rematerialization, and the
/// crate-internal `edge_with_value_fields` doors. Every PUBLIC timestamped
/// write is `BatchOp::PublicEdgeWithCreatedAt` and every untimestamped one is
/// `BatchOp::Edge`; nothing lowers public into the replicated variant
/// (`session_overlay::promotion_replay_op` rebuilds `Edge` as
/// `PublicEdgeWithCreatedAt` and REJECTS a journaled `EdgeWithCreatedAt`). A
/// child whose slot a public op also touches in the same batch is skipped
/// outright, so strict local cardinality can never be absorbed here even if a
/// future caller mixes the two shapes.
///
/// Only the deterministic LMDB projection moves. Losing candidates stay in the
/// CRDT edge map, are NOT quarantine records (they are valid remote ops that
/// simply lost), and cost zero LMDB writes when the stored parent wins. The
/// winner is left in the op vector to face the COMPLETE validator: dangling
/// parent, cycle (`CycleDetected` still quarantines — no auto-break), and TASK
/// role nesting all run against it.
pub(super) fn resolve_replicated_child_of_slots(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    ops: Vec<BatchOp>,
) -> Result<Vec<BatchOp>> {
    let mut children: Vec<EntityId> = Vec::new();
    for op in &ops {
        if let BatchOp::EdgeWithCreatedAt { src, kind, .. } = op
            && *kind == EdgeKind::ChildOf
            && !children.contains(src)
        {
            children.push(*src);
        }
    }
    if children.is_empty() {
        return Ok(ops);
    }

    let mut dropped: HashSet<usize> = HashSet::new();
    let mut injected: HashMap<usize, Vec<BatchOp>> = HashMap::new();

    for child in children {
        let mut candidates: Vec<ChildOfCandidate> = Vec::new();
        let mut deleted_in_batch: HashSet<EntityId> = HashSet::new();
        let mut public_touch = false;
        for (index, op) in ops.iter().enumerate() {
            match op {
                BatchOp::EdgeWithCreatedAt {
                    src,
                    kind,
                    tgt,
                    created_at,
                    ..
                } if *kind == EdgeKind::ChildOf && *src == child => {
                    candidates.push(ChildOfCandidate {
                        parent: *tgt,
                        learned_at: *created_at,
                        origin: ChildOfCandidateOrigin::Replicated { op_index: index },
                    });
                }
                BatchOp::Edge { src, kind, .. }
                | BatchOp::PublicEdgeWithCreatedAt { src, kind, .. }
                    if *kind == EdgeKind::ChildOf && *src == child =>
                {
                    public_touch = true;
                }
                BatchOp::DeleteEdge { src, kind, tgt }
                    if *kind == EdgeKind::ChildOf && *src == child =>
                {
                    deleted_in_batch.insert(*tgt);
                }
                _ => {}
            }
        }
        if public_touch {
            // A strict public write shares this slot: the public path judges
            // the whole batch, exactly as it does today.
            continue;
        }

        for entry in store
            .edges_out
            .prefix_iter(rtxn, &child_of_prefix(&child))?
        {
            let (key, value) = entry?;
            let record = parse_strict_edge_record(&key, &value)?;
            // A stored parent this batch already deletes is not a contender —
            // the reparent's own delete leg is not something to re-decide.
            if deleted_in_batch.contains(&record.target) {
                continue;
            }
            candidates.push(ChildOfCandidate {
                parent: record.target,
                learned_at: record.decoded.created_at,
                origin: ChildOfCandidateOrigin::Stored,
            });
        }

        let distinct: BTreeSet<EntityId> = candidates.iter().map(|c| c.parent).collect();
        if distinct.len() <= 1 {
            // No slot race: a re-delivery of the stored link, or the first
            // parent this child has ever had. Untouched.
            continue;
        }

        // This slot IS raced, so the op vector is about to be rewritten:
        // losers omitted, stored losers deleted. Both moves assume every
        // replicated candidate would actually APPLY. Prove that first, while
        // the rewrite is still hypothetical:
        //
        // * a malformed WINNER is otherwise rejected only by
        //   `apply_edge_with_created_at`, AFTER its injected stored-loser
        //   `DeleteEdge` has staged. `InvalidEdgeWeight`/`InvalidVad` are
        //   quarantine-and-CONTINUE kinds, so the sync path keeps the same
        //   `RwTxn` — and commits the reparent's demolition without its
        //   construction: a ZERO-parent slot.
        // * a malformed LOSER is otherwise omitted as if it were a valid
        //   outranked candidate — the one path on which a remote op fails no
        //   gate because it reaches none. Invalid remote ops stay
        //   quarantine-eligible; only VALID losers are silent.
        //
        // Raising the typed error HERE stages nothing, which is what the sync
        // caller already assumes of an up-front gate: the component retries
        // per-op (ONE-1124) and quarantines the one malformed op alone.
        //
        // The probe is `encode_edge_value` — the very function the apply path
        // runs — so the two cannot drift.
        for candidate in &candidates {
            let ChildOfCandidateOrigin::Replicated { op_index } = candidate.origin else {
                continue;
            };
            let Some(BatchOp::EdgeWithCreatedAt {
                weight,
                created_at,
                vad,
                provenance,
                ..
            }) = ops.get(op_index)
            else {
                return Err(Error::InvariantViolation(
                    "ChildOf candidate does not index a replicated edge op",
                ));
            };
            encode_edge_value(EdgeKind::ChildOf, *weight, *created_at, *vad, *provenance)?;
        }

        let winner = candidates
            .iter()
            .max_by_key(|candidate| candidate.precedence_key())
            .copied()
            .ok_or(Error::InvariantViolation(
                "ChildOf slot resolution ran with no candidates",
            ))?;

        // Every ChildOf op of this child sits at or after this index, so the
        // injected loser deletes precede the winning add.
        let anchor = candidates
            .iter()
            .filter_map(|candidate| match candidate.origin {
                ChildOfCandidateOrigin::Replicated { op_index } => Some(op_index),
                ChildOfCandidateOrigin::Stored => None,
            })
            .min()
            .ok_or(Error::InvariantViolation(
                "ChildOf slot resolution ran without a replicated add",
            ))?;

        for candidate in &candidates {
            if candidate.parent == winner.parent {
                continue;
            }
            match candidate.origin {
                // An incoming loser is omitted: valid, outranked, no LMDB write
                // and no quarantine row.
                ChildOfCandidateOrigin::Replicated { op_index } => {
                    dropped.insert(op_index);
                }
                // A stored loser is deleted in the SAME strict batch as the
                // winning add, so cardinality is one before any bytes stage.
                ChildOfCandidateOrigin::Stored => {
                    injected
                        .entry(anchor)
                        .or_default()
                        .push(BatchOp::DeleteEdge {
                            src: child,
                            kind: EdgeKind::ChildOf,
                            tgt: candidate.parent,
                        });
                }
            }
        }
    }

    if dropped.is_empty() && injected.is_empty() {
        return Ok(ops);
    }

    let mut normalized = Vec::with_capacity(ops.len());
    for (index, op) in ops.into_iter().enumerate() {
        if let Some(deletes) = injected.remove(&index) {
            normalized.extend(deletes);
        }
        if dropped.contains(&index) {
            continue;
        }
        normalized.push(op);
    }
    Ok(normalized)
}

/// The `ChildOf` tree gate, run once over the batch's FINAL state (STO-04).
///
/// The check ORDER is load-bearing and pinned:
/// 1. final single-parent cardinality;
/// 2. no-parent early success — a root has no nesting relation to validate,
///    so a root TASK of ANY role stays legal;
/// 3. parent existence in final state;
/// 4. self/ancestor cycle — BEFORE the role matrix, so a cycle-forming link
///    still reports `CycleDetected` instead of being masked by a role error;
/// 5. TASK role nesting, last.
///
/// Steps 1, 3, and 4 are domain-agnostic: every `ChildOf` user (code
/// revisions, sessions, …) keeps cardinality and cycle protection and now
/// also rejects a dangling parent. Only step 5 is productivity-specific, and
/// it engages solely when the edge SOURCE is a TASK.
///
/// This is the ONLY `ChildOf` tree gate. It runs once, before any op applies,
/// so no per-op door can judge a pair against half-applied state — a parent
/// put later in the same batch is a live parent here, and a role flip that
/// names no edge is still judged (see `children_to_validate`).
pub(super) fn validate_child_of_batch(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    child_of_overlay: &ChildOfBatchOverlay,
) -> Result<()> {
    for child in child_of_overlay.children_to_validate(store, rtxn)? {
        let parents = child_of_overlay.effective_parents(store, rtxn, &child)?;
        if parents.len() > 1 {
            // Typed (not InvariantViolation) so the sync replay classifier
            // can treat a remote ChildOf cardinality violation as a
            // quarantine-and-continue rejection instead of aborting the
            // whole materialization batch (ONE-1124).
            return Err(Error::ChildOfCardinality);
        }
        let Some(parent) = parents.iter().next() else {
            continue;
        };
        let parent_entity = effective_entity_after_batch(store, rtxn, child_of_overlay, parent)?;
        if parent_entity == EffectiveEntity::Missing {
            return Err(Error::ChildOfParentMissing { parent: *parent });
        }
        if child == *parent {
            return Err(Error::CycleDetected);
        }
        if would_create_child_of_cycle(store, rtxn, child_of_overlay, &child, parent)? {
            return Err(Error::CycleDetected);
        }
        if let EffectiveEntity::Task(child_role) =
            effective_entity_after_batch(store, rtxn, child_of_overlay, &child)?
        {
            validate_task_nesting(child_role, parent_entity)?;
        }
    }

    Ok(())
}

/// The productivity nesting matrix, applied to one already-resolved pair.
///
/// Reached only when the `ChildOf` SOURCE is a TASK: a `code_revision`
/// session tree or any other domain's `ChildOf` never lands here, and is
/// never decoded as a `TaskRole`.
pub(super) fn validate_task_nesting(child_role: TaskRole, parent: EffectiveEntity) -> Result<()> {
    match parent {
        EffectiveEntity::Task(parent_role) if parent_role.allows_child(child_role) => Ok(()),
        EffectiveEntity::Task(parent_role) => Err(Error::TaskChildOfNesting {
            parent_role: parent_role.role_byte(),
            child_role: child_role.role_byte(),
        }),
        EffectiveEntity::NonTask(parent_entity_type) => Err(Error::TaskChildOfParentNotTask {
            child_role: child_role.role_byte(),
            parent_entity_type,
        }),
        // Unreachable: the caller rejects a missing parent before the matrix.
        EffectiveEntity::Missing => Ok(()),
    }
}

/// One entity's state AFTER the batch — puts and deletes settled by op order,
/// falling through to LMDB for an entity the batch never names.
pub(super) fn effective_entity_after_batch(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    child_of_overlay: &ChildOfBatchOverlay,
    id: &EntityId,
) -> Result<EffectiveEntity> {
    let put = child_of_overlay.entity_puts.get(id);
    if child_of_overlay
        .entity_clears
        .get(id)
        .is_some_and(|clear_seq| put.is_none_or(|put| *clear_seq > put.seq))
    {
        return Ok(EffectiveEntity::Missing);
    }
    let Some(put) = put else {
        return stored_entity(store, rtxn, id);
    };
    let Some(body) = put.task_body.as_deref() else {
        return Ok(EffectiveEntity::NonTask(put.entity_type));
    };
    crate::habit::task_role_from_body_bytes(body).map(EffectiveEntity::Task)
}

/// One entity's CURRENTLY STORED state, before any of this batch's ops.
pub(super) fn stored_entity(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<EffectiveEntity> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(EffectiveEntity::Missing);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(EffectiveEntity::NonTask(header.entity_type));
    }
    crate::habit::task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map(EffectiveEntity::Task)
}

pub(super) fn stored_task_role(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<TaskRole>> {
    match stored_entity(store, rtxn, id)? {
        EffectiveEntity::Task(role) => Ok(Some(role)),
        EffectiveEntity::Missing | EffectiveEntity::NonTask(_) => Ok(None),
    }
}

/// Entities whose derived Habit counters this batch can invalidate.
///
/// Four families, all necessary — an edge op is only the most VISIBLE way a
/// check-in set moves:
/// * every parent named by an explicit `ChildOf` add or delete;
/// * every TASK put — the Habit BODY moved. This is what keeps the counters
///   derived rather than transmitted: a replicated Habit envelope arrives
///   carrying the peer's counters and a local body edit (a rename) carries
///   none at all, and the tail pass overwrites both from the local child set;
/// * every parent an ENTITY DELETE will orphan. `delete_related_edges` tears
///   the row's `ChildOf` edges down without a `DeleteEdge` op, so a check-in
///   deleted through the public batch door leaves no edge op to notice;
/// * every parent already linked to a TASK being put. The edge may PRE-EXIST
///   the child (the parent-role validator admits an edge whose child is not
///   yet a check-in), so the qualifying child set can change on a put that
///   names no edge at all.
///
/// The last two read the PRE-state, deliberately: an edge this batch removes
/// is unreachable at the tail, and over-collecting costs one idempotent
/// recompute while under-collecting strands a stale counter forever.
///
/// The role filter is deliberately NOT applied here: the stored role is read
/// at the tail, against the state the batch actually left behind.
pub(super) fn habit_streak_recompute_candidates(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    ops: &[BatchOp],
    child_of_overlay: &ChildOfBatchOverlay,
) -> Result<BTreeSet<EntityId>> {
    let mut candidates: BTreeSet<EntityId> = child_of_overlay.child_of_edge_parents().collect();
    for op in ops {
        let child = match op {
            BatchOp::Put {
                id, entity_type, ..
            } if *entity_type == ENTITY_TYPE_TASK => {
                candidates.insert(*id);
                id
            }
            BatchOp::Delete { id } => id,
            _ => continue,
        };
        for entry in store.edges_out.prefix_iter(rtxn, &child_of_prefix(child))? {
            let (key, value) = entry?;
            candidates.insert(parse_strict_edge_record(&key, &value)?.target);
        }
    }
    Ok(candidates)
}

pub(super) fn recompute_touched_habit_streaks_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    candidates: &BTreeSet<EntityId>,
) -> Result<()> {
    for habit_id in candidates {
        if stored_task_role(store, &*wtxn, habit_id)? == Some(TaskRole::Habit) {
            crate::habit::recompute_habit_streak_in_txn(store, wtxn, habit_id)?;
        }
    }
    Ok(())
}

pub(super) fn validate_task_checkin_immutable(
    old_record: &[u8],
    old_occurred: TimeRange,
    old_learned: u64,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
    body_changed: bool,
) -> Result<()> {
    let old_role =
        crate::habit::task_role_from_body_bytes(&old_record[ENTITY_METADATA_HEADER_LEN..])?;
    let new_role = crate::habit::task_role_from_body_bytes(data)?;
    if old_role != TaskRole::HabitCheckin && new_role != TaskRole::HabitCheckin {
        return Ok(());
    }
    if old_role == TaskRole::HabitCheckin
        && new_role == TaskRole::HabitCheckin
        && !body_changed
        && old_occurred == occurred
        && old_learned == learned_at
    {
        return Ok(());
    }
    Err(Error::InvalidTaskBody(
        "habit check-in records are immutable",
    ))
}

pub(super) fn would_create_child_of_cycle(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    child_of_overlay: &ChildOfBatchOverlay,
    child: &EntityId,
    proposed_parent: &EntityId,
) -> Result<bool> {
    let mut frontier = VecDeque::new();
    frontier.push_back(*proposed_parent);
    let mut visited = HashSet::new();
    visited.insert(*proposed_parent);
    let mut traversed_steps = 0usize;

    while let Some(node) = frontier.pop_front() {
        for parent in child_of_overlay.effective_parents(store, rtxn, &node)? {
            if traversed_steps >= MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS {
                return Err(Error::IndexOverflow(ERR_CHILD_OF_CYCLE_CHECK));
            }
            traversed_steps += 1;
            if parent == *child {
                return Ok(true);
            }
            if visited.insert(parent) {
                frontier.push_back(parent);
            }
        }
    }

    Ok(false)
}

pub(super) fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; 17] {
    let mut prefix = [0u8; 17];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = kind as u8;
    prefix
}

pub(crate) fn child_of_prefix(id: &EntityId) -> [u8; 17] {
    edge_kind_prefix(id, EdgeKind::ChildOf)
}
