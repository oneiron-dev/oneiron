//! ChildOf replay set, component ordering, and ordered edge-op application.

use std::collections::{HashMap, HashSet};

use loro::LoroMap;

use super::edges::{EdgeOpMeta, quarantine_edge_apply_failure};
use super::{format_edge_key, parse_edge_key};

use crate::batch::{self, BatchOp, child_of_prefix};
use crate::edge::{
    EdgeKind, decode_edge_value_for_kind, parse_strict_edge_record, parse_strict_edge_record_key,
};
use crate::entity_id::EntityId;
use crate::store::Store;
use crate::sync::loro_support::map_for_each_bytes;
use crate::sync::quarantine::remote_rejection_reason;
use crate::{Result, Vault};

/// HOLE-1871-F2 — the `ChildOf` presentation repair: the projection must follow
/// the LIVE candidate set, not the delta history.
///
/// `batch::resolve_replicated_child_of_slots` arbitrates over
/// {this batch's ops} ∪ {the row `edges_out` projects}. That is the complete,
/// CURRENT set only while the stored row is both live and unmoved. A delta can
/// break it two ways, and each has its own repair:
///
/// * **Stranding.** F5 deliberately leaves a losing candidate in the CRDT edge
///   map, and a loser leaves no LMDB trace — so the moment a delta REMOVES the
///   stored winner, the resolver is missing exactly the rows the projection
///   must now choose among. `A@100`+`B@90` land together (`A` projects), a
///   later delta drops `A` and adds `C@80`, and `C` projects while the live
///   maximum is `B`. Repair: re-present that child's remaining live candidates.
/// * **Displacement.** A delta can instead re-stamp the stored winner's own key
///   DOWNWARD — `A@100` → `A@80` — leaving the LMDB row holding a clock the map
///   no longer has anywhere. The resolver reads that ghost as a live `A@100`
///   and hands the slot back to `A`, over a `B@90` that now outranks it
///   (stranded in the map, or riding in this very delta). Re-presenting live
///   candidates cannot help: the ghost outranks them, which is the whole
///   defect. Repair: present the stale row's REMOVAL.
///   [`apply_materialized_edge_ops`] lands every `ChildOf` delete before any
///   `ChildOf` add, so the ghost is out of `edges_out` by the time the resolver
///   reads the row it must arbitrate against — and the winning add then writes
///   the row back, `A@80` included when `A` is still the maximum.
///
/// Either way, two replicas whose deltas were cut differently disagree on the
/// projection while agreeing on the edge map. Both repairs are presentation,
/// not arbitration: the bridge reads the map it already owns and hands the
/// resolver the full set it is already specified to judge. The resolver is
/// untouched.
///
/// Bounded, and silent on ordinary traffic:
/// * the only read is one `edges_out` prefix scan per child this delta
///   reparents — the same bounded scan the resolver makes on that child moments
///   later;
/// * a child whose stored row this delta leaves alone gets nothing presented at
///   all: while the stored winner keeps its clock it IS the maximum over the
///   live set, so an in-batch candidate that outranks it outranks every live
///   loser too;
/// * a re-stamp UPWARD is likewise nothing — a maximum that rises is still the
///   maximum;
/// * candidates the resolver can already see — named by this delta, or still
///   projected in `edges_out` — are never duplicated, which is what makes a
///   replay idempotent: the same live set re-resolves to the same winner.
///
/// Replayed entries are the map's own bytes under the map's own key, so they
/// run the delta loop's full gauntlet (decode, endpoint hydration, reserved
/// kinds, the `FacetOf` table, quarantine) exactly as the delivering delta did.
/// A value that no longer decodes as a `ChildOf` link is not a candidate and is
/// left where its own delta's verdict put it — replay never manufactures a
/// second judgement on an op this delta did not carry, and never reads a clock
/// off bytes the gauntlet would reject.
pub(super) fn replayed_child_of_candidates(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    edges_map: &LoroMap,
    delta: &loro::event::MapDelta<'_>,
) -> Result<Vec<(String, Option<loro::ValueOrContainer>)>> {
    // What this delta says about each child's `ChildOf` keys: every parent it
    // names, the ones it removes, and the clock it re-stamps a survivor to.
    let mut named = HashMap::<EntityId, HashSet<EntityId>>::new();
    let mut removed = HashMap::<EntityId, HashSet<EntityId>>::new();
    let mut restamped = HashMap::<(EntityId, EntityId), u64>::new();
    for (key, new_val) in &delta.updated {
        let Some((child, EdgeKind::ChildOf, parent)) = parse_edge_key(key.as_ref()) else {
            continue;
        };
        named.entry(child).or_default().insert(parent);
        match new_val {
            None => {
                removed.entry(child).or_default().insert(parent);
            }
            Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(buf))) => {
                if let Ok(decoded) = decode_edge_value_for_kind(EdgeKind::ChildOf, buf) {
                    restamped.insert((child, parent), decoded.created_at);
                }
            }
            // Not a `ChildOf` link at all: the delta loop quarantines it, and
            // an op no one can decode unseats nothing.
            Some(_) => {}
        }
    }
    if named.is_empty() {
        return Ok(Vec::new());
    }

    // Per named child: is the row `edges_out` projects still the value the map
    // holds? Only a child whose stored row this delta UNSEATS — by removing its
    // key or by lowering its clock — gets an entry at all.
    let mut displaced = Vec::<String>::new();
    let mut already_seen = HashMap::<EntityId, HashSet<EntityId>>::new();
    for (child, named_parents) in &named {
        let mut stored = HashSet::<EntityId>::new();
        let mut unseated = false;
        for entry in vault
            .store
            .edges_out
            .prefix_iter(rtxn, &child_of_prefix(child))?
        {
            let (row_key, row_value) = entry?;
            let (_, _, parent) = parse_strict_edge_record_key(&row_key)?;
            stored.insert(parent);
            if removed
                .get(child)
                .is_some_and(|parents| parents.contains(&parent))
            {
                unseated = true;
                continue;
            }
            let Some(restamped_at) = restamped.get(&(*child, parent)) else {
                continue;
            };
            // The stored CLOCK matters only for a key this delta re-stamps, so
            // only there is the row's VALUE decoded — and there the resolver is
            // about to decode the very same row, fail-closed, for the very same
            // reason. The removal path keeps its key-only read.
            if *restamped_at
                < parse_strict_edge_record(&row_key, &row_value)?
                    .decoded
                    .created_at
            {
                displaced.push(format_edge_key(child, EdgeKind::ChildOf, &parent));
                unseated = true;
            }
        }
        if !unseated {
            continue;
        }
        stored.extend(named_parents.iter().copied());
        already_seen.insert(*child, stored);
    }
    if already_seen.is_empty() {
        return Ok(Vec::new());
    }

    let mut keys = Vec::<String>::new();
    map_for_each_bytes(edges_map, |key, value| {
        let Some((child, EdgeKind::ChildOf, parent)) = parse_edge_key(key) else {
            return;
        };
        if already_seen
            .get(&child)
            .is_none_or(|seen| seen.contains(&parent))
            || decode_edge_value_for_kind(EdgeKind::ChildOf, value).is_err()
        {
            return;
        }
        keys.push(key.to_string());
    });
    // Neither walk has an order; the batch they feed must have one.
    displaced.sort_unstable();
    keys.sort_unstable();
    Ok(displaced
        .into_iter()
        .map(|key| (key, None))
        .chain(keys.into_iter().filter_map(|key| {
            let value = edges_map.get(&key)?;
            Some((key, Some(value)))
        }))
        .collect())
}

#[derive(Clone)]
pub(super) struct PendingChildOfOp {
    index: usize,
    src: EntityId,
    tgt: EntityId,
    op: BatchOp,
}

/// Applies materialized edge ops. A write-gate rejection quarantines the
/// rejected op (every op of a rejected ChildOf component) and continues;
/// a LOCAL failure propagates fail-closed.
pub(super) fn apply_materialized_edge_ops(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ops: Vec<BatchOp>,
    metas: &[EdgeOpMeta],
    window_key: &str,
) -> Result<()> {
    debug_assert_eq!(ops.len(), metas.len());
    let mut child_of_adds = Vec::<PendingChildOfOp>::new();
    let mut child_of_deletes = Vec::<PendingChildOfOp>::new();

    for (index, op) in ops.into_iter().enumerate() {
        // ARCH-0052 P6: no incident-edge membership walk here. A replicated
        // edge naming a live overlay member is refused by the K4 taint guard
        // inside the applying transaction and quarantined as
        // `OffRecordTaintedBaseWrite` on the ordinary rejection path, so a
        // second endpoint probe would only duplicate that verdict earlier.
        match &op {
            BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. }
            | BatchOp::Edge { src, kind, tgt, .. }
                if *kind == EdgeKind::ChildOf =>
            {
                child_of_adds.push(PendingChildOfOp {
                    index,
                    src: *src,
                    tgt: *tgt,
                    op,
                });
            }
            BatchOp::DeleteEdge { src, kind, tgt } if *kind == EdgeKind::ChildOf => {
                child_of_deletes.push(PendingChildOfOp {
                    index,
                    src: *src,
                    tgt: *tgt,
                    op,
                });
            }
            _ => {
                let apply_result = batch::apply_ops(
                    &vault.store,
                    &vault.config,
                    &vault.analyzer,
                    wtxn,
                    vec![op],
                    vault
                        .text_index_trusted
                        .load(std::sync::atomic::Ordering::Acquire),
                    false,
                    false,
                );
                match apply_result {
                    Err(e) if remote_rejection_reason(&e).is_none() => return Err(e),
                    Err(e) => {
                        quarantine_edge_apply_failure(vault, wtxn, window_key, &metas[index], &e)?;
                    }
                    Ok(()) => {}
                }
            }
        }
    }

    child_of_deletes.sort_by(cmp_pending_child_of_ops);
    for pending in child_of_deletes {
        let index = pending.index;
        let apply_result = batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![pending.op],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            false,
        );
        match apply_result {
            Err(e) if remote_rejection_reason(&e).is_none() => return Err(e),
            Err(e) => {
                quarantine_edge_apply_failure(vault, wtxn, window_key, &metas[index], &e)?;
            }
            Ok(()) => {}
        }
    }

    let mut components = child_of_components(&child_of_adds);
    components.sort_by(|left, right| {
        child_of_component_sort_key(left)
            .cmp(&child_of_component_sort_key(right))
            .then_with(|| left.len().cmp(&right.len()))
    });
    for component in components {
        let mut component_ops = component;
        component_ops.sort_by(cmp_pending_child_of_ops);
        let ops: Vec<BatchOp> = component_ops.iter().map(|entry| entry.op.clone()).collect();
        let apply_result = batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            ops,
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            false,
        );
        match apply_result {
            Err(e) if remote_rejection_reason(&e).is_none() => return Err(e),
            Err(_) => {
                // The component was rejected as a unit (a remote ChildOf cycle
                // or single-parent violation — both up-front validation gates,
                // nothing staged). Re-apply per-op in the same deterministic
                // order so only the ops that individually fail a gate are
                // quarantined — never falsely recording siblings that are valid
                // on their own.
                for pending in component_ops {
                    let apply_result = batch::apply_ops(
                        &vault.store,
                        &vault.config,
                        &vault.analyzer,
                        wtxn,
                        vec![pending.op],
                        vault
                            .text_index_trusted
                            .load(std::sync::atomic::Ordering::Acquire),
                        false,
                        false,
                    );
                    match apply_result {
                        Err(e) if remote_rejection_reason(&e).is_none() => return Err(e),
                        Err(e) => {
                            quarantine_edge_apply_failure(
                                vault,
                                wtxn,
                                window_key,
                                &metas[pending.index],
                                &e,
                            )?;
                        }
                        Ok(()) => {}
                    }
                }
            }
            Ok(()) => {}
        }
    }
    Ok(())
}

fn child_of_components(ops: &[PendingChildOfOp]) -> Vec<Vec<PendingChildOfOp>> {
    let mut adjacency = HashMap::<EntityId, HashSet<EntityId>>::new();
    for op in ops {
        adjacency.entry(op.src).or_default().insert(op.tgt);
        adjacency.entry(op.tgt).or_default().insert(op.src);
    }

    let mut components = Vec::new();
    let mut visited = HashSet::<EntityId>::new();
    let mut starts = adjacency.keys().copied().collect::<Vec<_>>();
    starts.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for start in starts {
        if !visited.insert(start) {
            continue;
        }

        let mut stack = vec![start];
        let mut nodes = HashSet::from([start]);
        while let Some(node) = stack.pop() {
            if let Some(neighbors) = adjacency.get(&node) {
                let mut sorted_neighbors = neighbors.iter().copied().collect::<Vec<_>>();
                sorted_neighbors.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                for neighbor in sorted_neighbors {
                    if visited.insert(neighbor) {
                        stack.push(neighbor);
                        nodes.insert(neighbor);
                    }
                }
            }
        }

        components.push(
            ops.iter()
                .filter(|op| nodes.contains(&op.src))
                .cloned()
                .collect(),
        );
    }

    components
}

fn pending_child_of_sort_key(op: &PendingChildOfOp) -> [u8; 33] {
    Store::encode_edge_key(&op.src, EdgeKind::ChildOf, &op.tgt)
}

fn cmp_pending_child_of_ops(
    left: &PendingChildOfOp,
    right: &PendingChildOfOp,
) -> std::cmp::Ordering {
    pending_child_of_sort_key(left)
        .cmp(&pending_child_of_sort_key(right))
        .then_with(|| left.index.cmp(&right.index))
}

fn child_of_component_sort_key(component: &[PendingChildOfOp]) -> [u8; 33] {
    component
        .iter()
        .map(pending_child_of_sort_key)
        .min()
        .expect("child-of component must be non-empty")
}
