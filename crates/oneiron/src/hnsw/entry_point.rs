//! Tarjan-SCC entry-point selection.

use std::collections::{HashMap, HashSet};

use crate::entity_id::EntityId;

pub(super) fn select_best_entry_point(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    suggested: Option<EntityId>,
) -> Option<EntityId> {
    select_best_entry_point_probed(neighbors_by_id, suggested, &mut 0)
}

/// Selects the rebuild entry point, counting unit operations into `ops`.
///
/// Reachability here is DIRECTED: `m_max_0` pruning makes neighbor lists
/// asymmetric, so undirected components are not equivalent. The previous
/// implementation ran one full BFS per candidate node (`O(V·(V+E))`); this
/// version is linear-class:
///
/// 1. Fast path: a single BFS from `suggested`. Fully reachable graphs (the
///    common case after a healthy rebuild) keep the cheap early-exit and the
///    suggested entry point.
/// 2. Otherwise: condense the graph into strongly connected components
///    (iterative Tarjan, `O(V+E)`) and pick from the source SCCs
///    (condensation in-degree zero). Every maximal-reach node lives in a
///    source SCC — a non-source SCC is reached from some predecessor SCC
///    whose forward closure is strictly larger (the condensation is acyclic,
///    so the predecessor's own nodes are not in the successor's closure) —
///    therefore comparing source closures suffices. Winner: the source SCC
///    whose forward closure covers the most nodes; ties break to the lowest
///    entity id among the tied sources' member nodes, preserving the
///    previous per-candidate scan's deterministic tie-break.
///
/// `ops` increments once per node visit and once per edge scan in every
/// phase, so tests can pin the complexity class.
pub(super) fn select_best_entry_point_probed(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    suggested: Option<EntityId>,
    ops: &mut u64,
) -> Option<EntityId> {
    let initial = suggested.or_else(|| neighbors_by_id.keys().copied().next())?;
    if reachable_from_entry_probed(neighbors_by_id, initial, ops).len() == neighbors_by_id.len() {
        return Some(initial);
    }

    let condensation = condense_sccs(neighbors_by_id, ops);
    best_source_scc_member(&condensation, ops)
}

/// Strongly-connected-component condensation of an in-memory rebuild graph.
struct SccCondensation {
    /// Member-node count per SCC.
    sizes: Vec<usize>,
    /// Lowest member entity id per SCC (deterministic tie-break key).
    min_ids: Vec<EntityId>,
    /// Outgoing condensation edges per SCC. May contain duplicates;
    /// consumers deduplicate via visited marks.
    adjacency: Vec<Vec<usize>>,
    /// True when the SCC has at least one incoming condensation edge,
    /// i.e. it is not a source.
    has_incoming: Vec<bool>,
}

const TARJAN_UNVISITED: usize = usize::MAX;

/// Iterative Tarjan SCC condensation, `O(V+E)`. Explicit DFS frames keep the
/// recursion depth off the thread stack (chain-shaped graphs are `O(V)`
/// deep). Neighbor ids absent from `neighbors_by_id` are skipped: rebuild
/// adjacency only references inserted nodes.
fn condense_sccs(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    ops: &mut u64,
) -> SccCondensation {
    let node_count = neighbors_by_id.len();
    let mut ids = Vec::with_capacity(node_count);
    let mut index_of = HashMap::with_capacity(node_count);
    for id in neighbors_by_id.keys() {
        index_of.insert(*id, ids.len());
        ids.push(*id);
    }

    let mut discovery = vec![TARJAN_UNVISITED; node_count];
    let mut lowlink = vec![0_usize; node_count];
    let mut on_stack = vec![false; node_count];
    let mut scc_of = vec![TARJAN_UNVISITED; node_count];
    let mut member_stack: Vec<usize> = Vec::new();
    let mut next_discovery = 0_usize;

    let mut sizes: Vec<usize> = Vec::new();
    let mut min_ids: Vec<EntityId> = Vec::new();

    // DFS frames: (node, offset of the next unexamined edge).
    let mut frames: Vec<(usize, usize)> = Vec::new();
    for root in 0..node_count {
        if discovery[root] != TARJAN_UNVISITED {
            continue;
        }
        frames.push((root, 0));
        while let Some(&mut (node, ref mut edge_pos)) = frames.last_mut() {
            if *edge_pos == 0 {
                *ops += 1;
                discovery[node] = next_discovery;
                lowlink[node] = next_discovery;
                next_discovery += 1;
                on_stack[node] = true;
                member_stack.push(node);
            }

            let neighbors = neighbors_by_id[&ids[node]].as_slice();
            let mut descend_into = None;
            while *edge_pos < neighbors.len() {
                let neighbor = &neighbors[*edge_pos];
                *edge_pos += 1;
                *ops += 1;
                let Some(&target) = index_of.get(neighbor) else {
                    continue;
                };
                if discovery[target] == TARJAN_UNVISITED {
                    descend_into = Some(target);
                    break;
                }
                if on_stack[target] {
                    lowlink[node] = lowlink[node].min(discovery[target]);
                }
            }
            if let Some(child) = descend_into {
                frames.push((child, 0));
                continue;
            }

            if lowlink[node] == discovery[node] {
                let scc = sizes.len();
                let mut size = 0_usize;
                let mut min_id = ids[node];
                loop {
                    let member = member_stack
                        .pop()
                        .expect("Tarjan member stack holds every open node until its root pops");
                    on_stack[member] = false;
                    scc_of[member] = scc;
                    size += 1;
                    if ids[member].as_bytes() < min_id.as_bytes() {
                        min_id = ids[member];
                    }
                    if member == node {
                        break;
                    }
                }
                sizes.push(size);
                min_ids.push(min_id);
            }

            frames.pop();
            if let Some(&mut (parent, _)) = frames.last_mut() {
                lowlink[parent] = lowlink[parent].min(lowlink[node]);
            }
        }
    }

    let scc_count = sizes.len();
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); scc_count];
    let mut has_incoming = vec![false; scc_count];
    for (node, id) in ids.iter().enumerate() {
        *ops += 1;
        let from = scc_of[node];
        for neighbor in &neighbors_by_id[id] {
            *ops += 1;
            let Some(&target) = index_of.get(neighbor) else {
                continue;
            };
            let to = scc_of[target];
            if from != to {
                adjacency[from].push(to);
                has_incoming[to] = true;
            }
        }
    }

    SccCondensation {
        sizes,
        min_ids,
        adjacency,
        has_incoming,
    }
}

/// Picks the entry point from the condensation: the lowest member entity id
/// among the source SCCs whose forward closure covers the most nodes.
///
/// Forward-closure node counts are computed once per SCC by a single
/// reverse-topological DP rather than a fresh per-source walk. Iterative
/// Tarjan finalizes SCCs sinks-first, so every condensation edge points to a
/// strictly smaller SCC index (see the `debug_assert` below); iterating
/// indices in increasing order therefore visits every child before its
/// parents — reverse topological order — without a separate sort.
///
/// An SCC's children have *disjoint* forward closures unless the SCC tops a
/// diamond (two child paths reconverge), so a single-child (or childless) SCC
/// reuses its child's already-computed count in `O(1)`. Only a genuine
/// diamond needs its exact closure recomputed via one bounded BFS — the
/// shared-suffix / chain shapes that broke the old per-source walk
/// (`Θ(sources · suffix)`) are diamond-free, so each condensation edge is
/// relaxed once and the whole pass stays `O(V+E)`.
fn best_source_scc_member(condensation: &SccCondensation, ops: &mut u64) -> Option<EntityId> {
    let scc_count = condensation.sizes.len();
    if scc_count == 0 {
        return None;
    }

    // Reachable-node count of each SCC's forward closure (the SCC included).
    let mut reach = vec![0_usize; scc_count];
    // Per-parent dedup stamp: the stored adjacency may repeat a target.
    let mut child_seen = vec![usize::MAX; scc_count];
    // Per-BFS visited stamp for the diamond fallback.
    let mut bfs_seen = vec![usize::MAX; scc_count];
    let mut frontier: Vec<usize> = Vec::new();

    for scc in 0..scc_count {
        *ops += 1;
        let mut unique_children = 0_usize;
        let mut single_child = usize::MAX;
        for &child in &condensation.adjacency[scc] {
            *ops += 1;
            debug_assert!(
                child < scc,
                "Tarjan finalizes sinks first, so condensation edges point to \
                 strictly smaller SCC indices already carrying a final reach count"
            );
            if child_seen[child] != scc {
                child_seen[child] = scc;
                unique_children += 1;
                single_child = child;
            }
        }

        reach[scc] = if unique_children <= 1 {
            // No siblings to overlap with: the child's closure is disjoint from
            // this SCC, so summing is exact and `O(1)`.
            condensation.sizes[scc]
                + if unique_children == 1 {
                    reach[single_child]
                } else {
                    0
                }
        } else {
            // Diamond: child closures may share descendants, so summing would
            // double count. Recompute the exact closure with one BFS that visits
            // every reachable SCC a single time.
            let mut closure_nodes = 0_usize;
            bfs_seen[scc] = scc;
            frontier.clear();
            frontier.push(scc);
            while let Some(node) = frontier.pop() {
                *ops += 1;
                closure_nodes += condensation.sizes[node];
                for &next in &condensation.adjacency[node] {
                    *ops += 1;
                    if bfs_seen[next] != scc {
                        bfs_seen[next] = scc;
                        frontier.push(next);
                    }
                }
            }
            closure_nodes
        };
    }

    // Winner: the source SCC (no incoming condensation edge) with the largest
    // forward closure; ties break to the lowest member entity id — the exact
    // selection the per-candidate reference scan makes.
    let mut best: Option<(usize, EntityId)> = None;
    for ((&closure_nodes, &has_incoming), &candidate_id) in reach
        .iter()
        .zip(&condensation.has_incoming)
        .zip(&condensation.min_ids)
    {
        *ops += 1;
        if has_incoming {
            continue;
        }

        let replace = match &best {
            None => true,
            Some((best_closure, best_id)) => {
                closure_nodes > *best_closure
                    || (closure_nodes == *best_closure
                        && candidate_id.as_bytes() < best_id.as_bytes())
            }
        };
        if replace {
            best = Some((closure_nodes, candidate_id));
        }
    }

    best.map(|(_, id)| id)
}

/// Test-facing wrapper: production code paths use
/// [`reachable_from_entry_probed`] so op counts cover the BFS fast path.
#[cfg(test)]
pub(super) fn reachable_from_entry(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    entry_point: EntityId,
) -> HashSet<EntityId> {
    reachable_from_entry_probed(neighbors_by_id, entry_point, &mut 0)
}

fn reachable_from_entry_probed(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    entry_point: EntityId,
    ops: &mut u64,
) -> HashSet<EntityId> {
    let mut visited = HashSet::with_capacity(neighbors_by_id.len().max(1));
    let mut frontier = vec![entry_point];

    while let Some(current) = frontier.pop() {
        if !visited.insert(current) {
            continue;
        }
        *ops += 1;
        if let Some(neighbors) = neighbors_by_id.get(&current) {
            for neighbor in neighbors {
                *ops += 1;
                frontier.push(*neighbor);
            }
        }
    }

    visited
}
