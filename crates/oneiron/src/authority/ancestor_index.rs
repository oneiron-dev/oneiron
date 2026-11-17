//! Claimed authority-entry ancestry index for deterministic fold scheduling.
//!
//! Each row's whole claimed ancestry is held as sorted runs of dense ids, not
//! as a set of hashes per row (row [ROSTER-KEY-LOG-FLOOD], PR 1; Engine
//! RULINGs 16 Nov 13:32 and 13:44 = A). Ids follow a topological order (an
//! ancestor's id is below its descendants'), so a chain's or a star's row
//! holds one run, where a set held one entry per ancestor. Members, counts
//! and the memory floor's verdict are the per-row sets' exactly: the door
//! `ancestor_index_door` keeps that set index as the reference and
//! `tests/ancestor_index_equivalence.rs` compares the two.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Each entry's whole claimed ancestry, and the counted pairs in it; or
/// None once the fold's projected peak passes `memory_floor` bytes (H72):
/// the fold then refuses the log rather than build the rest. Every pair
/// costs memory, but a pair counts toward the headroom check only when
/// neither end is a slip op of the slip issuer, which no bound counts.
pub(in crate::authority) fn entry_ancestor_index(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    memory_floor: u64,
) -> Option<(AncestorIndex, u64)> {
    if super::log_budget::fold_projected_bytes(by_hash.len(), 0) > memory_floor {
        return None;
    }
    let uncounted = super::log_budget::uncounted_rows(by_hash);
    let rows: Vec<_> = by_hash
        .iter()
        .map(|(hash, entry)| (*hash, entry.parent_hashes.as_slice()))
        .collect();
    AncestorIndex::build(&rows, &uncounted, |pairs| {
        super::log_budget::fold_projected_bytes(by_hash.len(), pairs) > memory_floor
    })
}

/// Every row's whole claimed ancestry: the rows and the claimed parents it
/// reaches through one parent claim or more, its own hash included only
/// when it sits on a cycle of claims. A claimed parent the log lacks is a
/// node (a member of its children's ancestry) with no ancestry of its own.
pub(in crate::authority) struct AncestorIndex {
    /// Every node's hash, sorted: each row and each claimed parent.
    nodes: Vec<AuthorityEntryHash>,
    /// Each node's id, by its place in `nodes`. Ids follow a topological
    /// order of the claims' strongly connected components, ancestors first.
    id_of_node: Vec<u32>,
    /// Each id's place in `nodes`.
    node_of_id: Vec<u32>,
    /// Each node's ancestry, by its place in `nodes`: sorted, disjoint and
    /// non-adjacent half-open id ranges; None for a claimed parent the log
    /// lacks, which the index holds no ancestry for.
    runs: Vec<Option<Box<[(u32, u32)]>>>,
    /// Each node's ancestor count, by its place in `nodes`.
    lens: Vec<u32>,
    /// The sum of every row's ancestor count.
    pairs: u64,
}

/// One row's ancestry in an [`AncestorIndex`].
#[derive(Clone, Copy)]
pub(in crate::authority) struct Ancestors<'a> {
    index: &'a AncestorIndex,
    runs: &'a [(u32, u32)],
    len: u32,
}

impl AncestorIndex {
    /// The index of `rows`, sorted by hash, each with its claimed parents in
    /// listed order; or None once `refuses` holds for the pairs built so
    /// far. `refuses` must be monotone in the pairs, as the memory floor is,
    /// so the verdict is the one the whole log's pairs give. Pairs whose
    /// descendant or ancestor is in `uncounted` are left out of the counted
    /// pairs returned beside the index.
    pub(in crate::authority) fn build(
        rows: &[(AuthorityEntryHash, &[AuthorityEntryHash])],
        uncounted: &BTreeSet<AuthorityEntryHash>,
        refuses: impl Fn(u64) -> bool,
    ) -> Option<(Self, u64)> {
        let mut nodes: Vec<_> = rows
            .iter()
            .flat_map(|(hash, parents)| std::iter::once(hash).chain(parents.iter()))
            .copied()
            .collect();
        nodes.sort_unstable();
        nodes.dedup();
        // Ids are u32. A log with more nodes claims at least as many
        // ancestor pairs, past any memory floor a machine can hold.
        let node_count = u32::try_from(nodes.len()).ok()?;
        let place = |hash: &AuthorityEntryHash| {
            nodes
                .binary_search(hash)
                .map(|place| place as u32)
                .expect("every claimed hash is a node")
        };
        // Each node's parent claims, by place: rows' in listed order, none
        // for a claimed parent the log lacks.
        let mut edge_start = vec![0_u32; nodes.len() + 1];
        let mut edges = Vec::new();
        let mut is_row = vec![false; nodes.len()];
        let mut next_row = rows.iter().peekable();
        for (node, hash) in nodes.iter().enumerate() {
            if let Some((_, parents)) = next_row.next_if(|(row, _)| row == hash) {
                is_row[node] = true;
                edges.extend(parents.iter().map(place));
            }
            edge_start[node + 1] = u32::try_from(edges.len()).ok()?;
        }
        debug_assert_eq!(
            is_row.iter().filter(|row| **row).count(),
            rows.len(),
            "rows are sorted by hash, one each"
        );
        let parents_of = |node: u32| {
            &edges[edge_start[node as usize] as usize..edge_start[node as usize + 1] as usize]
        };

        let (id_of_node, node_of_id, components) =
            strongly_connected_components(node_count, &is_row, parents_of);

        let mut uncounted_below = vec![0_u32; nodes.len() + 1];
        for (id, node) in node_of_id.iter().enumerate() {
            let uncounted_here = uncounted.contains(&nodes[*node as usize]);
            uncounted_below[id + 1] = uncounted_below[id] + u32::from(uncounted_here);
        }
        let uncounted_in = |runs: &[(u32, u32)]| -> u64 {
            runs.iter()
                .map(|&(start, end)| {
                    u64::from(uncounted_below[end as usize] - uncounted_below[start as usize])
                })
                .sum()
        };

        let mut runs: Vec<Option<Box<[(u32, u32)]>>> = vec![None; nodes.len()];
        let mut lens = vec![0_u32; nodes.len()];
        let (mut pairs, mut counted_pairs) = (0_u64, 0_u64);
        let mut gathered = Vec::new();
        // Components come ancestors first, so every parent outside a
        // component already holds its runs.
        for &(start, end) in &components {
            let members = &node_of_id[start as usize..end as usize];
            gathered.clear();
            let mut on_cycle = end - start > 1;
            for &member in members {
                for &parent in parents_of(member) {
                    let parent_id = id_of_node[parent as usize];
                    if (start..end).contains(&parent_id) {
                        on_cycle = true;
                        continue;
                    }
                    gathered.push((parent_id, parent_id + 1));
                    if let Some(parent_runs) = &runs[parent as usize] {
                        gathered.extend_from_slice(parent_runs);
                    }
                }
            }
            if on_cycle {
                gathered.push((start, end));
            }
            let merged = merge_runs(&mut gathered);
            let len: u32 = merged.iter().map(|&(start, end)| end - start).sum();
            let uncounted_ancestors = uncounted_in(&merged);
            for &member in members {
                if !is_row[member as usize] {
                    continue;
                }
                pairs += u64::from(len);
                if refuses(pairs) {
                    return None;
                }
                if !uncounted.contains(&nodes[member as usize]) {
                    counted_pairs += u64::from(len) - uncounted_ancestors;
                }
                lens[member as usize] = len;
                runs[member as usize] = Some(merged.clone().into_boxed_slice());
            }
        }
        Some((
            Self {
                nodes,
                id_of_node,
                node_of_id,
                runs,
                lens,
                pairs,
            },
            counted_pairs,
        ))
    }

    /// `hash`'s ancestry: None unless `hash` is a row of the log (a claimed
    /// parent the log lacks has none); an empty one for a row with no
    /// parent.
    pub(in crate::authority) fn get(&self, hash: &AuthorityEntryHash) -> Option<Ancestors<'_>> {
        let node = self.nodes.binary_search(hash).ok()?;
        let runs = self.runs[node].as_deref()?;
        Some(Ancestors {
            index: self,
            runs,
            len: self.lens[node],
        })
    }

    /// The sum of every row's ancestor count, the pairs a checkpoint image
    /// records.
    pub(in crate::authority) fn pairs(&self) -> u64 {
        self.pairs
    }

    fn id(&self, hash: &AuthorityEntryHash) -> Option<u32> {
        let node = self.nodes.binary_search(hash).ok()?;
        Some(self.id_of_node[node])
    }
}

impl<'a> Ancestors<'a> {
    /// The ancestor count.
    pub(in crate::authority) fn len(self) -> usize {
        self.len as usize
    }

    /// Whether `hash` is an ancestor.
    pub(in crate::authority) fn contains(self, hash: &AuthorityEntryHash) -> bool {
        self.index.id(hash).is_some_and(|id| {
            let run = self.runs.partition_point(|&(_, end)| end <= id);
            self.runs.get(run).is_some_and(|&(start, _)| start <= id)
        })
    }

    /// Every ancestor, in id order, not hash order: ancestors before their
    /// descendants. A reader whose result depends on the order collects
    /// [`Self::to_set`] instead.
    pub(in crate::authority) fn iter_unordered(
        self,
    ) -> impl Iterator<Item = &'a AuthorityEntryHash> + 'a {
        let index = self.index;
        self.runs.iter().flat_map(move |&(start, end)| {
            index.node_of_id[start as usize..end as usize]
                .iter()
                .map(move |node| &index.nodes[*node as usize])
        })
    }

    /// Every ancestor as a set, in hash order, for a reader that adds to it
    /// or walks it in that order.
    pub(in crate::authority) fn to_set(self) -> BTreeSet<AuthorityEntryHash> {
        self.iter_unordered().copied().collect()
    }

    /// Whether an ancestor is in `hashes`.
    pub(in crate::authority) fn intersects(self, hashes: &BTreeSet<AuthorityEntryHash>) -> bool {
        if hashes.len() < self.len() {
            hashes.iter().any(|hash| self.contains(hash))
        } else {
            self.iter_unordered().any(|hash| hashes.contains(hash))
        }
    }
}

/// Tarjan's strongly connected components of the claims (iterative), each
/// row a root in hash order and each node's parents in listed order. Returns
/// each node's id, each id's node, and each component's id range, in the
/// order Tarjan's algorithm closes them: a component after every component
/// its members claim, so ancestors take the lower ids. A claimed parent the
/// log lacks is reached from a row that claims it.
fn strongly_connected_components<'e>(
    node_count: u32,
    is_row: &[bool],
    parents_of: impl Fn(u32) -> &'e [u32],
) -> (Vec<u32>, Vec<u32>, Vec<(u32, u32)>) {
    let count = node_count as usize;
    let mut walk = ComponentWalk {
        seen_at: vec![ComponentWalk::UNSEEN; count],
        low: vec![0; count],
        on_stack: vec![false; count],
        stack: Vec::new(),
        path: Vec::new(),
        next_seen: 0,
    };
    let mut id_of_node = vec![ComponentWalk::UNSEEN; count];
    let mut node_of_id = Vec::with_capacity(count);
    let mut components = Vec::new();
    for root in (0..node_count).filter(|node| is_row[*node as usize]) {
        if walk.seen_at[root as usize] != ComponentWalk::UNSEEN {
            continue;
        }
        walk.enter(root);
        while let Some(&(node, next)) = walk.path.last() {
            if let Some(&parent) = parents_of(node).get(next) {
                walk.path.last_mut().expect("the path is not empty").1 += 1;
                if walk.seen_at[parent as usize] == ComponentWalk::UNSEEN {
                    walk.enter(parent);
                } else if walk.on_stack[parent as usize] {
                    walk.low[node as usize] =
                        walk.low[node as usize].min(walk.seen_at[parent as usize]);
                }
                continue;
            }
            walk.path.pop();
            if let Some(&(child, _)) = walk.path.last() {
                walk.low[child as usize] = walk.low[child as usize].min(walk.low[node as usize]);
            }
            if walk.low[node as usize] == walk.seen_at[node as usize] {
                let start = node_of_id.len() as u32;
                loop {
                    let member = walk
                        .stack
                        .pop()
                        .expect("the component's root is on the stack");
                    walk.on_stack[member as usize] = false;
                    id_of_node[member as usize] = node_of_id.len() as u32;
                    node_of_id.push(member);
                    if member == node {
                        break;
                    }
                }
                components.push((start, node_of_id.len() as u32));
            }
        }
    }
    debug_assert_eq!(
        node_of_id.len(),
        count,
        "every node is a row or claimed by one"
    );
    (id_of_node, node_of_id, components)
}

/// The depth-first walk of [`strongly_connected_components`].
struct ComponentWalk {
    /// Each node's visit number, or `UNSEEN`.
    seen_at: Vec<u32>,
    /// Each node's lowest visit number reachable within its component.
    low: Vec<u32>,
    on_stack: Vec<bool>,
    /// Visited nodes whose component is not closed yet.
    stack: Vec<u32>,
    /// The walk's path: each node and the place of its next parent claim.
    path: Vec<(u32, usize)>,
    next_seen: u32,
}

impl ComponentWalk {
    const UNSEEN: u32 = u32::MAX;

    fn enter(&mut self, node: u32) {
        self.seen_at[node as usize] = self.next_seen;
        self.low[node as usize] = self.next_seen;
        self.next_seen += 1;
        self.stack.push(node);
        self.on_stack[node as usize] = true;
        self.path.push((node, 0));
    }
}

/// `runs` sorted and merged into disjoint, non-adjacent ranges.
fn merge_runs(runs: &mut [(u32, u32)]) -> Vec<(u32, u32)> {
    runs.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(runs.len());
    for &(start, end) in runs.iter() {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}
