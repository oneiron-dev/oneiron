//! Graph projection and Leiden/CPM partition detection.

use std::collections::{BTreeMap, BTreeSet};

use crate::edge::{EdgeConfirmationStatus, EdgeKind};
use crate::entity_id::EntityId;

use super::types::{
    CommunityEdge, CommunityError, CommunityProjection, PPR_COMMUNITY_DETERMINISTIC_SEED, Result,
};

/// Explicit allowlist: future/nontraversable edge kinds fail closed.
pub const fn projection_weight(kind: EdgeKind) -> Option<f32> {
    match kind {
        EdgeKind::BelongsTo | EdgeKind::ParticipatesIn | EdgeKind::Mentions | EdgeKind::About => {
            Some(1.0)
        }
        EdgeKind::Supports | EdgeKind::DerivedFrom | EdgeKind::HasFacet | EdgeKind::FacetOf => {
            Some(0.8)
        }
        EdgeKind::ClaimOf | EdgeKind::ScopedTo => Some(0.5),
        EdgeKind::Supersedes
        | EdgeKind::PartOf
        | EdgeKind::EmployedBy
        | EdgeKind::AuthoredBy
        | EdgeKind::Attached
        | EdgeKind::InWorld
        | EdgeKind::SetIn
        | EdgeKind::MergedInto
        | EdgeKind::SplitInto => Some(0.1),
        _ => None,
    }
}

pub fn project_graph(
    entities: &[EntityId],
    edges: &[CommunityEdge],
) -> Result<CommunityProjection> {
    let nodes: BTreeSet<_> = entities.iter().copied().collect();
    let mut records = BTreeMap::new();
    for edge in edges {
        if !edge.value.weight.is_finite() || !(0.0..=1.0).contains(&edge.value.weight) {
            return Err(CommunityError::Graph);
        }
        let admitted = !edge.deleted
            && edge.value.weight > 0.0
            && !edge
                .value
                .provenance
                .is_some_and(|p| p.confirmation_status == EdgeConfirmationStatus::Retracted);
        let weight = if admitted {
            projection_weight(edge.kind).map_or(0, |w| (w * 10.0) as u64)
        } else {
            0
        };
        let key = (edge.source, edge.kind as u8, edge.target);
        if records.insert(key, weight).is_some_and(|old| old != weight) {
            return Err(CommunityError::Graph); // conflicting copies, not last-writer-wins
        }
    }
    let mut projected = BTreeMap::new();
    for ((a, _, b), weight) in records {
        if weight == 0 || a == b || !nodes.contains(&a) || !nodes.contains(&b) {
            continue;
        }
        *projected.entry((a.min(b), a.max(b))).or_default() += weight;
    }
    Ok(CommunityProjection {
        entities: nodes.into_iter().collect(),
        edges: projected,
    })
}

#[derive(Debug, Clone)]
pub(super) struct Graph {
    atoms: Vec<Vec<EntityId>>,
    pub(super) mass: Vec<usize>,
    pub(super) adj: Vec<BTreeMap<usize, u64>>,
}

pub(super) fn groups(labels: &[usize]) -> Vec<Vec<usize>> {
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (v, &c) in labels.iter().enumerate() {
        groups.entry(c).or_default().push(v);
    }
    let mut result: Vec<_> = groups.into_values().collect();
    result.sort_by_key(|g| g[0]);
    result
}

fn labels_for(groups: &[Vec<usize>], n: usize) -> Vec<usize> {
    let mut labels = vec![0; n];
    for (c, group) in groups.iter().enumerate() {
        for &v in group {
            labels[v] = c;
        }
    }
    labels
}

impl Graph {
    pub(super) fn from_projection(p: &CommunityProjection, selected: &BTreeSet<EntityId>) -> Self {
        let ids: Vec<_> = p
            .entities
            .iter()
            .copied()
            .filter(|id| selected.contains(id))
            .collect();
        let index: BTreeMap<_, _> = ids.iter().enumerate().map(|(i, &id)| (id, i)).collect();
        let mut graph = Self {
            atoms: ids.iter().map(|&id| vec![id]).collect(),
            mass: vec![1; ids.len()],
            adj: vec![BTreeMap::new(); ids.len()],
        };
        for (&(a, b), &w) in &p.edges {
            if let (Some(&a), Some(&b)) = (index.get(&a), index.get(&b)) {
                graph.adj[a].insert(b, w);
                graph.adj[b].insert(a, w);
            }
        }
        graph
    }

    fn order(&self) -> Vec<usize> {
        let mut order: Vec<_> = (0..self.mass.len()).collect();
        order.sort_by_key(|&v| {
            let mut h = blake3::Hasher::new();
            h.update(&PPR_COMMUNITY_DETERMINISTIC_SEED.to_le_bytes());
            h.update(self.atoms[v][0].as_bytes());
            (*h.finalize().as_bytes(), v)
        });
        order
    }

    pub(super) fn aggregate(&self, partition: &[Vec<usize>]) -> Self {
        let labels = labels_for(partition, self.mass.len());
        let mut atoms = Vec::new();
        let mut mass = Vec::new();
        for group in partition {
            let mut members: Vec<_> = group
                .iter()
                .flat_map(|&v| self.atoms[v].iter().copied())
                .collect();
            members.sort();
            atoms.push(members);
            mass.push(group.iter().map(|&v| self.mass[v]).sum());
        }
        let mut adj = vec![BTreeMap::new(); partition.len()];
        for (v, edges) in self.adj.iter().enumerate() {
            for (&u, &w) in edges {
                if labels[v] != labels[u] {
                    *adj[labels[v]].entry(labels[u]).or_default() += w;
                }
            }
        }
        // Internal edges are an additive CPM constant; only masses must survive contraction.
        Self { atoms, mass, adj }
    }

    fn members(&self, partition: &[Vec<usize>]) -> Vec<Vec<EntityId>> {
        partition
            .iter()
            .map(|g| {
                let mut ids: Vec<_> = g
                    .iter()
                    .flat_map(|&v| self.atoms[v].iter().copied())
                    .collect();
                ids.sort();
                ids
            })
            .collect()
    }
}

fn penalty(a: usize, b: usize) -> i128 {
    10 * a as i128 * b as i128
}

/// Split disconnected local-move communities. This strictly improves CPM.
pub(super) fn connected_groups(graph: &Graph, labels: &[usize]) -> Vec<Vec<usize>> {
    let mut seen = vec![false; labels.len()];
    let mut result = Vec::new();
    for v in 0..labels.len() {
        if seen[v] {
            continue;
        }
        let mut component = Vec::new();
        let mut queue = vec![v];
        seen[v] = true;
        while let Some(u) = queue.pop() {
            component.push(u);
            for &w in graph.adj[u].keys() {
                if !seen[w] && labels[w] == labels[v] {
                    seen[w] = true;
                    queue.push(w);
                }
            }
        }
        component.sort();
        result.push(component);
    }
    result
}

pub(super) fn local_move(graph: &Graph, labels: &mut Vec<usize>) {
    let order = graph.order();
    loop {
        let mut moved = false;
        let mut mass = vec![0; labels.len()];
        let mut count = vec![0; labels.len()];
        for (v, &c) in labels.iter().enumerate() {
            mass[c] += graph.mass[v];
            count[c] += 1;
        }
        let mut empty: BTreeSet<_> = count
            .iter()
            .enumerate()
            .filter_map(|(c, &n)| (n == 0).then_some(c))
            .collect();
        for &v in &order {
            let old = labels[v];
            let size = graph.mass[v];
            let mut weights: BTreeMap<usize, u64> = BTreeMap::new();
            for (&u, &w) in &graph.adj[v] {
                *weights.entry(labels[u]).or_default() += w;
            }
            let removal =
                i128::from(*weights.get(&old).unwrap_or(&0)) - penalty(size, mass[old] - size);
            let mut best = (0, old);
            if let Some(&target) = empty.first() {
                weights.entry(target).or_default();
            }
            for (target, weight) in weights {
                if target == old {
                    continue;
                }
                let gain = i128::from(weight) - penalty(size, mass[target]) - removal;
                // Zero-gain singleton merges reduce community count, so cannot cycle.
                let zero_merge = gain == 0 && count[old] == 1 && mass[target] > 0;
                if (gain > 0 || zero_merge)
                    && (gain > best.0 || (gain == best.0 && (best.1 == old || target < best.1)))
                {
                    best = (gain, target);
                }
            }
            if best.1 != old {
                labels[v] = best.1;
                mass[old] -= size;
                mass[best.1] += size;
                count[old] -= 1;
                count[best.1] += 1;
                empty.remove(&best.1);
                if count[old] == 0 {
                    empty.insert(old);
                }
                moved = true;
            }
        }
        let connected = connected_groups(graph, labels);
        let split = connected.len() != groups(labels).len();
        *labels = labels_for(&connected, labels.len());
        if !moved && !split {
            break;
        }
    }
}

/// Leiden refinement, not Louvain: start singleton subcommunities inside each
/// parent, merge only singleton atoms, require gamma-connected source/target
/// subsets, and allow only nonnegative CPM gains. Deterministic max-gain choice
/// is the zero-temperature refinement policy; seeded order resolves ties.
pub(super) fn refine_partition(graph: &Graph, parent: &[usize]) -> Vec<Vec<usize>> {
    let n = parent.len();
    let mut labels: Vec<_> = (0..n).collect();
    let mut mass = graph.mass.clone();
    let mut counts = vec![1; n];
    let mut parent_mass = vec![0; n];
    for (v, &c) in parent.iter().enumerate() {
        parent_mass[c] += graph.mass[v];
    }
    let mut cut: Vec<u64> = graph
        .adj
        .iter()
        .enumerate()
        .map(|(v, edges)| {
            edges
                .iter()
                .filter(|&(&u, _)| parent[u] == parent[v])
                .map(|(_, &w)| w)
                .sum()
        })
        .collect();
    for v in graph.order() {
        let source = labels[v];
        let total = parent_mass[parent[v]];
        if counts[source] != 1
            || i128::from(cut[source]) < penalty(mass[source], total - mass[source])
        {
            continue;
        }
        let mut weights: BTreeMap<usize, u64> = BTreeMap::new();
        for (&u, &w) in &graph.adj[v] {
            if parent[u] == parent[v] && labels[u] != source {
                *weights.entry(labels[u]).or_default() += w;
            }
        }
        let mut best = None;
        for (target, w) in weights {
            let gain = i128::from(w) - penalty(graph.mass[v], mass[target]);
            if gain >= 0
                && i128::from(cut[target]) >= penalty(mass[target], total - mass[target])
                && best.is_none_or(|(g, t, _)| gain > g || (gain == g && target < t))
            {
                best = Some((gain, target, w));
            }
        }
        if let Some((_, target, w)) = best {
            cut[target] = cut[target] + cut[source] - 2 * w;
            cut[source] = 0;
            mass[source] = 0;
            counts[source] = 0;
            labels[v] = target;
            mass[target] += graph.mass[v];
            counts[target] += 1;
        }
    }
    groups(&labels)
}

pub(super) fn leiden(mut graph: Graph) -> (Vec<Vec<EntityId>>, Vec<Vec<EntityId>>) {
    let mut labels: Vec<_> = (0..graph.mass.len()).collect();
    let mut fine = None;
    loop {
        local_move(&graph, &mut labels);
        let refined = refine_partition(&graph, &labels);
        if fine.is_none() {
            fine = Some(graph.members(&refined));
        }
        if refined.len() == graph.mass.len() || groups(&labels).len() == graph.mass.len() {
            return (fine.unwrap_or_default(), graph.members(&groups(&labels)));
        }
        // Lift the parent partition, not the refined partition, onto the quotient.
        let lifted: Vec<_> = refined.iter().map(|g| labels[g[0]]).collect();
        graph = graph.aggregate(&refined);
        labels = labels_for(&groups(&lifted), lifted.len());
    }
}
