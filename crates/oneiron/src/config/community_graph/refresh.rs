//! Refresh policy, affected-set expansion and read-side cache view.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::codec::CommunitySnapshot;
use super::detection::{Graph, leiden, project_graph};
use super::types::{
    CommunityCacheMeta, CommunityError, CommunityGraphInput, CommunityProjection,
    CommunityQueryView, CommunityRefreshReport, PPR_COMMUNITY_SCHEMA_VERSION, PprCommunityCache,
    PprCommunityConfig, Result,
};

/// Full snapshot input; incremental work is restricted to the union of affected
/// old coarse communities and current connected components. Frontier completeness
/// is an adapter obligation. Empty frontier with a new version means unknown churn.
pub fn compute_communities(
    input: &CommunityGraphInput<'_>,
    previous: Option<&CommunitySnapshot>,
    now: u64,
    config: &PprCommunityConfig,
) -> Result<(CommunitySnapshot, CommunityRefreshReport)> {
    let CommunityGraphInput {
        entities,
        edges,
        changed,
        graph_version,
    } = *input;
    config.validate()?;
    let projection = project_graph(entities, edges)?;
    let current: BTreeSet<_> = projection.entities.iter().copied().collect();
    let mut frontier: BTreeSet<_> = changed.iter().copied().collect();
    if let Some(old) = previous {
        old.validate(old.meta.graph_version)?;
        let old_nodes: BTreeSet<_> = old.nodes.keys().copied().collect();
        frontier.extend(current.symmetric_difference(&old_nodes).copied());
        if graph_version < old.meta.graph_version
            || (graph_version == old.meta.graph_version && !frontier.is_empty())
        {
            return Err(CommunityError::Version);
        }
    }
    let full = previous.is_none()
        || frontier.len().saturating_mul(20) > current.len()
        || previous
            .is_some_and(|old| old.meta.graph_version != graph_version && changed.is_empty());
    let affected = if full {
        current.clone()
    } else {
        affected_entities(&projection, previous, &frontier)
    };
    let graph = Graph::from_projection(&projection, &affected);
    let (mut fine, mut coarse) = leiden(graph);
    if let Some(old) = previous.filter(|_| !full) {
        let mut fine_ids = BTreeSet::new();
        let mut coarse_ids = BTreeSet::new();
        for (&id, m) in &old.nodes {
            if current.contains(&id) && !affected.contains(&id) {
                fine_ids.insert(m.fine);
                coarse_ids.insert(m.coarse);
            }
        }
        for id in fine_ids {
            fine.push(old.members[&id].clone());
        }
        for id in coarse_ids {
            coarse.push(old.members[&id].clone());
        }
    }
    let meta = CommunityCacheMeta {
        schema: PPR_COMMUNITY_SCHEMA_VERSION,
        graph_version,
        gamma: config.gamma,
        generated_at: now,
    };
    let snapshot = CommunitySnapshot::from_partitions(meta, &fine, &coarse)?;
    Ok((
        snapshot,
        CommunityRefreshReport {
            full_recompute: full,
            changed_entities: frontier.len(),
            recomputed_entities: affected.len(),
        },
    ))
}

fn affected_entities(
    p: &CommunityProjection,
    old: Option<&CommunitySnapshot>,
    frontier: &BTreeSet<EntityId>,
) -> BTreeSet<EntityId> {
    let mut adj: BTreeMap<EntityId, Vec<EntityId>> = BTreeMap::new();
    for &(a, b) in p.edges.keys() {
        adj.entry(a).or_default().push(b);
        adj.entry(b).or_default().push(a);
    }
    let mut seen = frontier.clone();
    let mut queue: Vec<_> = frontier.iter().copied().collect();
    let mut expanded = BTreeSet::new();
    while let Some(id) = queue.pop() {
        let mut neighbors = adj.get(&id).cloned().unwrap_or_default();
        if let Some(old) = old
            && let Some(m) = old.nodes.get(&id).filter(|m| expanded.insert(m.coarse))
        {
            neighbors.extend(&old.members[&m.coarse]);
        }
        for next in neighbors {
            if seen.insert(next) {
                queue.push(next);
            }
        }
    }
    seen.retain(|id| p.entities.binary_search(id).is_ok());
    seen
}

impl CommunityQueryView {
    pub(crate) fn from_snapshot(
        snapshot: &CommunitySnapshot,
        selected: &BTreeSet<EntityId>,
    ) -> Result<Self> {
        snapshot.validate(snapshot.meta.graph_version)?;
        let nodes: BTreeMap<_, _> = selected
            .iter()
            .filter_map(|id| snapshot.nodes.get(id).map(|&m| (*id, m)))
            .collect();
        let sizes = nodes
            .values()
            .flat_map(|m| [m.fine, m.coarse])
            .map(|id| (id, snapshot.members[&id].len()))
            .collect();
        Ok(Self {
            nodes,
            sizes,
            graph_size: snapshot.nodes.len(),
        })
    }

    pub(crate) fn cache(&self) -> PprCommunityCache<'_> {
        PprCommunityCache {
            nodes: &self.nodes,
            sizes: self.sizes.clone(),
            graph_size: self.graph_size,
        }
    }
}

impl<'a> PprCommunityCache<'a> {
    pub fn new(snapshot: &'a CommunitySnapshot, graph_version: u64) -> Result<Self> {
        snapshot.validate(graph_version)?;
        Ok(Self {
            nodes: &snapshot.nodes,
            sizes: snapshot
                .members
                .iter()
                .map(|(&id, rows)| (id, rows.len()))
                .collect(),
            graph_size: snapshot.nodes.len(),
        })
    }
}
