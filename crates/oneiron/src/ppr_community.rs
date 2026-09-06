//! Deterministic community projection, cache, and bounded retrieval prior.
//! The Store adapter supplies one consistent, canonical live-entity snapshot, decoded
//! outgoing edges (not both indexes), and every changed edge endpoint, including
//! deletions. Publish all returned rows atomically in `vault_meta`, never a new DB.
//! CPM uses integer tenths at gamma 1.0. Distinct directed relations add evidence;
//! duplicate records do not. Fine is the first Leiden refinement; coarse is its
//! mass-preserving multilevel partition. Both may coincide (no forced clustering).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::edge::{DecodedEdgeValue, EdgeConfirmationStatus, EdgeKind};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::pipeline::ScoredEntity;

pub const PPR_COMMUNITY_SCHEMA_VERSION: u8 = 0;
pub const PPR_COMMUNITY_CPM_GAMMA: f32 = 1.0;
pub const PPR_COMMUNITY_BETA_DEFAULT: f32 = 0.0;
pub const PPR_COMMUNITY_BETA_EXPERIMENT: f32 = 0.2;
pub const PPR_COMMUNITY_MULTIPLIER_CAP: f32 = 1.5;
pub const PPR_COMMUNITY_MAX_GRAPH_FRACTION: f32 = 0.10;
pub const PPR_COMMUNITY_MAX_TOP_K_FRACTION: f32 = 0.70;
pub const PPR_COMMUNITY_REFRESH_CHURN_FRACTION: f32 = 0.05;
pub const PPR_COMMUNITY_USAGE_DECAY: f32 = 0.10;
pub const PPR_COMMUNITY_DETERMINISTIC_SEED: u64 = 0x4f4e455f313837;
pub const PPR_COMMUNITY_CACHE_PREFIX: &str = "ppr_community_cache:v0:";
const META_KEY: &str = "ppr_community_cache:v0:meta";

type Result<T> = std::result::Result<T, CommunityError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommunityError {
    #[error("invalid community configuration")]
    Config,
    #[error("invalid community graph or frontier")]
    Graph,
    #[error("corrupt community cache")]
    Cache,
    #[error("stale community graph version")]
    Version,
    #[error("invalid community score evidence")]
    Scores,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommunityId([u8; 16]);

impl CommunityId {
    /// Domain-separated BLAKE3-128 of the sorted, unique member IDs.
    pub fn from_members(members: &[EntityId]) -> Result<Self> {
        let sorted: BTreeSet<_> = members.iter().copied().collect();
        if sorted.is_empty() { return Err(CommunityError::Cache); }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:ppr_community:v0:members\0");
        for id in sorted { hasher.update(id.as_bytes()); }
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] { &self.0 }
    pub fn to_hex(self) -> String { bytes_to_hex_lower(&self.0) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommunityMembership { pub fine: CommunityId, pub coarse: CommunityId }

/// Runtime configuration, also exported from [`crate::config`].
#[derive(Debug, Clone, PartialEq)]
pub struct PprCommunityConfig {
    pub beta: f32,
    pub gamma: f32,
    pub multiplier_cap: f32,
    pub max_graph_fraction: f32,
    pub max_top_k_fraction: f32,
}

impl Default for PprCommunityConfig {
    fn default() -> Self {
        Self { beta: PPR_COMMUNITY_BETA_DEFAULT, gamma: PPR_COMMUNITY_CPM_GAMMA,
            multiplier_cap: PPR_COMMUNITY_MULTIPLIER_CAP,
            max_graph_fraction: PPR_COMMUNITY_MAX_GRAPH_FRACTION,
            max_top_k_fraction: PPR_COMMUNITY_MAX_TOP_K_FRACTION }
    }
}

impl PprCommunityConfig {
    /// Safety bounds may be tightened, not relaxed. Gamma is pinned in v0.
    pub fn validate(&self) -> Result<()> {
        if !self.beta.is_finite() || self.beta < 0.0 || self.gamma != PPR_COMMUNITY_CPM_GAMMA
            || !(1.0..=PPR_COMMUNITY_MULTIPLIER_CAP).contains(&self.multiplier_cap)
            || !(0.0..=PPR_COMMUNITY_MAX_GRAPH_FRACTION).contains(&self.max_graph_fraction)
            || !(0.0..=PPR_COMMUNITY_MAX_TOP_K_FRACTION).contains(&self.max_top_k_fraction)
        { return Err(CommunityError::Config); }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CommunityEdge {
    pub source: EntityId,
    pub target: EntityId,
    pub kind: EdgeKind,
    pub value: DecodedEdgeValue,
    pub deleted: bool,
}

/// Explicit allowlist: future/nontraversable edge kinds fail closed.
pub const fn projection_weight(kind: EdgeKind) -> Option<f32> {
    match kind {
        EdgeKind::BelongsTo | EdgeKind::ParticipatesIn | EdgeKind::Mentions | EdgeKind::About => Some(1.0),
        EdgeKind::Supports | EdgeKind::DerivedFrom | EdgeKind::HasFacet | EdgeKind::FacetOf => Some(0.8),
        EdgeKind::ClaimOf | EdgeKind::ScopedTo => Some(0.5),
        EdgeKind::Supersedes | EdgeKind::PartOf | EdgeKind::EmployedBy | EdgeKind::AuthoredBy
        | EdgeKind::Attached | EdgeKind::InWorld | EdgeKind::SetIn | EdgeKind::MergedInto
        | EdgeKind::SplitInto => Some(0.1),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityProjection {
    pub entities: Vec<EntityId>,
    /// Canonical undirected pairs, in integer tenths of pinned family weight.
    pub edges: BTreeMap<(EntityId, EntityId), u64>,
}

pub fn project_graph(entities: &[EntityId], edges: &[CommunityEdge]) -> Result<CommunityProjection> {
    let nodes: BTreeSet<_> = entities.iter().copied().collect();
    let mut records = BTreeMap::new();
    for edge in edges {
        if !edge.value.weight.is_finite() || !(0.0..=1.0).contains(&edge.value.weight) {
            return Err(CommunityError::Graph);
        }
        let admitted = !edge.deleted && edge.value.weight > 0.0
            && !edge.value.provenance.is_some_and(|p| p.confirmation_status == EdgeConfirmationStatus::Retracted);
        let weight = if admitted { projection_weight(edge.kind).map_or(0, |w| (w * 10.0) as u64) } else { 0 };
        let key = (edge.source, edge.kind as u8, edge.target);
        if records.insert(key, weight).is_some_and(|old| old != weight) {
            return Err(CommunityError::Graph); // conflicting copies, not last-writer-wins
        }
    }
    let mut projected = BTreeMap::new();
    for ((a, _, b), weight) in records {
        if weight == 0 || a == b || !nodes.contains(&a) || !nodes.contains(&b) { continue; }
        *projected.entry((a.min(b), a.max(b))).or_default() += weight;
    }
    Ok(CommunityProjection { entities: nodes.into_iter().collect(), edges: projected })
}

#[derive(Debug, Clone)]
struct Graph { atoms: Vec<Vec<EntityId>>, mass: Vec<usize>, adj: Vec<BTreeMap<usize, u64>> }

fn groups(labels: &[usize]) -> Vec<Vec<usize>> {
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (v, &c) in labels.iter().enumerate() { groups.entry(c).or_default().push(v); }
    let mut result: Vec<_> = groups.into_values().collect();
    result.sort_by_key(|g| g[0]);
    result
}

fn labels_for(groups: &[Vec<usize>], n: usize) -> Vec<usize> {
    let mut labels = vec![0; n];
    for (c, group) in groups.iter().enumerate() { for &v in group { labels[v] = c; } }
    labels
}

impl Graph {
    fn from_projection(p: &CommunityProjection, selected: &BTreeSet<EntityId>) -> Self {
        let ids: Vec<_> = p.entities.iter().copied().filter(|id| selected.contains(id)).collect();
        let index: BTreeMap<_, _> = ids.iter().enumerate().map(|(i, &id)| (id, i)).collect();
        let mut graph = Self { atoms: ids.iter().map(|&id| vec![id]).collect(),
            mass: vec![1; ids.len()], adj: vec![BTreeMap::new(); ids.len()] };
        for (&(a, b), &w) in &p.edges {
            if let (Some(&a), Some(&b)) = (index.get(&a), index.get(&b)) {
                graph.adj[a].insert(b, w); graph.adj[b].insert(a, w);
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

    fn aggregate(&self, partition: &[Vec<usize>]) -> Self {
        let labels = labels_for(partition, self.mass.len());
        let mut atoms = Vec::new();
        let mut mass = Vec::new();
        for group in partition {
            let mut members: Vec<_> = group.iter().flat_map(|&v| self.atoms[v].iter().copied()).collect();
            members.sort(); atoms.push(members);
            mass.push(group.iter().map(|&v| self.mass[v]).sum());
        }
        let mut adj = vec![BTreeMap::new(); partition.len()];
        for (v, edges) in self.adj.iter().enumerate() {
            for (&u, &w) in edges {
                if labels[v] != labels[u] { *adj[labels[v]].entry(labels[u]).or_default() += w; }
            }
        }
        // Internal edges are an additive CPM constant; only masses must survive contraction.
        Self { atoms, mass, adj }
    }

    fn members(&self, partition: &[Vec<usize>]) -> Vec<Vec<EntityId>> {
        partition.iter().map(|g| {
            let mut ids: Vec<_> = g.iter().flat_map(|&v| self.atoms[v].iter().copied()).collect();
            ids.sort(); ids
        }).collect()
    }
}

fn penalty(a: usize, b: usize) -> i128 { 10 * a as i128 * b as i128 }

/// Split disconnected local-move communities. This strictly improves CPM.
fn connected_groups(graph: &Graph, labels: &[usize]) -> Vec<Vec<usize>> {
    let mut seen = vec![false; labels.len()];
    let mut result = Vec::new();
    for v in 0..labels.len() {
        if seen[v] { continue; }
        let mut component = Vec::new();
        let mut queue = vec![v]; seen[v] = true;
        while let Some(u) = queue.pop() {
            component.push(u);
            for &w in graph.adj[u].keys() {
                if !seen[w] && labels[w] == labels[v] { seen[w] = true; queue.push(w); }
            }
        }
        component.sort(); result.push(component);
    }
    result
}

fn local_move(graph: &Graph, labels: &mut Vec<usize>) {
    let order = graph.order();
    loop {
        let mut moved = false;
        let mut mass = vec![0; labels.len()];
        let mut count = vec![0; labels.len()];
        for (v, &c) in labels.iter().enumerate() { mass[c] += graph.mass[v]; count[c] += 1; }
        let mut empty: BTreeSet<_> = count.iter().enumerate().filter_map(|(c, &n)| (n == 0).then_some(c)).collect();
        for &v in &order {
            let old = labels[v];
            let size = graph.mass[v];
            let mut weights: BTreeMap<usize, u64> = BTreeMap::new();
            for (&u, &w) in &graph.adj[v] { *weights.entry(labels[u]).or_default() += w; }
            let removal = i128::from(*weights.get(&old).unwrap_or(&0)) - penalty(size, mass[old] - size);
            let mut best = (0, old);
            if let Some(&target) = empty.first() { weights.entry(target).or_default(); }
            for (target, weight) in weights {
                if target == old { continue; }
                let gain = i128::from(weight) - penalty(size, mass[target]) - removal;
                // Zero-gain singleton merges reduce community count, so cannot cycle.
                let zero_merge = gain == 0 && count[old] == 1 && mass[target] > 0;
                if (gain > 0 || zero_merge)
                    && (gain > best.0 || (gain == best.0 && (best.1 == old || target < best.1)))
                { best = (gain, target); }
            }
            if best.1 != old {
                labels[v] = best.1; mass[old] -= size; mass[best.1] += size;
                count[old] -= 1; count[best.1] += 1;
                empty.remove(&best.1); if count[old] == 0 { empty.insert(old); }
                moved = true;
            }
        }
        let connected = connected_groups(graph, labels);
        let split = connected.len() != groups(labels).len();
        *labels = labels_for(&connected, labels.len());
        if !moved && !split { break; }
    }
}

/// Leiden refinement, not Louvain: start singleton subcommunities inside each
/// parent, merge only singleton atoms, require gamma-connected source/target
/// subsets, and allow only nonnegative CPM gains. Deterministic max-gain choice
/// is the zero-temperature refinement policy; seeded order resolves ties.
fn refine_partition(graph: &Graph, parent: &[usize]) -> Vec<Vec<usize>> {
    let n = parent.len();
    let mut labels: Vec<_> = (0..n).collect();
    let mut mass = graph.mass.clone();
    let mut counts = vec![1; n];
    let mut parent_mass = vec![0; n];
    for (v, &c) in parent.iter().enumerate() { parent_mass[c] += graph.mass[v]; }
    let mut cut: Vec<u64> = graph.adj.iter().enumerate().map(|(v, edges)| {
        edges.iter().filter(|&(&u, _)| parent[u] == parent[v]).map(|(_, &w)| w).sum()
    }).collect();
    for v in graph.order() {
        let source = labels[v];
        let total = parent_mass[parent[v]];
        if counts[source] != 1 || i128::from(cut[source]) < penalty(mass[source], total - mass[source]) { continue; }
        let mut weights: BTreeMap<usize, u64> = BTreeMap::new();
        for (&u, &w) in &graph.adj[v] {
            if parent[u] == parent[v] && labels[u] != source { *weights.entry(labels[u]).or_default() += w; }
        }
        let mut best = None;
        for (target, w) in weights {
            let gain = i128::from(w) - penalty(graph.mass[v], mass[target]);
            if gain >= 0 && i128::from(cut[target]) >= penalty(mass[target], total - mass[target])
                && best.is_none_or(|(g, t, _)| gain > g || (gain == g && target < t))
            { best = Some((gain, target, w)); }
        }
        if let Some((_, target, w)) = best {
            cut[target] = cut[target] + cut[source] - 2 * w;
            cut[source] = 0; mass[source] = 0; counts[source] = 0;
            labels[v] = target; mass[target] += graph.mass[v]; counts[target] += 1;
        }
    }
    groups(&labels)
}

fn leiden(mut graph: Graph) -> (Vec<Vec<EntityId>>, Vec<Vec<EntityId>>) {
    let mut labels: Vec<_> = (0..graph.mass.len()).collect();
    let mut fine = None;
    loop {
        local_move(&graph, &mut labels);
        let refined = refine_partition(&graph, &labels);
        if fine.is_none() { fine = Some(graph.members(&refined)); }
        if refined.len() == graph.mass.len() || groups(&labels).len() == graph.mass.len() {
            return (fine.unwrap_or_default(), graph.members(&groups(&labels)));
        }
        // Lift the parent partition, not the refined partition, onto the quotient.
        let lifted: Vec<_> = refined.iter().map(|g| labels[g[0]]).collect();
        graph = graph.aggregate(&refined);
        labels = labels_for(&groups(&lifted), lifted.len());
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CommunityCacheMeta { pub schema: u8, pub graph_version: u64, pub gamma: f32, pub generated_at: u64 }

#[derive(Debug, Clone, PartialEq)]
pub struct CommunitySnapshot {
    pub meta: CommunityCacheMeta,
    pub nodes: BTreeMap<EntityId, CommunityMembership>,
    pub members: BTreeMap<CommunityId, Vec<EntityId>>,
}

impl CommunitySnapshot {
    pub fn from_partitions(meta: CommunityCacheMeta, fine: &[Vec<EntityId>], coarse: &[Vec<EntityId>]) -> Result<Self> {
        let mut snapshot = Self { meta, nodes: BTreeMap::new(), members: BTreeMap::new() };
        let mut fine_ids = BTreeMap::new();
        for group in fine {
            let id = CommunityId::from_members(group)?;
            for &entity in group {
                if fine_ids.insert(entity, id).is_some() { return Err(CommunityError::Cache); }
            }
        }
        for group in coarse {
            let coarse = CommunityId::from_members(group)?;
            for &entity in group {
                let fine = fine_ids.remove(&entity).ok_or(CommunityError::Cache)?;
                snapshot.nodes.insert(entity, CommunityMembership { fine, coarse });
            }
        }
        if !fine_ids.is_empty() { return Err(CommunityError::Cache); }
        snapshot.members = snapshot.expected_members()?;
        snapshot.validate(meta.graph_version)?;
        Ok(snapshot)
    }

    fn expected_members(&self) -> Result<BTreeMap<CommunityId, Vec<EntityId>>> {
        let mut fine: BTreeMap<CommunityId, Vec<EntityId>> = BTreeMap::new();
        let mut coarse: BTreeMap<CommunityId, Vec<EntityId>> = BTreeMap::new();
        let mut parents = BTreeMap::new();
        for (&entity, m) in &self.nodes {
            if parents.insert(m.fine, m.coarse).is_some_and(|old| old != m.coarse) { return Err(CommunityError::Cache); }
            fine.entry(m.fine).or_default().push(entity);
            coarse.entry(m.coarse).or_default().push(entity);
        }
        let mut result = BTreeMap::new();
        for (id, members) in fine.into_iter().chain(coarse) {
            if CommunityId::from_members(&members)? != id { return Err(CommunityError::Cache); }
            if result.insert(id, members.clone()).is_some_and(|old| old != members) { return Err(CommunityError::Cache); }
        }
        Ok(result)
    }

    pub fn validate(&self, graph_version: u64) -> Result<()> {
        if self.meta.graph_version != graph_version { return Err(CommunityError::Version); }
        if self.meta.schema != PPR_COMMUNITY_SCHEMA_VERSION || self.meta.gamma != PPR_COMMUNITY_CPM_GAMMA
            || self.members != self.expected_members()? { return Err(CommunityError::Cache); }
        Ok(())
    }

    /// Canonical lowercase hex keys; binary values use fixed-width little endian.
    pub fn encode_rows(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        self.validate(self.meta.graph_version)?;
        let mut rows = BTreeMap::new();
        let mut meta = vec![self.meta.schema];
        meta.extend(self.meta.graph_version.to_le_bytes()); meta.extend(self.meta.gamma.to_le_bytes());
        meta.extend(self.meta.generated_at.to_le_bytes()); rows.insert(META_KEY.as_bytes().to_vec(), meta);
        for (entity, m) in &self.nodes {
            let mut value = m.fine.0.to_vec(); value.extend(m.coarse.0);
            rows.insert(format!("{PPR_COMMUNITY_CACHE_PREFIX}node:{}", entity.to_hex()).into_bytes(), value);
        }
        for (id, members) in &self.members {
            let value = members.iter().flat_map(|e| e.as_bytes().iter().copied()).collect();
            rows.insert(format!("{PPR_COMMUNITY_CACHE_PREFIX}members:{}", id.to_hex()).into_bytes(), value);
        }
        Ok(rows)
    }

    /// Decode a complete logical family only. Bound rows and member bytes before
    /// allocation; reject unknown keys, duplicates, reserved IDs and torn indexes.
    pub fn decode_rows(rows: &[(Vec<u8>, Vec<u8>)], version: u64, max_nodes: usize) -> Result<Self> {
        if rows.len() > max_nodes.saturating_mul(3).saturating_add(1) { return Err(CommunityError::Cache); }
        let mut seen = BTreeSet::new();
        let mut meta = None;
        let mut nodes = BTreeMap::new();
        let mut members = BTreeMap::new();
        let mut member_count = 0usize;
        for (key, value) in rows {
            if !seen.insert(key) { return Err(CommunityError::Cache); }
            let key = std::str::from_utf8(key).map_err(|_| CommunityError::Cache)?;
            if key == META_KEY {
                if value.len() != 21 { return Err(CommunityError::Cache); }
                meta = Some(CommunityCacheMeta { schema: value[0], graph_version: u64::from_le_bytes(array(&value[1..9])?),
                    gamma: f32::from_le_bytes(array(&value[9..13])?), generated_at: u64::from_le_bytes(array(&value[13..21])?) });
            } else if let Some(hex) = key.strip_prefix("ppr_community_cache:v0:node:") {
                let id = EntityId::from_bytes(hex_id(hex)?).map_err(|_| CommunityError::Cache)?;
                if value.len() != 32 || nodes.len() >= max_nodes { return Err(CommunityError::Cache); }
                nodes.insert(id, CommunityMembership { fine: CommunityId(array(&value[..16])?), coarse: CommunityId(array(&value[16..])?) });
            } else if let Some(hex) = key.strip_prefix("ppr_community_cache:v0:members:") {
                if value.is_empty() || !value.len().is_multiple_of(16) { return Err(CommunityError::Cache); }
                member_count = member_count.checked_add(value.len() / 16).ok_or(CommunityError::Cache)?;
                if member_count > max_nodes.saturating_mul(2) { return Err(CommunityError::Cache); }
                let ids = value.chunks_exact(16).map(|v| EntityId::from_bytes(array(v)?).map_err(|_| CommunityError::Cache))
                    .collect::<Result<Vec<_>>>()?;
                members.insert(CommunityId(hex_id(hex)?), ids);
            } else { return Err(CommunityError::Cache); }
        }
        let snapshot = Self { meta: meta.ok_or(CommunityError::Cache)?, nodes, members };
        snapshot.validate(version)?;
        Ok(snapshot)
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> { bytes.try_into().map_err(|_| CommunityError::Cache) }
fn hex_id(hex: &str) -> Result<[u8; 16]> {
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err(CommunityError::Cache); }
    let mut bytes = [0; 16];
    for (i, byte) in bytes.iter_mut().enumerate() { *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| CommunityError::Cache)?; }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommunityRefreshReport { pub full_recompute: bool, pub changed_entities: usize, pub recomputed_entities: usize }

pub struct CommunityGraphInput<'a> {
    pub entities: &'a [EntityId],
    pub edges: &'a [CommunityEdge],
    pub changed: &'a [EntityId],
    pub graph_version: u64,
}

/// Full snapshot input; incremental work is restricted to the union of affected
/// old coarse communities and current connected components. Frontier completeness
/// is an adapter obligation. Empty frontier with a new version means unknown churn.
pub fn compute_communities(
    input: &CommunityGraphInput<'_>, previous: Option<&CommunitySnapshot>,
    now: u64, config: &PprCommunityConfig,
) -> Result<(CommunitySnapshot, CommunityRefreshReport)> {
    let CommunityGraphInput { entities, edges, changed, graph_version } = *input;
    config.validate()?;
    let projection = project_graph(entities, edges)?;
    let current: BTreeSet<_> = projection.entities.iter().copied().collect();
    let mut frontier: BTreeSet<_> = changed.iter().copied().collect();
    if let Some(old) = previous {
        old.validate(old.meta.graph_version)?;
        let old_nodes: BTreeSet<_> = old.nodes.keys().copied().collect();
        frontier.extend(current.symmetric_difference(&old_nodes).copied());
        if graph_version < old.meta.graph_version || (graph_version == old.meta.graph_version && !frontier.is_empty()) {
            return Err(CommunityError::Version);
        }
    }
    let full = previous.is_none() || frontier.len().saturating_mul(20) > current.len()
        || previous.is_some_and(|old| old.meta.graph_version != graph_version && changed.is_empty());
    let affected = if full { current.clone() } else { affected_entities(&projection, previous, &frontier) };
    let graph = Graph::from_projection(&projection, &affected);
    let (mut fine, mut coarse) = leiden(graph);
    if let Some(old) = previous.filter(|_| !full) {
        let mut fine_ids = BTreeSet::new(); let mut coarse_ids = BTreeSet::new();
        for (&id, m) in &old.nodes {
            if current.contains(&id) && !affected.contains(&id) { fine_ids.insert(m.fine); coarse_ids.insert(m.coarse); }
        }
        for id in fine_ids { fine.push(old.members[&id].clone()); }
        for id in coarse_ids { coarse.push(old.members[&id].clone()); }
    }
    let meta = CommunityCacheMeta { schema: PPR_COMMUNITY_SCHEMA_VERSION, graph_version, gamma: config.gamma, generated_at: now };
    let snapshot = CommunitySnapshot::from_partitions(meta, &fine, &coarse)?;
    Ok((snapshot, CommunityRefreshReport { full_recompute: full, changed_entities: frontier.len(), recomputed_entities: affected.len() }))
}

fn affected_entities(p: &CommunityProjection, old: Option<&CommunitySnapshot>, frontier: &BTreeSet<EntityId>) -> BTreeSet<EntityId> {
    let mut adj: BTreeMap<EntityId, Vec<EntityId>> = BTreeMap::new();
    for &(a, b) in p.edges.keys() { adj.entry(a).or_default().push(b); adj.entry(b).or_default().push(a); }
    let mut seen = frontier.clone(); let mut queue: Vec<_> = frontier.iter().copied().collect();
    let mut expanded = BTreeSet::new();
    while let Some(id) = queue.pop() {
        let mut neighbors = adj.get(&id).cloned().unwrap_or_default();
        if let Some(old) = old
            && let Some(m) = old.nodes.get(&id).filter(|m| expanded.insert(m.coarse))
        {
            neighbors.extend(&old.members[&m.coarse]);
        }
        for next in neighbors { if seen.insert(next) { queue.push(next); } }
    }
    seen.retain(|id| p.entities.binary_search(id).is_ok()); seen
}

/// A validated read view. Version must come from the same graph read transaction.
pub struct PprCommunityCache<'a> { snapshot: &'a CommunitySnapshot }
impl<'a> PprCommunityCache<'a> {
    pub fn new(snapshot: &'a CommunitySnapshot, graph_version: u64) -> Result<Self> {
        snapshot.validate(graph_version)?; Ok(Self { snapshot })
    }
}

pub struct CommunityBoostContext<'a> {
    pub ordered_seeds: &'a [ScoredEntity],
    pub result_limit: usize,
    pub session_usage: &'a HashMap<CommunityId, u32>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CommunityBoostReport {
    pub activated_communities: usize,
    pub boosted_candidates: usize,
    pub fine_entropy_bits: f64,
    pub coarse_entropy_bits: f64,
}

/// Exact cache-key bypass at beta zero. Adapter appends this only on Uniform PPR;
/// other config/seed/session inputs must also be accounted for or reranked uncached.
pub fn community_cache_identity(beta: f32, graph_version: u64) -> Result<Option<[u8; 12]>> {
    if beta == 0.0 { return Ok(None); }
    if !beta.is_finite() || beta < 0.0 { return Err(CommunityError::Config); }
    let mut bytes = [0; 12]; bytes[..8].copy_from_slice(&graph_version.to_le_bytes());
    bytes[8..].copy_from_slice(&beta.to_bits().to_le_bytes()); Ok(Some(bytes))
}

pub fn activated_communities(cache: &PprCommunityCache<'_>, seeds: &[ScoredEntity]) -> Result<BTreeSet<CommunityId>> {
    validate_scores(seeds)?;
    if seeds.windows(2).any(|w| w[0].score < w[1].score) { return Err(CommunityError::Scores); }
    let mut active = BTreeSet::new();
    if seeds.is_empty() { return Ok(active); }
    let membership = |s: &ScoredEntity| cache.snapshot.nodes.get(&s.id).map(|m| m.fine);
    if (seeds.len() == 1 || (seeds[0].score > 0.0 && f64::from(seeds[0].score) >= 1.5 * f64::from(seeds[1].score)))
        && let Some(id) = membership(&seeds[0])
    {
        active.insert(id);
    }
    let mut counts = BTreeMap::new();
    for seed in seeds.iter().take(5) {
        if let Some(id) = membership(seed) { *counts.entry(id).or_insert(0) += 1; }
    }
    active.extend(counts.into_iter().filter_map(|(id, count)| (count >= 2).then_some(id)));
    Ok(active)
}

fn validate_scores(scores: &[ScoredEntity]) -> Result<()> {
    let mut ids = BTreeSet::new();
    if scores.iter().any(|s| !s.score.is_finite() || s.score < 0.0 || !ids.insert(s.id)) { return Err(CommunityError::Scores); }
    Ok(())
}

pub fn community_multiplier(size: usize, graph_size: usize, usage: u32, config: &PprCommunityConfig) -> Result<f32> {
    if config.beta == 0.0 { return Ok(1.0); }
    config.validate()?;
    let oversized = if config.max_graph_fraction == PPR_COMMUNITY_MAX_GRAPH_FRACTION {
        size as u128 * 10 > graph_size as u128
    } else { size as f64 > graph_size as f64 * f64::from(config.max_graph_fraction) };
    if size == 0 || graph_size == 0 || oversized { return Ok(1.0); }
    let bonus = f64::from(config.beta) / (size as f64).ln_1p();
    let decay = (-f64::from(PPR_COMMUNITY_USAGE_DECAY) * f64::from(usage)).exp();
    Ok((1.0 + bonus * decay).min(f64::from(config.multiplier_cap)) as f32)
}

/// Beta zero returns before validation, copying, sorting, truncation or arithmetic.
/// Standalone PPR callers select here; the pipeline defers selection until fusion,
/// admission filters, reranking and budgets have finished.
pub fn apply_community_prior(
    scores: &mut Vec<ScoredEntity>, cache: &PprCommunityCache<'_>,
    context: &CommunityBoostContext<'_>, config: &PprCommunityConfig,
) -> Result<CommunityBoostReport> {
    let (mut report, boosted) = boost_community_scores(scores, cache, context, config)?;
    if report.activated_communities > 0 {
        let diversity = apply_community_diversity(scores, cache, &boosted, context.result_limit, config)?;
        report.fine_entropy_bits = diversity.fine_entropy_bits;
        report.coarse_entropy_bits = diversity.coarse_entropy_bits;
    }
    Ok(report)
}

/// Apply the multiplier once without dropping candidates needed by later filters.
pub(crate) fn boost_community_scores(
    scores: &mut Vec<ScoredEntity>, cache: &PprCommunityCache<'_>,
    context: &CommunityBoostContext<'_>, config: &PprCommunityConfig,
) -> Result<(CommunityBoostReport, BTreeSet<EntityId>)> {
    let mut boosted_ids = BTreeSet::new();
    if config.beta == 0.0 { return Ok((CommunityBoostReport::default(), boosted_ids)); }
    config.validate()?; validate_scores(scores)?;
    let active = activated_communities(cache, context.ordered_seeds)?;
    if active.is_empty() { return Ok((CommunityBoostReport::default(), boosted_ids)); }
    let mut ranked = Vec::with_capacity(scores.len());
    let mut report = CommunityBoostReport { activated_communities: active.len(), ..Default::default() };
    for &candidate in scores.iter() {
        let membership = cache.snapshot.nodes.get(&candidate.id).copied();
        let mut multiplier = 1.0;
        if let Some(m) = membership.filter(|m| active.contains(&m.fine)) {
            multiplier = community_multiplier(cache.snapshot.members[&m.fine].len(), cache.snapshot.nodes.len(),
                *context.session_usage.get(&m.fine).unwrap_or(&0), config)?;
        }
        if multiplier > 1.0 && candidate.score > 0.0 { boosted_ids.insert(candidate.id); }
        let score = candidate.score * multiplier;
        if !score.is_finite() { return Err(CommunityError::Scores); }
        ranked.push(ScoredEntity { score, ..candidate });
    }
    report.boosted_candidates = boosted_ids.len();
    ranked.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    *scores = ranked;
    Ok((report, boosted_ids))
}

/// Select only from admitted final candidates. Never expand membership into rows,
/// reapply the prior, or truncate a PPR channel before fusion and filtering.
pub(crate) fn apply_community_diversity(
    scores: &mut Vec<ScoredEntity>, cache: &PprCommunityCache<'_>,
    boosted: &BTreeSet<EntityId>, limit: usize, config: &PprCommunityConfig,
) -> Result<CommunityBoostReport> {
    if config.beta == 0.0 { return Ok(CommunityBoostReport::default()); }
    config.validate()?; validate_scores(scores)?;
    let ranked = scores.iter().map(|&entity| Ranked { entity,
        membership: cache.snapshot.nodes.get(&entity.id).copied(), boosted: boosted.contains(&entity.id) }).collect();
    let selected = diversify(ranked, limit, config.max_top_k_fraction);
    let report = CommunityBoostReport { fine_entropy_bits: entropy(&selected, false),
        coarse_entropy_bits: entropy(&selected, true), ..Default::default() };
    *scores = selected.into_iter().map(|r| r.entity).collect(); Ok(report)
}

#[derive(Clone, Copy)]
struct Ranked { entity: ScoredEntity, membership: Option<CommunityMembership>, boosted: bool }

fn diversify(mut pool: Vec<Ranked>, limit: usize, fraction: f32) -> Vec<Ranked> {
    let k = limit.min(pool.len());
    if k == 0 { return Vec::new(); }
    // Exact rational default avoids floor(10 * f64::from(0.7_f32)) == 6.
    let cap = if fraction == PPR_COMMUNITY_MAX_TOP_K_FRACTION {
        (k / 10 * 7 + k % 10 * 7 / 10).max(1)
    } else { ((k as f64 * f64::from(fraction)).floor() as usize).max(1) };
    let mut fine = BTreeMap::new(); let mut coarse = BTreeMap::new();
    // Reserve capacity BEFORE selecting boosted rows. A last-slot replacement
    // could exceed the fine cap when the only unboosted row shares that community.
    let protected = pool.iter().enumerate().filter(|(_, r)| !r.boosted)
        .min_by(|(_, a), (_, b)| b.entity.score.total_cmp(&a.entity.score).then_with(|| a.entity.id.cmp(&b.entity.id)))
        .map(|(i, _)| i).map(|i| pool.remove(i));
    if let Some(m) = protected.and_then(|r| r.membership) { fine.insert(m.fine, 1); coarse.insert(m.coarse, 1); }
    let mut selected: Vec<Ranked> = Vec::with_capacity(k);
    while selected.len() + usize::from(protected.is_some()) < k {
        let under_cap = |r: &Ranked| r.membership.is_none_or(|m| *fine.get(&m.fine).unwrap_or(&0) < cap);
        let enforce = pool.iter().any(under_cap);
        let novelty = |r: &Ranked| r.membership.map_or((0, 0), |m| (*fine.get(&m.fine).unwrap_or(&0), *coarse.get(&m.coarse).unwrap_or(&0)));
        // Community MMR is a score-tie breaker: prefer fewer fine matches, then
        // fewer coarse matches, then entity ID. It never changes score bits.
        let best = pool.iter().enumerate().filter(|(_, r)| !enforce || under_cap(r))
            .min_by(|(_, a), (_, b)| b.entity.score.total_cmp(&a.entity.score)
                .then_with(|| novelty(a).cmp(&novelty(b))).then_with(|| a.entity.id.cmp(&b.entity.id)))
            .map(|(i, _)| i);
        let Some(best) = best else { break; };
        let row = pool.remove(best);
        if let Some(m) = row.membership { *fine.entry(m.fine).or_insert(0) += 1; *coarse.entry(m.coarse).or_insert(0) += 1; }
        selected.push(row);
    }
    if let Some(row) = protected {
        let position = selected.iter().position(|r| r.entity.score < row.entity.score).unwrap_or(selected.len());
        selected.insert(position, row);
    }
    selected
}

fn entropy(rows: &[Ranked], coarse: bool) -> f64 {
    let mut counts = BTreeMap::new();
    for row in rows {
        // Uncached entities count as separate alternatives, not one fake community.
        let key = row.membership.map_or((None, Some(row.entity.id)), |m| (Some(if coarse { m.coarse } else { m.fine }), None));
        *counts.entry(key).or_insert(0usize) += 1;
    }
    counts.values().map(|&n| { let p = n as f64 / rows.len() as f64; -p * p.log2() }).sum()
}

/// Executes the canonical-vault Uniform round path with ordered seed evidence.
/// This returns PPR scores, not the pipeline's final fused ranking. It does not
/// replace an actor-scoped read or an off-record session query. Beta zero calls
/// the original PPR path directly, including its existing cache identity.
pub fn expand_ppr(
    vault: &crate::Vault,
    depth: u32,
    context: &CommunityBoostContext<'_>,
) -> crate::error::Result<(Vec<ScoredEntity>, CommunityBoostReport)> {
    let mut seeds: Vec<_> = context.ordered_seeds.iter().map(|seed| seed.id).collect();
    seeds.sort_unstable();
    let (scores, write, report) = {
        let txn = vault.store.env.read_txn()?;
        crate::ppr::ppr_query_in_txn_with_community_deferred_cache(
            &vault.store,
            &txn,
            crate::ppr::CommunityPprRequest {
                seeds: &seeds,
                depth,
                teleport_alpha: 0.15,
                weighting: crate::ppr::SeedWeighting::Uniform,
                config: &vault.config,
                context,
            },
        )?
    };
    if let Some(write) = write {
        crate::ppr::flush_deferred_ppr_cache_writes(&vault.store, &[write])?;
    }
    Ok((scores, report))
}

/// Preserves fused evidence before the base PPR path sorts seed IDs. An explicit
/// seed absent from the fused list has zero evidence, not a fabricated advantage.
pub fn ordered_seed_evidence(seeds: &[EntityId], fused: &[ScoredEntity]) -> Result<Vec<ScoredEntity>> {
    validate_scores(fused)?;
    let evidence: HashMap<_, _> = fused.iter().map(|seed| (seed.id, seed.score)).collect();
    let mut ordered: Vec<_> = seeds.iter().copied().collect::<BTreeSet<_>>().into_iter()
        .map(|id| ScoredEntity { id, score: *evidence.get(&id).unwrap_or(&0.0) }).collect();
    ordered.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    Ok(ordered)
}

/// Refreshes the canonical vault cache atomically. `changed` must contain every
/// changed edge endpoint since the previous snapshot, including deleted IDs.
/// An empty frontier at a newer graph version means unknown churn and forces a
/// full recomputation. This cache must never be used for an actor-scoped walk.
pub fn refresh_communities(
    store: &crate::store::Store,
    changed: &[EntityId],
    now: u64,
    config: &PprCommunityConfig,
) -> crate::error::Result<CommunityRefreshReport> {
    store.refresh_ppr_communities(changed, now, config)
}

impl crate::Vault {
    /// Refreshes the local, canonical-vault community cache. This does not enable
    /// boosting; production beta stays zero unless the caller explicitly opts in.
    pub fn refresh_ppr_communities(
        &self,
        changed: &[EntityId],
        now: u64,
    ) -> crate::error::Result<CommunityRefreshReport> {
        refresh_communities(&self.store, changed, now, &self.config.ppr_community)
    }

    /// Reads current canonical-vault membership. Stale snapshots return `None`.
    /// This is not an actor-scoped or session-composed disclosure API.
    pub fn ppr_community_membership(
        &self,
        entity: &EntityId,
    ) -> crate::error::Result<Option<CommunityMembership>> {
        let txn = self.store.env.read_txn()?;
        self.store.ppr_community_membership_in_txn(&txn, entity)
    }
}

#[cfg(test)]
mod tests;
