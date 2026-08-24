//! Edge loading and multi-hop neighbor expansion during pack assembly.
//!
//! Carries its own `#[cfg(test)]` scan instrumentation, which the module's tests
//! read directly.

#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};

use heed::RoTxn;

use crate::disclosure::DisclosureContext;
use crate::edge::{EdgeConfirmationStatus, EdgeInfo, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

use super::validation::disclosure_admits_target;
use super::world_partition::claim_world_by_id;

#[cfg(not(test))]
pub(super) const MAX_EDGE_SCAN_RESULTS: usize = 100_000;
#[cfg(test)]
pub(super) const MAX_EDGE_SCAN_RESULTS: usize = 64;

#[cfg(test)]
thread_local! {
    pub(super) static EDGE_SCAN_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Default)]
pub(super) struct EdgeWalkResult {
    pub(super) neighbor_ids: Vec<EntityId>,
    pub(super) scanned_edges: HashMap<EntityId, Vec<EdgeInfo>>,
}

pub(super) fn load_entity_edges(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    edge_cache: Option<&HashMap<EntityId, Vec<EdgeInfo>>>,
    clamp: Option<&DisclosureContext>,
) -> Result<Vec<EdgeInfo>> {
    let edges = if let Some(edges) = edge_cache.and_then(|cache| cache.get(id)) {
        edges.clone()
    } else {
        scan_edges_for_entity(store, rtxn, id)?
    };
    // ARCH-0052 P6: no off-record subtraction here. A base edge cannot name a
    // live overlay member — the K4 taint guard rejects that write — and a
    // session's own edges are overlay rows a canonical reader cannot address.
    // The OF-365 clamp below is the only target filter this list needs.
    let mut kept = Vec::with_capacity(edges.len());
    for edge in edges {
        if !disclosure_admits_target(store, rtxn, clamp, &edge.target)? {
            continue;
        }
        kept.push(edge);
    }
    Ok(kept)
}

/// Scans the outbound edge rows for one entity, failing closed on any
/// malformed row.
///
/// Every row is parsed through [`crate::vault::parse_edge_record`] so the
/// context-pack read path (result-edge hydration and the `walk_edges`
/// neighbor expansion) classifies corruption exactly like the canonical
/// vault readers (`edges_out` / `edges_in` / `targets` / `sources`): a key
/// that is not 33 bytes, an unknown edge-kind byte, a reserved target id,
/// or a value whose length is not a valid layout for the kind (12/24/26 B
/// per ARCH-0034) returns `Error::CorruptedIndex("edge record")` — never a
/// silent skip (ONE-1101 / pinned decision D9).
pub(super) fn scan_edges_for_entity(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EdgeInfo>> {
    #[cfg(test)]
    EDGE_SCAN_COUNT.with(|count| count.set(count.get().saturating_add(1)));

    let mut edges = Vec::new();

    for entry in store.edges_out.prefix_iter(rtxn, id.as_bytes())? {
        let (key, value) = entry?;
        if edges.len() >= MAX_EDGE_SCAN_RESULTS {
            return Err(Error::CorruptedIndex("edge scan exceeded bound"));
        }
        edges.push(crate::vault::parse_edge_record(&key, &value)?);
    }

    Ok(edges)
}

/// Read-side policy for one neighbor expansion.
#[derive(Clone, Copy)]
pub(super) struct EdgeWalkOptions<'a> {
    pub(super) hops: u32,
    pub(super) budget: usize,
    /// Ids already surfaced as results: never re-admitted as neighbors.
    pub(super) exclude: &'a HashSet<EntityId>,
    /// OF-365 disclosure clamp.
    pub(super) clamp: Option<&'a DisclosureContext>,
    /// ONE-1411: `Some` only for the scopes that drop stale federated claims
    /// from the candidate set (`All` / `Base`). The explicit world scopes pass
    /// `None` because naming a dead world is a request to read it, and the
    /// caller marks what comes back instead of hiding it.
    pub(super) stale_worlds: Option<&'a BTreeMap<EntityId, crate::federation::WorldStaleStamp>>,
}

/// Expands the seed set along its edges under `options`.
pub(super) fn walk_edges(
    store: &Store,
    rtxn: &RoTxn<'_>,
    seed_ids: &[EntityId],
    options: EdgeWalkOptions<'_>,
) -> Result<EdgeWalkResult> {
    let EdgeWalkOptions {
        hops,
        budget,
        exclude,
        clamp,
        stale_worlds,
    } = options;
    if hops == 0 || budget == 0 || seed_ids.is_empty() {
        return Ok(EdgeWalkResult::default());
    }

    let mut visited = HashSet::with_capacity(budget);
    let mut ordered_neighbors = Vec::with_capacity(budget);
    let mut frontier = seed_ids.to_vec();
    frontier.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut scanned_edges = HashMap::<EntityId, Vec<EdgeInfo>>::new();

    for _ in 0..hops {
        if frontier.is_empty() || visited.len() >= budget {
            break;
        }

        let mut candidates = HashMap::<EntityId, f32>::new();

        for id in &frontier {
            if !scanned_edges.contains_key(id) {
                scanned_edges.insert(*id, scan_edges_for_entity(store, rtxn, id)?);
            }

            let Some(edges) = scanned_edges.get(id) else {
                continue;
            };
            for edge in edges {
                // `child_of` / `assigned_to` / `blocked_by` are STRUCTURAL
                // plumbing with no retrieval scoring (ARCH-0004 edgeKinds:
                // lambda null, "Not traversed.") — never neighbor-expanded
                // regardless of the stored weight bytes. They still hydrate on
                // the seed's own edge list; only the walk skips them.
                if matches!(
                    edge.kind,
                    EdgeKind::ChildOf | EdgeKind::AssignedTo | EdgeKind::BlockedBy
                ) {
                    continue;
                }
                // D8-consistent: a provenanced edge whose hot flag says
                // retracted contributes nothing to expansion. Unlike PPR
                // (λ_opposes = 0), `opposes` IS followed here — a surfaced
                // contradiction is useful context-pack signal.
                if edge.provenance.is_some_and(|flags| {
                    flags.confirmation_status == EdgeConfirmationStatus::Retracted
                }) {
                    continue;
                }
                if exclude.contains(&edge.target) || visited.contains(&edge.target) {
                    continue;
                }
                // OF-365 clamp (enforcement point 2): a non-admitted entity
                // is never admitted as a neighbor NOR traversed through.
                if !disclosure_admits_target(store, rtxn, clamp, &edge.target)? {
                    continue;
                }
                // ONE-1411, on the same rule: content the scope already
                // dropped for being stale is never admitted as a neighbor NOR
                // traversed through, so it cannot spend the edge budget it was
                // excluded from either.
                if let Some(stale) = stale_worlds
                    && claim_world_by_id(store, rtxn, &edge.target)?
                        .is_some_and(|world| stale.contains_key(&world))
                {
                    continue;
                }
                candidates
                    .entry(edge.target)
                    .and_modify(|best_weight| {
                        if edge.weight.total_cmp(best_weight).is_gt() {
                            *best_weight = edge.weight;
                        }
                    })
                    .or_insert(edge.weight);
            }
        }

        if candidates.is_empty() {
            break;
        }

        let remaining = budget.saturating_sub(visited.len());
        let mut next_frontier: Vec<(EntityId, f32)> = candidates.into_iter().collect();
        next_frontier.sort_unstable_by(|a, b| {
            b.1.total_cmp(&a.1)
                .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });
        next_frontier.truncate(remaining);

        frontier = next_frontier
            .into_iter()
            .map(|(id, _)| {
                visited.insert(id);
                ordered_neighbors.push(id);
                id
            })
            .collect();
    }

    Ok(EdgeWalkResult {
        neighbor_ids: ordered_neighbors,
        scanned_edges,
    })
}
