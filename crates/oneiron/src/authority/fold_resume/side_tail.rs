//! A resumed fold's tail as a small DAG (FIX 4881): the main rows still one
//! chain off the base's main head, and beside them a world's key records
//! (`WorldKeyWraps`, the side rows), each on frontier states the base kept
//! (its main head, or a side leaf of the record's own world) and on earlier
//! tail rows, folded parents first. Every row still folds through its own
//! transition on its actual parents' states: nothing here counts or
//! validates a row. A row naming anything else (a covered row off the
//! frontier, a leaf of another world, a stateless row) declines, and the
//! caller folds the whole log.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;
use crate::authority::world_privacy::side_world;

/// A frontier row a tail row may name: its fold state (a summary is no fold
/// state), and its ancestors and counted ancestors as
/// `entry_ancestor_index` counts them.
#[derive(Clone)]
pub(super) struct FrontierPoint {
    pub(super) state: Arc<FoldState>,
    pub(super) ancestors: u64,
    pub(super) counted_ancestors: u64,
}

/// The frontier a once fold keeps for a resumed one: its one main `head`
/// and each side row no row names, each with its state. `None` when the
/// head has no state.
pub(super) fn frontier_of(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    entry_ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    uncounted: &BTreeSet<AuthorityEntryHash>,
    head: AuthorityEntryHash,
) -> Option<BTreeMap<AuthorityEntryHash, FrontierPoint>> {
    let named: BTreeSet<_> = by_hash
        .values()
        .flat_map(|entry| entry.parent_hashes.iter())
        .collect();
    let leaves = by_hash
        .iter()
        .filter(|(hash, entry)| side_world(&entry.op).is_some() && !named.contains(hash))
        .map(|(hash, _)| *hash);
    let frontier: BTreeMap<_, _> = std::iter::once(head)
        .chain(leaves)
        .filter_map(|hash| {
            let past = entry_ancestors.get(&hash)?;
            let point = FrontierPoint {
                state: Arc::new(states.get(&hash)?.clone()),
                ancestors: past.len() as u64,
                counted_ancestors: past.iter().filter(|row| !uncounted.contains(*row)).count()
                    as u64,
            };
            Some((hash, point))
        })
        .collect();
    frontier.contains_key(&head).then_some(frontier)
}

/// The new rows past a base, folded on its frontier.
pub(super) struct FoldedTail {
    /// The new rows, parents first.
    pub(super) order: Vec<AuthorityEntryHash>,
    /// The new main rows: the writer frontiers and bound keys read them
    /// alone, as a full fold's do.
    pub(super) main: BTreeSet<AuthorityEntryHash>,
    /// The main chain's tip: the next base's main head.
    pub(super) tip: AuthorityEntryHash,
    /// Each new row's state.
    pub(super) states: BTreeMap<AuthorityEntryHash, FoldState>,
    /// Each new row's ancestors and counted ancestors.
    pub(super) ancestry: BTreeMap<AuthorityEntryHash, (u64, u64)>,
    pub(super) uncounted: BTreeSet<AuthorityEntryHash>,
    pub(super) pairs: u64,
    pub(super) counted_pairs: u64,
    pub(super) confirms: ConfirmKeys,
}

/// `new_rows`, the stored rows past `once`'s base, folded on its frontier,
/// with the whole log's pairs and counted pairs; None wherever the whole
/// log must fold instead. `base_rows` is the base's summary of each row it
/// folded.
pub(super) fn fold_tail(
    once: &Once,
    base_rows: &BTreeMap<AuthorityEntryHash, RowSummary>,
    new_rows: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    context: FoldContext<'_>,
) -> Option<FoldedTail> {
    let (order, main, tip) = shape(once, base_rows, new_rows)?;
    let settlement = &once.settlement;
    let mut confirms = (once.confirm_ids.clone(), once.confirm_nonces.clone());
    for hash in &order {
        let entry = new_rows[hash];
        let retired = std::iter::once(&entry.signer)
            .chain(&entry.cosigns)
            .any(|signature| settlement.retired_keys.contains(&signature.public_key));
        let below_floor = context
            .sequence_floors
            .and_then(|floors| floors.get(hash))
            .is_some_and(|floor| entry.seq < *floor);
        if settlement.missing_parents.contains(hash)
            || below_floor
            || retired
            || !once.admits(entry, &mut confirms)
        {
            return None;
        }
    }
    // The memory floor and counted pairs over the whole log, exactly as
    // `entry_ancestor_index` counts them. The tail adds no slip issuer, so
    // only its own slip rows join the uncounted.
    let mut uncounted = once.uncounted.clone();
    uncounted.extend(
        order.iter().filter(|hash| {
            crate::authority::log_budget::is_uncounted(new_rows[*hash], &once.issuers)
        }),
    );
    let past = Past {
        new_rows,
        judged: &once.judged,
        base_rows,
    };
    let counted = |hash: &AuthorityEntryHash| u64::from(!uncounted.contains(hash));
    let rows = once.judged.len() + new_rows.len();
    let (mut pairs, mut counted_pairs) = (once.pairs, once.counted_pairs);
    let mut ancestry = BTreeMap::<AuthorityEntryHash, (u64, u64)>::new();
    for hash in &order {
        let parents = past.parents(hash);
        let point = |parent: &AuthorityEntryHash| {
            ancestry.get(parent).copied().or_else(|| {
                let point = once.frontier.get(parent)?;
                Some((point.ancestors, point.counted_ancestors))
            })
        };
        // A row on one parent with known counts adds that parent's
        // ancestry and the parent; a join walks its exact union.
        let single = match parents {
            [parent] => point(parent).map(|(ancestors, counted_ancestors)| {
                (ancestors + 1, counted_ancestors + counted(parent))
            }),
            _ => None,
        };
        let (ancestors, counted_ancestors) = single.unwrap_or_else(|| {
            let mut seen = BTreeSet::new();
            let mut stack = parents.to_vec();
            while let Some(at) = stack.pop() {
                if seen.insert(at) {
                    stack.extend_from_slice(past.parents(&at));
                }
            }
            (seen.len() as u64, seen.iter().map(counted).sum())
        });
        ancestry.insert(*hash, (ancestors, counted_ancestors));
        pairs = pairs.saturating_add(ancestors);
        counted_pairs = counted_pairs.saturating_add(counted(hash) * counted_ancestors);
        if crate::authority::log_budget::fold_projected_bytes(rows, pairs)
            > context.memory_floor_bytes
        {
            return None;
        }
    }
    // Each new row folds on its actual parents' states as the scheduler
    // folds it, the frontier's kept states seeding it.
    let mut states = BTreeMap::new();
    for parent in order.iter().flat_map(|hash| &new_rows[hash].parent_hashes) {
        if let Some(point) = once.frontier.get(parent) {
            states
                .entry(*parent)
                .or_insert_with(|| FoldState::clone(&point.state));
        }
    }
    for hash in &order {
        let EntryFold::Ready(state) = crate::authority::entry_transition::fold_entry_state(
            new_rows[hash],
            *hash,
            &states,
            context,
        ) else {
            return None;
        };
        if state.federation_pacts != once.merged.federation_pacts {
            return None;
        }
        states.insert(*hash, state);
    }
    states.retain(|hash, _| new_rows.contains_key(hash));
    Some(FoldedTail {
        order,
        main,
        tip,
        states,
        ancestry,
        uncounted,
        pairs,
        counted_pairs,
        confirms,
    })
}

/// The tail's order and shape: the new main rows one chain off the base's
/// main head, as before, and each side row on main rows, on its own world's
/// side rows, and on frontier states or tail rows alone. The rows parents
/// first, the main ones, and the main chain's tip; None for any other shape.
fn shape(
    once: &Once,
    base_rows: &BTreeMap<AuthorityEntryHash, RowSummary>,
    new_rows: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> Option<(
    Vec<AuthorityEntryHash>,
    BTreeSet<AuthorityEntryHash>,
    AuthorityEntryHash,
)> {
    let mut next = BTreeMap::new();
    for (hash, entry) in new_rows {
        let Some(world) = side_world(&entry.op) else {
            let [parent] = entry.parent_hashes.as_slice() else {
                return None;
            };
            if next.insert(*parent, *hash).is_some() {
                return None;
            }
            continue;
        };
        let stands = entry.parent_hashes.iter().all(|parent| {
            let parent_world = match new_rows.get(parent) {
                Some(row) => side_world(&row.op),
                None if once.frontier.contains_key(parent) => {
                    base_rows.get(parent).and_then(|row| row.world)
                }
                None => return false,
            };
            parent_world.is_none_or(|parent_world| parent_world == world)
        });
        if !stands {
            return None;
        }
    }
    let mut main = BTreeSet::new();
    let mut tip = once.head;
    while let Some(child) = next.get(&tip) {
        main.insert(*child);
        tip = *child;
    }
    if main.len() != next.len() {
        return None;
    }
    let order = parents_first(new_rows)?;
    Some((order, main, tip))
}

/// `rows`' hashes, each after every parent of it among `rows`, ties by
/// hash; None when some row is on a cycle.
fn parents_first(
    rows: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> Option<Vec<AuthorityEntryHash>> {
    let mut waiting = BTreeMap::new();
    let mut children = BTreeMap::<_, Vec<_>>::new();
    let mut ready = BTreeSet::new();
    for (hash, entry) in rows {
        let parents: BTreeSet<_> = entry
            .parent_hashes
            .iter()
            .filter(|parent| rows.contains_key(*parent))
            .collect();
        for parent in &parents {
            children.entry(**parent).or_default().push(*hash);
        }
        if parents.is_empty() {
            ready.insert(*hash);
        } else {
            waiting.insert(*hash, parents.len());
        }
    }
    let mut order = Vec::with_capacity(rows.len());
    while let Some(hash) = ready.pop_first() {
        order.push(hash);
        for child in children.get(&hash).into_iter().flatten() {
            if let Some(count) = waiting.get_mut(child) {
                *count -= 1;
                if *count == 0 {
                    waiting.remove(child);
                    ready.insert(*child);
                }
            }
        }
    }
    waiting.is_empty().then_some(order)
}

/// The parents an ancestor walk reads, as `entry_ancestor_index` reads them
/// over the whole log: a new row's, a judged base row's from its summary,
/// and none of any other row.
struct Past<'a> {
    new_rows: &'a BTreeMap<AuthorityEntryHash, &'a AuthorityLogEntry>,
    judged: &'a BTreeSet<AuthorityEntryHash>,
    base_rows: &'a BTreeMap<AuthorityEntryHash, RowSummary>,
}

impl<'a> Past<'a> {
    fn parents(&self, hash: &AuthorityEntryHash) -> &'a [AuthorityEntryHash] {
        if let Some(entry) = self.new_rows.get(hash) {
            return &entry.parent_hashes;
        }
        match self.base_rows.get(hash) {
            Some(row) if self.judged.contains(hash) => &row.parents,
            _ => &[],
        }
    }
}

impl FoldedTail {
    /// The frontier the next base keeps once this tail joined `once`'s: the
    /// main chain's tip, each old side leaf no new row names, and each new
    /// side row no new row names, each new one's state taken from the tail.
    pub(super) fn take_frontier(
        &mut self,
        once: &Once,
        new_rows: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    ) -> BTreeMap<AuthorityEntryHash, FrontierPoint> {
        let named: BTreeSet<_> = new_rows
            .values()
            .flat_map(|entry| entry.parent_hashes.iter())
            .collect();
        let mut frontier: BTreeMap<_, _> = once
            .frontier
            .iter()
            .filter(|(hash, _)| **hash != once.head && !named.contains(hash))
            .map(|(hash, point)| (*hash, point.clone()))
            .collect();
        if let Some(point) = once.frontier.get(&self.tip) {
            frontier.insert(self.tip, point.clone());
        }
        let (tip, main) = (self.tip, &self.main);
        let leaves: Vec<_> = new_rows
            .keys()
            .filter(|hash| **hash == tip || (!main.contains(*hash) && !named.contains(hash)))
            .copied()
            .collect();
        for hash in leaves {
            if let (Some(state), Some((ancestors, counted_ancestors))) =
                (self.states.remove(&hash), self.ancestry.get(&hash).copied())
            {
                let point = FrontierPoint {
                    state: Arc::new(state),
                    ancestors,
                    counted_ancestors,
                };
                frontier.insert(hash, point);
            }
        }
        frontier
    }
}
