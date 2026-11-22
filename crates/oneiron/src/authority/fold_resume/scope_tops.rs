//! Each signer's top rows per sequence scope in a base, so that a fold past
//! it takes only new rows that move no row's sequence floor (`rows_floor`).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;
use crate::authority::world_privacy::side_world;

/// Each signer's top rows among a side row and its ancestors along its
/// world's rows, as a walk down from the row that passes only through held
/// rows of its world reads them: the signer's highest sequence there, and
/// every row of the signer at it.
type SignerTops = im::OrdMap<AuthorityKey, Arc<(u64, BTreeSet<AuthorityEntryHash>)>>;

/// Per signer and sequence scope (`world_privacy::side_world`): the highest
/// sequence among the base's rows and the rows at it. Beside them, the
/// [`SignerTops`] at each side row of the base's frontier.
#[derive(Clone, Default)]
pub(super) struct ScopeTops {
    tops: im::OrdMap<(AuthorityKey, Option<EntityId>), Arc<(u64, Vec<AuthorityEntryHash>)>>,
    /// A new side row stands on new rows, main rows and the frontier's side
    /// rows of its world alone (`side_tail::shape`), and no base row names a
    /// new one, so its world's rows below it are new rows and the rows at
    /// and below these (FIX [ADOPTED-FOLD-TAIL-WALK-SIGNER-COST]).
    leaves: im::OrdMap<AuthorityEntryHash, SignerTops>,
}

impl ScopeTops {
    /// The tops of `rows`, and the signer tops at each side row of them
    /// `frontier` holds.
    pub(super) fn of(
        rows: &[(AuthorityEntryHash, &AuthorityLogEntry)],
        frontier: impl Fn(&AuthorityEntryHash) -> bool,
    ) -> Self {
        let mut tops = BTreeMap::<_, (u64, Vec<_>)>::new();
        for (hash, entry) in rows {
            let key = (entry.signer_key().clone(), side_world(&entry.op));
            let top = tops.entry(key).or_insert((entry.seq, Vec::new()));
            if entry.seq > top.0 {
                *top = (entry.seq, Vec::new());
            }
            if entry.seq == top.0 {
                top.1.push(*hash);
            }
        }
        Self {
            tops: tops
                .into_iter()
                .map(|(key, top)| (key, Arc::new(top)))
                .collect(),
            leaves: frontier_signer_tops(rows, frontier).unwrap_or_default(),
        }
    }

    /// The tops with `order`'s rows, the new rows past the base parents
    /// first, added; None where one of them would move a row's floor or
    /// sit past its own. The base holds no row past its floor (`Once::of`),
    /// so each of its rows is an ancestor of every higher row of its signer
    /// and scope. A new main row lies on one chain off the base's one main
    /// head (`side_tail::shape`), so every earlier main row is among its
    /// ancestors, and it need only rise above its signer's top. A new side
    /// row must rise above its signer's top in its world and descend from
    /// every row at it, along that world's rows: the signer tops its parents
    /// carry, the new rows' and the frontier's, hold every row of that top
    /// exactly then. Every row of the signer there is at or below the top,
    /// so no other row can stand in for one.
    ///
    /// Cost: O(log K) per new row, for K signers in its world, and at a join
    /// O(m log K) for the m entries of each smaller map merged in. No base
    /// row is read, and no row is walked once per signer (FIX
    /// [ADOPTED-FOLD-TAIL-WALK-SIGNER-COST]). None too where a new side row
    /// stands on a base row of its world off the frontier, which
    /// `side_tail::fold_tail` declines first.
    pub(super) fn past(
        &self,
        base_rows: &BaseRows,
        new_rows: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
        order: &[AuthorityEntryHash],
    ) -> Option<Self> {
        let mut tops = self.tops.clone();
        let mut at = BTreeMap::<AuthorityEntryHash, SignerTops>::new();
        for hash in order {
            let entry = new_rows[hash];
            let world = side_world(&entry.op);
            let signer = entry.signer_key();
            let mut below = SignerTops::new();
            if world.is_some() {
                for parent in &entry.parent_hashes {
                    let parent_tops = match new_rows.get(parent) {
                        Some(row) if side_world(&row.op) == world => at.get(parent)?,
                        Some(_) => continue,
                        None if base_rows.get(parent).is_some_and(|row| row.world == world) => {
                            self.leaves.get(parent)?
                        }
                        None => continue,
                    };
                    below = joined(below, parent_tops.clone());
                }
            }
            let key = (signer.clone(), world);
            if let Some(top) = tops.get(&key) {
                let (top_seq, top_rows) = &**top;
                let descends = || {
                    below.get(signer).is_some_and(|reached| {
                        reached.0 == *top_seq && top_rows.iter().all(|row| reached.1.contains(row))
                    })
                };
                if entry.seq <= *top_seq || (world.is_some() && !descends()) {
                    return None;
                }
            }
            if world.is_some() {
                with_row(&mut below, signer, entry.seq, *hash);
                at.insert(*hash, below);
            }
            tops.insert(key, Arc::new((entry.seq, vec![*hash])));
        }
        // The next base's frontier side rows, as `FoldedTail::take_frontier`
        // keeps them: each old one no new row names, and each new side row
        // no new row names.
        let named: BTreeSet<_> = new_rows
            .values()
            .flat_map(|entry| &entry.parent_hashes)
            .collect();
        let mut leaves = self.leaves.clone();
        for hash in &named {
            leaves.remove(*hash);
        }
        for (hash, row_tops) in at {
            if !named.contains(&hash) {
                leaves.insert(hash, row_tops);
            }
        }
        Some(Self { tops, leaves })
    }
}

/// The [`SignerTops`] at each side row of `rows` that `frontier` holds, from
/// one pass over the side rows, each after its parents of its own world: a
/// row with one such parent shares that parent's map and adds itself, a join
/// merges each smaller map into the larger, and a row's map is dropped once
/// its last child has read it. A parent outside `rows` or of another scope
/// is not followed. None where a row comes before a parent of its world, as
/// only a cycle puts it, which no hash-linked log holds.
fn frontier_signer_tops(
    rows: &[(AuthorityEntryHash, &AuthorityLogEntry)],
    frontier: impl Fn(&AuthorityEntryHash) -> bool,
) -> Option<im::OrdMap<AuthorityEntryHash, SignerTops>> {
    let side: BTreeMap<_, _> = rows
        .iter()
        .filter_map(|(hash, entry)| Some((*hash, (side_world(&entry.op)?, *entry))))
        .collect();
    let links: BTreeMap<_, Vec<_>> = side
        .iter()
        .map(|(hash, (world, entry))| {
            let parents: BTreeSet<_> = entry
                .parent_hashes
                .iter()
                .filter(|parent| {
                    side.get(*parent)
                        .is_some_and(|(parent_world, _)| parent_world == world)
                })
                .copied()
                .collect();
            (*hash, parents.into_iter().collect())
        })
        .collect();
    let mut readers = BTreeMap::<AuthorityEntryHash, usize>::new();
    for parent in links.values().flatten() {
        *readers.entry(*parent).or_default() += 1;
    }
    let mut carried = BTreeMap::<AuthorityEntryHash, SignerTops>::new();
    let mut leaves = im::OrdMap::new();
    for hash in crate::authority::checkpoint_image::parents_first_of(&links) {
        let mut at = SignerTops::new();
        for parent in &links[&hash] {
            let left = readers.get_mut(parent)?;
            *left -= 1;
            let parent_tops = if *left == 0 {
                carried.remove(parent)?
            } else {
                carried.get(parent)?.clone()
            };
            at = joined(at, parent_tops);
        }
        let entry = side[&hash].1;
        with_row(&mut at, entry.signer_key(), entry.seq, hash);
        if frontier(&hash) {
            leaves.insert(hash, at.clone());
        }
        if readers.get(&hash).is_some_and(|left| *left > 0) {
            carried.insert(hash, at);
        }
    }
    Some(leaves)
}

/// The signer tops of two rows' ancestries together: each signer's higher
/// top, and at one sequence the rows of both.
fn joined(left: SignerTops, right: SignerTops) -> SignerTops {
    if left.ptr_eq(&right) {
        return left;
    }
    left.union_with(right, |left, right| match left.0.cmp(&right.0) {
        Ordering::Greater => left,
        Ordering::Less => right,
        Ordering::Equal if Arc::ptr_eq(&left, &right) || left.1.is_superset(&right.1) => left,
        Ordering::Equal if right.1.is_superset(&left.1) => right,
        Ordering::Equal => Arc::new((left.0, left.1.union(&right.1).copied().collect())),
    })
}

/// `tops` with the row `hash` of `signer` at `seq` among them.
fn with_row(tops: &mut SignerTops, signer: &AuthorityKey, seq: u64, hash: AuthorityEntryHash) {
    let rows = match tops.get(signer) {
        Some(kept) if kept.0 > seq => return,
        Some(kept) if kept.0 == seq => kept.1.iter().copied().chain([hash]).collect(),
        _ => BTreeSet::from([hash]),
    };
    tops.insert(signer.clone(), Arc::new((seq, rows)));
}

/// [`ScopeTops::past`] over each of `tails` in turn from the tops of `base`,
/// each tail's rows parents first: whether it takes each one. Past a tail it
/// declines, the next base is every row so far, as a full fold captures it.
/// A base's frontier side rows are its side rows no row names. For the
/// scope-tops door (FIX [ADOPTED-FOLD-TAIL-WALK-SIGNER-COST]).
#[cfg(oneiron_test_support)]
pub(in crate::authority) fn scope_tops_tails_taken_for_door(
    base: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    tails: &[BTreeMap<AuthorityEntryHash, AuthorityLogEntry>],
) -> Vec<bool> {
    fn tops_of(rows: &[(AuthorityEntryHash, &AuthorityLogEntry)]) -> ScopeTops {
        let named: BTreeSet<_> = rows
            .iter()
            .flat_map(|(_, entry)| &entry.parent_hashes)
            .collect();
        ScopeTops::of(rows, |hash| !named.contains(hash))
    }
    let mut rows: Vec<(AuthorityEntryHash, &AuthorityLogEntry)> =
        base.iter().map(|(hash, entry)| (*hash, entry)).collect();
    let mut tops = tops_of(&rows);
    let mut taken = Vec::new();
    for tail in tails {
        let base_rows: BaseRows = rows
            .iter()
            .map(|(hash, entry)| (*hash, Arc::new(RowSummary::of(entry))))
            .collect();
        let new_rows: BTreeMap<_, _> = tail
            .iter()
            .filter(|(hash, _)| !base_rows.contains_key(*hash))
            .map(|(hash, entry)| (*hash, entry))
            .collect();
        let links = new_rows
            .iter()
            .map(|(hash, entry)| (*hash, entry.parent_hashes.clone()))
            .collect();
        let order = crate::authority::checkpoint_image::parents_first_of(&links);
        let next = tops.past(&base_rows, &new_rows, &order);
        taken.push(next.is_some());
        rows.extend(new_rows);
        tops = match next {
            Some(next) => next,
            None => tops_of(&rows),
        };
    }
    taken
}
