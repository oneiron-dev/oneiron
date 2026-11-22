//! Sequence floors from the rows themselves (Engine RULING SEQ-FLOOR-SHAPE =
//! A, 15 Nov 16:37; FIX [SEQUENCE-FLOOR-DELIVERY-ORDER]).
//!
//! A row's floor is the highest sequence among its signer's rows in its
//! sequence scope (the main log, or one world's key records,
//! `world_privacy::side_world`) that do not have it among their ancestors.
//! The rows alone decide it, so every install, and every resumed, adopted and
//! checkpoint fold, reads the same floor for each row, whatever order the
//! rows arrived in. The receipts each install keeps (`sequence_observation`)
//! count ingest only; no fold reads them.
use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The floor of each row past it: the highest sequence among its signer's
/// rows in its scope that do not have it among their ancestors, where that
/// sequence is above the row's own. A row no such row passes is absent. Every
/// row sets floors, whatever its op. `ancestors` is the whole log's ancestor
/// index (`entry_ancestor_index`).
///
/// Cost, for a signer's k rows in one scope: rows that form one chain (each
/// an ancestor of the next, sequences strictly rising) cost k index lookups
/// and set no floor. Otherwise each row, from the top down, looks up the rows
/// below it that no higher row has floored yet: each lookup either floors a
/// row (k at most) or finds a same-scope ancestor pair the index already
/// holds, so the scan costs k plus those pairs, each one index lookup.
pub(super) fn rows_sequence_floors(
    by_hash: &BTreeMap<AuthorityEntryHash, FoldRow>,
    ancestors: &AncestorIndex,
) -> BTreeMap<AuthorityEntryHash, u64> {
    let mut scopes = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    // A row that passes through keys on its signer's main log: no sealed
    // kind is a side entry (census L5-22 1a-iii).
    for (hash, row) in by_hash {
        scopes
            .entry((
                row.signer_key(),
                row.op().and_then(super::world_privacy::side_world),
            ))
            .or_default()
            .push((row.seq(), *hash));
    }
    let below = |lower: &AuthorityEntryHash, upper: &AuthorityEntryHash| {
        ancestors
            .get(upper)
            .is_some_and(|upper_ancestors| upper_ancestors.contains(lower))
    };
    let mut floors = BTreeMap::new();
    for rows in scopes.values_mut() {
        rows.sort_unstable();
        if rows
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0 && below(&pair[0].1, &pair[1].1))
        {
            continue;
        }
        // From the top down, the first row that does not have a lower row
        // among its ancestors sets that row's floor; no later row can set a
        // higher one.
        let mut unfloored: BTreeSet<usize> = (0..rows.len()).collect();
        for &(seq, setter) in rows.iter().rev() {
            let lower = rows.partition_point(|(row_seq, _)| *row_seq < seq);
            let floored: Vec<_> = unfloored
                .range(..lower)
                .copied()
                .filter(|index| !below(&rows[*index].1, &setter))
                .collect();
            for index in floored {
                unfloored.remove(&index);
                floors.insert(rows[index].1, seq);
            }
        }
    }
    floors
}

/// A row as [`highest_key_row_below`] reads it: its parents, its sequence
/// scope and sequence, and the index of its (signer, scope) where the pass
/// tracks that key.
pub(super) struct ScopeRow<'a> {
    pub(super) parents: &'a [AuthorityEntryHash],
    pub(super) scope: Option<crate::EntityId>,
    pub(super) seq: u64,
    pub(super) key: Option<usize>,
}

/// The highest row of each tracked key below each row, carried down a pass:
/// the key's index to the highest (sequence, hash) among that key's rows.
type HighestByKey = im::OrdMap<usize, (u64, AuthorityEntryHash)>;

/// For each tracked row of `rows`, the highest-sequence row of its own key
/// among its ancestors along rows of its scope: a parent outside `rows` or
/// of another scope is not followed. A tracked row absent from the result
/// has no row of its key below it.
///
/// One pass, each row after its parents (`parents_first_of` over the links
/// within a scope), carrying the highest row of each tracked key below it in
/// a persistent map: a row with one parent takes or shares that parent's map
/// and adds itself, a join merges each smaller map into the largest, and a
/// row's map is dropped once its last child has read it. None where a parent
/// comes after its child in that order, as only a cycle puts it, which no
/// hash-linked log holds.
///
/// Cost: the order over `rows` and their links, O((rows + links) log rows);
/// then O(log K) per row for K tracked keys, and at a join O(m log K) for
/// the m entries of each smaller map merged in, m at most K. No row is
/// visited once per key (FIX [ADOPTED-FOLD-GATE-SIGNER-COST]).
pub(super) fn highest_key_row_below(
    rows: &BTreeMap<AuthorityEntryHash, ScopeRow<'_>>,
) -> Option<BTreeMap<AuthorityEntryHash, AuthorityEntryHash>> {
    let links: BTreeMap<_, Vec<_>> = rows
        .iter()
        .map(|(hash, row)| {
            let parents: BTreeSet<_> = row
                .parents
                .iter()
                .filter(|parent| {
                    rows.get(*parent)
                        .is_some_and(|parent| parent.scope == row.scope)
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
    let mut carried = BTreeMap::<AuthorityEntryHash, HighestByKey>::new();
    let mut below = BTreeMap::new();
    for hash in super::checkpoint_image::parents_first_of(&links) {
        let row = &rows[&hash];
        let mut highest: Option<HighestByKey> = None;
        for parent in &links[&hash] {
            let left = readers.get_mut(parent)?;
            *left -= 1;
            let parent_highest = if *left == 0 {
                carried.remove(parent)?
            } else {
                carried.get(parent)?.clone()
            };
            highest = Some(match highest {
                Some(merged) if merged.ptr_eq(&parent_highest) => merged,
                Some(merged) => merged.union_with(parent_highest, std::cmp::max),
                None => parent_highest,
            });
        }
        let mut highest = highest.unwrap_or_default();
        if let Some(key) = row.key
            && let Some((_, lower)) = highest.get(&key)
        {
            below.insert(hash, *lower);
        }
        if readers.get(&hash).is_some_and(|left| *left > 0) {
            if let Some(key) = row.key {
                let own = (row.seq, hash);
                if highest.get(&key).is_none_or(|kept| *kept < own) {
                    highest.insert(key, own);
                }
            }
            carried.insert(hash, highest);
        }
    }
    Some(below)
}
