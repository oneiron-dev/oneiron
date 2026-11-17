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
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
) -> BTreeMap<AuthorityEntryHash, u64> {
    let mut scopes = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    for (hash, entry) in by_hash {
        scopes
            .entry((
                entry.signer_key(),
                super::world_privacy::side_world(&entry.op),
            ))
            .or_default()
            .push((entry.seq, *hash));
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

/// Whether `lower` is among the ancestors of a row with `parents`, along
/// rows of `scope` alone: `row` gives a held row's parents and scope. A path
/// through another scope's rows or a row not held is not followed, so a
/// false answer only sends a fold past a base or an image to the whole log.
pub(super) fn descends_within_scope<'a>(
    lower: &AuthorityEntryHash,
    parents: &'a [AuthorityEntryHash],
    scope: Option<crate::EntityId>,
    row: impl Fn(&AuthorityEntryHash) -> Option<(&'a [AuthorityEntryHash], Option<crate::EntityId>)>,
) -> bool {
    let mut stack: Vec<_> = parents.iter().collect();
    let mut visited = BTreeSet::new();
    while let Some(hash) = stack.pop() {
        if hash == lower {
            return true;
        }
        if !visited.insert(*hash) {
            continue;
        }
        if let Some((row_parents, row_scope)) = row(hash)
            && row_scope == scope
        {
            stack.extend(row_parents);
        }
    }
    false
}
