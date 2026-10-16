//! Claimed authority-entry ancestry index for deterministic fold scheduling.

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
) -> Option<(
    BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    u64,
)> {
    if super::log_budget::fold_projected_bytes(by_hash.len(), 0) > memory_floor {
        return None;
    }
    let uncounted = super::log_budget::uncounted_rows(by_hash);
    let mut index = BTreeMap::new();
    let (mut pairs, mut counted_pairs) = (0_u64, 0_u64);
    for (hash, entry) in by_hash {
        let counted = !uncounted.contains(hash);
        let mut ancestors = BTreeSet::new();
        let mut stack = entry.parent_hashes.clone();
        while let Some(parent) = stack.pop() {
            if !ancestors.insert(parent) {
                continue;
            }
            pairs += 1;
            if super::log_budget::fold_projected_bytes(by_hash.len(), pairs) > memory_floor {
                return None;
            }
            counted_pairs += u64::from(counted && !uncounted.contains(&parent));
            if let Some(parent_entry) = by_hash.get(&parent) {
                stack.extend(parent_entry.parent_hashes.iter().copied());
            }
        }
        index.insert(*hash, ancestors);
    }
    Some((index, counted_pairs))
}
