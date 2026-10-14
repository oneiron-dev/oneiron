//! Claimed authority-entry ancestry index for deterministic fold scheduling.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Each entry's whole claimed ancestry, or `None` once the index would hold
/// more than [`MAX_AUTHORITY_ANCESTOR_EDGES`] pairs (H72): the fold then
/// refuses the log rather than build the rest.
///
/// [`MAX_AUTHORITY_ANCESTOR_EDGES`]: super::log_budget::MAX_AUTHORITY_ANCESTOR_EDGES
pub(in crate::authority) fn entry_ancestor_index(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> Option<BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>> {
    let mut index = BTreeMap::new();
    let mut edges = 0_usize;
    for hash in by_hash.keys().copied() {
        let mut ancestors = BTreeSet::new();
        let mut stack = by_hash[&hash].parent_hashes.clone();
        while let Some(parent) = stack.pop() {
            if !ancestors.insert(parent) {
                continue;
            }
            edges += 1;
            if edges > super::log_budget::MAX_AUTHORITY_ANCESTOR_EDGES {
                return None;
            }
            if let Some(parent_entry) = by_hash.get(&parent) {
                stack.extend(parent_entry.parent_hashes.iter().copied());
            }
        }
        index.insert(hash, ancestors);
    }
    Some(index)
}
