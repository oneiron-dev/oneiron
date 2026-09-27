//! Claimed authority-entry ancestry index for deterministic fold scheduling.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::authority) fn entry_ancestor_index(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>> {
    let mut index = BTreeMap::new();
    for hash in by_hash.keys().copied() {
        let mut ancestors = BTreeSet::new();
        let mut stack = by_hash[&hash].parent_hashes.clone();
        while let Some(parent) = stack.pop() {
            if !ancestors.insert(parent) {
                continue;
            }
            if let Some(parent_entry) = by_hash.get(&parent) {
                stack.extend(parent_entry.parent_hashes.iter().copied());
            }
        }
        index.insert(hash, ancestors);
    }
    index
}
