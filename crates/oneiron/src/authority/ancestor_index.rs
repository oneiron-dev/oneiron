//! Claimed authority-entry ancestry index for deterministic fold scheduling.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Each entry's whole claimed ancestry, or, once the counted pairs pass
/// the bound (H72), the signer of the row that took them there: the fold
/// then refuses the log rather than build the rest. A pair counts unless
/// either end is a slip op of the slip issuer, which no bound counts.
pub(in crate::authority) fn entry_ancestor_index(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> Result<BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>, AuthorityKey> {
    let uncounted = super::log_budget::uncounted_rows(by_hash);
    let bound = super::log_budget::ancestor_edges_bound();
    let mut index = BTreeMap::new();
    let mut edges = 0_usize;
    for (hash, entry) in by_hash {
        let counted = !uncounted.contains(hash);
        let mut ancestors = BTreeSet::new();
        let mut stack = entry.parent_hashes.clone();
        while let Some(parent) = stack.pop() {
            if !ancestors.insert(parent) {
                continue;
            }
            if counted && !uncounted.contains(&parent) {
                edges += 1;
                if edges > bound {
                    return Err(entry.signer_key().clone());
                }
            }
            if let Some(parent_entry) = by_hash.get(&parent) {
                stack.extend(parent_entry.parent_hashes.iter().copied());
            }
        }
        index.insert(*hash, ancestors);
    }
    Ok(index)
}
