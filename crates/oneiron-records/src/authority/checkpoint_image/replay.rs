//! Moved from `crates/oneiron/src/authority/checkpoint_image/replay.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::checkpoint_image::*;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// How many rows down a first-parent chain a whole state is kept again: the
/// most fields deltas any reconstruction applies is one point's (CALLS "FIX
/// 3007 replay representation").
pub const AUTHORITY_REPLAY_FULL_STRIDE: u32 = 32;

/// What an image whose encoded bytes would still pass the size cap after
/// dropping its replay evidence marks its residence rows with instead of
/// their bodies (FIX 11400, CALLS AUTHORITY_RESIDENCE_BODY_OVERFLOW): no
/// residence body, as before #4095 carried them, so a fold past it asks for
/// that history as at fold 14. An image that fits keeps its residence
/// bodies.
pub const AUTHORITY_RESIDENCE_BODY_OVERFLOW: bool = true;

/// `rows`' hashes, each after every parent of it among `rows`, ties by
/// hash; a row on a cycle comes last.
pub fn parents_first_of(
    rows: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
) -> Vec<AuthorityEntryHash> {
    let mut waiting = BTreeMap::new();
    let mut children = BTreeMap::<_, Vec<_>>::new();
    let mut ready = BTreeSet::new();
    for (hash, parents) in rows {
        let parents: BTreeSet<_> = parents
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
    order.extend(waiting.into_keys());
    order
}
