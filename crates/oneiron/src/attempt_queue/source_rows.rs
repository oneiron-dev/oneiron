//! Deterministic union of known source row sets.

use crate::entity_id::EntityId;

/// The union of source sets (FIX 5482), sorted and deduplicated: `None` once
/// any set is unknown; no set at all unions to a known empty one.
pub fn union_source_rows<S: AsRef<[EntityId]>>(
    sets: impl IntoIterator<Item = Option<S>>,
) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    for set in sets {
        rows.extend_from_slice(set?.as_ref());
    }
    rows.sort_unstable();
    rows.dedup();
    Some(rows)
}
