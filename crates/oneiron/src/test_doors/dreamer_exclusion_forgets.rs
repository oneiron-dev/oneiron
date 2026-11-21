//! Doors for `tests/setting_dreamer_1.rs`: the sets the `dreamer.excluded_conversations` hook
//! asked the follower to forget. Tests run in parallel in one process, so a test finds its own
//! sets by its conversation ids.

use std::collections::BTreeSet;

use crate::EntityId;

/// Each set the hook asked the follower to forget in this process, oldest first.
#[must_use]
pub fn dreamer_exclusion_forgets() -> Vec<BTreeSet<EntityId>> {
    crate::dreamer_consolidation::excluded_conversations::forgotten_sets()
}
