//! Doors for `tests/setting_dreamer_1.rs`: the sets the `dreamer.excluded_conversations` hook
//! asked the follower to forget, kept by the vault the hook ran on.

use std::collections::BTreeSet;

use crate::{EntityId, Vault};

/// Each set the hook asked the follower to forget on `vault`, oldest first.
#[must_use]
pub fn dreamer_exclusion_forgets(vault: &Vault) -> Vec<BTreeSet<EntityId>> {
    crate::dreamer_consolidation::excluded_conversations::forgotten_sets(vault)
}
