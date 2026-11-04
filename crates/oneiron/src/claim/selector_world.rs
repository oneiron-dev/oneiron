//! World filter vocabulary for a closed-subgraph CLAIM selector.

use crate::entity_id::LocalWorldId;

/// World component of a closed-subgraph selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncSelectorWorld {
    /// Include base and all world-scoped claims.
    All,
    /// Include only base-reality claims.
    Base,
    /// Include base-reality claims and claims scoped to this world.
    World(LocalWorldId),
}
