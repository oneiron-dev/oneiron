//! Moved from `crates/oneiron/src/memory/resolved_recall_scope.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One recall's resolved scope, as the device read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRecallSelection {
    /// The worlds read; `None` reads every world. An empty set reads none:
    /// it is a narrowing, not its absence.
    pub worlds: Option<ResolvedRecallWorlds>,
    /// The project audiences read, sorted and unique; empty reads every one.
    pub project_ids: Vec<EntityId>,
    /// The explicit/PERSON-authored conversations read, sorted and unique;
    /// `None` adds no narrowing, and an empty set reads none.
    pub conversation_ids: Option<Vec<EntityId>>,
    /// The facet a strict facet narrowing keeps.
    pub facet: Option<EntityId>,
    /// The registry kinds returned, sorted and unique; `None` is recall's
    /// default, every kind but the containers (`CONTAINER_KINDS`).
    pub kinds: Option<Vec<u8>>,
}

/// A resolved world set: base reality, and the named worlds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRecallWorlds {
    /// Whether base reality is read.
    pub include_base: bool,
    /// The world ids read, sorted and unique.
    pub world_ids: Vec<EntityId>,
}
