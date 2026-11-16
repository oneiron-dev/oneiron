//! Moved from `crates/oneiron/src/self_heal/blocked_reports/source.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The worlds a run's host scoped it to, as the report's filing read them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunWorlds {
    /// The agent dispatch the run served: its scope's world and its task's.
    Scoped { worlds: Vec<EntityId> },
    /// The host bound the run to no dispatch: any world it could read may
    /// have been read.
    Unscoped,
    /// A world of the dispatch it served could not be proved.
    Unproved,
}
