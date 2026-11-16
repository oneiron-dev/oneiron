//! Moved from `crates/oneiron/src/workspace_roster/project/asks.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Where one project ask went: the project, the TASK that placed it there and
/// the ask's handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectAsk {
    pub project: EntityId,
    pub task: EntityId,
    pub ask: EntityId,
}
