//! Moved from `crates/oneiron/src/workspace_roster/project/widen.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectWidenAxis {
    Scope,
    Budget,
    Roster,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWidenAsk {
    pub requesting_project: EntityId,
    pub other_project: EntityId,
    pub board_project: EntityId,
    pub axis: ProjectWidenAxis,
    pub ask: EntityId,
}
