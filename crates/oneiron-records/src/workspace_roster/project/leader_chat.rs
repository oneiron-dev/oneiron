//! Moved from `crates/oneiron/src/workspace_roster/project/leader_chat.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::project::*;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaderChat {
    pub projects: [EntityId; 2],
    pub actors: [EntityId; 2],
    /// Each speaker's PERSON, or `None` for an AGENT_DEF that speaks as itself.
    pub persons: [Option<EntityId>; 2],
}
