//! Moved from `crates/oneiron/src/workspace_roster/rooms/participants.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::participation::JoinCause;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_contracts::room_join::JoinSubject;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::ops::Bound;

/// One page of a room's, or one thread's, participants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParticipantsRequest {
    pub room: EntityId,
    /// A thread of the room, by its root turn; `None` reads the room itself.
    #[serde(default)]
    pub branch: Option<EntityId>,
    /// The `next_after` of the page before.
    #[serde(default)]
    pub after: Option<String>,
    /// Rows per page, positive; the room message page's bound when unset.
    /// A page holds at most that bound; the rest follow through its cursor.
    #[serde(default)]
    pub limit: Option<u32>,
}
