//! Moved from `crates/oneiron/src/workspace_roster/rooms/offers.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Bound;

/// A page of the current cards in a room, or in one of its threads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffersRequest {
    pub room: EntityId,
    /// One thread's cards; `None` reads every card in the room.
    #[serde(default)]
    pub branch: Option<EntityId>,
    /// The `next_after` of the previous page.
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}
