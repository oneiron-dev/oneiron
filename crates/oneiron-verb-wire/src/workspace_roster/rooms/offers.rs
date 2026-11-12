//! Moved from `crates/oneiron/src/workspace_roster/rooms/offers.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::spend_scope::SpendState;
use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_authority::claim_history_handoff::PointRead;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_contracts::room_join::ConsentNeed;
use oneiron_contracts::room_join::JoinSubject;
use oneiron_run_budget::run_budget::DeclaredMaximum;
use oneiron_store::write_envelope::WriteActor;
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
