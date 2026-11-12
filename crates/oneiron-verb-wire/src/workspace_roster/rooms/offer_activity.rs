//! Moved from `crates/oneiron/src/workspace_roster/rooms/offer_activity.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::offer_settle::OfferAnswer;
use oneiron_base::edge::EdgeKind;
use oneiron_base::error::ClaimError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_MESSAGE;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::conversation_record::AppendRecord;
use oneiron_store::ports::records::EdgeDirection;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// An advisory ballot on a room-wide card, from someone in its room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferVoteRequest {
    pub offer_id: String,
    /// What the voter would have the host answer: join, or not now.
    pub action: OfferAnswer,
}
