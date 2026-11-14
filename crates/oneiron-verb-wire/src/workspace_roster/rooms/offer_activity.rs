//! Moved from `crates/oneiron/src/workspace_roster/rooms/offer_activity.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::offer_settle::OfferAnswer;
use serde::Deserialize;
use serde::Serialize;

/// An advisory ballot on a room-wide card, from someone in its room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferVoteRequest {
    pub offer_id: String,
    /// What the voter would have the host answer: join, or not now.
    pub action: OfferAnswer,
}
