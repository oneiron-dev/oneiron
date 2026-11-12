//! Moved from `crates/oneiron/src/workspace_roster/rooms/offer_settle.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The host's verb on a card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfferAnswer {
    Join,
    NotNow,
}

/// An answer to one card. It cannot change the card, its payer, thread or
/// cap: those are read back from the stored card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferAnswerRequest {
    pub offer_id: String,
    pub action: OfferAnswer,
    /// The answerer's idempotency key: one or more printable bytes.
    pub intent_key: String,
}
