//! Moved from `crates/oneiron/src/workspace_roster/rooms/offer_reopen.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// The host's reopening of one aged-out room-wide card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferReopenRequest {
    pub offer_id: String,
    /// The card's `last_engaged_at` as the host saw it aged out.
    pub expected_last_engaged_at: u64,
    /// A new fixed deadline, in Unix seconds; `None` reopens the card for a
    /// day without engagement.
    #[serde(default)]
    pub until: Option<u64>,
}
