//! Moved from `crates/oneiron/src/workspace_roster/rooms/audience_history.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// `vault.rooms.thread_audience.open_full_history`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadAudienceOpenFullHistoryRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
}
