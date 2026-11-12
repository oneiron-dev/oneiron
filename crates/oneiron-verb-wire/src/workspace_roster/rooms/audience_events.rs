//! Moved from `crates/oneiron/src/workspace_roster/rooms/audience_events.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::*;
pub(crate) use oneiron_store::conversation_body::ROOM_THREAD_AUDIENCE_KEY;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// What an add shares with the person it adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreadAudienceHistory {
    /// The whole thread, its earlier turns included.
    Full,
    /// The turns from the add on; the earlier ones stay withheld.
    FromNow,
}
