//! Moved from `crates/oneiron/src/calendar/ingest/feed_door.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::ingest::poll::IcsFeedCursorSnapshot;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarIcsFeedRequest {
    pub system: String,
}

/// A successful call is a completion barrier, not an approval of imported claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarIcsPollCompletion {
    pub poll_ref: String,
    pub completed_at: u64,
    pub result: CalendarIcsPollResult,
    pub cursor: Option<IcsFeedCursorSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CalendarIcsPollResult {
    Reenqueued { next_not_before: u64 },
    PausedNeedsInput { inbox_exception_ref: String },
}
