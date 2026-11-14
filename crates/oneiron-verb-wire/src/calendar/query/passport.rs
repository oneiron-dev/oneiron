//! Moved from `crates/oneiron/src/calendar/query/passport.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::claims::values::CalendarPassportValue;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarPassportReadRequest {
    pub event_ref: String,
    pub system: String,
    pub uid: String,
}

/// Approval and lifecycle are explicit: a recorded proposal is not an admitted head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarPassportRevision {
    pub claim_ref: String,
    pub event_ref: String,
    pub recorded_at: u64,
    pub approval: String,
    pub lifecycle: String,
    pub stale: bool,
    pub passport: CalendarPassportValue,
}
