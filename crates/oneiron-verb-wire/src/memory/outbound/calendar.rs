//! Moved from `crates/oneiron/src/memory/outbound/calendar.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One source-redacted busy interval, half-open `[start_utc, end_utc)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarFreebusyIntervalDto {
    /// Inclusive half-open start, Unix seconds.
    pub start_utc: u64,
    /// Exclusive half-open end, Unix seconds.
    pub end_utc: u64,
}
