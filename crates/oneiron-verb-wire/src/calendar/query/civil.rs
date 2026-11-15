//! Moved from `crates/oneiron/src/calendar/query/civil.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// What a calendar shows for an all-day or floating occurrence.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct CalendarCivilSpan {
    /// `all_day` (dates) or `floating` (wall times in any zone).
    pub time_kind: String,
    /// The first day (`2026-11-06`), or the wall time it starts
    /// (`2026-11-06T09:00:00`).
    pub start: String,
    /// The day, or the wall time, it ends before; the start itself for a
    /// floating occurrence that names no end.
    pub end: String,
}
