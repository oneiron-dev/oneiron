//! Dependency-free serde request/response DTOs.

use crate::temporal::TimeRange;

/// Upper bound on one `calendar.search` page, mirroring the bounded-list
/// convention the rest of the read surface uses.
pub const MAX_CALENDAR_SEARCH_LIMIT: u32 = 200;

/// Serde-safe range DTO.
///
/// [`TimeRange`] carries no serde derives at HEAD (`crate::temporal`), so every
/// serialized calendar request shape carries this inline pair and converts to
/// `TimeRange` at the handler boundary — the same boundary that performs the
/// inclusive-to-half-open checked conversion for freebusy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarRangeDto {
    /// Inclusive start, Unix seconds.
    pub start: u64,
    /// Inclusive end, Unix seconds.
    pub end: u64,
}

impl CalendarRangeDto {
    /// Converts to the engine's inclusive [`TimeRange`].
    #[must_use]
    pub const fn to_time_range(self) -> TimeRange {
        TimeRange {
            start: self.start,
            end: self.end,
        }
    }

    /// True when the pair is a well-formed inclusive interval.
    #[must_use]
    pub const fn is_ordered(self) -> bool {
        self.start <= self.end
    }
}

/// One calendar selector.
///
/// `system` is accepted and deliberately ignored until CAL-02 (ONE-1784) lands
/// the passport index: 1791 precedes 1784 in the frontier, so filtering on a
/// selector that has no index yet would silently empty every result. An empty
/// selector slice likewise means "every calendar EVENT visible under the
/// caller's existing read scope".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarSel {
    /// Calendar system key (e.g. a passport `system`); ignored on this baseline.
    #[serde(default)]
    pub system: Option<String>,
}

/// One projected calendar EVENT.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarEventView {
    /// Hex EVENT entity id.
    pub event_ref: String,
    /// EVENT display name, when the body carries one.
    pub name: Option<String>,
    /// Inclusive UTC occurrence start; `None` when the EVENT stores no
    /// occurrence at all (both header bounds zero).
    pub start_utc: Option<u64>,
    /// Inclusive UTC occurrence end; `None` under the same condition as
    /// [`Self::start_utc`].
    pub end_utc: Option<u64>,
    /// Calendar systems this EVENT holds a passport for, sorted and deduped.
    pub calendar_systems: Vec<String>,
    /// Whether this EVENT consumes availability (the Busy-only law input).
    pub blocks_time: bool,
}

/// `calendar.read` request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarReadRequest {
    /// Hex EVENT entity id.
    pub event_ref: String,
}

/// `calendar.search` request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarSearchRequest {
    /// Calendar selectors; see [`CalendarSel`] for the deferred-selection rule.
    pub calendars: Vec<CalendarSel>,
    /// Inclusive UTC window; `None` means unbounded.
    pub range: Option<CalendarRangeDto>,
    /// Case-insensitive substring matched against the EVENT name.
    pub text: Option<String>,
    /// Maximum rows returned, clamped to [`MAX_CALENDAR_SEARCH_LIMIT`].
    pub limit: u32,
}
