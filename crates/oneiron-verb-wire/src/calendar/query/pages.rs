//! Moved from `crates/oneiron/src/calendar/query/pages.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::query::requests::CalendarEventView;
use crate::calendar::query::requests::CalendarRangeDto;
use crate::calendar::query::requests::CalendarSel;
use crate::calendar::query::window::CalendarOccurrenceView;
use crate::memory::outbound::calendar::CalendarFreebusyIntervalDto;
use serde::Deserialize;
use serde::Serialize;

/// One page of `vault.calendar.search`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarSearchPage {
    /// The page's EVENT views: earliest occurrence first, then end and
    /// entity id; undated EVENTs last.
    pub events: Vec<CalendarEventView>,
    /// Whether this page reached the window's end: no later page holds more.
    pub complete: bool,
    /// Where the next page starts, UTC seconds, while `complete` is false:
    /// pass it back with the same request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_from: Option<u64>,
}

impl CalendarSearchPage {
    pub fn of(events: Vec<CalendarEventView>, resume_from: Option<u64>) -> Self {
        Self {
            events,
            complete: resume_from.is_none(),
            resume_from,
        }
    }
}

/// `vault.calendar.occurrences` as a page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarOccurrencesPageRequest {
    pub master_ref: String,
    /// Inclusive UTC seconds. An unbounded expansion is not a public call.
    pub range: CalendarRangeDto,
    /// Milliseconds this call may read for, 1 to 60000, checked between
    /// slices; none reads the whole range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// The `resume_from` an earlier page of this same request answered;
    /// none starts at the range's start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_from: Option<u64>,
}

/// One page of `vault.calendar.occurrences`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarOccurrencesPage {
    /// The occurrences that start in the covered part of the range, by
    /// actual start, then end, UID, original start and EVENT.
    pub occurrences: Vec<CalendarOccurrenceView>,
    /// Whether this page reached the range's end.
    pub complete: bool,
    /// Where the next page starts, UTC seconds, while `complete` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_from: Option<u64>,
}

/// `vault.calendar.freebusy` as a page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarFreebusyPageRequest {
    pub calendars: Vec<CalendarSel>,
    /// Inclusive UTC seconds.
    pub range: CalendarRangeDto,
    /// Milliseconds this call may read for, 1 to 60000, checked between
    /// slices; none reads the whole range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// The `resume_from` an earlier page of this same request answered;
    /// none starts at the range's start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_from: Option<u64>,
}

/// One page of `vault.calendar.freebusy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarFreebusyPage {
    /// The exact busy union of the covered part of the range, from the
    /// page's start to `resume_from` (or the range's end), clipped to it:
    /// an interval that crosses into the next page continues there, so a
    /// caller joins touching intervals.
    pub intervals: Vec<CalendarFreebusyIntervalDto>,
    /// Whether this page reached the range's end.
    pub complete: bool,
    /// Where the next page starts, UTC seconds, while `complete` is false:
    /// the time from it on is not yet read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_from: Option<u64>,
}
