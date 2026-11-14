//! Moved from `crates/oneiron/src/calendar/query/pages.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::query::requests::CalendarEventView;
use crate::calendar::query::requests::CalendarRangeDto;
use crate::calendar::query::requests::CalendarSearchRequest;
use crate::calendar::query::requests::CalendarSel;
use crate::calendar::query::window::CalendarOccurrenceView;
use crate::memory::outbound::calendar::CalendarFreebusyIntervalDto;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use std::time::Instant;

/// `vault.calendar.search` as a page: [`CalendarSearchRequest`]'s fields,
/// a deadline, and the frontier an earlier page answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarSearchPageRequest {
    /// Calendar selectors; see [`CalendarSel`] for passport matching.
    pub calendars: Vec<CalendarSel>,
    /// Inclusive UTC window; `None` means unbounded (then nothing expands
    /// and the page is the whole answer).
    pub range: Option<CalendarRangeDto>,
    /// Case-insensitive substring matched against the EVENT name.
    pub text: Option<String>,
    /// Maximum rows one page holds, clamped to
    /// [`super::MAX_CALENDAR_SEARCH_LIMIT`]; a page ends only between two
    /// distinct starts, so one start shared by more rows than the limit is
    /// returned whole.
    pub limit: u32,
    /// Milliseconds this call may read for, 1 to 60000, checked between
    /// slices; none reads to the window's end or the limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// The `resume_from` an earlier page of this same request answered;
    /// none starts at the range's start. Needs a range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_from: Option<u64>,
    /// The caller's retrieval filter (FIX 3977): it narrows every EVENT the
    /// page reads, conjoined with the calendar, window and name selectors.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

impl CalendarSearchPageRequest {
    fn search(&self) -> CalendarSearchRequest {
        CalendarSearchRequest {
            calendars: self.calendars.clone(),
            range: self.range,
            text: self.text.clone(),
            limit: self.limit,
            filter: self.filter.clone(),
        }
    }
}

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
