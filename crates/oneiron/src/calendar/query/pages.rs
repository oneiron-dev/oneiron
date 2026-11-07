//! Deadline-bound, resumable pages of the public calendar queries (FIX 11998,
//! FIX 12164): `vault.calendar.search`, `vault.calendar.occurrences` and
//! `vault.calendar.freebusy`.
//!
//! A page reads its window in consecutive time slices from a frontier: the
//! window's start on a first page, the `resume_from` an earlier page answered
//! on the next. Each slice is read whole, across every admitted EVENT, before
//! the next begins, so what a page answers is exact up to where it stopped:
//! search keeps its chronological order (an occurrence belongs to the slice
//! that holds its start; the starts before the window that still overlap it
//! belong to the first page), occurrences keep their start-in-window rule,
//! and freebusy is the exact busy union of the covered prefix, clipped to it.
//!
//! A page stops at the window's end, at the search's limit (only between two
//! distinct starts), or at the caller's `deadline_ms`, which is checked
//! between slices; a slice is never interrupted, so a page may run past its
//! deadline by its last slice. The first slice is one day, and a slice
//! doubles only while the deadline leaves more than twice the time the last
//! one took. An uncounted rule's walk in a slice is bounded by the slice's
//! span; a COUNT rule's walk starts again at its DTSTART in every slice
//! (bounded by its COUNT). The first slice always runs, so every call moves
//! the frontier on. With neither a deadline nor a limit the window is one
//! slice, as before.
//!
//! The frontier is a position, not a snapshot: an EVENT written between two
//! pages is read by the later page only where it falls after its frontier.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::requests::{CalendarEventView, CalendarRangeDto, CalendarSearchRequest, CalendarSel};
use super::window::{CalendarOccurrenceView, CalendarOccurrencesRequest};
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::memory::{CalendarFreebusyIntervalDto, Memory, MemoryError, MemoryResult};
use crate::temporal::TimeRange;

/// The first slice a deadline- or limit-bound page reads, in seconds: one
/// day.
const FIRST_SLICE_SECS: u64 = 86_400;

/// Consecutive inclusive slices of a page's window, from its frontier.
pub(in crate::calendar) struct Slices {
    /// The next slice's start; `None` once the window is read.
    next: Option<u64>,
    /// The window's inclusive end.
    end: u64,
    len: u64,
    deadline: Option<Instant>,
    /// When the slice last handed out began.
    began: Option<Instant>,
}

impl Slices {
    /// Slices of `[from, end]`. A page with neither a deadline nor a limit
    /// (`bounded`) reads its window as one slice.
    pub(in crate::calendar) fn new(
        from: u64,
        end: u64,
        deadline: Option<Instant>,
        bounded: bool,
    ) -> Self {
        Self {
            next: (from <= end).then_some(from),
            end,
            len: if deadline.is_some() || bounded {
                FIRST_SLICE_SECS
            } else {
                u64::MAX
            },
            deadline,
            began: None,
        }
    }

    /// The next slice, inclusive: `None` once the window is read, or once
    /// the deadline has passed after at least one slice.
    pub(in crate::calendar) fn next_slice(&mut self) -> Option<TimeRange> {
        let start = self.next?;
        let now = Instant::now();
        if let Some(began) = self.began {
            let took = now.saturating_duration_since(began);
            match self.deadline {
                Some(deadline) if now >= deadline => return None,
                Some(deadline) => {
                    if deadline.saturating_duration_since(now) > took.saturating_mul(2) {
                        self.len = self.len.saturating_mul(2);
                    }
                }
                None => self.len = self.len.saturating_mul(2),
            }
        }
        self.began = Some(now);
        let end = start.saturating_add(self.len - 1).min(self.end);
        self.next = end.checked_add(1).filter(|_| end < self.end);
        Some(TimeRange { start, end })
    }

    /// Where the next page starts: `None` once the window is read.
    pub(in crate::calendar) const fn resume_from(&self) -> Option<u64> {
        self.next
    }
}

/// `vault.calendar.search` as a page: [`CalendarSearchRequest`]'s fields,
/// a deadline, and the frontier an earlier page answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
}

impl CalendarSearchPageRequest {
    fn search(&self) -> CalendarSearchRequest {
        CalendarSearchRequest {
            calendars: self.calendars.clone(),
            range: self.range,
            text: self.text.clone(),
            limit: self.limit,
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
    pub(in crate::calendar) fn of(
        events: Vec<CalendarEventView>,
        resume_from: Option<u64>,
    ) -> Self {
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

impl Memory<'_> {
    /// One page of a calendar search under the caller's read scope (FIX
    /// 11998), read in time slices as this module describes.
    pub fn calendar_search_page(
        &self,
        request: &CalendarSearchPageRequest,
    ) -> MemoryResult<ScopedReadResult<CalendarSearchPage>> {
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        if request.range.is_some_and(|range| !range.is_ordered()) {
            return Err(unordered_range());
        }
        let deadline = page_deadline(request.deadline_ms)?;
        let from = match request.range {
            Some(range) => page_frontier(range, request.resume_from)?,
            None if request.resume_from.is_some() => {
                return Err(MemoryError::bad_request_with(
                    "calendar search resume_from needs the range its pages read",
                    &[
                        "Pass the same request, range included, with the resume_from a page answered.",
                    ],
                ));
            }
            None => None,
        };
        Ok(super::service::search_events_page_scoped(
            &lane,
            &request.search(),
            from,
            deadline,
        )?)
    }

    /// One page of a stored master's occurrences under the caller's read
    /// scope (FIX 11998).
    pub fn calendar_occurrences_page(
        &self,
        request: &CalendarOccurrencesPageRequest,
    ) -> MemoryResult<ScopedReadResult<CalendarOccurrencesPage>> {
        if !request.range.is_ordered() {
            return Err(unordered_range());
        }
        let deadline = page_deadline(request.deadline_ms)?;
        let from = page_frontier(request.range, request.resume_from)?;
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let occurrences = CalendarOccurrencesRequest {
            master_ref: request.master_ref.clone(),
            range: request.range,
        };
        Ok(super::window::read_occurrences_page_scoped(
            &lane,
            &occurrences,
            from,
            deadline,
        )?)
    }

    /// One page of source-redacted busy occupancy under the caller's read
    /// scope (FIX 11998): the busy union of the covered prefix of the range.
    pub fn calendar_freebusy_page(
        &self,
        request: &CalendarFreebusyPageRequest,
    ) -> MemoryResult<ScopedReadResult<CalendarFreebusyPage>> {
        if !request.range.is_ordered() {
            return Err(unordered_range());
        }
        let deadline = page_deadline(request.deadline_ms)?;
        let from = page_frontier(request.range, request.resume_from)?;
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let page = crate::calendar::freebusy::freebusy_page_scoped(
            &lane,
            &request.calendars,
            request.range.to_time_range(),
            from,
            deadline,
        )?;
        Ok(page.map(|(union, resume_from)| CalendarFreebusyPage {
            intervals: union
                .into_iter()
                .map(|interval| CalendarFreebusyIntervalDto {
                    start_utc: interval.start_utc,
                    end_utc: interval.end_utc,
                })
                .collect(),
            complete: resume_from.is_none(),
            resume_from,
        }))
    }
}

fn unordered_range() -> MemoryError {
    MemoryError::bad_request_with(
        "calendar range start must not exceed end",
        &["Pass an inclusive range with start <= end."],
    )
}

/// When this call's page stops reading: `deadline_ms` from now.
fn page_deadline(deadline_ms: Option<u64>) -> MemoryResult<Option<Instant>> {
    crate::memory::caps::check_deadline_ms(deadline_ms)?;
    Ok(deadline_ms.map(|ms| Instant::now() + Duration::from_millis(ms)))
}

/// A resumed page's frontier, which lies inside the range its pages read.
fn page_frontier(range: CalendarRangeDto, resume_from: Option<u64>) -> MemoryResult<Option<u64>> {
    match resume_from {
        Some(from) if from < range.start || from > range.end => Err(MemoryError::bad_request_with(
            "calendar resume_from lies outside the range",
            &["Pass the resume_from an earlier page of this same request answered."],
        )),
        resume_from => Ok(resume_from),
    }
}
