//! Read/search entry points plus pure projection helpers.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::time::Instant;

use rmpv::Value;

use super::facts::{CalendarEventRow, CalendarRead, event_row, receipted, visit_calendar_events};
use super::pages::{CalendarSearchPage, Slices};
use super::requests::{
    CalendarEventView, CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest, CalendarSel,
    MAX_CALENDAR_SEARCH_LIMIT,
};
use crate::calendar::claims::CalendarSeriesExceptionValue;
use crate::claim::{ScopedRead, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Body key an EVENT stores its display name under (`serialize.rs` EVENT
/// profile: `name`, `at`, `ppl`, `place`, `desc`).
const EVENT_BODY_NAME_KEY: &str = "name";

/// Rejects structurally unusable selectors.
///
/// Selection itself is deferred to CAL-02, but a blank `system` token is
/// malformed input in every future baseline, so it fails now rather than
/// becoming a silently-ignored no-op once the passport index lands.
pub(in crate::calendar) fn validate_selectors(calendars: &[CalendarSel]) -> Result<()> {
    for selector in calendars {
        if selector
            .system
            .as_deref()
            .is_some_and(|system| system.trim().is_empty())
        {
            return Err(Error::InvalidKey);
        }
    }
    Ok(())
}

/// Reads one calendar EVENT through the internal lane.
pub fn read_event(vault: &Vault, req: &CalendarReadRequest) -> Result<Option<CalendarEventView>> {
    read_event_in(&CalendarRead::Vault(vault), req)
}

/// Reads one calendar EVENT through an actor's scoped-read lane, with the
/// receipt of every claim read the projection made.
pub fn read_event_scoped(
    read: &ScopedRead<'_>,
    req: &CalendarReadRequest,
) -> Result<ScopedReadResult<Option<CalendarEventView>>> {
    receipted(read, |lane| read_event_in(lane, req))
}

fn read_event_in(
    read: &CalendarRead<'_>,
    req: &CalendarReadRequest,
) -> Result<Option<CalendarEventView>> {
    let id = EntityId::from_hex(req.event_ref.trim())?;
    let Some(row) = event_row(read, id)? else {
        return Ok(None);
    };
    Ok(Some(project(&row)?))
}

/// Searches calendar EVENTs through the internal lane.
pub fn search_events(vault: &Vault, req: &CalendarSearchRequest) -> Result<Vec<CalendarEventView>> {
    search_events_in(&CalendarRead::Vault(vault), req)
}

/// Searches calendar EVENTs through an actor's scoped-read lane, with the
/// receipt of every claim read the projection made.
pub fn search_events_scoped(
    read: &ScopedRead<'_>,
    req: &CalendarSearchRequest,
) -> Result<ScopedReadResult<Vec<CalendarEventView>>> {
    receipted(read, |lane| search_events_in(lane, req))
}

fn search_events_in(
    read: &CalendarRead<'_>,
    req: &CalendarSearchRequest,
) -> Result<Vec<CalendarEventView>> {
    let Some(prepared) = prepare_search(read, req)? else {
        return Ok(Vec::new());
    };
    let mut matched = prepared.matched(req.range.map(CalendarRangeDto::to_time_range), None)?;
    matched.sort_unstable_by_key(|(key, _)| *key);
    matched.truncate(prepared.limit);
    Ok(views(matched))
}

/// [`search_events_scoped`] as one page (FIX 11998): over a range, the
/// window from `resume_from` (or its start, with the lookback of starts
/// before it) is read in time slices, each whole, until the window's end,
/// the limit or `deadline` (see `super::pages`). With no range nothing
/// expands, and the page is the whole answer, as [`search_events_scoped`].
pub(super) fn search_events_page_scoped(
    read: &ScopedRead<'_>,
    req: &CalendarSearchRequest,
    resume_from: Option<u64>,
    deadline: Option<Instant>,
) -> Result<ScopedReadResult<CalendarSearchPage>> {
    receipted(read, |lane| {
        search_events_page_in(lane, req, resume_from, deadline)
    })
}

fn search_events_page_in(
    read: &CalendarRead<'_>,
    req: &CalendarSearchRequest,
    resume_from: Option<u64>,
    deadline: Option<Instant>,
) -> Result<CalendarSearchPage> {
    let Some(prepared) = prepare_search(read, req)? else {
        return Ok(CalendarSearchPage::of(Vec::new(), None));
    };
    let Some(window) = req.range.map(CalendarRangeDto::to_time_range) else {
        let mut matched = prepared.matched(None, None)?;
        matched.sort_unstable_by_key(|(key, _)| *key);
        matched.truncate(prepared.limit);
        return Ok(CalendarSearchPage::of(views(matched), None));
    };
    let mut slices = Slices::new(
        resume_from.unwrap_or(window.start),
        window.end,
        deadline,
        true,
    );
    // Only a first page's first slice holds the starts before the window
    // that still overlap it.
    let mut lookback = resume_from.is_none();
    let mut matched = Vec::new();
    while let Some(slice) = slices.next_slice() {
        let owned_from = (!lookback).then_some(slice.start);
        lookback = false;
        let mut found = prepared.matched(Some(slice), owned_from)?;
        found.sort_unstable_by_key(|(key, _)| *key);
        matched.extend(found);
        if matched.len() > prepared.limit {
            return Ok(cut_at_limit(matched, prepared.limit, window));
        }
        if matched.len() == prepared.limit {
            break;
        }
    }
    Ok(CalendarSearchPage::of(views(matched), slices.resume_from()))
}

/// A page past its limit ends between two distinct starts: every row that
/// starts before its end is kept, none after. One start held by more rows
/// than the limit (or the first page's lookback) is kept whole.
fn cut_at_limit(
    mut matched: Vec<(PageKey, CalendarEventView)>,
    limit: usize,
    window: TimeRange,
) -> CalendarSearchPage {
    let start = matched[limit].0.1.max(window.start);
    let (keep, resume_from) = match matched.partition_point(|(key, _)| key.1 < start) {
        0 => (
            matched.partition_point(|(key, _)| key.1 <= start),
            start.checked_add(1).filter(|next| *next <= window.end),
        ),
        keep => (keep, Some(start)),
    };
    matched.truncate(keep);
    CalendarSearchPage::of(views(matched), resume_from)
}

fn views(matched: Vec<(PageKey, CalendarEventView)>) -> Vec<CalendarEventView> {
    matched.into_iter().map(|(_, view)| view).collect()
}

/// One search's admitted rows its selectors keep, with the exceptions and
/// withheld series every row's expansion is masked by: read once, then
/// expanded over a whole window or one slice of it at a time.
struct PreparedSearch {
    rows: Vec<CalendarEventRow>,
    exceptions: Vec<CalendarSeriesExceptionValue>,
    withheld: BTreeSet<(EntityId, String)>,
    needle: Option<String>,
    /// The rows a page holds, after the clamp; never zero.
    limit: usize,
}

/// Reads the search's rows: `None` when its limit is zero. Exceptions come
/// from every admitted row, before the selectors filter them.
fn prepare_search(
    read: &CalendarRead<'_>,
    req: &CalendarSearchRequest,
) -> Result<Option<PreparedSearch>> {
    validate_selectors(&req.calendars)?;
    let limit = req.limit.min(MAX_CALENDAR_SEARCH_LIMIT) as usize;
    if limit == 0 {
        return Ok(None);
    }
    let needle = req
        .text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_lowercase);

    let mut rows = Vec::new();
    visit_calendar_events(read, |row| {
        rows.push(row);
        Ok(())
    })?;
    let exceptions: Vec<_> = rows
        .iter()
        .filter_map(|row| row.facts.exception().cloned())
        .collect();
    let withheld: BTreeSet<_> = read.withheld_exception_series()?.into_keys().collect();
    rows.retain(|row| matches_selectors(row.facts.systems(), &req.calendars));
    Ok(Some(PreparedSearch {
        rows,
        exceptions,
        withheld,
        needle,
        limit,
    }))
}

impl PreparedSearch {
    /// Each row's view that matches the text, by its page key, unsorted:
    /// over `window`, each occurrence that meets it (and, with `owned_from`,
    /// starts at or after it: a slice past the first owns only the starts
    /// it holds); with no window, each row once. Rows are projected and
    /// expanded in their read order, so the first failing row's error is
    /// the one returned.
    fn matched(
        &self,
        window: Option<TimeRange>,
        owned_from: Option<u64>,
    ) -> Result<Vec<(PageKey, CalendarEventView)>> {
        let mut matched = Vec::new();
        for row in &self.rows {
            let view = project(row)?;
            if self
                .needle
                .as_deref()
                .is_some_and(|needle| !matches_text(&view, needle))
            {
                continue;
            }
            if let Some(window) = window {
                let occurrences =
                    super::occurrences::occurrences(row, window, &self.exceptions, &self.withheld)?;
                for at in occurrences {
                    if intersects(at, window) && owned_from.is_none_or(|from| at.start >= from) {
                        let mut occurrence = view.clone();
                        // A floating or all-day EVENT matches by its civil span
                        // and keeps no UTC instant in the view.
                        if row.occurred.is_some() {
                            occurrence.start_utc = Some(at.start);
                            occurrence.end_utc = Some(at.end);
                        }
                        matched.push((page_key(Some(at), row.id), occurrence));
                    }
                }
            } else {
                matched.push((page_key(row.occurred.or(row.wall_span), row.id), view));
            }
        }
        Ok(matched)
    }
}

/// A search row's place in its page: undated last, then start, end and
/// entity id.
type PageKey = (bool, u64, u64, EntityId);

/// Deterministic page order: earliest occurrence (or civil span) first,
/// undated EVENTs last, entity id breaking ties, so `limit` truncates the same
/// rows on every run.
fn page_key(occurred: Option<TimeRange>, id: EntityId) -> PageKey {
    match occurred {
        Some(at) => (false, at.start, at.end, id),
        None => (true, 0, 0, id),
    }
}

/// Inclusive-interval intersection, matching `TimeRange`'s inclusive contract.
fn intersects(event: TimeRange, window: TimeRange) -> bool {
    event.start <= window.end && event.end >= window.start
}

fn matches_text(view: &CalendarEventView, needle: &str) -> bool {
    view.name
        .as_deref()
        .is_some_and(|name| name.to_lowercase().contains(needle))
}

/// The row as the surface shows it: every field, the name included, from the
/// snapshot and the lane the row was admitted through.
fn project(row: &CalendarEventRow) -> Result<CalendarEventView> {
    Ok(CalendarEventView {
        origin: row
            .facts
            .origin()
            .ok_or(Error::InvalidClaimBody("withheld calendar origin"))?
            .as_str()
            .to_owned(),
        event_ref: row.id.to_hex(),
        name: row.name.clone(),
        start_utc: row.occurred.map(|at| at.start),
        end_utc: row.occurred.map(|at| at.end),
        calendar_systems: row.facts.systems().to_vec(),
        blocks_time: row.facts.blocks_time(),
    })
}

/// Reads the EVENT body's `name` field, tolerating bodies that are not a
/// MessagePack map: the EVENT profile is app-shaped, not engine-pinned.
pub(super) fn event_name(body: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(body);
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some(EVENT_BODY_NAME_KEY))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    })
}

pub(in crate::calendar) fn matches_selectors(
    systems: &[String],
    selectors: &[CalendarSel],
) -> bool {
    selectors.is_empty()
        || selectors.iter().any(|selector| {
            selector
                .system
                .as_ref()
                .is_none_or(|system| systems.contains(system))
        })
}
