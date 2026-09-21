//! Read/search entry points plus pure projection helpers.

use std::io::Cursor;

use rmpv::Value;

use super::facts::{CalendarEventRow, CalendarRead, event_row, visit_calendar_events};
use super::requests::{
    CalendarEventView, CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest, CalendarSel,
    MAX_CALENDAR_SEARCH_LIMIT,
};
use crate::claim::ScopedRead;
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

/// Reads one calendar EVENT through an actor's scoped-read lane.
pub fn read_event_scoped(
    read: &ScopedRead<'_>,
    req: &CalendarReadRequest,
) -> Result<Option<CalendarEventView>> {
    read_event_in(&CalendarRead::Scoped(read), req)
}

fn read_event_in(
    read: &CalendarRead<'_>,
    req: &CalendarReadRequest,
) -> Result<Option<CalendarEventView>> {
    let id = EntityId::from_hex(req.event_ref.trim())?;
    let Some(row) = event_row(read, id)? else {
        return Ok(None);
    };
    Ok(Some(project(read.vault(), &row)?))
}

/// Searches calendar EVENTs through the internal lane.
pub fn search_events(vault: &Vault, req: &CalendarSearchRequest) -> Result<Vec<CalendarEventView>> {
    search_events_in(&CalendarRead::Vault(vault), req)
}

/// Searches calendar EVENTs through an actor's scoped-read lane.
pub fn search_events_scoped(
    read: &ScopedRead<'_>,
    req: &CalendarSearchRequest,
) -> Result<Vec<CalendarEventView>> {
    search_events_in(&CalendarRead::Scoped(read), req)
}

fn search_events_in(
    read: &CalendarRead<'_>,
    req: &CalendarSearchRequest,
) -> Result<Vec<CalendarEventView>> {
    validate_selectors(&req.calendars)?;
    let limit = req.limit.min(MAX_CALENDAR_SEARCH_LIMIT) as usize;
    if limit == 0 {
        return Ok(Vec::new());
    }
    let range = req.range.map(CalendarRangeDto::to_time_range);
    let needle = req
        .text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_lowercase);

    let vault = read.vault();
    let mut rows = Vec::new();
    visit_calendar_events(read, |row| {
        rows.push(row);
        Ok(())
    })?;
    let exceptions: Vec<_> = rows
        .iter()
        .filter_map(|row| row.facts.exception().cloned())
        .collect();
    let withheld = read.withheld_exception_series()?;
    let mut matched = Vec::new();
    for row in rows {
        if !matches_selectors(row.facts.systems(), &req.calendars) {
            continue;
        }
        let view = project(vault, &row)?;
        if needle
            .as_deref()
            .is_some_and(|needle| !matches_text(&view, needle))
        {
            continue;
        }
        if let Some(window) = range {
            for at in super::occurrences::occurrences(&row, window, &exceptions, &withheld)? {
                if intersects(at, window) {
                    let mut occurrence = view.clone();
                    occurrence.start_utc = Some(at.start);
                    occurrence.end_utc = Some(at.end);
                    matched.push((page_key(Some(at), row.id), occurrence));
                }
            }
        } else {
            matched.push((page_key(row.occurred, row.id), view));
        }
    }

    matched.sort_unstable_by_key(|(key, _)| *key);
    matched.truncate(limit);
    Ok(matched.into_iter().map(|(_, view)| view).collect())
}

/// Deterministic page order: earliest occurrence first, undated EVENTs last,
/// entity id breaking ties, so `limit` truncates the same rows on every run.
fn page_key(occurred: Option<TimeRange>, id: EntityId) -> (bool, u64, u64, EntityId) {
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

fn project(vault: &Vault, row: &CalendarEventRow) -> Result<CalendarEventView> {
    Ok(CalendarEventView {
        origin: row
            .facts
            .origin()
            .ok_or(Error::InvalidClaimBody("withheld calendar origin"))?
            .as_str()
            .to_owned(),
        event_ref: row.id.to_hex(),
        name: vault.get(&row.id)?.as_deref().and_then(event_name),
        start_utc: row.occurred.map(|at| at.start),
        end_utc: row.occurred.map(|at| at.end),
        calendar_systems: row.facts.systems().to_vec(),
        blocks_time: row.facts.blocks_time(),
    })
}

/// Reads the EVENT body's `name` field, tolerating bodies that are not a
/// MessagePack map: the EVENT profile is app-shaped, not engine-pinned.
fn event_name(body: &[u8]) -> Option<String> {
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
