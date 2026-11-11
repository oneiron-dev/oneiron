//! A CalDAV collection's zone across the sync cursor and the pulled bytes
//! (fix list row 19192).
//!
//! The zone a collection names its own places the all-day days of every
//! resource it carries that names none. So that each such resource reads
//! the zone the collection names now, the cursor this adapter hands the seat
//! records the zone its sync gave beside the DAV sync token, and a sync that
//! reads another zone starts again from an empty token: a full listing, whose
//! omissions the wire reconciles as deletions. The wire only ever sends and
//! returns the DAV token itself.

use crate::calendar::connectors::{RemoteCalendarChange, RemoteCalendarObject, RemoteSyncBatch};
use crate::calendar::ics::{
    ics_vtimezone_tzid, ics_with_calendar_timezone, parse_ics_feed, plain_zone_name,
};

/// What a cursor this adapter writes starts with. The zone its sync gave the
/// collection's resources follows (empty for none), then a line break, then
/// the DAV sync token.
const CURSOR_ZONE_PREFIX: &str = "oneiron-zone:";

/// The zone a CalDAV collection names its own: its RFC 7809
/// `CALDAV:calendar-timezone-id` when that is a plain zone name, else the
/// `TZID` of the one VTIMEZONE its RFC 4791 `CALDAV:calendar-timezone`
/// carries. RFC 7809 has the two agree; when a server's do not, the id is
/// read. `None` when neither names a plain zone: no fallback, never UTC.
#[must_use]
pub fn caldav_collection_timezone(
    timezone_id: Option<&str>,
    calendar_timezone: Option<&str>,
) -> Option<String> {
    timezone_id
        .and_then(plain_zone_name)
        .map(str::to_owned)
        .or_else(|| calendar_timezone.and_then(ics_vtimezone_tzid))
}

/// The DAV sync token to send from the seat's `cursor` while the collection
/// names `zone`: the recorded token when the cursor's sync gave the same zone
/// (none for a cursor written before zones were recorded), else `None`, a
/// full listing. A cursor whose framing does not read is a full listing too.
pub(super) fn sync_token<'c>(cursor: Option<&'c str>, zone: Option<&str>) -> Option<&'c str> {
    let (recorded, token) = recorded_cursor(cursor?)?;
    (recorded == zone && !token.is_empty()).then_some(token)
}

/// The zone and DAV sync token `cursor` records; a cursor without the prefix
/// is a token alone that names no zone. `None` when the framing has no line
/// break or names a zone that is not a plain zone name.
fn recorded_cursor(cursor: &str) -> Option<(Option<&str>, &str)> {
    let Some(rest) = cursor.strip_prefix(CURSOR_ZONE_PREFIX) else {
        return Some((None, cursor));
    };
    let (zone, token) = rest.split_once('\n')?;
    if zone.is_empty() {
        return Some((None, token));
    }
    let zone = plain_zone_name(zone).filter(|plain| *plain == zone)?;
    Some((Some(zone), token))
}

/// `cursor` with its DAV token dropped and its zone kept: the next pull lists
/// the collection whole again (fix list row 19192). A cursor whose framing
/// does not read is left as it is; it lists whole already.
pub(super) fn owing_full_listing(cursor: &str) -> String {
    match recorded_cursor(cursor) {
        Some((zone, _)) => format!("{CURSOR_ZONE_PREFIX}{}\n", zone.unwrap_or_default()),
        None => cursor.to_owned(),
    }
}

/// `batch` as the adapter returns it while the collection names `zone`:
/// each upserted resource's bytes take `zone` where they name no plain zone
/// of their own, and lose a collection's zone written in before when the
/// collection names none now (the bytes the seat archives and parses); the
/// next cursor records `zone` beside the DAV token.
pub(super) fn zoned_batch(batch: RemoteSyncBatch, zone: Option<&str>) -> RemoteSyncBatch {
    let RemoteSyncBatch {
        next_cursor,
        changes,
    } = batch;
    let changes = changes
        .into_iter()
        .map(|change| match change {
            RemoteCalendarChange::Upsert(object) => {
                RemoteCalendarChange::Upsert(zoned_object(object, zone))
            }
            other => other,
        })
        .collect();
    RemoteSyncBatch {
        next_cursor: next_cursor
            .map(|token| format!("{CURSOR_ZONE_PREFIX}{}\n{token}", zone.unwrap_or_default())),
        changes,
    }
}

/// `object` with its bytes given the collection's `zone` where they name
/// none of their own, and the convenience hash read from those bytes when
/// they changed.
fn zoned_object(mut object: RemoteCalendarObject, zone: Option<&str>) -> RemoteCalendarObject {
    let ics = ics_with_calendar_timezone(&object.ics, zone);
    if ics == object.ics {
        return object;
    }
    object.ics = ics;
    if let Ok(feed) = parse_ics_feed(&object.ics)
        && let Some(event) = feed.events.first()
    {
        object.content_hash = event.content_hash;
    }
    object
}
