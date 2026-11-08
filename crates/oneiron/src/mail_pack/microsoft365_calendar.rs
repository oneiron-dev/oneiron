//! The Microsoft 365 wire of the pack's calendar sources (FIX 12559 row 3;
//! MAIL-PROVIDERS = A): the person's primary calendar through Microsoft
//! Graph's calendar-view delta, over `reqwest::blocking`.
//!
//! Each call reads the source's own credential at its door
//! ([`Vault::with_source_token_at_door`]), effector
//! `connector:microsoft365_calendar`. HTTPS to Graph only, no redirects; a
//! link Graph answers with is followed only on Graph's own origin. Before a
//! source's first read the wire checks that the credential's user is the
//! person the source names (its `mail` or `userPrincipalName`).
//!
//! Graph tracks a calendar view, a fixed window of time: this wire's window
//! runs from a month before it was opened to a year after, and opens again
//! a month later, so the view moves with time. Each opening's first listing
//! also reads the four years past the view once, without tracking them
//! (fix list row 16313): an event that far ahead lands at once, and a
//! change to it lands at the next opening. The view lists occurrences,
//! not series: each occurrence, exception or single event lands as its own
//! event, its UID the Graph id (`graph:<id>`), its times in UTC (an all-day
//! event keeps its UTC span). A removed occurrence is a delete. An event
//! shown as free, or one the person declined, stays free.
//!
//! Call it from a blocking context: `reqwest::blocking` owns its own runtime.

use std::fmt::Write as _;

use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::calendar::{MailCalendarPull, MailCalendarRead, MailCalendarWire};
use super::credential::WireReads;
use super::rest::{self, RestAnswer, VerifiedCredentials, array, bearer_header, refused, text_of};
use super::source::MailProvider;
use super::wire::MailSyncSource;
use crate::Vault;
use crate::calendar::{RemoteCalendarChange, RemoteCalendarObject};
use crate::error::{Error, Result};

/// The custody effector a Microsoft 365 calendar credential is bound to.
pub const MICROSOFT365_CALENDAR_CONNECTOR_EFFECTOR: &str = "connector:microsoft365_calendar";

const GRAPH_ORIGIN: &str = "https://graph.microsoft.com/";
const GRAPH_ME_URL: &str = "https://graph.microsoft.com/v1.0/me";
const PREFER: &str = "IdType=\"ImmutableId\", outlook.timezone=\"UTC\", outlook.body-content-type=\"text\", odata.maxpagesize=100";
/// How far before its opening a view starts.
const VIEW_BEFORE_SECS: u64 = 31 * 24 * 3600;
/// How far after its opening a view ends.
const VIEW_AFTER_SECS: u64 = 366 * 24 * 3600;
/// How long a view stands before it opens again.
const VIEW_STANDS_SECS: u64 = 30 * 24 * 3600;
/// How far past a view's end its opening's far listing reads: within the
/// five years one Graph calendar view may span.
const FAR_AFTER_SECS: u64 = 4 * 366 * 24 * 3600;
/// The longest Graph id read.
const MAX_GRAPH_ID_BYTES: usize = 512;

/// Where a calendar source's view stands: when it opened, and the link its
/// next round or next page reads.
#[derive(Debug, Serialize, Deserialize)]
struct GraphCalendarCursor {
    opened_at: u64,
    link: String,
    /// Whether `link` continues the first full round of this view.
    listing: bool,
    /// The next page of this opening's far listing while it runs: the
    /// events past the view's end, read once (fix list row 16313). `link`
    /// then holds the view's delta link for the rounds after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    far: Option<String>,
}

/// Host-side Microsoft Graph calendar wire over `reqwest::blocking`.
pub struct HttpGraphCalendarWire<'v> {
    vault: &'v Vault,
    client: reqwest::blocking::Client,
    /// The credentials this wire has seen be their source's person.
    verified: VerifiedCredentials,
}

impl<'v> HttpGraphCalendarWire<'v> {
    /// Builds the wire: HTTPS only, no redirects, a 60 s timeout.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn new(vault: &'v Vault) -> Result<Self> {
        Ok(Self {
            vault,
            client: rest::https_client()?,
            verified: VerifiedCredentials::new(),
        })
    }

    fn get(
        &self,
        source: &MailSyncSource,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<RestAnswer> {
        self.get_preferring(source, url, query, PREFER)
    }

    /// [`Self::get`] with its own `Prefer` header: a read in another zone.
    fn get_preferring(
        &self,
        source: &MailSyncSource,
        url: &str,
        query: &[(&str, String)],
        prefer: &str,
    ) -> Result<RestAnswer> {
        if source.provider != MailProvider::Microsoft365 {
            return Err(refused(
                "graph_calendar_wire_reads_microsoft365_calendars_only",
            ));
        }
        if !url.starts_with(GRAPH_ORIGIN) {
            return Err(refused("graph_calendar_link_not_on_graph"));
        }
        let mut answer: Option<RestAnswer> = None;
        let _receipt = self.vault.with_source_token_at_door(
            source,
            WireReads::Calendar,
            MICROSOFT365_CALENDAR_CONNECTOR_EFFECTOR,
            &mut |token: &[u8]| {
                let auth = bearer_header(token)?;
                // The credential presented here is the one checked: its user
                // is the person the source names.
                if !self.verified.holds(source.source_ref, token) {
                    let request = self
                        .client
                        .get(GRAPH_ME_URL)
                        .query(&[("$select", "mail,userPrincipalName")])
                        .header(AUTHORIZATION, auth.clone())
                        .header("Prefer", PREFER);
                    let me = rest::send(request)?
                        .found_or_gone("graph_calendar")?
                        .ok_or_else(|| refused("graph_calendar_user_not_found"))?;
                    is_source_person(&me, source)?;
                    self.verified.insert(source.source_ref, token);
                }
                let request = self
                    .client
                    .get(url)
                    .query(query)
                    .header(AUTHORIZATION, auth)
                    .header("Prefer", prefer);
                answer = Some(rest::send(request)?);
                Ok(())
            },
        )?;
        answer.ok_or_else(|| refused("graph_calendar_credential_door_refused"))
    }

    /// The first link of a view opened at `now`.
    fn view_link(now: u64) -> Result<String> {
        let start = graph_time(now.saturating_sub(VIEW_BEFORE_SECS))?;
        let end = graph_time(now.saturating_add(VIEW_AFTER_SECS))?;
        Ok(format!(
            "{GRAPH_ME_URL}/calendarView/delta?startDateTime={start}&endDateTime={end}"
        ))
    }

    /// The far listing of the view opened at `opened_at`: the occurrences
    /// from the view's end to four years past it, read without a delta.
    fn far_link(opened_at: u64) -> Result<String> {
        let view_end = opened_at.saturating_add(VIEW_AFTER_SECS);
        let start = graph_time(view_end)?;
        let end = graph_time(view_end.saturating_add(FAR_AFTER_SECS))?;
        Ok(format!(
            "{GRAPH_ME_URL}/calendarView?startDateTime={start}&endDateTime={end}"
        ))
    }
}

impl MailCalendarWire for HttpGraphCalendarWire<'_> {
    fn pull(&self, source: &MailSyncSource, cursor: Option<&str>) -> Result<MailCalendarRead> {
        let now = crate::unix_seconds_now();
        let cursor = match cursor {
            Some(cursor) => {
                let cursor: GraphCalendarCursor = serde_json::from_str(cursor)
                    .map_err(|_| refused("graph_calendar_cursor_unreadable"))?;
                // A view that has stood its month opens again: the listing
                // starts over in a window that has moved with time.
                if now >= cursor.opened_at.saturating_add(VIEW_STANDS_SECS) {
                    return Ok(MailCalendarRead::Expired);
                }
                cursor
            }
            None => GraphCalendarCursor {
                opened_at: now,
                link: Self::view_link(now)?,
                listing: true,
                far: None,
            },
        };
        let page = match self.get(source, cursor.far.as_ref().unwrap_or(&cursor.link), &[])? {
            RestAnswer::Found(page) => page,
            RestAnswer::Failed { status, code }
                if status == 410
                    || code
                        .as_deref()
                        .is_some_and(|code| code.to_ascii_lowercase().contains("syncstate")) =>
            {
                return Ok(MailCalendarRead::Expired);
            }
            RestAnswer::Failed { status, .. } => {
                return Err(Error::InvalidConfig(format!(
                    "graph_calendar_status_{status}"
                )));
            }
        };
        let mut changes = Vec::new();
        for event in array(&page, "value") {
            let change = if event.get("@removed").is_some() {
                self.removed(source, event)?
            } else {
                self.upsert(source, event)?
            };
            changes.extend(change);
        }
        let next_page = text_of(page.get("@odata.nextLink"));
        let (next, complete) = if cursor.far.is_some() {
            // The far listing's pages end the opening's listing; the view's
            // delta link waits in `link`.
            let complete = next_page.is_none();
            (
                GraphCalendarCursor {
                    opened_at: cursor.opened_at,
                    link: cursor.link,
                    listing: false,
                    far: next_page,
                },
                complete,
            )
        } else {
            match (next_page, text_of(page.get("@odata.deltaLink"))) {
                (Some(next), _) => (
                    GraphCalendarCursor {
                        opened_at: cursor.opened_at,
                        link: next,
                        listing: cursor.listing,
                        far: None,
                    },
                    false,
                ),
                // The view's first listing ends: its far listing follows.
                (None, Some(delta)) if cursor.listing => (
                    GraphCalendarCursor {
                        opened_at: cursor.opened_at,
                        link: delta,
                        listing: false,
                        far: Some(Self::far_link(cursor.opened_at)?),
                    },
                    false,
                ),
                (None, Some(delta)) => (
                    GraphCalendarCursor {
                        opened_at: cursor.opened_at,
                        link: delta,
                        listing: false,
                        far: None,
                    },
                    true,
                ),
                (None, None) => return Err(refused("graph_calendar_page_without_a_link")),
            }
        };
        let listing = cursor.listing || cursor.far.is_some();
        Ok(MailCalendarRead::Pull(MailCalendarPull {
            changes,
            next_cursor: Some(
                serde_json::to_string(&next)
                    .map_err(|_| refused("graph_calendar_cursor_unencodable"))?,
            ),
            complete: complete || !listing,
            // The opening's listing reads the view and its far listing: what
            // it did not see in either span is gone.
            covers: Some(crate::TimeRange {
                start: cursor.opened_at.saturating_sub(VIEW_BEFORE_SECS),
                end: cursor
                    .opened_at
                    .saturating_add(VIEW_AFTER_SECS)
                    .saturating_add(FAR_AFTER_SECS),
            }),
            vacated: Vec::new(),
        }))
    }
}

impl HttpGraphCalendarWire<'_> {
    /// One listed event as its resource; nothing for a series master, which
    /// is not an occurrence (the view lists those).
    fn upsert(
        &self,
        source: &MailSyncSource,
        event: &Value,
    ) -> Result<Option<RemoteCalendarChange>> {
        if event.get("type").and_then(Value::as_str) == Some("seriesMaster") {
            return Ok(None);
        }
        let id = graph_id(event.get("id"))?;
        let uid = format!("graph:{id}");
        let days = self.all_day_days(source, event)?;
        let ics = event_ics(&uid, event, days.as_ref())?.into_bytes();
        Ok(Some(RemoteCalendarChange::Upsert(RemoteCalendarObject {
            href: id,
            etag: text_of(event.get("@odata.etag")),
            uid,
            sequence: 0,
            content_hash: *blake3::hash(&ics).as_bytes(),
            ics,
        })))
    }

    /// An event the view names removed. The view names so an event deleted
    /// in its range, and also one outside its range added, changed or
    /// deleted (Graph's event delta), such as one the far listing landed
    /// (fix list row 16313). So the event is read again: one that still
    /// exists lands as it is now, and only one gone is a delete.
    fn removed(
        &self,
        source: &MailSyncSource,
        event: &Value,
    ) -> Result<Option<RemoteCalendarChange>> {
        let id = graph_id(event.get("id"))?;
        let url = format!(
            "{GRAPH_ME_URL}/events/{}",
            super::microsoft365::path_segment(&id)
        );
        match self.get(source, &url, &[])? {
            RestAnswer::Found(current) => self.upsert(source, &current),
            RestAnswer::Failed {
                status: 404 | 410, ..
            } => Ok(Some(RemoteCalendarChange::Delete {
                uid: format!("graph:{id}"),
                href: id,
            })),
            RestAnswer::Failed { status, .. } => Err(Error::InvalidConfig(format!(
                "graph_calendar_status_{status}"
            ))),
        }
    }

    /// The days an all-day event covers (FIX 16309), `YYYYMMDD` start and
    /// exclusive end, in the zone it was made in. The view answers in UTC, so
    /// its midnight-to-midnight arrives shifted by that zone's offset: a UTC
    /// time after noon is a zone east of UTC, one before 10:00 a zone west of
    /// it. Between them both a zone of UTC-10 to -12 and one of UTC+12 to +14
    /// fit, and the event read again in its own zone settles which. `None`
    /// for a timed event, or one whose days do not read: it keeps its span.
    fn all_day_days(
        &self,
        source: &MailSyncSource,
        event: &Value,
    ) -> Result<Option<(String, String)>> {
        if event.get("isAllDay").and_then(Value::as_bool) != Some(true) {
            return Ok(None);
        }
        let at = |field: &str| {
            event
                .pointer(&format!("/{field}/dateTime"))
                .and_then(Value::as_str)
                .and_then(utc_wall_seconds)
        };
        let (Some(start), Some(end)) = (at("start"), at("end")) else {
            return Ok(None);
        };
        let day = 24 * 3_600_u64;
        let time = start % day;
        let east = |offset: u64| (start + offset, end + offset);
        let local = if time == 0 {
            Some((start, end))
        } else if time > 12 * 3_600 {
            Some(east(day - time))
        } else if time < 10 * 3_600 {
            Some((start - time, end.saturating_sub(time)))
        } else {
            None
        };
        let Some((start, end)) = local else {
            return self.all_day_days_in_own_zone(source, event);
        };
        // A day boundary the zone's daylight saving moved by an hour still
        // names its day: the end is read at its nearest midnight.
        let end = (end + day / 2) / day * day;
        if start % day != 0 || end <= start {
            return Ok(None);
        }
        Ok(day_digits(start).zip(day_digits(end)))
    }

    /// The days of an all-day event read again in the zone it was made in.
    fn all_day_days_in_own_zone(
        &self,
        source: &MailSyncSource,
        event: &Value,
    ) -> Result<Option<(String, String)>> {
        let (Some(id), Some(zone)) = (
            text_of(event.get("id")),
            text_of(event.get("originalStartTimeZone")),
        ) else {
            return Ok(None);
        };
        if zone
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
        {
            return Ok(None);
        }
        let url = format!(
            "{GRAPH_ME_URL}/events/{}",
            super::microsoft365::path_segment(&id)
        );
        let prefer = format!("IdType=\"ImmutableId\", outlook.timezone=\"{zone}\"");
        let query = [("$select", "start,end,isAllDay".to_owned())];
        let RestAnswer::Found(own) = self.get_preferring(source, &url, &query, &prefer)? else {
            return Ok(None);
        };
        let date = |field: &str| {
            own.pointer(&format!("/{field}/dateTime"))
                .and_then(Value::as_str)
                .and_then(midnight_date)
        };
        Ok(match (date("start"), date("end")) {
            (Some(start), Some(end)) if start < end => Some((start, end)),
            _ => None,
        })
    }
}

/// The `YYYYMMDD` date of `seconds`, a midnight on the UTC carrier.
fn day_digits(seconds: u64) -> Option<String> {
    let at = chrono::DateTime::from_timestamp(i64::try_from(seconds).ok()?, 0)?;
    Some(at.format("%Y%m%d").to_string())
}

/// The IANA zone an all-day Graph event's days fall in: the zone it was
/// made in (`originalStartTimeZone`), an IANA name as it is or a Windows
/// name through CLDR's table (fix list row 17868). `None` for a name
/// neither reads, whose days keep the all-zone envelope.
fn event_zone(event: &Value) -> Option<String> {
    let zone = text_of(event.get("originalStartTimeZone"))?;
    let zone = zone.trim();
    if crate::calendar::tz::ResolvedTimeZone::new(zone).is_ok() {
        return Some(zone.to_owned());
    }
    crate::calendar::windows_zones::iana_of_windows(zone).map(str::to_owned)
}

/// One Graph event as a `VCALENDAR` resource of one VEVENT: an all-day
/// event's `days`, else its times UTC.
fn event_ics(uid: &str, event: &Value, days: Option<&(String, String)>) -> Result<String> {
    let mut ics = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n");
    ics.push_str("PRODID:-//oneiron//mail-pack microsoft graph calendar//EN\r\n");
    // An all-day event's days are in the zone it was made in, which heads
    // its resource (fix list row 17868).
    if days.is_some()
        && let Some(zone) = event_zone(event)
    {
        ics.push_str("X-WR-TIMEZONE:");
        ics.push_str(&zone);
        ics.push_str("\r\n");
    }
    ics.push_str("BEGIN:VEVENT\r\n");
    line(&mut ics, "UID", &text(uid));
    if let Some(stamp) = event
        .get("lastModifiedDateTime")
        .and_then(Value::as_str)
        .and_then(rfc3339_seconds)
    {
        line(&mut ics, "DTSTAMP", &utc_stamp(stamp)?);
    }
    // An all-day event lands as its days (FIX 16309), not as a UTC span.
    if let Some((start, end)) = days {
        line(&mut ics, "DTSTART;VALUE=DATE", &start);
        line(&mut ics, "DTEND;VALUE=DATE", &end);
    } else {
        for (name, field) in [("DTSTART", "start"), ("DTEND", "end")] {
            if let Some(at) = event
                .pointer(&format!("/{field}/dateTime"))
                .and_then(Value::as_str)
                .and_then(utc_wall_seconds)
            {
                line(&mut ics, name, &utc_stamp(at)?);
            }
        }
    }
    if let Some(subject) = text_of(event.get("subject")) {
        line(&mut ics, "SUMMARY", &text(&subject));
    }
    if let Some(body) = event
        .pointer("/body/content")
        .and_then(Value::as_str)
        .map(rest::tidy_text)
        .filter(|body| !body.is_empty())
    {
        line(&mut ics, "DESCRIPTION", &text(&body));
    }
    if let Some(location) = event
        .pointer("/location/displayName")
        .and_then(Value::as_str)
        .filter(|location| !location.trim().is_empty())
    {
        line(&mut ics, "LOCATION", &text(location));
    }
    let cancelled = event.get("isCancelled").and_then(Value::as_bool) == Some(true);
    let status = if cancelled {
        "CANCELLED"
    } else if event.get("showAs").and_then(Value::as_str) == Some("tentative") {
        "TENTATIVE"
    } else {
        "CONFIRMED"
    };
    line(&mut ics, "STATUS", status);
    let free = event.get("showAs").and_then(Value::as_str) == Some("free")
        || event
            .pointer("/responseStatus/response")
            .and_then(Value::as_str)
            == Some("declined");
    line(
        &mut ics,
        "TRANSP",
        if free { "TRANSPARENT" } else { "OPAQUE" },
    );
    if let Some(email) = event
        .pointer("/organizer/emailAddress/address")
        .and_then(Value::as_str)
        .filter(|email| !email.is_empty())
    {
        let name = cn_param(event.pointer("/organizer/emailAddress/name"));
        line(
            &mut ics,
            &format!("ORGANIZER{name}"),
            &format!("mailto:{}", text(email)),
        );
    }
    for attendee in array(event, "attendees") {
        let Some(email) = attendee
            .pointer("/emailAddress/address")
            .and_then(Value::as_str)
            .filter(|email| !email.is_empty())
        else {
            continue;
        };
        let name = cn_param(attendee.pointer("/emailAddress/name"));
        let partstat = match attendee.pointer("/status/response").and_then(Value::as_str) {
            Some("accepted" | "organizer") => "ACCEPTED",
            Some("declined") => "DECLINED",
            Some("tentativelyAccepted") => "TENTATIVE",
            _ => "NEEDS-ACTION",
        };
        let role = if attendee.get("type").and_then(Value::as_str) == Some("optional") {
            "OPT-PARTICIPANT"
        } else {
            "REQ-PARTICIPANT"
        };
        line(
            &mut ics,
            &format!("ATTENDEE{name};PARTSTAT={partstat};ROLE={role}"),
            &format!("mailto:{}", text(email)),
        );
    }
    if let Some(join) = event
        .pointer("/onlineMeeting/joinUrl")
        .and_then(Value::as_str)
        .filter(|join| !join.is_empty())
    {
        line(&mut ics, "URL", &text(join));
    }
    ics.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    Ok(ics)
}

/// A Graph `dateTime` in UTC (the wire asks for UTC): `2026-11-06T15:00:00.0000000`.
/// The `YYYYMMDD` date of a Graph wall time at midnight; `None` for any
/// other time, which is not a day boundary.
fn midnight_date(value: &str) -> Option<String> {
    let bare = value.split('.').next().unwrap_or(value);
    let bare = bare.strip_suffix('Z').unwrap_or(bare);
    let at = chrono::NaiveDateTime::parse_from_str(bare, "%Y-%m-%dT%H:%M:%S").ok()?;
    bare.ends_with("T00:00:00")
        .then(|| at.format("%Y%m%d").to_string())
}

fn utc_wall_seconds(value: &str) -> Option<u64> {
    let bare = value.split('.').next().unwrap_or(value);
    let bare = bare.strip_suffix('Z').unwrap_or(bare);
    chrono::NaiveDateTime::parse_from_str(bare, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .and_then(|date| u64::try_from(date.and_utc().timestamp()).ok())
}

fn rfc3339_seconds(value: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .and_then(|date| u64::try_from(date.timestamp()).ok())
}

fn utc_stamp(seconds: u64) -> Result<String> {
    let date = i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .ok_or_else(|| refused("graph_calendar_time_out_of_range"))?;
    Ok(date.format("%Y%m%dT%H%M%SZ").to_string())
}

/// Unix seconds as the UTC time a Graph view takes.
fn graph_time(seconds: u64) -> Result<String> {
    let date = i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .ok_or_else(|| refused("graph_calendar_time_out_of_range"))?;
    Ok(date.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn line(ics: &mut String, name: &str, value: &str) {
    let _ = write!(ics, "{name}:{value}\r\n");
}

/// An RFC 5545 TEXT value: backslash, semicolon, comma and newline escaped,
/// other control characters dropped.
fn text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            ch if ch.is_control() => {}
            ch => out.push(ch),
        }
    }
    out
}

fn cn_param(name: Option<&Value>) -> String {
    let Some(name) = name.and_then(Value::as_str) else {
        return String::new();
    };
    let name: String = name
        .chars()
        .filter(|ch| *ch != '"' && !ch.is_control())
        .collect();
    if name.trim().is_empty() {
        String::new()
    } else {
        format!(";CN=\"{}\"", name.trim())
    }
}

fn graph_id(value: Option<&Value>) -> Result<String> {
    let id = value.and_then(Value::as_str).unwrap_or_default();
    if id.is_empty()
        || id.len() > MAX_GRAPH_ID_BYTES
        || !id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(refused("graph_calendar_id_not_plain"));
    }
    Ok(id.to_owned())
}

/// The Graph user `me` is the person the source names (its `mail` or
/// `userPrincipalName`), or the source names its credential's own primary
/// calendar.
fn is_source_person(me: &Value, source: &MailSyncSource) -> Result<()> {
    let wanted = source.address.trim();
    let reads = wanted.eq_ignore_ascii_case("primary")
        || ["mail", "userPrincipalName"].iter().any(|field| {
            me.get(*field)
                .and_then(Value::as_str)
                .is_some_and(|address| address.trim().eq_ignore_ascii_case(wanted))
        });
    if reads {
        Ok(())
    } else {
        Err(refused("graph_calendar_credential_is_another_person"))
    }
}
