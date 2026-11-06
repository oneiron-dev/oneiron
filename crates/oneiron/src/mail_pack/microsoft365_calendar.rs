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
//! a month later, so the view moves with time. The view lists occurrences,
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
                    .header("Prefer", PREFER);
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
            },
        };
        let page = match self.get(source, &cursor.link, &[])? {
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
            let id = graph_id(event.get("id"))?;
            let uid = format!("graph:{id}");
            if event.get("@removed").is_some() {
                changes.push(RemoteCalendarChange::Delete { href: id, uid });
                continue;
            }
            // A series master is not an occurrence; the view lists those.
            if event.get("type").and_then(Value::as_str) == Some("seriesMaster") {
                continue;
            }
            let ics = event_ics(&uid, event)?.into_bytes();
            changes.push(RemoteCalendarChange::Upsert(RemoteCalendarObject {
                href: id,
                etag: text_of(event.get("@odata.etag")),
                uid,
                sequence: 0,
                content_hash: *blake3::hash(&ics).as_bytes(),
                ics,
            }));
        }
        let (link, listing, complete) = match (
            text_of(page.get("@odata.nextLink")),
            text_of(page.get("@odata.deltaLink")),
        ) {
            (Some(next), _) => (next, cursor.listing, false),
            (None, Some(delta)) => (delta, false, true),
            (None, None) => return Err(refused("graph_calendar_page_without_a_link")),
        };
        let next = GraphCalendarCursor {
            opened_at: cursor.opened_at,
            link,
            listing,
        };
        Ok(MailCalendarRead::Pull(MailCalendarPull {
            changes,
            next_cursor: Some(
                serde_json::to_string(&next)
                    .map_err(|_| refused("graph_calendar_cursor_unencodable"))?,
            ),
            complete: complete || !cursor.listing,
            covers: Some(crate::TimeRange {
                start: cursor.opened_at.saturating_sub(VIEW_BEFORE_SECS),
                end: cursor.opened_at.saturating_add(VIEW_AFTER_SECS),
            }),
        }))
    }
}

/// One Graph event as a `VCALENDAR` resource of one VEVENT, its times UTC.
fn event_ics(uid: &str, event: &Value) -> Result<String> {
    let mut ics = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n");
    ics.push_str("PRODID:-//oneiron//mail-pack microsoft graph calendar//EN\r\n");
    ics.push_str("BEGIN:VEVENT\r\n");
    line(&mut ics, "UID", &text(uid));
    if let Some(stamp) = event
        .get("lastModifiedDateTime")
        .and_then(Value::as_str)
        .and_then(rfc3339_seconds)
    {
        line(&mut ics, "DTSTAMP", &utc_stamp(stamp)?);
    }
    // An all-day event lands as its days (FIX 16309), not as a UTC span:
    // Graph gives it as midnight to midnight, whose dates are the days.
    let all_day = event.get("isAllDay").and_then(Value::as_bool) == Some(true);
    let days = match (
        all_day,
        event
            .pointer("/start/dateTime")
            .and_then(Value::as_str)
            .and_then(midnight_date),
        event
            .pointer("/end/dateTime")
            .and_then(Value::as_str)
            .and_then(midnight_date),
    ) {
        (true, Some(start), Some(end)) if start < end => Some((start, end)),
        _ => None,
    };
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
