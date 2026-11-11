//! The Google Calendar wire of the pack's calendar sources (FIX 12559 row
//! 5; MAIL-PROVIDERS = A, Google Workspace first): Calendar API v3 over
//! `reqwest::blocking`, for a Google Workspace or Google calendar source.
//!
//! Each call reads the source's own credential at its door
//! ([`Vault::with_source_token_at_door`]), effector
//! `connector:google_calendar`. HTTPS only, no redirects; the Bearer header
//! exists only inside the door callback, marked sensitive. Before a source's
//! first read the wire checks that the credential's user owns the calendar
//! the source names (its calendar-list access role is `owner`).
//!
//! A pull is one page of `events.list`: the full listing first, then the
//! changes since its sync token (an expired token, Google's 410, lists the
//! calendar again). Each changed UID becomes one resource: the event, or a
//! recurring series' master with its changed instances, read whole by its
//! iCalendar UID and written as one `VCALENDAR` document the calendar
//! engine's own parser reads. A deleted event, or a deleted series, is a
//! delete. An instance shared with the person without its series is left
//! out: no resource carries an instance without its master.
//!
//! Call it from a blocking context: `reqwest::blocking` owns its own runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::calendar::{MailCalendarPull, MailCalendarRead, MailCalendarWire, landed_uid};
use super::credential::WireReads;
use super::gmail::reads_google_mail;
use super::rest::{
    self, FreshGoogleTokens, RestAnswer, VerifiedCredentials, array, refused, text_of,
};
use super::wire::MailSyncSource;
use crate::Vault;
use crate::calendar::{RemoteCalendarChange, RemoteCalendarObject};
use crate::error::{Error, Result};

/// The custody effector a Google Calendar credential is bound to.
pub const GOOGLE_CALENDAR_CONNECTOR_EFFECTOR: &str = "connector:google_calendar";

const CALENDAR_API_URL: &str = "https://www.googleapis.com/calendar/v3";
const EVENTS_PAGE_SIZE: u32 = 250;
/// The longest iCalendar UID or Google id read.
const MAX_ID_BYTES: usize = 1_024;

/// Where a calendar source's pull stands: the sync token of the last
/// finished listing, the next page of the listing in progress, and the
/// calendar's zone that listing wrote into its resources (fix list row
/// 17868).
#[derive(Debug, Default, Serialize, Deserialize)]
struct GoogleCalendarCursor {
    sync: Option<String>,
    page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    zone: Option<String>,
}

/// The longest calendar zone name written into a resource.
const MAX_ZONE_BYTES: usize = 64;

/// The calendar's zone a listing page names (its top-level `timeZone`),
/// when it is a plain zone name: ASCII letters, digits and `/_+-` only.
fn page_zone(page: &Value) -> Option<String> {
    text_of(page.get("timeZone")).filter(|zone| {
        !zone.is_empty()
            && zone.len() <= MAX_ZONE_BYTES
            && zone
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_+-".contains(&byte))
    })
}

/// Host-side Google Calendar wire over `reqwest::blocking`, for the calendar
/// sources of one vault.
pub struct HttpGoogleCalendarWire<'v> {
    vault: &'v Vault,
    client: reqwest::blocking::Client,
    /// The credentials this wire has seen own their source's calendar.
    verified: VerifiedCredentials,
    /// The fresh access tokens its sources' stored grants were exchanged
    /// for (fix list row 16311).
    tokens: FreshGoogleTokens,
}

impl<'v> HttpGoogleCalendarWire<'v> {
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
            tokens: FreshGoogleTokens::new(),
        })
    }

    /// One GET with the source's credential, read at its door.
    fn get(
        &self,
        source: &MailSyncSource,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<RestAnswer> {
        if !reads_google_mail(source.provider) {
            return Err(refused("google_calendar_wire_reads_google_calendars_only"));
        }
        let calendar = source.address.trim();
        require_id(calendar)?;
        let entry_url = format!(
            "{CALENDAR_API_URL}/users/me/calendarList/{}",
            path_segment(calendar)
        );
        let mut answer: Option<RestAnswer> = None;
        let _receipt = self.vault.with_source_token_at_door(
            source,
            WireReads::Calendar,
            GOOGLE_CALENDAR_CONNECTOR_EFFECTOR,
            &mut |token: &[u8]| {
                let auth = self.tokens.bearer(&self.client, source.source_ref, token)?;
                // The credential presented here is the one checked: its user
                // owns the calendar the source names.
                if !self.verified.holds(source.source_ref, token) {
                    let request = self
                        .client
                        .get(&entry_url)
                        .header(AUTHORIZATION, auth.clone());
                    let entry = rest::send(request)?
                        .found_or_gone("google_calendar")?
                        .ok_or_else(|| {
                            refused("google_calendar_not_in_the_credentials_calendar_list")
                        })?;
                    if entry.get("accessRole").and_then(Value::as_str) != Some("owner") {
                        return Err(refused(
                            "google_calendar_credential_does_not_own_the_calendar",
                        ));
                    }
                    self.verified.insert(source.source_ref, token);
                }
                let request = self
                    .client
                    .get(url)
                    .query(query)
                    .header(AUTHORIZATION, auth);
                answer = Some(rest::send(request)?);
                Ok(())
            },
        )?;
        answer.ok_or_else(|| refused("google_calendar_credential_door_refused"))
    }

    fn calendar_url(source: &MailSyncSource) -> Result<String> {
        let calendar = source.address.trim();
        require_id(calendar)?;
        Ok(format!(
            "{CALENDAR_API_URL}/calendars/{}",
            path_segment(calendar)
        ))
    }

    /// Every event of the series with iCalendar UID `uid`: its master and
    /// its changed instances, deleted ones included.
    fn series(&self, source: &MailSyncSource, uid: &str) -> Result<Vec<Value>> {
        let url = format!("{}/events", Self::calendar_url(source)?);
        let mut query = vec![
            ("iCalUID", uid.to_owned()),
            ("showDeleted", "true".to_owned()),
            ("singleEvents", "false".to_owned()),
            ("maxResults", EVENTS_PAGE_SIZE.to_string()),
        ];
        let mut events = Vec::new();
        loop {
            let page = self
                .get(source, &url, &query)?
                .found_or_gone("google_calendar")?
                .ok_or_else(|| refused("google_calendar_not_found"))?;
            events.extend(array(&page, "items").iter().cloned());
            let Some(next) = text_of(page.get("nextPageToken")) else {
                return Ok(events);
            };
            query.retain(|(name, _)| *name != "pageToken");
            query.push(("pageToken", next));
        }
    }
}

impl MailCalendarWire for HttpGoogleCalendarWire<'_> {
    fn pull(&self, source: &MailSyncSource, cursor: Option<&str>) -> Result<MailCalendarRead> {
        let cursor: GoogleCalendarCursor = match cursor {
            Some(cursor) => serde_json::from_str(cursor)
                .map_err(|_| refused("google_calendar_cursor_unreadable"))?,
            None => GoogleCalendarCursor::default(),
        };
        let url = format!("{}/events", Self::calendar_url(source)?);
        let mut query = vec![
            ("showDeleted", "true".to_owned()),
            ("singleEvents", "false".to_owned()),
            ("maxResults", EVENTS_PAGE_SIZE.to_string()),
        ];
        // An incremental read sends its sync token on every page, the page
        // token beside it; a full listing sends its page token alone.
        if let Some(sync) = &cursor.sync {
            query.push(("syncToken", sync.clone()));
        }
        if let Some(page) = &cursor.page {
            query.push(("pageToken", page.clone()));
        }
        let page = match self.get(source, &url, &query)? {
            RestAnswer::Found(page) => page,
            // Google answers 410 for a sync token it no longer honours.
            RestAnswer::Failed { status: 410, .. } => return Ok(MailCalendarRead::Expired),
            RestAnswer::Failed { status, .. } => {
                return Err(Error::InvalidConfig(format!(
                    "google_calendar_status_{status}"
                )));
            }
        };
        // The calendar's zone places its all-day days, and every resource
        // carries it. A zone other than the one this pull's earlier pages or
        // listing wrote leaves those resources on the old one: the calendar
        // is listed again whole, so each all-day event takes the new zone.
        let zone = page_zone(&page);
        if (cursor.sync.is_some() || cursor.page.is_some()) && cursor.zone != zone {
            return Ok(MailCalendarRead::Expired);
        }
        let mut by_uid: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        // UIDs whose series is read again whole, and deleted resources by UID.
        let mut reread: BTreeSet<String> = BTreeSet::new();
        let mut gone: BTreeMap<String, String> = BTreeMap::new();
        for event in array(&page, "items") {
            if let Some(uid) = text_of(event.get("iCalUID")) {
                require_id(&uid)?;
                by_uid.entry(uid).or_default().push(event.clone());
                continue;
            }
            // A deleted event may carry no more than its id: its UID is the
            // one landed for it, or for its series' master. One never
            // landed here has nothing to take back.
            let Some(id) = text_of(event.get("id")) else {
                continue;
            };
            require_id(&id)?;
            if let Some(uid) = landed_uid(self.vault, source.source_ref, &id)? {
                if event.get("status").and_then(Value::as_str) == Some("cancelled") {
                    gone.insert(uid, id);
                } else {
                    reread.insert(uid);
                }
                continue;
            }
            let master = text_of(event.get("recurringEventId"))
                .or_else(|| id.rsplit_once('_').map(|(master, _)| master.to_owned()));
            if let Some(master) = master
                && let Some(uid) = landed_uid(self.vault, source.source_ref, &master)?
            {
                reread.insert(uid);
            }
        }
        let mut changes = Vec::new();
        for (uid, events) in by_uid {
            let series_member = reread.remove(&uid)
                || events.iter().any(|event| {
                    event.get("recurrence").is_some() || event.get("recurringEventId").is_some()
                });
            let series = if series_member {
                self.series(source, &uid)?
            } else {
                events
            };
            gone.remove(&uid);
            if let Some(change) = resource_change(&uid, &series, zone.as_deref())? {
                changes.push(change);
            }
        }
        for uid in reread {
            gone.remove(&uid);
            let series = self.series(source, &uid)?;
            if let Some(change) = resource_change(&uid, &series, zone.as_deref())? {
                changes.push(change);
            }
        }
        for (uid, href) in gone {
            changes.push(RemoteCalendarChange::Delete { href, uid });
        }
        let (next_cursor, complete) = match (
            text_of(page.get("nextPageToken")),
            text_of(page.get("nextSyncToken")),
        ) {
            (Some(next), _) => (
                GoogleCalendarCursor {
                    sync: cursor.sync,
                    page: Some(next),
                    zone,
                },
                false,
            ),
            (None, Some(sync)) => (
                GoogleCalendarCursor {
                    sync: Some(sync),
                    page: None,
                    zone,
                },
                true,
            ),
            (None, None) => (
                GoogleCalendarCursor {
                    sync: cursor.sync,
                    page: None,
                    zone,
                },
                true,
            ),
        };
        Ok(MailCalendarRead::Pull(MailCalendarPull {
            changes,
            next_cursor: Some(
                serde_json::to_string(&next_cursor)
                    .map_err(|_| refused("google_calendar_cursor_unencodable"))?,
            ),
            complete,
            covers: None,
            vacated: Vec::new(),
        }))
    }
}

/// One UID's resource from its events: a delete when its master is
/// cancelled, the master with its instances otherwise, nothing when no
/// master is among them. The calendar's `zone` heads the resource as its
/// `X-WR-TIMEZONE`, which places its all-day days (fix list row 17868).
fn resource_change(
    uid: &str,
    events: &[Value],
    zone: Option<&str>,
) -> Result<Option<RemoteCalendarChange>> {
    let Some(master) = events
        .iter()
        .find(|event| event.get("recurringEventId").is_none())
    else {
        return Ok(None);
    };
    let href = text_of(master.get("id")).unwrap_or_else(|| uid.to_owned());
    if master.get("status").and_then(Value::as_str) == Some("cancelled") {
        return Ok(Some(RemoteCalendarChange::Delete {
            href,
            uid: uid.to_owned(),
        }));
    }
    let mut ics = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n");
    ics.push_str("PRODID:-//oneiron//mail-pack google calendar//EN\r\n");
    if let Some(zone) = zone {
        ics.push_str("X-WR-TIMEZONE:");
        ics.push_str(zone);
        ics.push_str("\r\n");
    }
    write_vevent(&mut ics, uid, master, None)?;
    for instance in events
        .iter()
        .filter(|event| event.get("recurringEventId").is_some())
    {
        let Some(original) = instance.get("originalStartTime") else {
            continue;
        };
        write_vevent(&mut ics, uid, instance, Some(original))?;
    }
    ics.push_str("END:VCALENDAR\r\n");
    let ics = ics.into_bytes();
    Ok(Some(RemoteCalendarChange::Upsert(RemoteCalendarObject {
        href,
        etag: text_of(master.get("etag")),
        uid: uid.to_owned(),
        sequence: sequence_of(master),
        content_hash: *blake3::hash(&ics).as_bytes(),
        ics,
    })))
}

/// One event as a VEVENT: a series master (with its recurrence lines) when
/// `original` is `None`, else the instance that replaced the occurrence
/// starting at `original`. An all-day occurrence is named by its date, the
/// civil key its series steps on (FIX 16568).
fn write_vevent(
    ics: &mut String,
    uid: &str,
    event: &Value,
    original: Option<&Value>,
) -> Result<()> {
    let cancelled = event.get("status").and_then(Value::as_str) == Some("cancelled");
    ics.push_str("BEGIN:VEVENT\r\n");
    line(ics, "UID", &text(uid));
    line(ics, "SEQUENCE", &sequence_of(event).to_string());
    if let Some(stamp) = event
        .get("updated")
        .and_then(Value::as_str)
        .and_then(rfc3339_seconds)
    {
        line(ics, "DTSTAMP", &utc_stamp(stamp)?);
    }
    if let Some(original) = original {
        let recurrence_id = match original.get("date").and_then(Value::as_str) {
            Some(date) => day_recurrence_id(date)?,
            None => time_property("RECURRENCE-ID", original)?
                .ok_or_else(|| refused("google_calendar_instance_without_original_start"))?,
        };
        ics.push_str(&recurrence_id);
    }
    // A deleted instance may carry no times of its own: it starts where the
    // occurrence it removes started.
    if let Some(start) = event.get("start").or(original)
        && let Some(start) = time_property("DTSTART", start)?
    {
        ics.push_str(&start);
    }
    if let Some(end) = event.get("end")
        && let Some(end) = time_property("DTEND", end)?
    {
        ics.push_str(&end);
    }
    if original.is_none() {
        for rule in array(event, "recurrence").iter().filter_map(Value::as_str) {
            let rule = rule.trim();
            let name = rule
                .split([';', ':'])
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            if matches!(name.as_str(), "RRULE" | "EXRULE" | "RDATE" | "EXDATE")
                && rule.chars().all(|ch| !ch.is_control())
            {
                ics.push_str(rule);
                ics.push_str("\r\n");
            }
        }
    }
    if let Some(summary) = text_of(event.get("summary")) {
        line(ics, "SUMMARY", &text(&summary));
    }
    if let Some(description) = text_of(event.get("description")) {
        line(ics, "DESCRIPTION", &text(&description));
    }
    if let Some(location) = text_of(event.get("location")) {
        line(ics, "LOCATION", &text(&location));
    }
    let status = if cancelled {
        "CANCELLED"
    } else if event.get("status").and_then(Value::as_str) == Some("tentative") {
        "TENTATIVE"
    } else {
        "CONFIRMED"
    };
    line(ics, "STATUS", status);
    // The calendar's own person declined: their time stays free.
    let declined = array(event, "attendees").iter().any(|attendee| {
        attendee.get("self").and_then(Value::as_bool) == Some(true)
            && attendee.get("responseStatus").and_then(Value::as_str) == Some("declined")
    });
    let transparent =
        declined || event.get("transparency").and_then(Value::as_str) == Some("transparent");
    line(
        ics,
        "TRANSP",
        if transparent { "TRANSPARENT" } else { "OPAQUE" },
    );
    if let Some(organizer) = event.get("organizer")
        && let Some(email) = text_of(organizer.get("email"))
    {
        let name = cn_param(organizer.get("displayName"));
        line(
            ics,
            &format!("ORGANIZER{name}"),
            &format!("mailto:{}", text(&email)),
        );
    }
    for attendee in array(event, "attendees") {
        let Some(email) = text_of(attendee.get("email")) else {
            continue;
        };
        let name = cn_param(attendee.get("displayName"));
        let partstat = match attendee.get("responseStatus").and_then(Value::as_str) {
            Some("accepted") => "ACCEPTED",
            Some("declined") => "DECLINED",
            Some("tentative") => "TENTATIVE",
            _ => "NEEDS-ACTION",
        };
        let role = if attendee.get("optional").and_then(Value::as_bool) == Some(true) {
            "OPT-PARTICIPANT"
        } else {
            "REQ-PARTICIPANT"
        };
        line(
            ics,
            &format!("ATTENDEE{name};PARTSTAT={partstat};ROLE={role}"),
            &format!("mailto:{}", text(&email)),
        );
    }
    if let Some(link) = text_of(event.get("hangoutLink")) {
        line(ics, "URL", &text(&link));
    }
    ics.push_str("END:VEVENT\r\n");
    Ok(())
}

/// One Google time (`date` or `dateTime` with `timeZone`) as a content line:
/// an all-day date, a wall time in its IANA zone, or UTC when it names no
/// zone the calendar engine knows.
fn time_property(name: &str, time: &Value) -> Result<Option<String>> {
    if let Some(date) = time.get("date").and_then(Value::as_str) {
        let digits: String = date.chars().filter(char::is_ascii_digit).collect();
        if digits.len() != 8 {
            return Err(refused("google_calendar_date_unreadable"));
        }
        return Ok(Some(format!("{name};VALUE=DATE:{digits}\r\n")));
    }
    let Some(instant) = time
        .get("dateTime")
        .and_then(Value::as_str)
        .and_then(rfc3339_seconds)
    else {
        return Ok(None);
    };
    if let Some(zone) = text_of(time.get("timeZone"))
        && zone.chars().all(|ch| ch.is_ascii_graphic())
        && let Ok(wall) = crate::calendar::utc_to_wall(instant, &zone)
    {
        return Ok(Some(format!(
            "{name};TZID={zone}:{:04}{:02}{:02}T{:02}{:02}{:02}\r\n",
            wall.y, wall.mo, wall.d, wall.h, wall.mi, wall.s
        )));
    }
    Ok(Some(format!("{name}:{}\r\n", utc_stamp(instant)?)))
}

/// The recurrence id of the all-day occurrence on `date` (`YYYY-MM-DD`):
/// that date, as its series' dated start names its days.
fn day_recurrence_id(date: &str) -> Result<String> {
    let digits: String = date.chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 8 {
        return Err(refused("google_calendar_date_unreadable"));
    }
    Ok(format!("RECURRENCE-ID;VALUE=DATE:{digits}\r\n"))
}

fn utc_stamp(seconds: u64) -> Result<String> {
    let date = i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .ok_or_else(|| refused("google_calendar_time_out_of_range"))?;
    Ok(date.format("%Y%m%dT%H%M%SZ").to_string())
}

fn rfc3339_seconds(value: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .and_then(|date| u64::try_from(date.timestamp()).ok())
}

fn sequence_of(event: &Value) -> u32 {
    event
        .get("sequence")
        .and_then(Value::as_u64)
        .and_then(|sequence| u32::try_from(sequence).ok())
        .unwrap_or(0)
}

/// One content line, unfolded: the calendar engine's parser reads unfolded
/// lines.
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

/// A `;CN="…"` parameter for a display name, or nothing.
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

fn require_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_ID_BYTES || id.chars().any(char::is_control) {
        return Err(refused("google_calendar_id_unreadable"));
    }
    Ok(())
}

/// `text` percent-escaped as one URL path segment.
fn path_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}
