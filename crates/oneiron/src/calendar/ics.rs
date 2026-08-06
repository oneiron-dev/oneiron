//! ICS (RFC 5545) parse half of the CAL-02 ingest adapter (ONE-1784).
//!
//! This module is the *parse* half only: it turns a complete `.ics` feed body
//! into calendar-owned Rust rows. Parsing runs through the already-landed
//! `icalendar` dependency, but no `icalendar` type crosses a public signature
//! here — the crate's parser types stay private to this module, exactly like
//! the IANA database stays private to [`super::tz`]. CAL-04 later adds the
//! emit half to this same file.
//!
//! Three laws this half owns:
//!
//! * **Per-VEVENT hashing, never whole-feed.** [`ParsedVEvent::content_hash`]
//!   is SHA-256 over a deterministic canonical VEVENT representation
//!   ([`canonical_vevent`]), so one unchanged event in a changed feed still
//!   diffs as unchanged. `DTSTAMP` is excluded from the canonical form: it
//!   changes on every export and would make the same-SEQUENCE skip path
//!   unreachable.
//! * **Completeness before truth.** [`parse_ics_feed`] fails the whole feed
//!   unless the input is a complete `VCALENDAR` document (strict begin/end
//!   sentinel check plus a full parse). A truncated or malformed body is a
//!   typed [`CalendarError::IcsParse`], never a partial event set the diff
//!   could mistake for source absence.
//! * **Transparency is validated to the wire tokens.** `TRANSP` maps through
//!   [`CalendarBusyTransparency::from_ics_transp`], which fails closed to
//!   busy for absent, opaque, or unknown values.
//!
//! Timezone handling: `DTSTART`/`DTEND` in UTC (`...Z`) form convert directly;
//! `TZID`-parametrized wall times cross the CAL-01 border
//! ([`super::tz::wall_to_utc`]); floating times (no `Z`, no `TZID`) convert
//! to `None` — the adapter never guesses a zone for them, and the runner
//! treats a missing instant as "no usable time", not as an error.

use sha2::{Digest, Sha256};

use super::CalendarError;
use super::claims::CalendarBusyTransparency;

/// One parsed VEVENT, in calendar-owned types only.
///
/// `summary`, `description`, and `cancelled` extend the keystone skeleton:
/// the runner needs the summary to name the minted EVENT, the description to
/// build the CAL-09 safeguard's [`super::safeguard::CalendarInboundBody`], and
/// the cancelled flag to write `calendar.status` with basis
/// `imported_cancel`. Declared in WORKLOG-ONE-1784 as a proposed amendment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVEvent {
    /// VEVENT `UID` — the cross-calendar identity the passport index keys on.
    pub uid: String,
    /// VEVENT `SEQUENCE`, defaulting to 0 when absent.
    pub sequence: u32,
    /// SHA-256 over the canonical VEVENT representation (see module docs).
    pub content_hash: [u8; 32],
    /// `DTSTART` as UTC seconds, when the feed expressed a convertible time.
    pub starts_at_utc: Option<u64>,
    /// `DTEND` as UTC seconds, when the feed expressed a convertible time.
    pub ends_at_utc: Option<u64>,
    /// Busy transparency normalized from `TRANSP` at parse time.
    pub busy_transparency: CalendarBusyTransparency,
    /// Deterministic re-rendering of the VEVENT's own properties in source
    /// order (nested components such as `VALARM` excluded). Provenance only —
    /// the authoritative raw bytes live in the feed's blob archive.
    pub raw_component: Vec<u8>,
    /// `SUMMARY`, unescaped, when present.
    pub summary: Option<String>,
    /// `DESCRIPTION`, unescaped, when present.
    pub description: Option<String>,
    /// `STATUS:CANCELLED` as sent by the feed.
    pub cancelled: bool,
}

/// A completely parsed feed: every VEVENT in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIcsFeed {
    /// All VEVENTs, in the order the feed carried them.
    pub events: Vec<ParsedVEvent>,
}

/// Parses one complete `.ics` feed body.
///
/// Strict by design: the input must be UTF-8, wrapped in a single
/// `BEGIN:VCALENDAR` … `END:VCALENDAR` document, and fully parseable. Every
/// VEVENT must carry a non-empty `UID`, and any present `SEQUENCE`,
/// `DTSTART`, or `DTEND` must be well-formed — a feed the adapter cannot read
/// completely fails as one typed error rather than diffing as a partial
/// feed, so a parse failure can never be read as event removal.
///
/// # Errors
///
/// [`CalendarError::IcsParse`] on any structural or field-level failure, and
/// the CAL-01 border errors ([`CalendarError::UnknownTimeZone`],
/// [`CalendarError::InvalidWallTime`], [`CalendarError::NonexistentWallTime`])
/// for `TZID`-parametrized times.
pub fn parse_ics_feed(input: &[u8]) -> Result<ParsedIcsFeed, CalendarError> {
    let text = std::str::from_utf8(input).map_err(|_| ics_parse("feed body is not valid UTF-8"))?;
    let trimmed = text.trim();
    if !trimmed.starts_with("BEGIN:VCALENDAR") || !trimmed.ends_with("END:VCALENDAR") {
        return Err(ics_parse("feed body is not a complete VCALENDAR document"));
    }
    let calendar = icalendar::parser::read_calendar(text)
        .map_err(|message| ics_parse(&format!("feed body did not parse: {message}")))?;

    let mut events = Vec::new();
    for component in &calendar.components {
        if component.name.as_str() == "VEVENT" {
            events.push(parse_vevent(component)?);
        }
    }
    Ok(ParsedIcsFeed { events })
}

/// Parses one VEVENT parser component into the calendar-owned row.
fn parse_vevent(
    component: &icalendar::parser::Component<'_>,
) -> Result<ParsedVEvent, CalendarError> {
    let uid = required_text_prop(component, "UID")?;
    let sequence = match component.find_prop("SEQUENCE") {
        None => 0,
        Some(prop) => prop
            .val
            .as_str()
            .trim()
            .parse::<u32>()
            .map_err(|_| ics_parse("VEVENT SEQUENCE is not an unsigned integer"))?,
    };
    let starts_at_utc = optional_datetime_prop(component, "DTSTART")?;
    let ends_at_utc = optional_datetime_prop(component, "DTEND")?;
    let busy_transparency = CalendarBusyTransparency::from_ics_transp(
        component.find_prop("TRANSP").map(|prop| prop.val.as_str()),
    );
    let cancelled = component
        .find_prop("STATUS")
        .is_some_and(|prop| prop.val.as_str() == "CANCELLED");
    let summary = component
        .find_prop("SUMMARY")
        .map(|prop| prop.val.clone().unescape_text().as_str().to_owned());
    let description = component
        .find_prop("DESCRIPTION")
        .map(|prop| prop.val.clone().unescape_text().as_str().to_owned());

    Ok(ParsedVEvent {
        content_hash: canonical_vevent_hash(component),
        raw_component: render_raw_component(component),
        uid,
        sequence,
        starts_at_utc,
        ends_at_utc,
        busy_transparency,
        summary,
        description,
        cancelled,
    })
}

/// Reads a required single text property, unescaped.
fn required_text_prop(
    component: &icalendar::parser::Component<'_>,
    name: &'static str,
) -> Result<String, CalendarError> {
    let prop = component
        .find_prop(name)
        .ok_or_else(|| ics_parse("VEVENT is missing its UID"))?;
    let value = prop.val.clone().unescape_text().as_str().to_owned();
    if value.is_empty() {
        return Err(ics_parse("VEVENT carries an empty UID"));
    }
    Ok(value)
}

/// Converts an optional date-time property to UTC seconds.
///
/// `None` in, `None` out. A floating wall time (no `Z` suffix, no `TZID`)
/// converts to `Ok(None)`: the adapter never guesses a zone, and the runner
/// distinguishes "no usable time" from "no property" only through the
/// property's presence, which the hash already covers.
fn optional_datetime_prop(
    component: &icalendar::parser::Component<'_>,
    name: &'static str,
) -> Result<Option<u64>, CalendarError> {
    let Some(prop) = component.find_prop(name) else {
        return Ok(None);
    };
    let fields = parse_datetime_fields(prop.val.as_str().trim())?;
    if fields.utc {
        return unix_seconds(&fields)
            .map(Some)
            .ok_or_else(|| ics_parse("VEVENT date-time is outside the supported UTC range"));
    }
    let tzid = prop.params.iter().find_map(|param| {
        if param.key.as_str().eq_ignore_ascii_case("TZID") {
            param
                .val
                .as_ref()
                .map(icalendar::parser::ParseString::as_str)
        } else {
            None
        }
    });
    let Some(tzid) = tzid else {
        // Floating time: no zone claim, no conversion.
        return Ok(None);
    };
    let wall = super::tz::WallTime {
        y: fields.year,
        mo: fields.month,
        d: fields.day,
        h: fields.hour,
        mi: fields.minute,
        s: fields.second,
    };
    super::tz::wall_to_utc(&wall, tzid).map(Some)
}

/// The parsed scalar fields of one RFC 5545 date-time value.
struct DateTimeFields {
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    /// The `Z` suffix: the value is already a UTC instant.
    utc: bool,
}

/// Parses `YYYYMMDD`, `YYYYMMDDTHHMMSS`, and `YYYYMMDDTHHMMSSZ`.
fn parse_datetime_fields(value: &str) -> Result<DateTimeFields, CalendarError> {
    let (body, utc) = match value.strip_suffix('Z') {
        Some(body) => (body, true),
        None => (value, false),
    };
    let digits = body.as_bytes();
    let (date, time) = match digits.len() {
        8 => (digits, &b"000000"[..]),
        15 if digits[8] == b'T' => (&digits[..8], &digits[9..]),
        _ => return Err(ics_parse("VEVENT date-time property is malformed")),
    };
    let all_digits = date.iter().chain(time.iter()).all(u8::is_ascii_digit);
    if !all_digits {
        return Err(ics_parse("VEVENT date-time property is malformed"));
    }
    let number = |bytes: &[u8]| -> i64 {
        bytes
            .iter()
            .fold(0_i64, |acc, b| acc * 10 + i64::from(b - b'0'))
    };
    let fields = DateTimeFields {
        year: i32::try_from(number(&date[0..4]))
            .map_err(|_| ics_parse("VEVENT date-time year is out of range"))?,
        month: u8::try_from(number(&date[4..6]))
            .map_err(|_| ics_parse("VEVENT date-time month is out of range"))?,
        day: u8::try_from(number(&date[6..8]))
            .map_err(|_| ics_parse("VEVENT date-time day is out of range"))?,
        hour: u8::try_from(number(&time[0..2]))
            .map_err(|_| ics_parse("VEVENT date-time hour is out of range"))?,
        minute: u8::try_from(number(&time[2..4]))
            .map_err(|_| ics_parse("VEVENT date-time minute is out of range"))?,
        second: u8::try_from(number(&time[4..6]))
            .map_err(|_| ics_parse("VEVENT date-time second is out of range"))?,
        utc,
    };
    // Structural range check, mirroring the calendar.wall_time claim's
    // storage-level bounds: day-of-month is not validated against the month
    // here either; the civil-existence check happens at conversion.
    if !(1..=12).contains(&fields.month)
        || !(1..=31).contains(&fields.day)
        || fields.hour > 23
        || fields.minute > 59
        || fields.second > 60
    {
        return Err(ics_parse("VEVENT date-time field is out of range"));
    }
    Ok(fields)
}

/// Days-from-civil UTC conversion for `...Z` values, kept local so this module
/// adds no second datetime dependency at the border: Howard Hinnant's
/// proleptic-Gregorian algorithm, pre-epoch instants excluded by the `u64`
/// image.
fn unix_seconds(fields: &DateTimeFields) -> Option<u64> {
    let year = i64::from(fields.year);
    let month = i64::from(fields.month);
    let adjusted_year = if month <= 2 { year - 1 } else { year };
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(fields.day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(fields.hour) * 3_600)?
        .checked_add(i64::from(fields.minute) * 60)?
        .checked_add(i64::from(fields.second))?;
    u64::try_from(seconds).ok()
}

/// The deterministic canonical VEVENT representation the content hash covers.
///
/// One line per own property except `DTSTAMP` (a per-export timestamp that
/// would make the unchanged-skip path unreachable), each line
/// `NAME;PARAM=VALUE;…:VALUE` with parameters sorted by key, the lines sorted
/// lexicographically and joined by CRLF. Nested components (VALARM) are
/// excluded: reminders are not event content. Two feeds that agree on every
/// content property therefore hash equal regardless of property order, and
/// any content drift under an unchanged SEQUENCE still hashes differently —
/// the same-sequence-drift update path.
fn canonical_vevent(component: &icalendar::parser::Component<'_>) -> Vec<u8> {
    let mut lines: Vec<String> = component
        .properties
        .iter()
        .filter(|prop| prop.name.as_str() != "DTSTAMP")
        .map(|prop| {
            let mut params: Vec<String> = prop
                .params
                .iter()
                .map(|param| match &param.val {
                    Some(value) => format!("{}={}", param.key.as_str(), value.as_str()),
                    None => param.key.as_str().to_owned(),
                })
                .collect();
            params.sort();
            let mut line = prop.name.as_str().to_owned();
            for param in &params {
                line.push(';');
                line.push_str(param);
            }
            line.push(':');
            line.push_str(prop.val.as_str());
            line
        })
        .collect();
    lines.sort();
    lines.join("\r\n").into_bytes()
}

/// SHA-256 over [`canonical_vevent`].
fn canonical_vevent_hash(component: &icalendar::parser::Component<'_>) -> [u8; 32] {
    let digest = Sha256::digest(canonical_vevent(component));
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Renders the VEVENT's own properties in source order for provenance.
fn render_raw_component(component: &icalendar::parser::Component<'_>) -> Vec<u8> {
    let mut out = String::from("BEGIN:VEVENT\r\n");
    for prop in &component.properties {
        out.push_str(&prop.to_string());
    }
    out.push_str("END:VEVENT\r\n");
    out.into_bytes()
}

fn ics_parse(reason: &str) -> CalendarError {
    CalendarError::IcsParse {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = "BEGIN:VCALENDAR\r\n\
        VERSION:2.0\r\n\
        PRODID:-//oneiron//test//EN\r\n\
        BEGIN:VEVENT\r\n\
        UID:uid-1@example.com\r\n\
        DTSTAMP:20260805T100000Z\r\n\
        DTSTART:20260806T140000Z\r\n\
        DTEND:20260806T150000Z\r\n\
        SEQUENCE:3\r\n\
        SUMMARY:Design review\\, take 2\r\n\
        TRANSP:TRANSPARENT\r\n\
        END:VEVENT\r\n\
        END:VCALENDAR\r\n";

    #[test]
    fn parse_complete_feed_extracts_calendar_rows() {
        let feed = parse_ics_feed(FEED.as_bytes()).expect("parse");
        assert_eq!(feed.events.len(), 1);
        let event = &feed.events[0];
        assert_eq!(event.uid, "uid-1@example.com");
        assert_eq!(event.sequence, 3);
        assert_eq!(
            event.starts_at_utc,
            Some(
                unix_seconds(&DateTimeFields {
                    year: 2026,
                    month: 8,
                    day: 6,
                    hour: 14,
                    minute: 0,
                    second: 0,
                    utc: true,
                })
                .expect("in range")
            )
        );
        assert_eq!(
            event.ends_at_utc,
            event.starts_at_utc.map(|start| start + 3_600)
        );
        assert_eq!(event.busy_transparency, CalendarBusyTransparency::Free);
        assert_eq!(event.summary.as_deref(), Some("Design review, take 2"));
        assert!(!event.cancelled);
    }

    #[test]
    fn dtstamp_is_excluded_from_the_content_hash() {
        let restamped = FEED.replace("20260805T100000Z", "20270805T100000Z");
        let a = parse_ics_feed(FEED.as_bytes()).expect("parse a");
        let b = parse_ics_feed(restamped.as_bytes()).expect("parse b");
        assert_eq!(a.events[0].content_hash, b.events[0].content_hash);
    }

    #[test]
    fn property_order_does_not_drift_the_hash() {
        let reordered = FEED.replace(
            "SEQUENCE:3\r\nSUMMARY:Design review\\, take 2\r\n",
            "SUMMARY:Design review\\, take 2\r\nSEQUENCE:3\r\n",
        );
        let a = parse_ics_feed(FEED.as_bytes()).expect("parse a");
        let b = parse_ics_feed(reordered.as_bytes()).expect("parse b");
        assert_eq!(a.events[0].content_hash, b.events[0].content_hash);
    }

    #[test]
    fn truncated_feed_is_a_typed_parse_error() {
        let truncated = &FEED[..FEED.len() - "END:VCALENDAR\r\n".len()];
        assert!(matches!(
            parse_ics_feed(truncated.as_bytes()),
            Err(CalendarError::IcsParse { .. })
        ));
        assert!(matches!(
            parse_ics_feed(b"not ics at all"),
            Err(CalendarError::IcsParse { .. })
        ));
        // A VEVENT without a UID can never be tracked, so it fails the feed
        // rather than diffing as absence.
        let uidless = FEED.replace("UID:uid-1@example.com\r\n", "");
        assert!(matches!(
            parse_ics_feed(uidless.as_bytes()),
            Err(CalendarError::IcsParse { .. })
        ));
    }

    #[test]
    fn transp_normalization_defaults_busy() {
        let opaque = FEED.replace("TRANSP:TRANSPARENT", "TRANSP:OPAQUE");
        let missing = FEED.replace("TRANSP:TRANSPARENT\r\n", "");
        let unknown = FEED.replace("TRANSP:TRANSPARENT", "TRANSP:X-VENDOR");
        for input in [opaque, missing, unknown] {
            let feed = parse_ics_feed(input.as_bytes()).expect("parse");
            assert_eq!(
                feed.events[0].busy_transparency,
                CalendarBusyTransparency::Busy
            );
        }
    }

    #[test]
    fn tzid_times_cross_the_calendar_border() {
        let zoned = FEED.replace(
            "DTSTART:20260806T140000Z",
            "DTSTART;TZID=Europe/Warsaw:20260806T140000",
        );
        let feed = parse_ics_feed(zoned.as_bytes()).expect("parse");
        // Warsaw is UTC+2 in August.
        let warsaw = feed.events[0].starts_at_utc.expect("converted");
        let utc = parse_ics_feed(FEED.as_bytes()).expect("parse utc").events[0]
            .starts_at_utc
            .expect("utc");
        assert_eq!(warsaw + 7_200, utc);

        let floating = FEED.replace("DTSTART:20260806T140000Z", "DTSTART:20260806T140000");
        let feed = parse_ics_feed(floating.as_bytes()).expect("parse");
        assert_eq!(feed.events[0].starts_at_utc, None);

        let bad_zone = FEED.replace(
            "DTSTART:20260806T140000Z",
            "DTSTART;TZID=Mars/Olympus_Mons:20260806T140000",
        );
        assert!(matches!(
            parse_ics_feed(bad_zone.as_bytes()),
            Err(CalendarError::UnknownTimeZone { .. })
        ));
    }

    #[test]
    fn cancelled_status_surfaces() {
        let cancelled = FEED.replace(
            "TRANSP:TRANSPARENT\r\n",
            "TRANSP:TRANSPARENT\r\nSTATUS:CANCELLED\r\n",
        );
        let feed = parse_ics_feed(cancelled.as_bytes()).expect("parse");
        assert!(feed.events[0].cancelled);
    }
}
