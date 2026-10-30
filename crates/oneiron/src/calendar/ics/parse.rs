//! ICS feed parse half (CAL-02, ONE-1784): RFC 5545 bytes into calendar-owned rows.

mod properties;
pub use properties::ParsedCalendarProperties;

use sha2::{Digest, Sha256};

use crate::calendar::CalendarError;
use crate::calendar::claims::CalendarBusyTransparency;

/// One parsed VEVENT, in calendar-owned types only.
///
/// `summary`, `description`, and `cancelled` extend the keystone skeleton:
/// the runner needs the summary to name the minted EVENT, the description to
/// build the CAL-09 safeguard's [`CalendarInboundBody`](crate::calendar::CalendarInboundBody), and
/// the cancelled flag to write `calendar.status` with basis
/// `imported_cancel` and the pre-start cancellation outcome. The three fields
/// are a deliberate CAL-02 amendment to that skeleton, not an accidental
/// widening of the parsed surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVEvent {
    /// Original calendar semantics, before UTC conversion.
    pub properties: ParsedCalendarProperties,
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
    /// `SUMMARY`, decoded once by the parser, when present.
    pub summary: Option<String>,
    /// `DESCRIPTION`, decoded once by the parser, when present.
    pub description: Option<String>,
    /// An explicit cancellation as sent by the feed: the VEVENT's own
    /// `STATUS:CANCELLED`, or `METHOD:CANCEL` on the VCALENDAR carrying it.
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
/// Strict by design: the input must be UTF-8, wrapped in `BEGIN:VCALENDAR` …
/// `END:VCALENDAR`, and fully parseable once RFC 5545 line folding is undone.
/// Every VEVENT must carry a non-empty `UID`, and any present `SEQUENCE`,
/// `DTSTART`, or `DTEND` must be well-formed — a feed the adapter cannot read
/// completely fails as one typed error rather than diffing as a partial
/// feed, so a parse failure can never be read as event removal. Component
/// names match case-insensitively, so every VEVENT the feed carries, under any
/// spelling, is in the present set the absence sweep reads.
///
/// # Errors
///
/// [`CalendarError::IcsParse`] on any structural or field-level failure, and
/// the CAL-01 border errors ([`CalendarError::UnknownTimeZone`],
/// [`CalendarError::InvalidWallTime`], [`CalendarError::NonexistentWallTime`])
/// for `TZID`-parametrized times.
pub fn parse_ics_feed(input: &[u8]) -> Result<ParsedIcsFeed, CalendarError> {
    let text = std::str::from_utf8(input).map_err(|_| ics_parse("feed body is not valid UTF-8"))?;
    let unfolded = icalendar::parser::unfold(text);
    let trimmed = unfolded.trim();
    let starts = trimmed
        .get(..BEGIN_VCALENDAR.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(BEGIN_VCALENDAR));
    let ends = trimmed
        .get(trimmed.len().saturating_sub(END_VCALENDAR.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(END_VCALENDAR));
    if !starts || !ends {
        return Err(ics_parse("feed body is not a complete VCALENDAR document"));
    }
    let roots = icalendar::parser::read_components(&unfolded)
        .map_err(|message| ics_parse(&format!("feed body did not parse: {message}")))?;

    let mut events = Vec::new();
    let mut seen_uids = std::collections::HashSet::new();
    for calendar in roots.iter().filter(|root| is_named(root, "VCALENDAR")) {
        let method_cancel = calendar.properties.iter().any(|prop| {
            prop.name.as_str().eq_ignore_ascii_case("METHOD")
                && prop.val.as_str().trim().eq_ignore_ascii_case("CANCEL")
        });
        for component in calendar
            .components
            .iter()
            .filter(|component| is_named(component, "VEVENT"))
        {
            let event = parse_vevent(component, method_cancel)?;
            // A duplicated UID would attach two live passports for the same
            // (system, uid) — the one-live law fails closed at parse.
            if !seen_uids.insert((event.uid.clone(), event.properties.recurrence_id_utc)) {
                return Err(ics_parse("feed carries a duplicate VEVENT UID"));
            }
            events.push(event);
        }
    }
    events.sort_by_key(|event| event.properties.recurrence_id_utc.is_some());
    Ok(ParsedIcsFeed { events })
}

const BEGIN_VCALENDAR: &str = "BEGIN:VCALENDAR";
const END_VCALENDAR: &str = "END:VCALENDAR";

/// Whether `component` is named `name` under any ASCII spelling (RFC 5545
/// names are case-insensitive).
fn is_named(component: &icalendar::parser::Component<'_>, name: &str) -> bool {
    component.name.as_str().eq_ignore_ascii_case(name)
}

/// What one invitation's ICS actually says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InviteIcsIdentity {
    /// The VCALENDAR `METHOD`, as written.
    pub(crate) method: String,
    /// The single VEVENT's UID, decoded once by the parser.
    pub(crate) uid: String,
    /// The single VEVENT's SEQUENCE (absent reads as 0).
    pub(crate) sequence: u32,
    /// The ORGANIZER address without its `mailto:` scheme.
    pub(crate) organizer: String,
}

/// Extracts one invitation's actual identity using the existing ICS parser.
///
/// An invite is read strictly, in the shape the emitter writes: exactly one
/// VCALENDAR carrying exactly one VEVENT and nothing else, upper-case names
/// throughout, and one METHOD, UID, ORGANIZER and at most one SEQUENCE. The
/// transport sends these bytes whole, so a second calendar, a second event
/// under any spelling, or a repeated identity property is refused rather
/// than shipped beside the event that was checked. Folded lines are unfolded
/// first, so the identity read is the one the delivered bytes denote.
pub(crate) fn invite_identity(input: &[u8]) -> Result<InviteIcsIdentity, CalendarError> {
    let text = std::str::from_utf8(input).map_err(|_| ics_parse("invite is not UTF-8"))?;
    let unfolded = icalendar::parser::unfold(text);
    let roots = icalendar::parser::read_calendar_simple(&unfolded)
        .map_err(|_| ics_parse("invite did not parse"))?;
    let [calendar] = roots.as_slice() else {
        return Err(ics_parse("invite must be exactly one VCALENDAR"));
    };
    if calendar.name.as_str() != "VCALENDAR" || !names_are_upper_case(calendar) {
        return Err(ics_parse("invite names must be upper-case iCalendar names"));
    }
    let [event] = calendar.components.as_slice() else {
        return Err(ics_parse(
            "invite must carry exactly one VEVENT and nothing else",
        ));
    };
    if event.name.as_str() != "VEVENT" || nests_a_vevent(event) {
        return Err(ics_parse(
            "invite must carry exactly one VEVENT and nothing else",
        ));
    }
    let method = single_prop(&calendar.properties, "METHOD")?
        .ok_or_else(|| ics_parse("invite has no METHOD"))?
        .val
        .as_str()
        .trim()
        .to_owned();
    single_prop(&event.properties, "UID")?;
    single_prop(&event.properties, "SEQUENCE")?;
    let organizer = single_prop(&event.properties, "ORGANIZER")?
        .ok_or_else(|| ics_parse("invite has no organizer"))?
        .val
        .as_str()
        .trim();
    let organizer = organizer
        .strip_prefix("mailto:")
        .or_else(|| organizer.strip_prefix("MAILTO:"))
        .unwrap_or(organizer);
    if organizer.is_empty() {
        return Err(ics_parse("invite has an empty organizer"));
    }
    Ok(InviteIcsIdentity {
        method,
        uid: required_uid(event)?,
        sequence: vevent_sequence(event)?,
        organizer: organizer.to_owned(),
    })
}

/// Whether a VEVENT sits anywhere below `component`.
fn nests_a_vevent(component: &icalendar::parser::Component<'_>) -> bool {
    component
        .components
        .iter()
        .any(|child| child.name.as_str() == "VEVENT" || nests_a_vevent(child))
}

/// The one property named `name`, or none; a repeat is refused.
fn single_prop<'c, 'a>(
    properties: &'c [icalendar::parser::Property<'a>],
    name: &str,
) -> Result<Option<&'c icalendar::parser::Property<'a>>, CalendarError> {
    let mut matching = properties.iter().filter(|prop| prop.name.as_str() == name);
    let first = matching.next();
    if matching.next().is_some() {
        return Err(ics_parse("invite repeats an identity property"));
    }
    Ok(first)
}

/// Whether every component and property name below `component` is written
/// upper-case, as the emitter writes them, so exact-name reads see them all.
fn names_are_upper_case(component: &icalendar::parser::Component<'_>) -> bool {
    let upper = |name: &str| !name.bytes().any(|byte| byte.is_ascii_lowercase());
    upper(component.name.as_str())
        && component
            .properties
            .iter()
            .all(|prop| upper(prop.name.as_str()))
        && component.components.iter().all(names_are_upper_case)
}

/// Parses one VEVENT parser component into the calendar-owned row.
///
/// The pinned parser has already decoded every TEXT value once, so `UID`,
/// `SUMMARY`, and `DESCRIPTION` are read as it returns them; decoding again
/// would turn a literal backslash sequence into different content.
fn parse_vevent(
    component: &icalendar::parser::Component<'_>,
    method_cancel: bool,
) -> Result<ParsedVEvent, CalendarError> {
    let uid = required_uid(component)?;
    let sequence = vevent_sequence(component)?;
    let starts_at_utc = optional_datetime_prop(component, "DTSTART")?;
    let ends_at_utc = optional_datetime_prop(component, "DTEND")?;
    let busy_transparency = CalendarBusyTransparency::from_ics_transp(
        component.find_prop("TRANSP").map(|prop| prop.val.as_str()),
    );
    let cancelled = method_cancel
        || component
            .find_prop("STATUS")
            .is_some_and(|prop| prop.val.as_str().trim().eq_ignore_ascii_case("CANCELLED"));
    let summary = component
        .find_prop("SUMMARY")
        .map(|prop| prop.val.as_str().to_owned());
    let description = component
        .find_prop("DESCRIPTION")
        .map(|prop| prop.val.as_str().to_owned());

    Ok(ParsedVEvent {
        properties: properties::parse(component)?,
        content_hash: canonical_vevent_hash(component, method_cancel),
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

/// Reads the VEVENT SEQUENCE; an absent one is 0.
fn vevent_sequence(component: &icalendar::parser::Component<'_>) -> Result<u32, CalendarError> {
    match component.find_prop("SEQUENCE") {
        None => Ok(0),
        Some(prop) => prop
            .val
            .as_str()
            .trim()
            .parse::<u32>()
            .map_err(|_| ics_parse("VEVENT SEQUENCE is not an unsigned integer")),
    }
}

/// Reads the required VEVENT UID as the parser decoded it, so a literal
/// backslash in the UID stays in the passport and invite identity.
fn required_uid(component: &icalendar::parser::Component<'_>) -> Result<String, CalendarError> {
    let prop = component
        .find_prop("UID")
        .ok_or_else(|| ics_parse("VEVENT is missing its UID"))?;
    let value = prop.val.as_str().to_owned();
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
    super::tz::wall_to_utc(&wall, tzid.trim_matches('"')).map(Some)
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
/// adds no second datetime dependency at the border; pre-epoch instants are
/// excluded by the `u64` image.
fn unix_seconds(fields: &DateTimeFields) -> Option<u64> {
    if fields.hour > 23 || fields.minute > 59 || fields.second > 59 {
        return None;
    }
    let days = days_from_civil(fields.year, fields.month, fields.day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(fields.hour) * 3_600)?
        .checked_add(i64::from(fields.minute) * 60)?
        .checked_add(i64::from(fields.second))?;
    u64::try_from(seconds).ok()
}

/// Days since 1970-01-01 for one proleptic-Gregorian date (Howard Hinnant's
/// algorithm), or `None` for a day its month does not have.
fn days_from_civil(year: i32, month: u8, day: u8) -> Option<i64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > month_days {
        return None;
    }
    let month = i64::from(month);
    let adjusted_year = i64::from(year) - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

/// The proleptic-Gregorian `(year, month, day)` for days since 1970-01-01,
/// the inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> Option<(i32, u8, u8)> {
    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    Some((
        i32::try_from(year).ok()?,
        u8::try_from(month).ok()?,
        u8::try_from(day).ok()?,
    ))
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
/// the same-sequence-drift update path. A `METHOD:CANCEL` on the carrying
/// VCALENDAR is event content too and adds its own line, so a cancellation
/// that leaves the VEVENT untouched still reads as an update.
fn canonical_vevent(component: &icalendar::parser::Component<'_>, method_cancel: bool) -> Vec<u8> {
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
    if method_cancel {
        lines.push("METHOD:CANCEL".to_owned());
    }
    lines.sort();
    lines.join("\r\n").into_bytes()
}

/// SHA-256 over [`canonical_vevent`].
fn canonical_vevent_hash(
    component: &icalendar::parser::Component<'_>,
    method_cancel: bool,
) -> [u8; 32] {
    let digest = Sha256::digest(canonical_vevent(component, method_cancel));
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
    fn duplicate_uid_fails_closed() {
        let duplicated = FEED.replace(
            "END:VEVENT\r\n",
            "END:VEVENT\r\nBEGIN:VEVENT\r\nUID:uid-1@example.com\r\nDTSTART:20260807T140000Z\r\nEND:VEVENT\r\n",
        );
        assert!(matches!(
            parse_ics_feed(duplicated.as_bytes()),
            Err(CalendarError::IcsParse { .. })
        ));
    }
}
