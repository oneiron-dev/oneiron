//! RFC 5545 fields retained for calendar claim admission.
use super::{civil_from_days, days_from_civil, ics_parse, parse_datetime_fields};
use crate::calendar::{
    CalendarError,
    claims::{CalendarAttendeeValue, CalendarTimeKind, CalendarWallTimeValue},
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedCalendarProperties {
    pub recurrence_id_utc: Option<u64>,
    pub time_kind: Option<CalendarTimeKind>,
    pub wall_time: Option<CalendarWallTimeValue>,
    /// The exclusive wall end of an all-day or floating event, the kinds with
    /// no UTC bounds: `DTEND`, or the RFC 5545 one-day default for all-day.
    pub wall_end: Option<CalendarWallTimeValue>,
    pub timezone: Option<String>,
    pub rrule: Option<String>,
    pub attendees: Vec<CalendarAttendeeValue>,
    pub meeting_links: Vec<String>,
    pub organizer: Option<String>,
}
pub(super) fn parse(
    component: &icalendar::parser::Component<'_>,
) -> Result<ParsedCalendarProperties, CalendarError> {
    let mut properties = ParsedCalendarProperties {
        recurrence_id_utc: super::optional_datetime_prop(component, "RECURRENCE-ID")?,
        ..ParsedCalendarProperties::default()
    };
    if component.find_prop("RECURRENCE-ID").is_some() && properties.recurrence_id_utc.is_none() {
        return Err(ics_parse(
            "recurrence exception requires a UTC instant or explicit TZID",
        ));
    }
    if let Some(start) = component.find_prop("DTSTART") {
        let text = start.val.as_str().trim();
        let fields = parse_datetime_fields(text)?;
        let zone = parameter(start, "TZID");
        let kind = if text.len() == 8 {
            CalendarTimeKind::AllDay
        } else if fields.utc {
            CalendarTimeKind::Absolute
        } else if zone.is_some() {
            CalendarTimeKind::Zoned
        } else {
            CalendarTimeKind::Floating
        };
        properties.time_kind = Some(kind);
        if kind != CalendarTimeKind::Absolute {
            let wall = wall_value(&fields);
            properties.wall_time = Some(wall);
            if kind != CalendarTimeKind::Zoned {
                properties.wall_end = wall_end(component, kind, wall)?;
            }
        }
        properties.timezone = zone.map(str::to_owned);
    }
    properties.rrule = component
        .find_prop("RRULE")
        .map(|p| p.val.as_str().to_owned());
    properties.organizer = component
        .find_prop("ORGANIZER")
        .map(|p| p.val.as_str().to_owned());
    // Every valid attendee and link is kept, however many the event carries;
    // the link set dedups through a hash set so a long body stays linear.
    let mut seen_links = std::collections::HashSet::new();
    for property in &component.properties {
        if property.name.as_str().eq_ignore_ascii_case("ATTENDEE") {
            let who = property.val.as_str().to_owned();
            if who.is_empty() {
                return Err(ics_parse("empty attendee"));
            }
            properties.attendees.push(CalendarAttendeeValue {
                who,
                role: parameter(property, "ROLE")
                    .unwrap_or("REQ-PARTICIPANT")
                    .into(),
                partstat: parameter(property, "PARTSTAT")
                    .unwrap_or("NEEDS-ACTION")
                    .into(),
            });
        }
        if matches!(
            property.name.as_str(),
            "URL" | "CONFERENCE" | "LOCATION" | "DESCRIPTION"
        ) {
            // The pinned parser already decoded TEXT values once.
            for token in property.val.as_str().split_whitespace() {
                let token = token.trim_matches(|ch: char| {
                    matches!(ch, '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | '"')
                });
                if (token.starts_with("https://") || token.starts_with("http://"))
                    && token.len() <= 4096
                    && seen_links.insert(token)
                {
                    properties.meeting_links.push(token.into());
                }
            }
        }
    }
    Ok(properties)
}
fn wall_value(fields: &super::DateTimeFields) -> CalendarWallTimeValue {
    CalendarWallTimeValue {
        y: fields.year,
        mo: fields.month,
        d: fields.day,
        h: fields.hour,
        mi: fields.minute,
        s: fields.second,
    }
}

/// The exclusive wall end stored beside a wall start.
///
/// `DTEND` as written when it is a wall value. With no `DTEND`, an all-day
/// event ends after its whole-day `DURATION` (`PnD`, `PnW`), or with neither
/// property one day after its start (RFC 5545 §3.6.1). The end stays a civil
/// date or wall time: it is never coerced into a UTC instant. A timed wall
/// start with neither property, or with a duration this form does not cover,
/// stores no end.
fn wall_end(
    component: &icalendar::parser::Component<'_>,
    kind: CalendarTimeKind,
    start: CalendarWallTimeValue,
) -> Result<Option<CalendarWallTimeValue>, CalendarError> {
    if let Some(end) = component.find_prop("DTEND") {
        let fields = parse_datetime_fields(end.val.as_str().trim())?;
        return Ok((!fields.utc).then(|| wall_value(&fields)));
    }
    if kind != CalendarTimeKind::AllDay {
        return Ok(None);
    }
    let days = match component.find_prop("DURATION") {
        None => 1,
        Some(duration) => match whole_days(duration.val.as_str().trim()) {
            Some(days) => days,
            None => return Ok(None),
        },
    };
    // A start date its month does not have is stored as written, with no end.
    Ok(days_from_civil(start.y, start.mo, start.d)
        .and_then(|day| day.checked_add(i64::from(days)))
        .and_then(civil_from_days)
        .map(|(y, mo, d)| CalendarWallTimeValue { y, mo, d, ..start }))
}

/// Days in a whole-day RFC 5545 duration (`P3D`, `P2W`), or `None` for any
/// other form.
fn whole_days(value: &str) -> Option<u32> {
    let value = value.to_ascii_uppercase();
    let body = value
        .strip_prefix('+')
        .unwrap_or(&value)
        .strip_prefix('P')?;
    let unit = body.chars().last()?;
    let count = &body[..body.len() - unit.len_utf8()];
    if count.is_empty() || !count.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let count: u32 = count.parse().ok()?;
    match unit {
        'D' => Some(count),
        'W' => count.checked_mul(7),
        _ => None,
    }
}

fn parameter<'a>(property: &'a icalendar::parser::Property<'_>, name: &str) -> Option<&'a str> {
    property
        .params
        .iter()
        .find(|p| p.key.as_str().eq_ignore_ascii_case(name))
        .and_then(|p| p.val.as_ref())
        .map(|value| value.as_str().trim_matches('"'))
}
