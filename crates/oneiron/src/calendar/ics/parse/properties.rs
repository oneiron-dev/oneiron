//! RFC 5545 fields retained for calendar claim admission.
use super::{ics_parse, parse_datetime_fields};
use crate::calendar::{
    CalendarError,
    claims::{CalendarAttendeeValue, CalendarTimeKind, CalendarWallTimeValue},
};
const MAX_MEETING_LINKS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedCalendarProperties {
    pub recurrence_id_utc: Option<u64>,
    pub time_kind: Option<CalendarTimeKind>,
    pub wall_time: Option<CalendarWallTimeValue>,
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
            properties.wall_time = Some(CalendarWallTimeValue {
                y: fields.year,
                mo: fields.month,
                d: fields.day,
                h: fields.hour,
                mi: fields.minute,
                s: fields.second,
            });
        }
        properties.timezone = zone.map(str::to_owned);
    }
    properties.rrule = component
        .find_prop("RRULE")
        .map(|p| p.val.as_str().to_owned());
    properties.organizer = component
        .find_prop("ORGANIZER")
        .map(|p| p.val.as_str().to_owned());
    for property in &component.properties {
        if property.name.as_str().eq_ignore_ascii_case("ATTENDEE") {
            if properties.attendees.len() >= 1024 {
                return Err(ics_parse("too many attendees"));
            }
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
            let text = property.val.clone().unescape_text();
            for token in text.as_str().split_whitespace() {
                let token = token.trim_matches(|ch: char| {
                    matches!(ch, '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | '"')
                });
                if (token.starts_with("https://") || token.starts_with("http://"))
                    && token.len() <= 4096
                    && !properties.meeting_links.iter().any(|link| link == token)
                {
                    if properties.meeting_links.len() >= MAX_MEETING_LINKS {
                        return Err(ics_parse("too many meeting links"));
                    }
                    properties.meeting_links.push(token.into());
                }
            }
        }
    }
    Ok(properties)
}
fn parameter<'a>(property: &'a icalendar::parser::Property<'_>, name: &str) -> Option<&'a str> {
    property
        .params
        .iter()
        .find(|p| p.key.as_str().eq_ignore_ascii_case(name))
        .and_then(|p| p.val.as_ref())
        .map(|value| value.as_str().trim_matches('"'))
}
