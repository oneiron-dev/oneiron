//! A CalDAV collection's zone, read from its VTIMEZONE and given to the
//! resources it carries (fix list row 19192).
//!
//! Both halves go through the parse half's one plain-zone-name rule
//! ([`super::parse::plain_zone_name`]); neither reads a VTIMEZONE's
//! transition rules. The name alone places the days, through the zone
//! database, exactly as a VCALENDAR's own `X-WR-TIMEZONE` does.

use super::parse::{
    calendar_timezone, is_named, plain_zone_name, push_collection_zone_line, zone_from_collection,
};

/// The `TZID` of the one VTIMEZONE the VCALENDAR `value` carries, as a
/// CalDAV collection's `CALDAV:calendar-timezone` property holds it (RFC
/// 4791 §5.2.2), when it is a plain zone name.
///
/// `None` unless `value` parses as exactly one VCALENDAR carrying exactly
/// one top-level VTIMEZONE with exactly one `TZID` of its own (a
/// `STANDARD`/`DAYLIGHT` child's properties and a `DTSTART`'s `TZID`
/// parameter are not read), and that name is plain.
pub(crate) fn ics_vtimezone_tzid(value: &str) -> Option<String> {
    let unfolded = icalendar::parser::unfold(value.trim());
    let roots = icalendar::parser::read_components(&unfolded).ok()?;
    let [calendar] = roots.as_slice() else {
        return None;
    };
    if !is_named(calendar, "VCALENDAR") {
        return None;
    }
    let zone = single(
        calendar
            .components
            .iter()
            .filter(|component| is_named(component, "VTIMEZONE")),
    )?;
    let tzid = single(
        zone.properties
            .iter()
            .filter(|prop| prop.name.as_str().eq_ignore_ascii_case("TZID")),
    )?;
    plain_zone_name(tzid.val.as_str()).map(str::to_owned)
}

/// The one item `items` yields; `None` for none or several.
fn single<T>(mut items: impl Iterator<Item = T>) -> Option<T> {
    let first = items.next()?;
    items.next().is_none().then_some(first)
}

/// `ics` with `zone` as the `X-WR-TIMEZONE` of each VCALENDAR in it that
/// names no plain zone of its own: the zone a CalDAV collection gives the
/// resources it carries (fix list row 19192), written into the bytes so the
/// archived copy, every later parse of it and the content hash all read it.
/// It is written as a collection's zone ([`push_collection_zone_line`]), so
/// a later write or pull gives the resource the collection's zone as it is
/// then, never this one frozen as the resource's own.
///
/// A VCALENDAR's own plain zone stands. Its first `X-WR-TIMEZONE`, when that
/// one is not plain or is a collection's zone written in before, is replaced
/// (the parse half reads only the first, so a line appended after it would
/// never be read); else the zone heads the VCALENDAR, on the line right
/// after its `BEGIN:VCALENDAR`. With no `zone`, a collection's zone written
/// in before is taken out and nothing is written. Every other byte is kept
/// as the server sent it. `ics` comes back unchanged when `zone` is not a
/// plain zone name or `ics` does not parse.
pub(crate) fn ics_with_calendar_timezone(ics: &[u8], zone: Option<&str>) -> Vec<u8> {
    let zone = match zone {
        Some(zone) => match plain_zone_name(zone) {
            Some(plain) => Some(plain),
            None => return ics.to_vec(),
        },
        None => None,
    };
    let Ok(text) = std::str::from_utf8(ics) else {
        return ics.to_vec();
    };
    let unfolded = icalendar::parser::unfold(text);
    let Ok(roots) = icalendar::parser::read_components(&unfolded) else {
        return ics.to_vec();
    };
    // Per VCALENDAR: whether it names a plain zone of its own, and whether
    // its first zone is a collection's written in before.
    let zones: Vec<(bool, bool)> = roots
        .iter()
        .filter(|root| is_named(root, "VCALENDAR"))
        .map(|calendar| {
            let written = zone_from_collection(calendar);
            (calendar_timezone(calendar).is_some() && !written, written)
        })
        .collect();
    let Some(calendars) = root_calendars(text).filter(|found| found.len() == zones.len()) else {
        return ics.to_vec();
    };
    let line_bytes = zone.map_or(0, |zone| zone.len() + 48);
    let mut out = String::with_capacity(text.len() + calendars.len() * line_bytes);
    let mut at = 0;
    for (calendar, (own, written)) in calendars.iter().zip(zones) {
        if own {
            continue;
        }
        if let Some(zone) = zone {
            let (start, end) = calendar.zone.unwrap_or((calendar.head, calendar.head));
            out.push_str(&text[at..start]);
            push_collection_zone_line(&mut out, zone, calendar.line_end);
            at = end;
        } else if written && let Some((start, end)) = calendar.zone {
            out.push_str(&text[at..start]);
            at = end;
        }
    }
    out.push_str(&text[at..]);
    out.into_bytes()
}

/// Where one top-level VCALENDAR of a resource's raw text takes its zone.
struct RootCalendar {
    /// The byte offset right after its `BEGIN:VCALENDAR` line.
    head: usize,
    /// That line's terminator, which a written zone line ends with too.
    line_end: &'static str,
    /// The bytes of its own first `X-WR-TIMEZONE` content line, folds and
    /// terminator included.
    zone: Option<(usize, usize)>,
}

/// Every top-level VCALENDAR of `text`, in document order, read over its
/// content lines unfolded exactly as the parser unfolds them (a line break
/// followed by one space or tab continues the line). `None` when a
/// `BEGIN:VCALENDAR` line has no terminator or an `END` closes nothing.
fn root_calendars(text: &str) -> Option<Vec<RootCalendar>> {
    let mut calendars = Vec::new();
    let mut depth = 0_usize;
    let mut in_calendar = false;
    for (start, end, content) in content_lines(text) {
        let line = content.trim_end();
        if let Some(name) = strip_prefix_ignore_case(line, "BEGIN:") {
            if depth == 0 && name.trim().eq_ignore_ascii_case("VCALENDAR") {
                let line_end = if text[..end].ends_with("\r\n") {
                    "\r\n"
                } else if text[..end].ends_with('\n') {
                    "\n"
                } else {
                    return None;
                };
                calendars.push(RootCalendar {
                    head: end,
                    line_end,
                    zone: None,
                });
                in_calendar = true;
            }
            depth += 1;
        } else if strip_prefix_ignore_case(line, "END:").is_some() {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                in_calendar = false;
            }
        } else if depth == 1
            && in_calendar
            && content
                .split([';', ':'])
                .next()
                .is_some_and(|name| name.trim().eq_ignore_ascii_case("X-WR-TIMEZONE"))
            && let Some(calendar) = calendars.last_mut()
            && calendar.zone.is_none()
        {
            calendar.zone = Some((start, end));
        }
    }
    Some(calendars)
}

/// The content lines of `text`: each one's byte span, its folds and its
/// terminator included, and its unfolded content without the terminator.
fn content_lines(text: &str) -> Vec<(usize, usize, String)> {
    let mut lines: Vec<(usize, usize, String)> = Vec::new();
    let mut offset = 0;
    for physical in text.split_inclusive('\n') {
        let start = offset;
        offset += physical.len();
        let bare = physical
            .strip_suffix('\n')
            .map_or(physical, |line| line.strip_suffix('\r').unwrap_or(line));
        let continued = bare.strip_prefix(' ').or_else(|| bare.strip_prefix('\t'));
        if let Some(rest) = continued
            && let Some((_, end, content)) = lines.last_mut()
        {
            *end = offset;
            content.push_str(rest);
        } else {
            lines.push((start, offset, bare.to_owned()));
        }
    }
    lines
}

/// `text` after `prefix`, when it starts with `prefix` under any ASCII
/// spelling.
fn strip_prefix_ignore_case<'t>(text: &'t str, prefix: &str) -> Option<&'t str> {
    if text.get(..prefix.len())?.eq_ignore_ascii_case(prefix) {
        text.get(prefix.len()..)
    } else {
        None
    }
}
