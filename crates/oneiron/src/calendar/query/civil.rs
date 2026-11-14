//! The civil time of an all-day or floating occurrence (FIX 17869), carried
//! on the calendar views beside UTC bounds, which such an occurrence has
//! none of: it happens on its days, or at its wall times. A floating one,
//! or an all-day one in no zone, happens so in whatever zone its reader is
//! in; an all-day one whose calendar names a zone, on its days there (fix
//! list row 17868).

#[doc(hidden)]
pub use oneiron_verb_wire::calendar::query::civil::CalendarCivilSpan;

/// The civil span of an occurrence starting at `start`, a key on the UTC
/// carrier (civil fields read as UTC), `duration` seconds of civil time to
/// its exclusive end; with no duration it ends where it starts.
pub(in crate::calendar) fn civil_span(
    all_day: bool,
    start: u64,
    duration: Option<u64>,
) -> Option<CalendarCivilSpan> {
    let end = start.checked_add(duration.unwrap_or(0))?;
    let format = if all_day {
        "%Y-%m-%d"
    } else {
        "%Y-%m-%dT%H:%M:%S"
    };
    let civil = |seconds: u64| {
        chrono::DateTime::from_timestamp(i64::try_from(seconds).ok()?, 0)
            .map(|at| at.format(format).to_string())
    };
    Some(CalendarCivilSpan {
        time_kind: if all_day { "all_day" } else { "floating" }.to_owned(),
        start: civil(start)?,
        end: civil(end)?,
    })
}
