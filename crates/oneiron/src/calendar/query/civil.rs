//! The civil time of an all-day or floating occurrence (FIX 17869), carried
//! on the calendar views beside UTC bounds, which such an occurrence has
//! none of: it happens on its days, or at its wall times. A floating one,
//! or an all-day one in no zone, happens so in whatever zone its reader is
//! in; an all-day one whose calendar names a zone, on its days there (fix
//! list row 17868).

/// What a calendar shows for an all-day or floating occurrence.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct CalendarCivilSpan {
    /// `all_day` (dates) or `floating` (wall times in any zone).
    pub time_kind: String,
    /// The first day (`2026-11-06`), or the wall time it starts
    /// (`2026-11-06T09:00:00`).
    pub start: String,
    /// The day, or the wall time, it ends before; the start itself for a
    /// floating occurrence that names no end.
    pub end: String,
}

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
