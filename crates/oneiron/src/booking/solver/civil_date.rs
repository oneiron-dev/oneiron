//! Civil-date arithmetic and the host/visitor zone-error constructors.

use crate::booking::BookingError;
use crate::booking::config::{DAYS_PER_WEEK, MINUTES_PER_DAY};
use crate::booking::constraint::ConstraintWeekday;
use crate::calendar::CalendarError;
use crate::calendar::tz::{WallTime, utc_to_wall, wall_to_utc};
use crate::temporal::TimeRange;

/// Days from the UNIX epoch to Monday of the epoch week. `1970-01-01` was a
/// Thursday, so a Monday-anchored week index is `(days + 3) / 7`.
const EPOCH_WEEKDAY_OFFSET: i64 = 3;

// -------------------------------------------------------------------------
// Civil-date arithmetic
//
// The calendar border hands out and takes back civil fields; turning those
// fields into a day number, a weekday, and back is pure integer arithmetic
// (Howard Hinnant's `days_from_civil` / `civil_from_days`) with no database
// behind it. Doing it here rather than reaching for a third-party date type is
// what keeps every signature in this module free of one.
// -------------------------------------------------------------------------

/// Days since `1970-01-01` for a proleptic Gregorian civil date.
pub(super) fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let month = i64::from(month);
    let day = i64::from(day);
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`].
pub(super) fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    // Every cast is lossless: `month` is 1..=12 and `day` is 1..=31 by
    // construction, and the year is bounded by the border's own range.
    (
        (year + i64::from(month <= 2)) as i32,
        month as u8,
        day as u8,
    )
}

/// `0 = Monday ..= 6 = Sunday`.
pub(super) const fn weekday_of(days: i64) -> u8 {
    ((days + EPOCH_WEEKDAY_OFFSET).rem_euclid(DAYS_PER_WEEK as i64)) as u8
}

/// Monday-anchored week index for a day number.
pub(super) const fn week_of(days: i64) -> i64 {
    (days + EPOCH_WEEKDAY_OFFSET).div_euclid(DAYS_PER_WEEK as i64)
}

pub(super) const fn weekday_index(weekday: ConstraintWeekday) -> u8 {
    match weekday {
        ConstraintWeekday::Monday => 0,
        ConstraintWeekday::Tuesday => 1,
        ConstraintWeekday::Wednesday => 2,
        ConstraintWeekday::Thursday => 3,
        ConstraintWeekday::Friday => 4,
        ConstraintWeekday::Saturday => 5,
        ConstraintWeekday::Sunday => 6,
    }
}

/// The civil day number `utc` falls on in `tz`.
pub(super) fn local_day(utc: u64, tz: &str) -> Result<i64, CalendarError> {
    let wall = utc_to_wall(utc, tz)?;
    Ok(days_from_civil(wall.y, wall.mo, wall.d))
}

/// One occurrence of a wall window, as a half-open UTC range.
///
/// `None` when a boundary falls in a spring-forward gap, or when the zone maps
/// the window to nothing.
pub(super) fn wall_window_to_utc(
    day: i64,
    start_minute: u16,
    end_minute: u16,
    tz: &str,
) -> Result<Option<TimeRange>, BookingError> {
    let (Some(start), Some(end)) = (
        wall_minute_to_utc(day, start_minute, tz)?,
        wall_minute_to_utc(day, end_minute, tz)?,
    ) else {
        return Ok(None);
    };
    Ok((start < end).then_some(TimeRange { start, end }))
}

/// A minute-of-day in a zone, as a UTC instant.
///
/// `end_minute == MINUTES_PER_DAY` denotes the following midnight and carries
/// into the next civil day. A fall-back fold resolves to the earliest offset
/// (the border's policy); a spring-forward gap yields `None`, which the caller
/// reads as "this occurrence does not exist".
fn wall_minute_to_utc(day: i64, minute: u16, tz: &str) -> Result<Option<u64>, BookingError> {
    let carry = i64::from(minute / MINUTES_PER_DAY);
    let minute = minute % MINUTES_PER_DAY;
    let (year, month, civil_day) = civil_from_days(day + carry);
    let wall = WallTime {
        y: year,
        mo: month,
        d: civil_day,
        h: (minute / 60) as u8,
        mi: (minute % 60) as u8,
        s: 0,
    };
    match wall_to_utc(&wall, tz) {
        Ok(utc) => Ok(Some(utc)),
        Err(CalendarError::NonexistentWallTime { .. }) => Ok(None),
        Err(error) => Err(host_zone_error(error)),
    }
}

/// The one calendar-error wrapper for a HOST zone.
///
/// [`BookingError`] deliberately does not restate the TZ taxonomy: whose zone
/// failed is what picks the variant, and the border's own `Display` carries
/// every detail a caller needs.
pub(super) fn host_zone_error(error: CalendarError) -> BookingError {
    BookingError::InvalidConfig(format!("host time zone: {error}"))
}

/// The same wrapper for the VISITOR zone, which is request data rather than
/// configuration.
pub(super) fn visitor_zone_error(error: CalendarError) -> BookingError {
    BookingError::InvalidConstraint(format!("visitor time zone: {error}"))
}
