//! IANA time-zone border (CAL-01).
//!
//! The engine core — [`crate::temporal`], [`crate::store`], [`crate::batch`] —
//! is `u64` seconds since the UNIX epoch and stays that way. Wall time and its
//! IANA zone live one layer out, as the separate `calendar.wall_time` and
//! `calendar.tz` claims CAL-00 stores. This module is the single place those
//! two representations meet.
//!
//! It is therefore also the single place an IANA database lives. The embedded
//! 2026c TZif data and its parser are private implementation details here: no
//! third-party type appears in a public signature or a public field. Unlike
//! the older `chrono-tz` tables, these data include BC's 2026 permanent UTC-7.
//!
//! # Gap and fold policy
//!
//! A spring-forward gap has no UTC instant at all, so [`wall_to_utc`] returns
//! [`CalendarError::NonexistentWallTime`] and the caller decides skip-vs-shift.
//! The border never silently slides a nonexistent wall time into the adjacent
//! hour, and never silently falls back to UTC when a zone is unknown.
//!
//! A fall-back fold has two UTC instants, and [`wall_to_utc`] takes the earlier
//! one — the pre-transition offset — deterministically. Ambiguity is a resolved
//! `Ok`, not a failure: there is no `AmbiguousWallTime` variant and no caller
//! branch to write.
//!
//! # Representable range
//!
//! Pre-epoch civil times are outside the engine's `u64` model by construction,
//! so [`wall_to_utc`] rejects them as [`CalendarError::InvalidWallTime`] rather
//! than inventing a signed core. A `calendar.wall_time` claim stores seconds up
//! to 60 to admit a leap second; a leap second is not a convertible civil time
//! and is rejected the same way. [`utc_to_wall`] rejects timestamps past the
//! conversion library's supported range as
//! [`CalendarError::TimestampOutOfRange`].
//!
//! Both directions close over that one range, and the zone is part of what
//! decides it: the supported range is a range of UTC instants, so at its top a
//! positive offset — and at its bottom the epoch floor — takes a civil time out
//! of range even though its fields look ordinary. A wall time [`utc_to_wall`]
//! hands out is therefore always one [`wall_to_utc`] takes back. Falling off
//! the range is never reported as a zone transition.

use chrono::{DateTime, NaiveDate};
use tz::datetime::FoundDateTimeKind;
use tz::timezone::TimeZone;

use super::CalendarError;

/// Last instant in the existing chrono conversion range (262142-12-31 UTC).
/// Keep CAL-01's established range even though the TZif parser supports more.
const MAX_SUPPORTED_UTC: u64 = 8_210_266_876_799;

/// A civil (local) date and time: no zone, no offset, no instant.
/// The IANA zone travels separately as `calendar.tz`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallTime {
    pub y: i32,
    pub mo: u8,
    pub d: u8,
    pub h: u8,
    pub mi: u8,
    pub s: u8,
}

/// Resolve the exact IANA identifier from the embedded database. The lookup
/// library is case-insensitive, so insist on its canonical spelling here.
fn resolve_zone(name: &str) -> Result<TimeZone, CalendarError> {
    let (canonical, bytes) = jiff_tzdb::get(name)
        .filter(|(canonical, _)| *canonical == name)
        .ok_or_else(|| CalendarError::UnknownTimeZone {
            tz: name.to_owned(),
        })?;
    TimeZone::from_tz_data(bytes).map_err(|_| CalendarError::UnknownTimeZone {
        tz: canonical.to_owned(),
    })
}

/// Converts a civil wall time in an IANA zone to UNIX seconds. A fold picks
/// its earlier instant. A gap is refused rather than shifted to a nearby hour.
///
/// # Errors
/// Unknown zones, invalid or out-of-range wall times, and gaps have their
/// own [`CalendarError`] variants; no branch silently chooses UTC.
pub fn wall_to_utc(w: &WallTime, tz: &str) -> Result<u64, CalendarError> {
    let zone = resolve_zone(tz)?;
    // `tz-rs` admits leap seconds; the stored civil calendar does not map
    // them to a UNIX instant. Preserve CAL-01's exact input range.
    NaiveDate::from_ymd_opt(w.y, u32::from(w.mo), u32::from(w.d))
        .and_then(|date| date.and_hms_opt(u32::from(w.h), u32::from(w.mi), u32::from(w.s)))
        .ok_or(CalendarError::InvalidWallTime)?;
    let candidates = tz::DateTime::find(w.y, w.mo, w.d, w.h, w.mi, w.s, 0, zone.as_ref())
        .map_err(|_| CalendarError::InvalidWallTime)?;
    let earliest = candidates.into_inner().into_iter().next();
    let instant = match earliest {
        Some(FoundDateTimeKind::Normal(instant)) => instant,
        Some(FoundDateTimeKind::Skipped { .. }) => {
            return Err(CalendarError::NonexistentWallTime {
                wall: *w,
                tz: tz.to_owned(),
            });
        }
        None => return Err(CalendarError::InvalidWallTime),
    };
    let utc = u64::try_from(instant.unix_time()).map_err(|_| CalendarError::InvalidWallTime)?;
    if utc > MAX_SUPPORTED_UTC {
        return Err(CalendarError::InvalidWallTime);
    }
    Ok(utc)
}

/// Converts UNIX seconds to the civil wall time observed in an IANA zone.
///
/// # Errors
/// Unknown zones and instants outside CAL-01's supported range are refused.
pub fn utc_to_wall(utc: u64, tz: &str) -> Result<WallTime, CalendarError> {
    let zone = resolve_zone(tz)?;
    if utc > MAX_SUPPORTED_UTC {
        return Err(CalendarError::TimestampOutOfRange { utc });
    }
    let seconds = i64::try_from(utc).map_err(|_| CalendarError::TimestampOutOfRange { utc })?;
    let local = tz::DateTime::from_timespec(seconds, 0, zone.as_ref())
        .map_err(|_| CalendarError::TimestampOutOfRange { utc })?;
    // Preserve the earlier calendar border's closure over its range: a
    // positive offset near the upper bound must not yield a civil time that
    // `wall_to_utc` cannot accept. Checking through chrono avoids treating a
    // TZif parser's wider year range as a new storage ABI.
    let instant =
        DateTime::from_timestamp(seconds, 0).ok_or(CalendarError::TimestampOutOfRange { utc })?;
    instant
        .naive_utc()
        .checked_add_signed(chrono::Duration::seconds(i64::from(
            local.local_time_type().ut_offset(),
        )))
        .ok_or(CalendarError::TimestampOutOfRange { utc })?;
    Ok(WallTime {
        y: local.year(),
        mo: local.month(),
        d: local.month_day(),
        h: local.hour(),
        mi: local.minute(),
        s: local.second(),
    })
}

#[cfg(test)]
mod tests {

    use super::{WallTime, utc_to_wall, wall_to_utc};
    use crate::calendar::CalendarError;

    /// `2026-01-15T09:30:00Z`.
    const JAN_15_0930Z: u64 = 1_768_469_400;
    /// `+262142-12-31T23:59:59Z` — the last instant the conversion library
    /// represents, and so the last one this border can convert in UTC itself.
    const MAX_SUPPORTED_UTC: u64 = 8_210_266_876_799;

    const fn wall(y: i32, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> WallTime {
        WallTime { y, mo, d, h, mi, s }
    }

    fn convert(w: &WallTime, tz: &str) -> u64 {
        wall_to_utc(w, tz).expect("wall time converts")
    }

    fn invert(utc: u64, tz: &str) -> WallTime {
        utc_to_wall(utc, tz).expect("timestamp converts")
    }

    #[test]
    fn both_directions_close_over_the_same_range() {
        // The supported range is a *UTC* limit. Localising its last instant in
        // a +14:00 zone lands on a civil date past the library's civil
        // maximum, and the datetime accessors read that overflowed value
        // without complaint — so the border must not hand out a wall time its
        // own inverse cannot take back.
        assert_eq!(
            utc_to_wall(MAX_SUPPORTED_UTC, "Pacific/Kiritimati"),
            Err(CalendarError::TimestampOutOfRange {
                utc: MAX_SUPPORTED_UTC
            })
        );

        // The rejection is the +14:00 shift, not a blanket retreat from the
        // top of the range: UTC reaches that instant, and Kiritimati reaches
        // its own last representable one.
        assert_eq!(
            invert(MAX_SUPPORTED_UTC, "UTC"),
            wall(262142, 12, 31, 23, 59, 59)
        );
        let last_in_kiritimati = MAX_SUPPORTED_UTC - 14 * 3600;
        assert_eq!(
            invert(last_in_kiritimati, "Pacific/Kiritimati"),
            wall(262142, 12, 31, 23, 59, 59)
        );
        assert_eq!(
            convert(&wall(262142, 12, 31, 23, 59, 59), "Pacific/Kiritimati"),
            last_in_kiritimati
        );

        // Closure as a law rather than a fixture: across every zone the
        // database ships, and at both ends of the range, anything
        // `utc_to_wall` admits is something `wall_to_utc` takes back.
        for tz in jiff_tzdb::available() {
            for utc in [
                0,
                JAN_15_0930Z,
                MAX_SUPPORTED_UTC - 14 * 3600,
                MAX_SUPPORTED_UTC,
            ] {
                if let Ok(w) = utc_to_wall(utc, tz) {
                    assert!(
                        wall_to_utc(&w, tz).is_ok(),
                        "{tz} at {utc} yields {w:?}, which does not convert back"
                    );
                }
            }
        }
    }

    #[test]
    fn range_overflow_is_not_reported_as_a_dst_gap() {
        // The library answers "no instant" for two unrelated reasons: a real
        // spring-forward gap, and a unique civil time whose instant is past
        // the top of the supported range. Only the first is a gap, and only
        // the first is the one callers apply skip-or-shift policy to.
        let top = wall(262142, 12, 31, 23, 59, 59);
        assert_eq!(
            wall_to_utc(&top, "Pacific/Pago_Pago"),
            Err(CalendarError::InvalidWallTime),
            "a unique civil time pushed past the range is not a gap"
        );

        // The same civil fields in UTC are the top of the range and convert,
        // so the failure above is the -11:00 shift, not the fields.
        assert_eq!(wall_to_utc(&top, "UTC"), Ok(MAX_SUPPORTED_UTC));

        // A real gap keeps its own typed error, with the wall time and zone
        // the caller needs to act on it.
        let gap = wall(2026, 3, 29, 1, 30, 0);
        assert_eq!(
            wall_to_utc(&gap, "Europe/London"),
            Err(CalendarError::NonexistentWallTime {
                wall: gap,
                tz: "Europe/London".to_owned(),
            })
        );
    }
}
