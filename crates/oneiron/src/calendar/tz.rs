//! IANA time-zone border (CAL-01).
//!
//! The engine core — [`crate::temporal`], [`crate::store`], [`crate::batch`] —
//! is `u64` seconds since the UNIX epoch and stays that way. Wall time and its
//! IANA zone live one layer out, as the separate `calendar.wall_time` and
//! `calendar.tz` claims CAL-00 stores. This module is the single place those
//! two representations meet.
//!
//! It is therefore also the single place an IANA database lives. `chrono` and
//! `chrono-tz` are private implementation details here: no third-party type
//! appears in a public signature or a public field, so swapping the database
//! is a change to this file and nothing else.
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

use chrono::{DateTime, Datelike, MappedLocalTime, NaiveDate, TimeZone, Timelike};
use chrono_tz::Tz;

use super::CalendarError;

/// A civil (local) date and time: no zone, no offset, no instant.
///
/// Field-for-field the scalar shape a `calendar.wall_time` claim stores. The
/// zone travels separately as the `calendar.tz` string, exactly as it is
/// stored, so nothing has to carry a third-party datetime type to cross this
/// border.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallTime {
    /// Proleptic Gregorian year.
    pub y: i32,
    /// Month, 1-12.
    pub mo: u8,
    /// Day of month, 1-31.
    pub d: u8,
    /// Hour, 0-23.
    pub h: u8,
    /// Minute, 0-59.
    pub mi: u8,
    /// Second, 0-59.
    pub s: u8,
}

/// Resolves an IANA zone name exactly as written.
///
/// Case-sensitive and alias-free on purpose: an unrecognised name is an error,
/// never a silent UTC fallback.
fn resolve_zone(tz: &str) -> Result<Tz, CalendarError> {
    tz.parse::<Tz>()
        .map_err(|_| CalendarError::UnknownTimeZone { tz: tz.to_owned() })
}

/// Converts a civil wall time in an IANA zone to UNIX seconds.
///
/// A fall-back fold resolves to the earlier of its two UTC instants.
///
/// # Errors
///
/// - [`CalendarError::UnknownTimeZone`] — `tz` is not an IANA zone name.
/// - [`CalendarError::InvalidWallTime`] — the fields are not a real civil
///   date/time (a day the month does not have, a leap second), or the instant
///   is pre-epoch and so outside the engine's `u64` time model.
/// - [`CalendarError::NonexistentWallTime`] — the civil time falls in a
///   spring-forward gap in `tz`.
pub fn wall_to_utc(w: &WallTime, tz: &str) -> Result<u64, CalendarError> {
    let zone = resolve_zone(tz)?;
    let civil = NaiveDate::from_ymd_opt(w.y, u32::from(w.mo), u32::from(w.d))
        .and_then(|date| date.and_hms_opt(u32::from(w.h), u32::from(w.mi), u32::from(w.s)))
        .ok_or(CalendarError::InvalidWallTime)?;
    let instant = match zone.from_local_datetime(&civil) {
        MappedLocalTime::None => {
            return Err(CalendarError::NonexistentWallTime {
                wall: *w,
                tz: tz.to_owned(),
            });
        }
        MappedLocalTime::Single(instant) => instant,
        // Fall-back fold. `Ambiguous`'s first value is the earlier of the two
        // UTC instants — the pre-transition offset. Policy, not a caller
        // choice, so no ambiguity ever reaches the return type.
        MappedLocalTime::Ambiguous(earlier, _later) => earlier,
    };
    // Pre-epoch instants are negative here and have no `u64` image.
    u64::try_from(instant.timestamp()).map_err(|_| CalendarError::InvalidWallTime)
}

/// Converts UNIX seconds to the civil wall time observed in an IANA zone.
///
/// # Errors
///
/// - [`CalendarError::UnknownTimeZone`] — `tz` is not an IANA zone name.
/// - [`CalendarError::TimestampOutOfRange`] — `utc` is past the supported
///   conversion range.
pub fn utc_to_wall(utc: u64, tz: &str) -> Result<WallTime, CalendarError> {
    let zone = resolve_zone(tz)?;
    let seconds = i64::try_from(utc).map_err(|_| CalendarError::TimestampOutOfRange { utc })?;
    let local = DateTime::from_timestamp(seconds, 0)
        .ok_or(CalendarError::TimestampOutOfRange { utc })?
        .with_timezone(&zone);
    // Every cast below is lossless: the accessors are documented as 1-12,
    // 1-31, 0-23, 0-59 and 0-59 respectively.
    Ok(WallTime {
        y: local.year(),
        mo: local.month() as u8,
        d: local.day() as u8,
        h: local.hour() as u8,
        mi: local.minute() as u8,
        s: local.second() as u8,
    })
}

#[cfg(test)]
mod tests {
    use rmpv::Value;

    use super::{WallTime, utc_to_wall, wall_to_utc};
    use crate::calendar::CalendarError;
    use crate::calendar::claims::decode_wall_time_value;

    /// `2026-01-15T09:30:00Z`.
    const JAN_15_0930Z: u64 = 1_768_469_400;
    /// `2026-01-15T09:00:00Z` — London winter, GMT.
    const JAN_15_0900Z: u64 = 1_768_467_600;
    /// `2026-07-15T08:00:00Z` — London summer, BST, same 09:00 wall clock.
    const JUL_15_0800Z: u64 = 1_784_102_400;
    /// `2026-10-25T00:30:00Z` — the earlier of the London fold's two instants.
    const OCT_25_0030Z: u64 = 1_792_888_200;

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
    fn wall_to_utc_round_trips_unique_local_time() {
        // One civil time, three zones, no transition anywhere near it. The
        // pinned instants are what make this a conversion test rather than an
        // identity test: a border that ignored `tz` would agree with itself on
        // the round trip and still be wrong.
        let w = wall(2026, 1, 15, 9, 30, 0);
        for (tz, expected) in [
            ("Europe/London", JAN_15_0930Z),
            ("America/New_York", JAN_15_0930Z + 5 * 3600),
            ("Asia/Tokyo", JAN_15_0930Z - 9 * 3600),
        ] {
            assert_eq!(convert(&w, tz), expected, "{tz} instant");
            assert_eq!(invert(expected, tz), w, "{tz} round trip");
        }
    }

    #[test]
    fn wall_to_utc_preserves_london_dst_wall_clock() {
        // The same 09:00 London wall clock sits at a different UTC offset in
        // winter and summer. Nothing here assumes a fixed week: each side is
        // pinned against UTC independently.
        let winter = wall(2026, 1, 15, 9, 0, 0);
        let summer = wall(2026, 7, 15, 9, 0, 0);

        assert_eq!(convert(&winter, "Europe/London"), JAN_15_0900Z);
        assert_eq!(convert(&summer, "Europe/London"), JUL_15_0800Z);

        // GMT in winter: London and UTC agree. BST in summer: London is one
        // hour ahead, so the same wall clock lands an hour earlier in UTC.
        assert_eq!(convert(&winter, "Europe/London"), convert(&winter, "UTC"));
        assert_eq!(
            convert(&summer, "Europe/London") + 3600,
            convert(&summer, "UTC")
        );

        assert_eq!(invert(JAN_15_0900Z, "Europe/London"), winter);
        assert_eq!(invert(JUL_15_0800Z, "Europe/London"), summer);
    }

    #[test]
    fn wall_to_utc_rejects_dst_gap() {
        // Europe/London springs forward 2026-03-29 at 01:00 local; the hour
        // [01:00, 02:00) does not exist. America/New_York springs forward
        // 2026-03-08 at 02:00 local.
        for (w, tz) in [
            (wall(2026, 3, 29, 1, 30, 0), "Europe/London"),
            (wall(2026, 3, 8, 2, 30, 0), "America/New_York"),
        ] {
            assert_eq!(
                wall_to_utc(&w, tz),
                Err(CalendarError::NonexistentWallTime {
                    wall: w,
                    tz: tz.to_owned(),
                }),
                "{tz} gap is typed, never coerced into the adjacent hour"
            );
        }

        // One minute either side of the gap is a normal conversion, so the
        // rejection is the gap itself and not the whole day.
        assert!(wall_to_utc(&wall(2026, 3, 29, 0, 59, 0), "Europe/London").is_ok());
        assert!(wall_to_utc(&wall(2026, 3, 29, 2, 0, 0), "Europe/London").is_ok());
    }

    #[test]
    fn wall_to_utc_resolves_dst_fold_to_earliest_offset() {
        // Europe/London falls back 2026-10-25 at 02:00 BST -> 01:00 GMT, so
        // 01:30 local happens twice: 00:30Z under BST, then 01:30Z under GMT.
        let folded = wall(2026, 10, 25, 1, 30, 0);
        let later = OCT_25_0030Z + 3600;

        // Both instants really do map back to the same wall clock — the fold
        // is genuine, not an artefact of the fixture.
        assert_eq!(invert(OCT_25_0030Z, "Europe/London"), folded);
        assert_eq!(invert(later, "Europe/London"), folded);

        // The border picks the earlier instant, and does so every time. A fold
        // is an `Ok`, never an error the caller has to disambiguate.
        assert_eq!(wall_to_utc(&folded, "Europe/London"), Ok(OCT_25_0030Z));
        assert_eq!(wall_to_utc(&folded, "Europe/London"), Ok(OCT_25_0030Z));
    }

    #[test]
    fn unknown_iana_zone_is_typed_error() {
        // Including a case-mangled real zone: near-misses are errors, not a
        // silent UTC fallback.
        for tz in ["Mars/Olympus_Mons", "europe/london", "", "GMT+1:00"] {
            let w = wall(2026, 1, 15, 9, 30, 0);
            assert_eq!(
                wall_to_utc(&w, tz),
                Err(CalendarError::UnknownTimeZone { tz: tz.to_owned() })
            );
            assert_eq!(
                utc_to_wall(JAN_15_0930Z, tz),
                Err(CalendarError::UnknownTimeZone { tz: tz.to_owned() })
            );
        }
    }

    #[test]
    fn invalid_civil_date_is_typed_error() {
        for w in [
            wall(2026, 2, 30, 12, 0, 0),    // February has no 30th
            wall(2025, 2, 29, 12, 0, 0),    // 2025 is not a leap year
            wall(2026, 13, 1, 12, 0, 0),    // month out of range
            wall(2026, 1, 15, 24, 0, 0),    // hour out of range
            wall(2026, 1, 15, 12, 0, 60),   // leap second: storable, not convertible
            wall(1969, 12, 31, 23, 59, 59), // pre-epoch: outside the u64 core
        ] {
            assert_eq!(wall_to_utc(&w, "UTC"), Err(CalendarError::InvalidWallTime));
        }

        // The epoch itself is the first representable instant.
        assert_eq!(wall_to_utc(&wall(1970, 1, 1, 0, 0, 0), "UTC"), Ok(0));
    }

    #[test]
    fn oversized_utc_timestamp_is_typed_error() {
        // Past `i64`, and past the conversion library's range while still
        // inside `i64` — both guards report the same typed error.
        for utc in [u64::MAX, 1_000_000_000_000_000] {
            assert_eq!(
                utc_to_wall(utc, "UTC"),
                Err(CalendarError::TimestampOutOfRange { utc })
            );
        }

        assert_eq!(invert(0, "UTC"), wall(1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn wall_time_claim_fields_bridge_without_third_party_types() {
        // Exactly what CAL-00 persists: a `calendar.wall_time` map of scalars
        // and, separately, a `calendar.tz` string. Nothing else is needed to
        // reach UTC.
        let stored = decode_wall_time_value(&Value::Map(vec![
            (Value::from("y"), Value::from(2026)),
            (Value::from("mo"), Value::from(6)),
            (Value::from("d"), Value::from(1)),
            (Value::from("h"), Value::from(14)),
            (Value::from("mi"), Value::from(0)),
            (Value::from("s"), Value::from(0)),
        ]))
        .expect("decode calendar.wall_time");
        let stored_tz = "Europe/Warsaw";

        let bridged = WallTime {
            y: stored.y,
            mo: stored.mo,
            d: stored.d,
            h: stored.h,
            mi: stored.mi,
            s: stored.s,
        };

        // Warsaw is on CEST (UTC+2) on that date, so the zone claim did real
        // work: 14:00 local is 12:00Z.
        assert_eq!(convert(&bridged, stored_tz), 1_780_315_200);
        assert_eq!(invert(1_780_315_200, stored_tz), bridged);
    }
}
