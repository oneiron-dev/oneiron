//! UTC times for backup file names and reports, with no date library:
//! `20261008T123456.789Z` in file names, RFC 3339 in reports.

use std::time::{SystemTime, UNIX_EPOCH};

const MS_PER_DAY: u64 = 86_400_000;

pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

struct Parts {
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
    milli: u64,
}

fn parts(unix_ms: u64) -> Parts {
    let (year, month, day) = civil_from_days(unix_ms / MS_PER_DAY);
    let in_day = unix_ms % MS_PER_DAY;
    Parts {
        year,
        month,
        day,
        hour: in_day / 3_600_000,
        minute: in_day / 60_000 % 60,
        second: in_day / 1_000 % 60,
        milli: in_day % 1_000,
    }
}

/// `20261008T123456.789Z`: fixed width, so names sort by time.
pub(crate) fn file_stamp(unix_ms: u64) -> String {
    let p = parts(unix_ms);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}.{:03}Z",
        p.year, p.month, p.day, p.hour, p.minute, p.second, p.milli
    )
}

/// `2026-10-08T12:34:56.789Z`.
pub(crate) fn rfc3339(unix_ms: u64) -> String {
    let p = parts(unix_ms);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        p.year, p.month, p.day, p.hour, p.minute, p.second, p.milli
    )
}

/// Inverse of [`file_stamp`]; `None` for anything it did not produce.
pub(crate) fn parse_file_stamp(stamp: &str) -> Option<u64> {
    let bytes = stamp.as_bytes();
    if bytes.len() != 20 || bytes[8] != b'T' || bytes[15] != b'.' || bytes[19] != b'Z' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u64> {
        let text = stamp.get(range)?;
        text.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| text.parse().ok())?
    };
    let (year, month, day) = (number(0..4)?, number(4..6)?, number(6..8)?);
    let (hour, minute, second) = (number(9..11)?, number(11..13)?, number(13..15)?);
    let milli = number(16..19)?;
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let unix_ms = days_from_civil(year, month, day) * MS_PER_DAY
        + hour * 3_600_000
        + minute * 60_000
        + second * 1_000
        + milli;
    (file_stamp(unix_ms) == stamp).then_some(unix_ms)
}

/// Days since 1970-01-01 to `(year, month, day)` (H. Hinnant's algorithm,
/// restricted to the Unix era so it needs no signed arithmetic).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = year - u64::from(month <= 2);
    let era = year / 400;
    let yoe = year % 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_round_trip_and_sort_by_time() {
        // 2026-10-08T12:34:56.789Z
        let ms = 1_791_462_896_789;
        assert_eq!(file_stamp(ms), "20261008T123456.789Z");
        assert_eq!(rfc3339(ms), "2026-10-08T12:34:56.789Z");
        assert_eq!(parse_file_stamp("20261008T123456.789Z"), Some(ms));
        assert_eq!(file_stamp(0), "19700101T000000.000Z");
        assert_eq!(
            parse_file_stamp(&file_stamp(951_782_400_000)),
            Some(951_782_400_000)
        );
        assert!(file_stamp(ms) < file_stamp(ms + 1));
    }

    #[test]
    fn foreign_stamps_do_not_parse() {
        for stamp in [
            "",
            "20261008T123456Z",
            "20261332T123456.789Z",
            "20260230T123456.789Z",
            "2026100xT123456.789Z",
        ] {
            assert_eq!(parse_file_stamp(stamp), None, "{stamp}");
        }
    }
}
