//! The answer-schema check's suspension rules (HOUSE-SCHEMA-CHECK), as pure functions: the
//! grammar rule over one night's pairs, and the window rule over the last seven night dates.
//!
//! Grammar is tested first: two or more pairs in one night whose schema reply did not come
//! back whole while its shadow did suspend at once. Otherwise the window suspends when pairs
//! with quality over the last seven night dates number thirty or more and their paired
//! quality difference has a mean below zero with a 95 % bootstrap upper bound below zero.

use serde::{Deserialize, Serialize};

/// How many night dates the window looks back, this night included.
pub(crate) const WINDOW_DATES: i64 = 7;

/// How many pairs with quality the window needs before it can suspend.
pub(crate) const WINDOW_MIN_PAIRS: usize = 30;

/// How many resamples the window's bootstrap draws.
pub(crate) const BOOTSTRAP_RESAMPLES: usize = 10_000;

/// One night's grammar faults: pairs whose schema reply did not come back whole while its
/// shadow did. `pairs` holds `(schema_whole, shadow_whole)` per pair.
pub(crate) fn grammar_faults(pairs: &[(bool, bool)]) -> u32 {
    pairs
        .iter()
        .filter(|(schema_whole, shadow_whole)| !schema_whole && *shadow_whole)
        .count() as u32
}

/// Whether `faults` grammar faults in one night suspend at once: two or more.
pub(crate) fn grammar_suspends(faults: u32) -> bool {
    faults >= 2
}

/// The window's paired quality difference over its pairs: schema F1 minus shadow F1 per
/// pair, with its 95 % percentile bootstrap interval and size.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowStats {
    /// The mean of (schema F1 minus shadow F1) over the window's pairs.
    pub(crate) d: f64,
    /// The bootstrap interval's lower end (2.5th percentile).
    pub(crate) lower: f64,
    /// The bootstrap interval's upper end (97.5th percentile).
    pub(crate) upper: f64,
    /// How many pairs with quality the window holds.
    pub(crate) n: u32,
    /// How many distinct nights those pairs come from.
    pub(crate) nights: u32,
}

/// Evaluates the window over `diffs`, one (schema F1 minus shadow F1) per pair with quality
/// from the nights of the last seven night dates: `None` while fewer than thirty pairs.
/// The bootstrap draws 10,000 resamples over pairs with replacement, each resample's mean,
/// and reads the 95 % percentile interval off the sorted means. Its generator is splitmix64
/// seeded from `night`, so one night always evaluates one window.
pub(crate) fn evaluate_window(diffs: &[f64], night: &[u8; 16], nights: u32) -> Option<WindowStats> {
    if diffs.len() < WINDOW_MIN_PAIRS {
        return None;
    }
    let first = u64::from_le_bytes(night[0..8].try_into().ok()?);
    let second = u64::from_le_bytes(night[8..16].try_into().ok()?);
    let mut state = first ^ second;
    let mut means = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let mut sum = 0.0;
        for _ in 0..diffs.len() {
            let at = (splitmix64(&mut state) % diffs.len() as u64) as usize;
            sum += diffs[at];
        }
        means.push(sum / diffs.len() as f64);
    }
    means.sort_by(|left, right| left.total_cmp(right));
    let lower = means[BOOTSTRAP_RESAMPLES * 25 / 1000];
    let upper = means[BOOTSTRAP_RESAMPLES * 975 / 1000];
    Some(WindowStats {
        d: diffs.iter().sum::<f64>() / diffs.len() as f64,
        lower,
        upper,
        n: diffs.len() as u32,
        nights,
    })
}

/// Whether the window suspends: its mean below zero with its upper bound below zero.
pub(crate) fn window_suspends(stats: &WindowStats) -> bool {
    stats.d < 0.0 && stats.upper < 0.0
}

/// One step of splitmix64, the window's small deterministic generator.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Parses a `YYYY-MM-DD` night date.
pub(crate) fn parse_ymd(date: &str) -> Option<(i32, u32, u32)> {
    let (year, rest) = date.split_once('-')?;
    let (month, day) = rest.split_once('-')?;
    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return None;
    }
    let year = year.parse::<i32>().ok()?;
    let month = month.parse::<u32>().ok()?;
    let day = day.parse::<u32>().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

/// Days from the civil date, Howard Hinnant's algorithm: days since 1970-01-01.
pub(crate) fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year } as i64;
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400) as u64;
    let month = month as i64;
    let day = day as i64;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year as u64;
    era * 146_097 + day_of_era as i64 - 719_468
}

/// The civil date of days since 1970-01-01, the inverse of [`days_from_civil`].
pub(crate) fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = (if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    }) as u32;
    ((year + i64::from(month <= 2)) as i32, month, day)
}

/// Renders a `YYYY-MM-DD` night date.
pub(crate) fn format_ymd(year: i32, month: u32, day: u32) -> String {
    format!("{year:04}-{month:02}-{day:02}")
}

/// The window's first date for a night of `this_date`: this night included in the seven.
/// `None` when the date does not parse.
pub(crate) fn window_cutoff(this_date: &str) -> Option<String> {
    let (year, month, day) = parse_ymd(this_date)?;
    let days = days_from_civil(year, month, day) - (WINDOW_DATES - 1);
    let (year, month, day) = civil_from_days(days);
    Some(format_ymd(year, month, day))
}

/// Whether `date` falls in the window ending on `this_date`: the last seven night dates,
/// this one included. A date that does not parse falls outside.
pub(crate) fn date_in_window(date: &str, this_date: &str) -> bool {
    let Some(cutoff) = window_cutoff(this_date) else {
        return false;
    };
    parse_ymd(date).is_some() && cutoff.as_str() <= date && date <= this_date
}
