//! Re-seeding a rule at the last whole period before its window.
//!
//! The engine walks a rule from its seed, so a series that began years before
//! the window it is asked about would step through every occurrence in
//! between. A rule without `COUNT` names the same occurrences from any period
//! on its own interval grid, once every field the engine would infer from the
//! seed is stated: the walk can start at the period that holds the window's
//! first wall clock and lose nothing the window asked for.

use chrono::{DateTime, Datelike, Month, TimeDelta, TimeZone, Timelike};
use rrule::{Frequency, NWeekday, RRule, Tz, Unvalidated, Validated};

/// The seed and rule [`super::expand_window`] walks.
///
/// Returns `rule` on `seed` unchanged when the window opens inside the seed's
/// own period, when the rule counts its occurrences (`COUNT` numbers them
/// from the seed), or when the moved rule does not validate. Each of those
/// walks from the seed, as every rule did before.
pub(super) fn reseeded(
    parsed: &RRule<Unvalidated>,
    rule: RRule<Validated>,
    seed: DateTime<Tz>,
    first: DateTime<Tz>,
) -> (DateTime<Tz>, RRule<Validated>) {
    if rule.get_count().is_some() || first <= seed {
        return (seed, rule);
    }
    let Some(moved) = period_on_grid(&rule, &seed, &first) else {
        return (seed, rule);
    };
    match pinned(parsed, &rule).validate(moved) {
        Ok(pinned) => (moved, pinned),
        Err(_) => (seed, rule),
    }
}

/// `parsed` with every field the engine inferred from the seed written out,
/// so a later seed infers nothing different.
fn pinned(parsed: &RRule<Unvalidated>, rule: &RRule<Validated>) -> RRule<Unvalidated> {
    let mut pinned = parsed.clone();
    if parsed.get_by_month().is_empty() && !rule.get_by_month().is_empty() {
        let months: Vec<Month> = rule
            .get_by_month()
            .iter()
            .filter_map(|month| Month::try_from(*month).ok())
            .collect();
        pinned = pinned.by_month(&months);
    }
    if parsed.get_by_month_day().is_empty() && !rule.get_by_month_day().is_empty() {
        pinned = pinned.by_month_day(rule.get_by_month_day().to_vec());
    }
    if parsed.get_by_weekday().is_empty() && !rule.get_by_weekday().is_empty() {
        let weekdays: Vec<NWeekday> = rule.get_by_weekday().to_vec();
        pinned = pinned.by_weekday(weekdays);
    }
    if parsed.get_by_hour().is_empty() && !rule.get_by_hour().is_empty() {
        pinned = pinned.by_hour(rule.get_by_hour().to_vec());
    }
    if parsed.get_by_minute().is_empty() && !rule.get_by_minute().is_empty() {
        pinned = pinned.by_minute(rule.get_by_minute().to_vec());
    }
    if parsed.get_by_second().is_empty() && !rule.get_by_second().is_empty() {
        pinned = pinned.by_second(rule.get_by_second().to_vec());
    }
    pinned
}

/// The start of the latest period on the rule's interval grid that begins
/// after `seed`'s period and no later than `first`.
///
/// A period starts on its own boundary (January 1st, the 1st of the month,
/// the week-start day, midnight, the hour, the minute), so the engine builds
/// that period's whole day and time set, and `BYSETPOS` picks from the same
/// set it would have picked from walking there. `None` when no such period
/// exists or the arithmetic leaves the carrier's range.
fn period_on_grid(
    rule: &RRule<Validated>,
    seed: &DateTime<Tz>,
    first: &DateTime<Tz>,
) -> Option<DateTime<Tz>> {
    let interval = i64::from(rule.get_interval());
    let skip = |units: i64| -> Option<i64> {
        let skip = units / interval * interval;
        (skip > 0).then_some(skip)
    };
    match rule.get_freq() {
        Frequency::Yearly => {
            let years = skip(i64::from(first.year()) - i64::from(seed.year()))?;
            let year = i32::try_from(i64::from(seed.year()) + years).ok()?;
            Tz::UTC.with_ymd_and_hms(year, 1, 1, 0, 0, 0).single()
        }
        Frequency::Monthly => {
            let index = |dt: &DateTime<Tz>| i64::from(dt.year()) * 12 + i64::from(dt.month0());
            let months = skip(index(first) - index(seed))?;
            let target = index(seed) + months;
            let year = i32::try_from(target.div_euclid(12)).ok()?;
            let month = u32::try_from(target.rem_euclid(12)).ok()? + 1;
            Tz::UTC.with_ymd_and_hms(year, month, 1, 0, 0, 0).single()
        }
        Frequency::Weekly => {
            let back = (7 + seed.weekday().num_days_from_monday()
                - rule.get_week_start().num_days_from_monday())
                % 7;
            let week = midnight(seed)?.checked_sub_signed(TimeDelta::try_days(i64::from(back))?)?;
            let weeks = skip((*first - week).num_days() / 7)?;
            week.checked_add_signed(TimeDelta::try_weeks(weeks)?)
        }
        Frequency::Daily => {
            let day = midnight(seed)?;
            let days = skip((*first - day).num_days())?;
            day.checked_add_signed(TimeDelta::try_days(days)?)
        }
        Frequency::Hourly => {
            let hour = seed.with_minute(0)?.with_second(0)?;
            let hours = skip((*first - hour).num_hours())?;
            hour.checked_add_signed(TimeDelta::try_hours(hours)?)
        }
        Frequency::Minutely => {
            let minute = seed.with_second(0)?;
            let minutes = skip((*first - minute).num_minutes())?;
            minute.checked_add_signed(TimeDelta::try_minutes(minutes)?)
        }
        Frequency::Secondly => {
            let seconds = skip((*first - *seed).num_seconds())?;
            seed.checked_add_signed(TimeDelta::try_seconds(seconds)?)
        }
    }
}

fn midnight(dt: &DateTime<Tz>) -> Option<DateTime<Tz>> {
    Tz::UTC
        .with_ymd_and_hms(dt.year(), dt.month(), dt.day(), 0, 0, 0)
        .single()
}
