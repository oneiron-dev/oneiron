//! `TimeRange`, temporal expressions/parsing, granularity.
//!
//! `TemporalAnchorMode` stays in `oneiron::temporal`: retrieval scoring matches it
//! exhaustively, and `#[non_exhaustive]` only allows that inside the defining crate.

use serde::{Deserialize, Serialize};

/// Bi-temporal interval represented as UNIX timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    /// Inclusive start timestamp.
    pub start: u64,
    /// Inclusive end timestamp.
    pub end: u64,
}

const TEMPORAL_SECONDS_PER_DAY: u64 = 86_400;
const TEMPORAL_RECENT_DAYS: u64 = 7;
/// Largest count a quantity phrase resolves to; larger numbers clamp here.
const TEMPORAL_MAX_COUNT: u32 = 10_000;
/// Latest reference time query hints resolve against: 9999-12-31T23:59:59Z.
/// Past it, every hint is reported unresolved rather than resolved.
pub const TEMPORAL_MAX_REFERENCE_SECS: u64 = 253_402_300_799;

/// A unit a temporal phrase counts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemporalUnit {
    Second,
    Minute,
    Hour,
    Day,
    /// Monday to Sunday, UTC.
    Week,
    /// Saturday and Sunday of a week.
    Weekend,
    Month,
    Quarter,
    Year,
}

impl TemporalUnit {
    fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "second" | "seconds" => Self::Second,
            "minute" | "minutes" => Self::Minute,
            "hour" | "hours" => Self::Hour,
            "day" | "days" => Self::Day,
            "week" | "weeks" => Self::Week,
            "weekend" | "weekends" => Self::Weekend,
            "month" | "months" => Self::Month,
            "quarter" | "quarters" => Self::Quarter,
            "year" | "years" => Self::Year,
            _ => return None,
        })
    }

    const fn below_day(self) -> bool {
        matches!(self, Self::Second | Self::Minute | Self::Hour)
    }

    /// Nominal length of a rolling window step. Months, quarters and years
    /// count 30, 91 and 365 days.
    const fn seconds(self) -> u64 {
        match self {
            Self::Second => 1,
            Self::Minute => 60,
            Self::Hour => 3_600,
            Self::Day => TEMPORAL_SECONDS_PER_DAY,
            Self::Week | Self::Weekend => 7 * TEMPORAL_SECONDS_PER_DAY,
            Self::Month => 30 * TEMPORAL_SECONDS_PER_DAY,
            Self::Quarter => 91 * TEMPORAL_SECONDS_PER_DAY,
            Self::Year => 365 * TEMPORAL_SECONDS_PER_DAY,
        }
    }
}

/// Which weekday a `last|this|next <weekday>` phrase names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WeekdayRelation {
    /// The latest such day before the reference day.
    Last,
    /// That day of the reference week.
    This,
    /// The first such day after the reference day.
    Next,
}

/// Accepted natural-language temporal retrieval hint.
///
/// Every range is UTC and resolves against a reference time: the caller's
/// `as_of` when one is given, the clock otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemporalExpression {
    /// The 7 days up to the reference time.
    Recent,
    /// The day before the reference day (`yesterday`, `last night`).
    Yesterday,
    /// The 7 days before the reference day.
    LastWeek,
    /// The calendar month before the reference month.
    LastMonth,
    /// The calendar year before the reference year.
    LastYear,
    /// The calendar `unit` holding the reference time, moved by `offset`
    /// units: `today` is day 0, `tomorrow` day +1, `next quarter` quarter +1,
    /// `3 days ago` day -3.
    Calendar { unit: TemporalUnit, offset: i32 },
    /// A weekday, 0 = Monday.
    Weekday {
        weekday: u8,
        relation: WeekdayRelation,
    },
    /// `count` units ending at the reference time (`last 2 weeks`), or
    /// starting there when `ahead` (`next 3 days`).
    Rolling {
        unit: TemporalUnit,
        count: u32,
        ahead: bool,
    },
}

impl TemporalExpression {
    /// Parses a standalone temporal expression: exactly one phrase that
    /// [`temporal_hints_from_query`] would resolve, and nothing else.
    pub fn parse(expression: &str) -> std::result::Result<Self, TemporalExpressionParseError> {
        let tokens = temporal_query_tokens(expression);
        if tokens.is_empty() {
            return Err(TemporalExpressionParseError::Empty);
        }
        match hint_at(&tokens, 0) {
            Some((end, Some(expression))) if end == tokens.len() => Ok(expression),
            _ => Err(TemporalExpressionParseError::Unsupported {
                expression: tokens.join(" "),
            }),
        }
    }

    /// Resolves this expression to inclusive UTC Unix-second retrieval bounds
    /// from a caller-supplied clock.
    #[must_use]
    pub fn resolve(self, now: u64) -> TimeRange {
        match self {
            Self::Recent => TimeRange {
                start: now.saturating_sub(TEMPORAL_RECENT_DAYS * TEMPORAL_SECONDS_PER_DAY),
                end: now,
            },
            Self::Yesterday => {
                let today_start = utc_day_start(now);
                TimeRange {
                    start: today_start.saturating_sub(TEMPORAL_SECONDS_PER_DAY),
                    end: today_start.saturating_sub(1),
                }
            }
            Self::LastWeek => {
                let today_start = utc_day_start(now);
                TimeRange {
                    start: today_start.saturating_sub(7 * TEMPORAL_SECONDS_PER_DAY),
                    end: today_start.saturating_sub(1),
                }
            }
            Self::LastMonth => previous_calendar_month_range(now),
            Self::LastYear => previous_calendar_year_range(now),
            Self::Calendar { unit, offset } => calendar_range(unit, i64::from(offset), now),
            Self::Weekday { weekday, relation } => {
                let today = (now / TEMPORAL_SECONDS_PER_DAY) as i64;
                let today_weekday = monday_weekday(today);
                let target = i64::from(weekday);
                let day = match relation {
                    WeekdayRelation::This => today - today_weekday + target,
                    WeekdayRelation::Last => today - (today_weekday - target - 1).rem_euclid(7) - 1,
                    WeekdayRelation::Next => today + (target - today_weekday - 1).rem_euclid(7) + 1,
                };
                span(
                    i128::from(day) * i128::from(TEMPORAL_SECONDS_PER_DAY),
                    i128::from(TEMPORAL_SECONDS_PER_DAY),
                )
            }
            Self::Rolling { unit, count, ahead } => {
                let length = u64::from(count).saturating_mul(unit.seconds());
                if ahead {
                    TimeRange {
                        start: now,
                        end: now.saturating_add(length),
                    }
                } else {
                    TimeRange {
                        start: now.saturating_sub(length),
                        end: now,
                    }
                }
            }
        }
    }

    /// Whether this expression points after the reference time `now`, given
    /// its resolved `range`.
    fn looks_ahead(self, range: TimeRange, now: u64) -> bool {
        matches!(self, Self::Rolling { ahead: true, .. }) || range.start > now
    }
}

/// Typed parse failure for temporal retrieval hints.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TemporalExpressionParseError {
    #[error("empty temporal expression")]
    Empty,
    #[error("unsupported temporal expression: {expression}")]
    Unsupported { expression: String },
}

/// Parses a standalone temporal expression and resolves it to inclusive UTC
/// Unix-second bounds from `now`.
pub fn parse_temporal_expression(
    expression: &str,
    now: u64,
) -> std::result::Result<TimeRange, TemporalExpressionParseError> {
    Ok(TemporalExpression::parse(expression)?.resolve(now))
}

/// What retrieval did with one temporal phrase of a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TemporalHintStatus {
    /// Its range narrowed the occurred-time window.
    Used,
    /// The phrase reads as a time, but the parser cannot resolve it
    /// (`last several weeks`). Retrieval ran without it.
    Unresolved,
    /// It names a time after the reference time. Memories are dated when they
    /// were recorded, so a filter to that range would drop the turns that
    /// planned it. Retrieval ran without it.
    Future,
}

impl TemporalHintStatus {
    /// The wire spelling: `used`, `unresolved` or `future`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Used => "used",
            Self::Unresolved => "unresolved",
            Self::Future => "future",
        }
    }
}

/// One temporal phrase read from a query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalHintReport {
    /// The phrase, lowercased with punctuation dropped (`last 2 weeks`).
    pub phrase: String,
    pub status: TemporalHintStatus,
    /// Inclusive UTC Unix-second start the phrase resolved to.
    pub start: Option<u64>,
    /// Inclusive UTC Unix-second end the phrase resolved to.
    pub end: Option<u64>,
}

/// A query's temporal phrases and the occurred-time window they ask for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryTemporalHints {
    /// Every temporal phrase, in reading order.
    pub hints: Vec<TemporalHintReport>,
    /// The span covering every used phrase, or `None` when none was used.
    pub range: Option<TimeRange>,
}

/// Reads every temporal phrase in a retrieval query and resolves it from
/// `now`.
///
/// Never fails: a phrase the parser cannot resolve, or one that points after
/// `now`, is reported and left out of the window, so retrieval runs on its
/// other signals. Two or more usable phrases widen the window to cover them
/// all. A `now` past [`TEMPORAL_MAX_REFERENCE_SECS`] resolves nothing.
#[must_use]
pub fn temporal_hints_from_query(query: &str, now: u64) -> QueryTemporalHints {
    let tokens = temporal_query_tokens(query);
    let mut out = QueryTemporalHints::default();
    let mut index = 0;
    while index < tokens.len() {
        let Some((end, expression)) = hint_at(&tokens, index) else {
            // Never restart inside a count that read as no time: `half a
            // year` must not become `a year`.
            index =
                quantity_at(&tokens, index).map_or(index + 1, |(_, after)| after.max(index + 1));
            continue;
        };
        let resolved = expression
            .filter(|_| now <= TEMPORAL_MAX_REFERENCE_SECS)
            .map(|expression| (expression, expression.resolve(now)));
        let status = match resolved {
            None => TemporalHintStatus::Unresolved,
            Some((expression, range)) if expression.looks_ahead(range, now) => {
                TemporalHintStatus::Future
            }
            Some((_, range)) => {
                out.range = Some(match out.range {
                    Some(window) => TimeRange {
                        start: window.start.min(range.start),
                        end: window.end.max(range.end),
                    },
                    None => range,
                });
                TemporalHintStatus::Used
            }
        };
        out.hints.push(TemporalHintReport {
            phrase: tokens[index..end].join(" "),
            status,
            start: resolved.map(|(_, range)| range.start),
            end: resolved.map(|(_, range)| range.end),
        });
        index = end;
    }
    out
}

/// The temporal phrase starting at `tokens[index]`: where it ends (exclusive)
/// and its expression, `None` when it reads as a time but cannot resolve.
fn hint_at(tokens: &[String], index: usize) -> Option<(usize, Option<TemporalExpression>)> {
    let one = |expression| Some((index + 1, Some(expression)));
    match tokens[index].as_str() {
        "recent" => one(TemporalExpression::Recent),
        "yesterday" => one(TemporalExpression::Yesterday),
        "today" | "tonight" => one(TemporalExpression::Calendar {
            unit: TemporalUnit::Day,
            offset: 0,
        }),
        "tomorrow" => one(TemporalExpression::Calendar {
            unit: TemporalUnit::Day,
            offset: 1,
        }),
        "last" | "past" | "this" | "next" => anchored_hint(tokens, index),
        _ => ago_hint(tokens, index),
    }
}

/// `last|past|this|next` followed by a unit, a weekday, or a count of units.
fn anchored_hint(tokens: &[String], index: usize) -> Option<(usize, Option<TemporalExpression>)> {
    let anchor = tokens[index].as_str();
    let next = tokens.get(index + 1)?.as_str();
    let two = |expression| Some((index + 2, Some(expression)));
    match (anchor, next) {
        ("last", "night") => return two(TemporalExpression::Yesterday),
        ("this", "morning" | "afternoon" | "evening") => {
            return two(TemporalExpression::Calendar {
                unit: TemporalUnit::Day,
                offset: 0,
            });
        }
        ("last", "week") => return two(TemporalExpression::LastWeek),
        ("last", "month") => return two(TemporalExpression::LastMonth),
        ("last", "year") => return two(TemporalExpression::LastYear),
        _ => {}
    }
    if anchor != "past"
        && let Some(weekday) = weekday_index(next)
    {
        let relation = match anchor {
            "last" => WeekdayRelation::Last,
            "this" => WeekdayRelation::This,
            _ => WeekdayRelation::Next,
        };
        return two(TemporalExpression::Weekday { weekday, relation });
    }
    if let Some(unit) = TemporalUnit::from_token(next) {
        // `last minute`, `last second` and `this second` are idioms far more
        // often than times.
        if matches!(
            (anchor, unit),
            ("last", TemporalUnit::Minute | TemporalUnit::Second) | ("this", TemporalUnit::Second)
        ) {
            return None;
        }
        let rolling = |ahead| TemporalExpression::Rolling {
            unit,
            count: 1,
            ahead,
        };
        let calendar = |offset| TemporalExpression::Calendar { unit, offset };
        return two(match anchor {
            "past" => rolling(false),
            "last" if unit.below_day() => rolling(false),
            "next" if unit.below_day() => rolling(true),
            "this" => calendar(0),
            "last" => calendar(-1),
            _ => calendar(1),
        });
    }
    let (quantity, after) = quantity_at(tokens, index + 1)?;
    let unit = TemporalUnit::from_token(tokens.get(after)?)?;
    let expression = match (anchor, quantity) {
        ("this", _) | (_, Quantity::Vague) => None,
        (_, Quantity::Count(count)) => Some(TemporalExpression::Rolling {
            unit,
            count,
            ahead: anchor == "next",
        }),
    };
    Some((after + 1, expression))
}

/// `<count> <unit> ago`.
fn ago_hint(tokens: &[String], index: usize) -> Option<(usize, Option<TemporalExpression>)> {
    let (quantity, after) = quantity_at(tokens, index)?;
    let unit = TemporalUnit::from_token(tokens.get(after)?)?;
    if tokens.get(after + 1).map(String::as_str) != Some("ago") {
        return None;
    }
    let expression = match quantity {
        Quantity::Vague => None,
        // Under a day, `2 hours ago` means the span since then.
        Quantity::Count(count) if unit.below_day() => Some(TemporalExpression::Rolling {
            unit,
            count,
            ahead: false,
        }),
        Quantity::Count(count) => Some(TemporalExpression::Calendar {
            unit,
            offset: -i32::try_from(count).unwrap_or(i32::MAX),
        }),
    };
    Some((after + 2, expression))
}

#[derive(Debug, Clone, Copy)]
enum Quantity {
    Count(u32),
    /// `several`, `many`, `half`: a count the parser will not guess.
    Vague,
}

/// A count at `tokens[index]` and the index after it, past a trailing `of`
/// (`couple of`). Digits, number words (`twenty four`), `a`/`an`, `couple`,
/// `few` and `dozen` resolve; `several`, `many` and `half` are vague.
fn quantity_at(tokens: &[String], index: usize) -> Option<(Quantity, usize)> {
    let mut index = index;
    let token = tokens.get(index)?.as_str();
    if token.starts_with(|ch: char| ch.is_ascii_digit() || ch == '.')
        && token.bytes().any(|byte| byte.is_ascii_digit())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b',' || byte == b'.')
    {
        // A fraction is a count the parser will not round.
        if token.contains('.') {
            return Some((Quantity::Vague, skip_of(tokens, index + 1)));
        }
        let count = token
            .replace(',', "")
            .parse::<u32>()
            .map_or(TEMPORAL_MAX_COUNT, |count| count.min(TEMPORAL_MAX_COUNT));
        return Some((Quantity::Count(count), skip_of(tokens, index + 1)));
    }
    if matches!(token, "a" | "an") {
        match tokens.get(index + 1).map(String::as_str) {
            Some("couple" | "few" | "dozen" | "half") => index += 1,
            _ => return Some((Quantity::Count(1), index + 1)),
        }
    }
    let quantity = match tokens[index].as_str() {
        "couple" => Quantity::Count(2),
        "few" => Quantity::Count(3),
        "dozen" => Quantity::Count(12),
        "several" | "many" => Quantity::Vague,
        // `half a year`, `half of an hour`: the article belongs to the count.
        "half" => {
            let after = skip_of(tokens, index + 1);
            let after = match tokens.get(after).map(String::as_str) {
                Some("a" | "an") => after + 1,
                _ => after,
            };
            return Some((Quantity::Vague, after));
        }
        _ => {
            let (count, after) = number_words_at(tokens, index)?;
            return Some((Quantity::Count(count), skip_of(tokens, after)));
        }
    };
    Some((quantity, skip_of(tokens, index + 1)))
}

fn skip_of(tokens: &[String], index: usize) -> usize {
    if tokens.get(index).map(String::as_str) == Some("of") {
        index + 1
    } else {
        index
    }
}

/// Spelled-out numbers, added word by word (`twenty four` is 24), with
/// `hundred` and `thousand` multiplying what came before and `and` joining
/// them (`one hundred and two`).
fn number_words_at(tokens: &[String], index: usize) -> Option<(u32, usize)> {
    let mut total: u64 = 0;
    let mut current: u64 = 0;
    let mut end = index;
    while let Some(token) = tokens.get(end).map(String::as_str) {
        match (number_word(token), token) {
            (Some(value), _) => current += u64::from(value),
            (None, "hundred") if end > index => current *= 100,
            (None, "and")
                if end > index
                    && tokens
                        .get(end + 1)
                        .is_some_and(|next| number_word(next).is_some()) => {}
            (None, "thousand") if end > index => {
                total += current * 1_000;
                current = 0;
            }
            _ => break,
        }
        end += 1;
        if total + current > u64::from(TEMPORAL_MAX_COUNT) {
            total = u64::from(TEMPORAL_MAX_COUNT);
            current = 0;
        }
    }
    (end > index).then(|| {
        let count = (total + current).min(u64::from(TEMPORAL_MAX_COUNT));
        (count as u32, end)
    })
}

fn number_word(token: &str) -> Option<u32> {
    Some(match token {
        "zero" => 0,
        "one" => 1,
        "two" => 2,
        "three" => 3,
        "four" => 4,
        "five" => 5,
        "six" => 6,
        "seven" => 7,
        "eight" => 8,
        "nine" => 9,
        "ten" => 10,
        "eleven" => 11,
        "twelve" => 12,
        "thirteen" => 13,
        "fourteen" => 14,
        "fifteen" => 15,
        "sixteen" => 16,
        "seventeen" => 17,
        "eighteen" => 18,
        "nineteen" => 19,
        "twenty" => 20,
        "thirty" => 30,
        "forty" => 40,
        "fifty" => 50,
        "sixty" => 60,
        "seventy" => 70,
        "eighty" => 80,
        "ninety" => 90,
        _ => return None,
    })
}

/// Lowercased alphanumeric runs. A `.` or `,` between two digits, or a `.`
/// opening a number, stays in it (`0.5`, `.5`, `1,000`), so a decimal never
/// splits into a different count.
fn temporal_query_tokens(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut tokens = Vec::new();
    let mut current = String::new();
    for (index, &ch) in chars.iter().enumerate() {
        let before = index.checked_sub(1).map(|before| chars[before]);
        let in_number = matches!(ch, '.' | ',')
            && chars.get(index + 1).is_some_and(char::is_ascii_digit)
            && (before.is_some_and(|before| before.is_ascii_digit())
                || (ch == '.' && !before.is_some_and(char::is_alphanumeric)));
        if ch.is_ascii_alphanumeric() || in_number {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn weekday_index(token: &str) -> Option<u8> {
    Some(match token {
        "monday" => 0,
        "tuesday" => 1,
        "wednesday" => 2,
        "thursday" => 3,
        "friday" => 4,
        "saturday" => 5,
        "sunday" => 6,
        _ => return None,
    })
}

/// 0 = Monday. Unix day 0, 1970-01-01, was a Thursday.
fn monday_weekday(day: i64) -> i64 {
    (day + 3).rem_euclid(7)
}

/// `length` seconds from `start`, clamped to the representable range.
fn span(start: i128, length: i128) -> TimeRange {
    let clamp = |value: i128| value.clamp(0, i128::from(u64::MAX)) as u64;
    TimeRange {
        start: clamp(start),
        end: clamp(start + length - 1),
    }
}

/// The calendar `unit` holding `now`, moved by `offset` units.
fn calendar_range(unit: TemporalUnit, offset: i64, now: u64) -> TimeRange {
    let now = i128::from(now);
    let offset = i128::from(offset);
    let day = i128::from(TEMPORAL_SECONDS_PER_DAY);
    let aligned = |length: i128| span(now - now.rem_euclid(length) + offset * length, length);
    match unit {
        TemporalUnit::Second => aligned(1),
        TemporalUnit::Minute => aligned(60),
        TemporalUnit::Hour => aligned(3_600),
        TemporalUnit::Day => aligned(day),
        TemporalUnit::Week | TemporalUnit::Weekend => {
            let today = now.div_euclid(day);
            let monday = today - i128::from(monday_weekday(today as i64)) + offset * 7;
            if unit == TemporalUnit::Week {
                span(monday * day, 7 * day)
            } else {
                span((monday + 5) * day, 2 * day)
            }
        }
        TemporalUnit::Month => month_span(now, offset, 1),
        TemporalUnit::Quarter => month_span(now, offset * 3, 3),
        TemporalUnit::Year => month_span(now, offset * 12, 12),
    }
}

/// `months` calendar months starting at the `months`-aligned month that holds
/// `now`, moved by `shift` months.
fn month_span(now: i128, shift: i128, months: i128) -> TimeRange {
    let days = (now.div_euclid(i128::from(TEMPORAL_SECONDS_PER_DAY))) as i64;
    let (year, month, _) = civil_from_unix_days(days);
    let index = i128::from(year) * 12 + i128::from(month) - 1;
    let first = index - index.rem_euclid(months) + shift;
    let month_start = |index: i128| {
        let year = i32::try_from(index.div_euclid(12)).unwrap_or(i32::MAX);
        let month = (index.rem_euclid(12) + 1) as u32;
        i128::from(unix_days_from_civil(year, month, 1)) * i128::from(TEMPORAL_SECONDS_PER_DAY)
    };
    let start = month_start(first);
    span(start, month_start(first + months) - start)
}

fn utc_day_start(timestamp: u64) -> u64 {
    timestamp - timestamp % TEMPORAL_SECONDS_PER_DAY
}

fn previous_calendar_month_range(now: u64) -> TimeRange {
    let (year, month, _) = civil_from_unix_days(unix_days_from_timestamp(now));
    let current_month_start = unix_seconds_from_civil(year, month, 1);
    let (previous_year, previous_month) = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    TimeRange {
        start: unix_seconds_from_civil_saturating(previous_year, previous_month, 1),
        end: current_month_start.saturating_sub(1),
    }
}

fn previous_calendar_year_range(now: u64) -> TimeRange {
    let (year, _, _) = civil_from_unix_days(unix_days_from_timestamp(now));
    let current_year_start = unix_seconds_from_civil(year, 1, 1);
    TimeRange {
        start: unix_seconds_from_civil_saturating(year - 1, 1, 1),
        end: current_year_start.saturating_sub(1),
    }
}

fn unix_seconds_from_civil_saturating(year: i32, month: u32, day: u32) -> u64 {
    let days = unix_days_from_civil(year, month, day);
    if days <= 0 {
        0
    } else {
        (days as u64).saturating_mul(TEMPORAL_SECONDS_PER_DAY)
    }
}

fn unix_seconds_from_civil(year: i32, month: u32, day: u32) -> u64 {
    let days = unix_days_from_civil(year, month, day);
    assert!(
        days >= 0,
        "temporal UTC conversion is only defined for Unix epoch and later dates"
    );
    if days == 0 {
        0
    } else {
        (days as u64).saturating_mul(TEMPORAL_SECONDS_PER_DAY)
    }
}

fn unix_days_from_timestamp(timestamp: u64) -> i64 {
    i64::try_from(timestamp / TEMPORAL_SECONDS_PER_DAY)
        .expect("temporal UTC conversion supports Unix days representable as i64")
}

fn civil_from_unix_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(m <= 2);
    let year = i32::try_from(year)
        .expect("temporal UTC conversion supports civil years representable as i32");
    (year, m as u32, d as u32)
}

fn unix_days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);

    year -= i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * adjusted_month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Temporal query precision controls sigmoid width for temporal scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TemporalGranularity {
    Exact,
    Hour,
    Day,
    Week,
    Month,
    Season,
    Year,
    Vague,
}

impl TemporalGranularity {
    /// Returns the scoring sigma in seconds for this granularity.
    pub fn sigma_secs(self) -> u64 {
        match self {
            Self::Exact => 3_600,
            Self::Hour => 14_400,
            Self::Day => 86_400,
            Self::Week => 604_800,
            Self::Month => 2_592_000,
            Self::Season => 7_776_000,
            Self::Year => 15_552_000,
            Self::Vague => 31_536_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TemporalHintStatus::{Future, Unresolved, Used};
    use super::{
        QueryTemporalHints, TemporalExpressionParseError, TemporalHintReport, TimeRange,
        parse_temporal_expression, temporal_hints_from_query,
    };

    const FROZEN_NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    /// Hand-computed calendar bounds around Friday 2024-03-15 12:00 UTC.
    #[test]
    fn query_hints_resolve_the_forms_agents_write() {
        for (query, phrase, status, range) in [
            (
                "standup today",
                "today",
                Used,
                (1_710_460_800, 1_710_547_199),
            ),
            (
                "plans tonight",
                "tonight",
                Used,
                (1_710_460_800, 1_710_547_199),
            ),
            (
                "what runs tomorrow night",
                "tomorrow",
                Future,
                (1_710_547_200, 1_710_633_599),
            ),
            (
                "notes from this week",
                "this week",
                Used,
                (1_710_115_200, 1_710_719_999),
            ),
            (
                "notes from this weekend",
                "this weekend",
                Future,
                (1_710_547_200, 1_710_719_999),
            ),
            (
                "notes from last weekend",
                "last weekend",
                Used,
                (1_709_942_400, 1_710_115_199),
            ),
            (
                "notes from last friday",
                "last friday",
                Used,
                (1_709_856_000, 1_709_942_399),
            ),
            (
                "notes from this monday",
                "this monday",
                Used,
                (1_710_115_200, 1_710_201_599),
            ),
            (
                "notes from next monday",
                "next monday",
                Future,
                (1_710_720_000, 1_710_806_399),
            ),
            (
                "notes from this month",
                "this month",
                Used,
                (1_709_251_200, 1_711_929_599),
            ),
            (
                "goals next quarter",
                "next quarter",
                Future,
                (1_711_929_600, 1_719_791_999),
            ),
            (
                "errors in the last 2 weeks",
                "last 2 weeks",
                Used,
                (1_709_294_400, FROZEN_NOW),
            ),
            (
                "errors in the past two weeks",
                "past two weeks",
                Used,
                (1_709_294_400, FROZEN_NOW),
            ),
            (
                "last twenty four hours",
                "last twenty four hours",
                Used,
                (1_710_417_600, FROZEN_NOW),
            ),
            (
                "last couple of months",
                "last couple of months",
                Used,
                (1_705_320_000, FROZEN_NOW),
            ),
            (
                "deploys 3 days ago",
                "3 days ago",
                Used,
                (1_710_201_600, 1_710_287_999),
            ),
            (
                "deploys a few days ago",
                "a few days ago",
                Used,
                (1_710_201_600, 1_710_287_999),
            ),
            (
                "errors in the past minute",
                "past minute",
                Used,
                (FROZEN_NOW - 60, FROZEN_NOW),
            ),
            (
                "1,000 days ago",
                "1,000 days ago",
                Used,
                (1_624_060_800, 1_624_147_199),
            ),
            (
                "one hundred and two days ago",
                "one hundred and two days ago",
                Used,
                (1_701_648_000, 1_701_734_399),
            ),
            (
                "plans for next 2 weeks",
                "next 2 weeks",
                Future,
                (FROZEN_NOW, 1_711_713_600),
            ),
        ] {
            let hints = temporal_hints_from_query(query, FROZEN_NOW);
            assert_eq!(
                hints.hints,
                vec![TemporalHintReport {
                    phrase: phrase.to_owned(),
                    status,
                    start: Some(range.0),
                    end: Some(range.1),
                }],
                "{query}"
            );
            let window = (status == Used).then_some(TimeRange {
                start: range.0,
                end: range.1,
            });
            assert_eq!(hints.range, window, "{query}");
        }
    }

    #[test]
    fn query_hints_skip_what_they_cannot_resolve_and_cover_the_rest() {
        for (query, phrase) in [
            ("notes from the last several weeks", "last several weeks"),
            ("the agreement from half a year ago", "half a year ago"),
            (
                "the agreement from half of a year ago",
                "half of a year ago",
            ),
            ("the deployment from 0.5 days ago", "0.5 days ago"),
            ("the deployment from .5 days ago", ".5 days ago"),
        ] {
            let hints = temporal_hints_from_query(query, FROZEN_NOW);
            assert_eq!(hints.range, None, "{query}");
            assert_eq!(hints.hints.len(), 1, "{query}");
            assert_eq!(hints.hints[0].phrase, phrase);
            assert_eq!(hints.hints[0].status, Unresolved);
        }

        let hints = temporal_hints_from_query("recent notes from yesterday", FROZEN_NOW);
        assert_eq!(
            hints
                .hints
                .iter()
                .map(|hint| (hint.phrase.as_str(), hint.status))
                .collect::<Vec<_>>(),
            [("recent", Used), ("yesterday", Used)]
        );
        assert_eq!(
            hints.range,
            Some(TimeRange {
                start: 1_709_899_200,
                end: FROZEN_NOW,
            })
        );

        let hints = temporal_hints_from_query("rollout tomorrow, decided yesterday", FROZEN_NOW);
        assert_eq!(
            hints.range,
            Some(TimeRange {
                start: 1_710_374_400,
                end: 1_710_460_799,
            })
        );
    }

    #[test]
    fn query_hints_ignore_words_that_only_look_temporal() {
        for query in [
            "last commit",
            "my last note",
            "last update",
            "show me last",
            "next steps",
            "last 2 commits",
            "this second attempt",
            "last minute changes",
            "a week of notes",
        ] {
            assert_eq!(
                temporal_hints_from_query(query, FROZEN_NOW),
                QueryTemporalHints::default(),
                "{query}"
            );
        }
    }

    #[test]
    fn query_hints_past_the_calendar_resolve_nothing() {
        let hints = temporal_hints_from_query("notes from last month", u64::MAX);
        assert_eq!(hints.range, None);
        assert_eq!(hints.hints[0].status, Unresolved);
    }

    #[test]
    fn standalone_expression_is_one_resolvable_phrase() {
        assert_eq!(
            parse_temporal_expression("last 2 weeks", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_709_294_400,
                end: FROZEN_NOW,
            }
        );
        for expression in ["last several weeks", "yesterday at noon", "next steps"] {
            assert!(
                matches!(
                    parse_temporal_expression(expression, FROZEN_NOW),
                    Err(TemporalExpressionParseError::Unsupported { .. })
                ),
                "{expression}"
            );
        }
        assert_eq!(
            parse_temporal_expression(" ", FROZEN_NOW),
            Err(TemporalExpressionParseError::Empty)
        );
    }
}
