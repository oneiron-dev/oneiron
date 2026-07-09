//! `TimeRange`, temporal expressions/parsing, granularity/anchor enums.

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

/// Accepted natural-language temporal retrieval hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemporalExpression {
    Recent,
    Yesterday,
    LastWeek,
    LastMonth,
    LastYear,
}

impl TemporalExpression {
    /// Parses a standalone temporal expression. The accepted grammar is
    /// deliberately small: `recent`, `yesterday`, `last week`, `last month`,
    /// and `last year`.
    pub fn parse(expression: &str) -> std::result::Result<Self, TemporalExpressionParseError> {
        let normalized = normalize_temporal_expression(expression);
        if normalized.is_empty() {
            return Err(TemporalExpressionParseError::Empty);
        }

        match normalized.as_str() {
            "recent" => Ok(Self::Recent),
            "yesterday" => Ok(Self::Yesterday),
            "last week" => Ok(Self::LastWeek),
            "last month" => Ok(Self::LastMonth),
            "last year" => Ok(Self::LastYear),
            _ => Err(TemporalExpressionParseError::Unsupported {
                expression: normalized,
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
        }
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
    #[error("ambiguous temporal expression in query")]
    Ambiguous,
}

/// Parses a standalone temporal expression and resolves it to inclusive UTC
/// Unix-second bounds from `now`.
pub fn parse_temporal_expression(
    expression: &str,
    now: u64,
) -> std::result::Result<TimeRange, TemporalExpressionParseError> {
    Ok(TemporalExpression::parse(expression)?.resolve(now))
}

/// Extracts one accepted temporal hint from a larger retrieval query.
///
/// Queries without temporal hint words return `Ok(None)`. Queries containing
/// an unsupported temporal-looking phrase, or more than one temporal hint,
/// fail closed with a typed parse error.
pub fn temporal_expression_from_query(
    query: &str,
) -> std::result::Result<Option<TemporalExpression>, TemporalExpressionParseError> {
    let tokens = temporal_query_tokens(query);
    let mut found = None;
    let mut index = 0;

    while index < tokens.len() {
        let parsed = match tokens[index].as_str() {
            "recent" => Some(TemporalExpression::Recent),
            "yesterday" => Some(TemporalExpression::Yesterday),
            "today" | "tomorrow" | "tonight" => {
                return Err(TemporalExpressionParseError::Unsupported {
                    expression: tokens[index].clone(),
                });
            }
            "next" | "this" => match tokens.get(index + 1).map(String::as_str) {
                Some(next) if is_temporal_unit_token(next) || is_weekday_token(next) => {
                    return Err(TemporalExpressionParseError::Unsupported {
                        expression: format!("{} {next}", tokens[index]),
                    });
                }
                _ => None,
            },
            "last" => match tokens.get(index + 1).map(String::as_str) {
                None => None,
                Some("week") => {
                    index += 1;
                    Some(TemporalExpression::LastWeek)
                }
                Some("month") => {
                    index += 1;
                    Some(TemporalExpression::LastMonth)
                }
                Some("year") => {
                    index += 1;
                    Some(TemporalExpression::LastYear)
                }
                Some(next) if is_temporal_unit_token(next) || is_weekday_token(next) => {
                    return Err(TemporalExpressionParseError::Unsupported {
                        expression: format!("last {next}"),
                    });
                }
                Some(_) => {
                    if let Some(expression) = unsupported_last_quantity_expression(&tokens, index) {
                        return Err(TemporalExpressionParseError::Unsupported { expression });
                    }
                    None
                }
            },
            _ => None,
        };

        if let Some(expression) = parsed
            && found.replace(expression).is_some()
        {
            return Err(TemporalExpressionParseError::Ambiguous);
        }
        index += 1;
    }

    Ok(found)
}

fn normalize_temporal_expression(expression: &str) -> String {
    temporal_query_tokens(expression).join(" ")
}

fn temporal_query_tokens(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn is_temporal_unit_token(token: &str) -> bool {
    matches!(
        token,
        "day"
            | "days"
            | "hour"
            | "hours"
            | "minute"
            | "minutes"
            | "second"
            | "seconds"
            | "week"
            | "weeks"
            | "month"
            | "months"
            | "year"
            | "years"
            | "quarter"
            | "quarters"
    )
}

fn is_temporal_quantity_token(token: &str) -> bool {
    token.bytes().all(|byte| byte.is_ascii_digit())
        || matches!(
            token,
            "zero"
                | "a"
                | "an"
                | "one"
                | "two"
                | "three"
                | "four"
                | "five"
                | "six"
                | "seven"
                | "eight"
                | "nine"
                | "ten"
                | "eleven"
                | "twelve"
                | "thirteen"
                | "fourteen"
                | "fifteen"
                | "sixteen"
                | "seventeen"
                | "eighteen"
                | "nineteen"
                | "twenty"
                | "thirty"
                | "forty"
                | "fifty"
                | "sixty"
                | "seventy"
                | "eighty"
                | "ninety"
                | "hundred"
                | "thousand"
                | "dozen"
                | "half"
                | "couple"
                | "few"
                | "several"
                | "many"
        )
}

fn unsupported_last_quantity_expression(tokens: &[String], last_index: usize) -> Option<String> {
    let mut index = last_index + 1;
    let mut saw_quantity = false;

    while let Some(token) = tokens.get(index).map(String::as_str) {
        if token == "of" && saw_quantity {
            index += 1;
            continue;
        }

        if is_temporal_quantity_token(token) {
            saw_quantity = true;
            index += 1;
            continue;
        }

        if saw_quantity && (is_temporal_unit_token(token) || is_weekday_token(token)) {
            return Some(tokens[last_index..=index].join(" "));
        }

        return None;
    }

    None
}

fn is_weekday_token(token: &str) -> bool {
    matches!(
        token,
        "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday" | "sunday"
    )
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

/// Temporal anchor intent for bitemporal scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum TemporalAnchorMode {
    Occurred,
    Learned,
    Both,
    #[default]
    Auto,
}

#[cfg(test)]
mod tests {
    use super::TEMPORAL_SECONDS_PER_DAY;
    use super::TemporalExpressionParseError;
    use super::TimeRange;
    use super::parse_temporal_expression;
    use super::temporal_expression_from_query;
    use super::unix_seconds_from_civil;

    const FROZEN_NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    #[test]
    fn temporal_expression_parser_resolves_supported_forms_from_frozen_clock() {
        assert_eq!(
            parse_temporal_expression("recent", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_709_899_200,
                end: FROZEN_NOW,
            }
        );
        assert_eq!(
            parse_temporal_expression("yesterday", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_710_374_400,
                end: 1_710_460_799,
            }
        );
        assert_eq!(
            parse_temporal_expression("last week", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_709_856_000,
                end: 1_710_460_799,
            }
        );
        assert_eq!(
            parse_temporal_expression("last month", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_706_745_600,
                end: 1_709_251_199,
            }
        );
        assert_eq!(
            parse_temporal_expression("last year", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_672_531_200,
                end: 1_704_067_199,
            }
        );
    }

    #[test]
    fn temporal_expression_query_parser_rejects_unsupported_last_forms() {
        assert!(matches!(
            temporal_expression_from_query("notes from last friday"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last friday"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last 2 weeks"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last 2 weeks"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last 24 hours"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last 24 hours"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last 30 minutes"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last 30 minutes"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last eleven weeks"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last eleven weeks"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last twenty four hours"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last twenty four hours"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last two weeks"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last two weeks"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last few days"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last few days"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last couple of months"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last couple of months"
        ));
    }

    #[test]
    fn temporal_expression_query_parser_ignores_non_temporal_last_nouns() {
        for query in ["last commit", "my last note", "last update", "show me last"] {
            assert_eq!(
                temporal_expression_from_query(query).unwrap(),
                None,
                "{query}"
            );
        }
    }

    #[test]
    fn temporal_expression_query_parser_rejects_multiple_hints() {
        assert!(matches!(
            temporal_expression_from_query("recent notes from yesterday"),
            Err(TemporalExpressionParseError::Ambiguous)
        ));
    }

    #[test]
    fn temporal_expression_query_parser_rejects_unsupported_non_last_forms() {
        assert!(matches!(
            temporal_expression_from_query("notes from tomorrow"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "tomorrow"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from next week"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "next week"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from this month"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "this month"
        ));
        assert_eq!(temporal_expression_from_query("next steps").unwrap(), None);
    }

    #[test]
    fn unix_seconds_from_civil_keeps_epoch_boundary_at_zero() {
        assert_eq!(unix_seconds_from_civil(1970, 1, 1), 0);
        assert_eq!(unix_seconds_from_civil(1970, 1, 2), 86_400);
    }

    #[test]
    #[should_panic(expected = "only defined for Unix epoch and later dates")]
    fn unix_seconds_from_civil_rejects_pre_epoch_dates() {
        let _ = unix_seconds_from_civil(1969, 12, 31);
    }

    #[test]
    fn temporal_expression_calendar_ranges_saturate_at_epoch_boundary() {
        assert_eq!(
            parse_temporal_expression("last month", 0).unwrap(),
            TimeRange { start: 0, end: 0 }
        );
        assert_eq!(
            parse_temporal_expression("last year", 0).unwrap(),
            TimeRange { start: 0, end: 0 }
        );
        assert_eq!(
            parse_temporal_expression("last month", 15 * TEMPORAL_SECONDS_PER_DAY).unwrap(),
            TimeRange { start: 0, end: 0 }
        );
        assert_eq!(
            parse_temporal_expression("last year", 15 * TEMPORAL_SECONDS_PER_DAY).unwrap(),
            TimeRange { start: 0, end: 0 }
        );
    }

    #[test]
    #[should_panic(expected = "civil years representable as i32")]
    fn temporal_expression_rejects_extreme_timestamp_without_wrapping() {
        let _ = parse_temporal_expression("last month", u64::MAX);
    }
}
