//! How an adapter reads a provider's refusal as a spent quota or a rate
//! limit, and the reset the refusal names (OF-130: adapters classify, and
//! hold no retry policy; the caller decides what a reset means on its clock).

use std::collections::BTreeMap;

use serde_json::Value as JsonValue;

use super::{RetryableLlmError, SpentKind};

/// The words a provider's error type, code, status or message uses for a
/// spent quota or a rate limit. A bare "exhausted" is not one: a server out
/// of memory or workers is down, not limited.
const LIMIT_WORDS: [&str; 9] = [
    "rate_limit",
    "rate limit",
    "usage limit",
    "quota",
    "resource_exhausted",
    "too many requests",
    "limit reached",
    "cooling down",
    "cooldown",
];

/// The words a provider uses for spent prepaid credit: the account must be
/// topped up, and no window resets it.
const CREDIT_WORDS: [&str; 9] = [
    "insufficient_quota",
    "insufficient quota",
    "credit balance",
    "insufficient_credits",
    "insufficient credits",
    "out of credits",
    "billing",
    "payment required",
    "top up",
];

/// The words a provider uses for a spent usage window: a plan's daily,
/// weekly or monthly allowance, back at its reset.
const WINDOW_WORDS: [&str; 6] = [
    "usage limit",
    "usage_limit",
    "weekly",
    "daily limit",
    "monthly",
    "limit resets",
];

/// A wait this long or longer is a spent window, not a rate limit.
const WINDOW_WAIT_SECS: u64 = 15 * 60;

/// The most reset times one refusal contributes.
const MAX_RESET_TIMES: usize = 4;

/// Whether a provider's answer is a limit refusal: any 429 or 402, a 400
/// whose body reads as spent credit, or a 403 or a 5xx whose body reads as
/// a spent quota or a rate limit. A server error that only mentions
/// billing is a server error; an error inside an open stream that names
/// no status but reads as spent credit stands for a 402
/// ([`stream_error_status`]). Any other request error is never one,
/// whatever its body says.
#[must_use]
pub fn is_limit_status(status: u16, body: &JsonValue) -> bool {
    status == 429
        || status == 402
        || (status == 400 && reads_as(body, &CREDIT_WORDS))
        || ((status == 403 || status >= 500) && reads_as_limit(body))
}

/// A limit refusal with the waits its answer names, by its kind (OF-305): a
/// 402 or an answer that reads as spent credit is credit, one that reads as
/// a spent usage window or asks a long wait is a window, and any other is a
/// rate limit.
#[must_use]
pub fn limit_refusal(
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &JsonValue,
) -> RetryableLlmError {
    let retry_after = retry_after_seconds(headers, body);
    let resets_at = reset_times(body);
    let kind = if status == 402 || reads_as(body, &CREDIT_WORDS) {
        Some(SpentKind::Credit)
    } else if reads_as(body, &WINDOW_WORDS)
        || retry_after.is_some_and(|seconds| seconds >= WINDOW_WAIT_SECS)
    {
        Some(SpentKind::Window)
    } else {
        None
    };
    match kind {
        Some(kind) => RetryableLlmError::QuotaSpent {
            kind,
            retry_after,
            resets_at,
        },
        None => RetryableLlmError::RateLimited {
            retry_after,
            resets_at,
        },
    }
}

/// The HTTP status an error a provider sends inside an open stream stands
/// for: its own numeric `code` or `status`, else what its `type` or a
/// worded `code` names (a request error, a key refused, spent credit, a
/// rate limit), else spent credit when its words say so, else a server
/// error. An OpenAI-compatible provider may name the kind in `code` alone.
#[must_use]
pub fn stream_error_status(body: &JsonValue) -> u16 {
    let error = body.get("error").unwrap_or(body);
    let numeric = ["code", "status"].into_iter().find_map(|key| {
        let value = error.get(key)?;
        let status = value
            .as_u64()
            .or_else(|| value.as_str()?.trim().parse().ok())?;
        u16::try_from(status)
            .ok()
            .filter(|status| (400..=599).contains(status))
    });
    let named = ["type", "code"]
        .into_iter()
        .find_map(|key| match error.get(key)?.as_str()? {
            "invalid_request_error" | "not_found_error" => Some(400),
            "authentication_error" => Some(401),
            "billing_error" => Some(402),
            "permission_error" => Some(403),
            "rate_limit_error" => Some(429),
            _ => None,
        });
    numeric.or(named).unwrap_or_else(|| {
        if reads_as(body, &CREDIT_WORDS) {
            402
        } else {
            500
        }
    })
}

/// Whether a provider's error body reads as a spent quota or a rate limit:
/// its error's type, code, status or message names one. An error given as
/// a bare string is its message.
#[must_use]
pub fn reads_as_limit(body: &JsonValue) -> bool {
    reads_as(body, &LIMIT_WORDS)
}

/// Whether a provider's error body names one of `words`, in its error's
/// type, code, status or message.
fn reads_as(body: &JsonValue, words: &[&str]) -> bool {
    let error = body.get("error").unwrap_or(body);
    let texts: Vec<&str> = match error {
        JsonValue::String(message) => vec![message.as_str()],
        JsonValue::Object(fields) => ["type", "code", "status", "message"]
            .into_iter()
            .filter_map(|key| fields.get(key).and_then(JsonValue::as_str))
            .collect(),
        _ => Vec::new(),
    };
    texts.into_iter().any(|text| {
        let text = text.to_ascii_lowercase();
        words.iter().any(|word| text.contains(word))
    })
}

/// The seconds a refusal asks its caller to wait: a `reset_seconds` its body
/// carries (on its error or at the top), else a `Retry-After` header in
/// seconds, else a `retry_after` on its error.
#[must_use]
pub fn retry_after_seconds(headers: &BTreeMap<String, String>, body: &JsonValue) -> Option<u64> {
    let error = body.get("error");
    let field = |key: &str| {
        error
            .and_then(|error| error.get(key))
            .or_else(|| body.get(key))
            .and_then(JsonValue::as_u64)
    };
    field("reset_seconds")
        .filter(|seconds| *seconds > 0)
        .or_else(|| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("retry-after"))
                .and_then(|(_, value)| value.trim().parse::<u64>().ok())
        })
        .or_else(|| {
            error
                .and_then(|error| error.get("retry_after"))
                .and_then(JsonValue::as_u64)
        })
}

/// Each ISO-8601 time with a zone a refusal's body names, as Unix seconds in
/// the order the body names them, at most four: "resets at
/// 2026-10-19T00:00:00Z". Which of them is still ahead is the caller's to
/// judge on its own clock.
#[must_use]
pub fn reset_times(body: &JsonValue) -> Vec<u64> {
    let text = body.to_string();
    let bytes = text.as_bytes();
    let mut times = Vec::new();
    let mut at = 0;
    while at < bytes.len() && times.len() < MAX_RESET_TIMES {
        // A time starts at a number's first digit, never inside a longer one.
        let starts = at == 0 || !bytes[at - 1].is_ascii_digit();
        match iso_time_at(&bytes[at..]).filter(|_| starts) {
            Some((seconds, len)) => {
                times.push(seconds);
                at += len;
            }
            None => at += 1,
        }
    }
    times
}

/// `YYYY-MM-DD(T| )HH:MM[:SS[.frac]](Z|±HH[:]MM)` at the start of `bytes`:
/// its Unix seconds and its length. A time before 1970 is not a reset.
fn iso_time_at(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut cursor = Cursor { bytes, at: 0 };
    let year = cursor.digits(4)?;
    cursor.byte(b'-')?;
    let month = cursor.digits(2)?;
    cursor.byte(b'-')?;
    let day = cursor.digits(2)?;
    cursor.byte(b'T').or_else(|| cursor.byte(b' '))?;
    let hour = cursor.digits(2)?;
    cursor.byte(b':')?;
    let minute = cursor.digits(2)?;
    let mut second = 0;
    if cursor.byte(b':').is_some() {
        second = cursor.digits(2)?;
        if cursor.byte(b'.').is_some() {
            cursor.digits(1)?;
            while cursor.digits(1).is_some() {}
        }
    }
    let offset = match cursor.next()? {
        b'Z' => 0,
        sign @ (b'+' | b'-') => {
            let hours = cursor.digits(2)?;
            cursor.skip(b':');
            let minutes = cursor.digits(2)?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let seconds = i64::from(hours * 3600 + minutes * 60);
            if sign == b'+' { seconds } else { -seconds }
        }
        _ => return None,
    };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, day);
    let local = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second);
    let seconds = u64::try_from(local - offset).ok()?;
    Some((seconds, cursor.at))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn next(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn byte(&mut self, want: u8) -> Option<()> {
        (self.bytes.get(self.at) == Some(&want)).then(|| self.at += 1)
    }

    /// Steps over `want` when it is next; it may be absent.
    fn skip(&mut self, want: u8) {
        if self.bytes.get(self.at) == Some(&want) {
            self.at += 1;
        }
    }

    fn digits(&mut self, count: usize) -> Option<u32> {
        let digits = self.bytes.get(self.at..self.at + count)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        self.at += count;
        Some(
            digits
                .iter()
                .fold(0, |value, digit| value * 10 + u32::from(digit - b'0')),
        )
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}
