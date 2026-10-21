//! The anonymous training window's retry pace (TL-6, CALLS TL6_RETRY_PACE),
//! one per endpoint a self-hosted vault reaches at the intake: its
//! descriptor here, its batches and receipts with the shipper.
//!
//! A network error or a malformed reply waits 30 s, doubled after each
//! failure in a row up to 900 s, with no limit on attempts: the window is
//! never given up on. A `429` or `503` that names a wait in `Retry-After`
//! sets a floor no attempt starts before, and nothing here shortens it: the
//! backoff waits longer when it is the longer, never shorter. A success
//! clears both.
//!
//! `Retry-After` is read as delta-seconds or as an HTTP-date (FIX 6881):
//! a date names the wait from now to it on the system clock, none for a date
//! already past. A value that is neither waits the backoff alone.

use std::time::{Duration, Instant, SystemTime};

use reqwest::header::{HeaderMap, RETRY_AFTER};

/// The first wait after a failure.
const FIRST_WAIT: Duration = Duration::from_secs(30);
/// The longest wait the backoff reaches; a `Retry-After` may name longer.
const LONGEST_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// Why one request to the intake did not succeed. It names a class and a
/// status only: never a body, a key byte or a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failure {
    /// No reply: connecting, TLS, the timeout or reading the body failed.
    Network,
    /// A reply that is not the one asked for: another status (`Some`), or a
    /// body that does not decode or does not check (`None`).
    Reply(Option<u16>),
    /// The intake is busy: `429` or `503`, with the wait its `Retry-After`
    /// names, when it names one this reads.
    Busy {
        /// The reply's status.
        status: u16,
        /// The wait the reply names.
        retry_after: Option<Duration>,
    },
}

impl Failure {
    /// The failure's class, for a log line.
    pub(super) const fn class(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Reply(_) => "reply",
            Self::Busy { .. } => "busy",
        }
    }

    /// The reply's status, for a log line; `None` when there was no reply or
    /// its body failed.
    pub(super) const fn status(self) -> Option<u16> {
        match self {
            Self::Network => None,
            Self::Reply(status) => status,
            Self::Busy { status, .. } => Some(status),
        }
    }

    /// The not-before floor the reply named, if any.
    pub(super) const fn retry_after(self) -> Option<Duration> {
        match self {
            Self::Busy { retry_after, .. } => retry_after,
            Self::Network | Self::Reply(_) => None,
        }
    }
}

/// The wait a busy reply names in its `Retry-After` header: its
/// delta-seconds, or the time from now to its HTTP-date, zero once that
/// date has passed; `None` for none, or for a value that is neither.
pub(super) fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    // A date already past names no wait: the backoff paces the retry.
    Some(at.duration_since(SystemTime::now()).unwrap_or_default())
}

/// One endpoint's retry state.
#[derive(Debug, Default)]
pub(super) struct Retry {
    /// Failures in a row since the last success.
    failures: u32,
    /// The earliest the next attempt may start; `None` for any time.
    not_before: Option<Instant>,
    /// A `Retry-After` named a wait past what the clock counts: no attempt
    /// starts again in this process.
    held: bool,
}

impl Retry {
    /// Whether an attempt may start at `now`.
    pub(super) fn ready(&self, now: Instant) -> bool {
        !self.held && self.not_before.is_none_or(|at| now >= at)
    }

    /// Failures in a row since the last success.
    pub(super) const fn failures(&self) -> u32 {
        self.failures
    }

    /// An attempt succeeded: the next one may start at any time.
    pub(super) fn succeeded(&mut self) {
        *self = Self::default();
    }

    /// An attempt failed at `now`. The next one waits the backoff, or
    /// `floor`, a busy reply's `Retry-After`, when that is the longer.
    pub(super) fn failed(&mut self, now: Instant, floor: Option<Duration>) {
        self.failures = self.failures.saturating_add(1);
        let doubling = 2_u32.saturating_pow(self.failures.saturating_sub(1));
        let backoff = FIRST_WAIT.saturating_mul(doubling).min(LONGEST_BACKOFF);
        let wait = floor.map_or(backoff, |floor| floor.max(backoff));
        match now.checked_add(wait) {
            Some(at) => self.not_before = Some(at),
            None => self.held = true,
        }
    }
}
