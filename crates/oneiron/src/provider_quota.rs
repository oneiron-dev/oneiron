//! A provider's per-user quota windows (MAIL-GOOGLE = A, ARCH-0027
//! #mail-drive): the units one user spent in the current minute and the
//! bytes read in the current day, kept on the source an import reads, so
//! every step of it, the host's and the owner's own, shares them across
//! restarts. A Gmail mailbox and a Google Drive source pace their reads
//! within them.
//!
//! A call is charged before it is made. One that does not fit rests the
//! source until its window opens; a provider's rate-limit answer rests it
//! [`RATE_LIMIT_REST_SECS`]. The change feed may spend the whole minute; the
//! copy spends at most [`COPY_SHARE_PERCENT`] of it, so new changes still
//! read while a big copy runs.

use serde::{Deserialize, Serialize};

/// The minute window's length.
const MINUTE_SECS: u64 = 60;
/// The day window's length.
const DAY_SECS: u64 = 86_400;
/// How long a source rests after its provider's rate-limit answer: the
/// provider's minute refills in it.
pub(crate) const RATE_LIMIT_REST_SECS: u64 = 60;
/// The share of a minute's units the copy may spend, in percent: the rest
/// stays for the change feed (RESEARCH-1393 #backfill plans at 75%, to leave
/// room for live sync and retries).
const COPY_SHARE_PERCENT: u64 = 75;

/// The units of a minute of `units_per_minute` a call may bring the window
/// to: the whole minute for the change feed (`live`), the copy's share
/// otherwise.
pub(crate) fn minute_ceiling(units_per_minute: u32, live: bool) -> u64 {
    let minute = u64::from(units_per_minute);
    if live {
        minute
    } else {
        minute * COPY_SHARE_PERCENT / 100
    }
}

/// The day's byte cap a call is charged against: a call runs only while the
/// day has room for the largest answer one call reads, so a step never
/// crosses the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DayBytes {
    pub(crate) cap: u64,
    pub(crate) largest_answer: u64,
}

/// Where one source's quota windows stand. Each window opens at its first
/// charge after the last one closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct ProviderQuotaWindow {
    /// When the minute window opened, Unix seconds.
    pub(crate) minute_start: u64,
    /// The units charged in it.
    pub(crate) minute_units: u64,
    /// When the day window opened, Unix seconds.
    pub(crate) day_start: u64,
    /// The bytes read in it.
    pub(crate) day_bytes: u64,
    /// Until when the source rests: no provider call is made before it.
    #[serde(default)]
    pub(crate) resting_until: Option<u64>,
}

impl ProviderQuotaWindow {
    /// When the source's rest ends, while it still rests at `now`.
    pub(crate) fn resting_at(&self, now: u64) -> Option<u64> {
        self.resting_until.filter(|until| *until > now)
    }

    /// Opens a new window for each one closed at `now` (or one a clock set
    /// back left in the future).
    pub(crate) fn roll(&mut self, now: u64) {
        if now < self.minute_start || now >= self.minute_start.saturating_add(MINUTE_SECS) {
            self.minute_start = now;
            self.minute_units = 0;
        }
        if now < self.day_start || now >= self.day_start.saturating_add(DAY_SECS) {
            self.day_start = now;
            self.day_bytes = 0;
        }
    }

    /// Charges `units` to a window rolled to now, within `ceiling` units of
    /// the minute and, when `day` is given, while the day has room for the
    /// largest answer. When the call does not fit, nothing is charged and
    /// the answer is when the source may call again: the end of the window
    /// that refused it.
    pub(crate) fn charge(
        &mut self,
        units: u64,
        ceiling: u64,
        day: Option<DayBytes>,
    ) -> Result<(), u64> {
        let spent = self.minute_units.saturating_add(units);
        if spent > ceiling {
            return Err(self.minute_start + MINUTE_SECS);
        }
        if let Some(day) = day
            && self.day_bytes.saturating_add(day.largest_answer) > day.cap
        {
            return Err(self.day_start + DAY_SECS);
        }
        self.minute_units = spent;
        Ok(())
    }

    /// Counts `bytes` an answer read against the day.
    pub(crate) fn count_bytes(&mut self, bytes: u64) {
        self.day_bytes = self.day_bytes.saturating_add(bytes);
    }
}
