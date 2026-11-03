//! Monthly CRDT window keys and their timestamp conversion.

/// A window key identifying a base or world-scoped monthly Doc.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WindowKey(pub(crate) String);

impl WindowKey {
    /// Creates a new window key from a "YYYY-MM" string.
    ///
    /// Panics on malformed input.
    pub fn new(key: impl Into<String>) -> Self {
        let key = key.into();
        assert!(
            parse_window_key_str(&key).is_some(),
            "malformed window key {key:?}; expected YYYY-MM with year >= 1970 and month 01-12"
        );
        Self(key)
    }

    /// Creates a new window key from a "YYYY-MM" string, returning `None`
    /// on malformed input.
    ///
    /// Non-panicking counterpart to [`WindowKey::new`] for wire-derived keys
    /// (the server-side chokepoint for client-supplied window keys).
    pub fn try_new(key: impl Into<String>) -> Option<Self> {
        let key = key.into();
        parse_window_key_str(&key)?;
        Some(Self(key))
    }

    #[cfg(test)]
    pub(super) fn new_unchecked_for_test(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// Creates a window key from a Unix timestamp (seconds).
    ///
    /// Timestamps at or beyond year 10000 are clamped to the last
    /// representable window, `"9999-12"`: the ARCH-0023b window-key format is
    /// `YYYY-MM` (exactly 7 bytes), so a larger year would produce a key that
    /// `parse_window_key_str` rejects everywhere — `sync_state` rows written
    /// under such a key become unreachable through validated read paths,
    /// `SyncQueue::push` refuses it, and the wire encoders assert on it.
    /// `learned_at` is caller-supplied, so this conversion must stay total
    /// and bounded.
    pub fn from_timestamp(ts: u64) -> Self {
        // Delegates to the always-compiled deletion module so the `pt:`
        // pending-tombstone marker (written even in non-`sync` builds,
        // ONE-1132) addresses EXACTLY the window this key would name.
        Self(crate::deletion::window_label_from_timestamp(ts))
    }

    /// World-scoped key for a timestamp. Base rows continue to use `from_timestamp`.
    pub fn for_world(ts: u64, world: crate::EntityId) -> Self {
        Self::for_month_world(&Self::from_timestamp(ts), world)
    }

    /// Address a world in the same month as an existing key.
    pub fn for_month_world(month: &Self, world: crate::EntityId) -> Self {
        Self(format!("{}@{}", &month.0[..7], world.to_hex()))
    }

    /// World axis, or `None` for the shared base partition.
    pub fn world(&self) -> Option<crate::EntityId> {
        self.0
            .split_once('@')
            .and_then(|(_, hex)| crate::EntityId::from_hex(hex).ok())
    }

    /// Returns the key string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the start timestamp (first second of the month) as Unix seconds.
    /// Returns `None` for pre-1970 dates (negative Unix timestamps).
    pub fn start_timestamp(&self) -> Option<u64> {
        let (year, month) = self.parse_year_month()?;
        date_to_unix(year, month, 1)
    }

    /// Returns the end timestamp (first second of the next month) as Unix seconds.
    /// Returns `None` for pre-1970 dates (negative Unix timestamps).
    pub fn end_timestamp(&self) -> Option<u64> {
        let (year, month) = self.parse_year_month()?;
        let (next_year, next_month) = if month == 12 {
            (year + 1, 1)
        } else {
            (year, month + 1)
        };
        date_to_unix(next_year, next_month, 1)
    }

    /// Returns the previous month's `WindowKey`.
    pub fn previous_month(&self) -> Option<WindowKey> {
        let (year, month) = self.parse_year_month()?;
        let (prev_year, prev_month) = if month == 1 {
            (year - 1, 12)
        } else {
            (year, month - 1)
        };
        if prev_year < 1970 {
            return None;
        }
        Some(match self.world() {
            Some(world) => WindowKey::for_month_world(
                &WindowKey(format!("{prev_year:04}-{prev_month:02}")),
                world,
            ),
            None => WindowKey(format!("{prev_year:04}-{prev_month:02}")),
        })
    }

    fn parse_year_month(&self) -> Option<(i32, u32)> {
        parse_window_key_str(&self.0)
    }
}

pub(crate) fn parse_window_key_str(key: &str) -> Option<(i32, u32)> {
    crate::deletion::parse_window_label(key)
}

impl std::fmt::Display for WindowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Convert year/month/day to Unix timestamp (seconds).
///
/// Returns `None` for pre-1970 dates where the result would be negative.
pub(crate) fn date_to_unix(year: i32, month: u32, day: u32) -> Option<u64> {
    // Days from 1970-01-01 to the given date
    let mut days: i64 = 0;

    // Years
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    // Handle years before 1970
    for y in year..1970 {
        days -= if is_leap_year(y) { 366 } else { 365 };
    }

    // Months within the target year
    let month_days = [
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    for &d in &month_days[..(month as usize - 1)] {
        days += d as i64;
    }

    // Days within the month
    days += (day as i64) - 1;

    if days < 0 {
        return None;
    }

    Some((days * 86_400) as u64)
}
