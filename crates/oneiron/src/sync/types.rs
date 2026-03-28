//! Sync-specific types for the CRDT sync layer.

/// Configuration for the sync layer.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Number of windows loaded by default (current + previous month). Default: 2.
    pub default_window_count: u8,
    /// Byte threshold for triggering compaction. Default: 512 KB.
    pub compaction_threshold_bytes: u32,
    /// Minimum seconds between compaction runs. Default: 30.
    pub compaction_throttle_secs: u32,
    /// Whether to sync vectors (for devices without local embedding model).
    pub sync_vectors: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            default_window_count: 2,
            compaction_threshold_bytes: 524_288,
            compaction_throttle_secs: 30,
            sync_vectors: false,
        }
    }
}

/// A window key identifying a time-partitioned Doc (format: "YYYY-MM").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WindowKey(String);

impl WindowKey {
    /// Creates a new window key from a "YYYY-MM" string.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// Creates a window key from a Unix timestamp (seconds).
    pub fn from_timestamp(ts: u64) -> Self {
        // Convert unix seconds to YYYY-MM
        let secs = ts as i64;
        // Simple calculation: days since epoch → year/month
        // Using chrono-free approach: 86400 secs/day, approximate month/year
        let days = secs / 86_400;
        // Approximate: 1970-01-01 is day 0
        let mut year = 1970i32;
        let mut remaining_days = days;

        loop {
            let days_in_year = if is_leap_year(year) { 366 } else { 365 };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }

        let mut month = 1u32;
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
        for &md in &month_days {
            if remaining_days < md {
                break;
            }
            remaining_days -= md;
            month += 1;
        }

        Self(format!("{year:04}-{month:02}"))
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
        Some(WindowKey(format!("{prev_year:04}-{prev_month:02}")))
    }

    fn parse_year_month(&self) -> Option<(i32, u32)> {
        let parts: Vec<&str> = self.0.split('-').collect();
        if parts.len() != 2 {
            return None;
        }
        let year: i32 = parts[0].parse().ok()?;
        let month: u32 = parts[1].parse().ok()?;
        if !(1..=12).contains(&month) {
            return None;
        }
        Some((year, month))
    }
}

impl std::fmt::Display for WindowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Generates the Doc GUID for a window.
pub fn window_doc_guid(user_id: &str, key: &WindowKey) -> String {
    format!("vault:{user_id}:w:{key}")
}

/// Generates the Doc GUID for a root doc.
pub fn root_doc_guid(user_id: &str) -> String {
    format!("vault:{user_id}")
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Convert year/month/day to Unix timestamp (seconds).
///
/// Returns `None` for pre-1970 dates where the result would be negative.
fn date_to_unix(year: i32, month: u32, day: u32) -> Option<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_key_from_timestamp() {
        // 2026-02-15 ~ Unix 1771027200
        let key = WindowKey::from_timestamp(1_771_027_200);
        assert_eq!(key.as_str(), "2026-02");
    }

    #[test]
    fn window_key_round_trip_timestamps() {
        let key = WindowKey::new("2026-03");
        let start = key.start_timestamp().unwrap();
        let end = key.end_timestamp().unwrap();
        // March 2026 has 31 days
        assert_eq!(end - start, 31 * 86_400);
        // Verify the start timestamp produces the same key
        assert_eq!(WindowKey::from_timestamp(start).as_str(), "2026-03");
    }

    #[test]
    fn window_key_from_timestamp_epoch() {
        let key = WindowKey::from_timestamp(0);
        assert_eq!(key.as_str(), "1970-01");
    }

    #[test]
    fn window_doc_guid_format() {
        let key = WindowKey::new("2026-02");
        assert_eq!(window_doc_guid("user123", &key), "vault:user123:w:2026-02");
    }
}
