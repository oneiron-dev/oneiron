//! Shared wall-clock time in Unix milliseconds.
//! `wall_clock_ms` returns zero before the epoch and saturates on overflow.
//! Runtime callers share this helper without owning a second clock.

pub(crate) fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
