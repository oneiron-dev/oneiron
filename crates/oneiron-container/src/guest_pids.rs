//! Physical guest pids limits and pressure observations (FIX 8013).
//!
//! The launch limit is the larger of the manifest pids and what the
//! guest's memory can hold, bounded by this host's fair share of free
//! pid space. A `pids.events` hit becomes `GuestPressure::Processes` on
//! the session manifest. Container backend only.

use std::sync::atomic::{AtomicU32, Ordering};

/// Lowest kernel memory one more task can cost the guest's cgroup (FIX 8013):
/// a 16 KiB kernel stack plus task_struct and per-task slab.
pub const TASK_KERNEL_MEMORY_FLOOR_BYTES: u64 = 32 * 1024;

/// This host's pid space as one launch saw it: the ceiling and the live tasks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPidSpace {
    /// `min(pid_max, threads-max)`: no host holds more tasks than this.
    pub ceiling: u32,
    /// Live kernel tasks, from `/proc/loadavg` field 4 (`running/total`).
    pub live_tasks: u32,
}

impl HostPidSpace {
    /// Reads pid_max, threads-max and the loadavg task count (Linux only):
    /// `None` where pid space cannot be seen (non-Linux, unreadable files).
    /// Never refuses; a launch without a bound still launches.
    pub fn read() -> Option<Self> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let number =
            |path: &str| -> Option<u32> { std::fs::read_to_string(path).ok()?.trim().parse().ok() };
        let ceiling =
            number("/proc/sys/kernel/pid_max")?.min(number("/proc/sys/kernel/threads-max")?);
        let loadavg = std::fs::read_to_string("/proc/loadavg").ok()?;
        let fourth = loadavg.split_whitespace().nth(3)?;
        let (_, total) = fourth.split_once('/')?;
        let live_tasks = total.parse().ok()?;
        (ceiling > 0).then_some(Self {
            ceiling,
            live_tasks,
        })
    }

    /// Pids no live task holds: `ceiling - live_tasks`, saturating.
    #[must_use]
    pub fn free(self) -> u32 {
        self.ceiling.saturating_sub(self.live_tasks)
    }

    /// One guest's fair share of the free space among `live_guests` guests.
    /// A zero divisor counts one; a zero share reads one, so the limit that
    /// uses it never refuses a launch for arithmetic.
    #[must_use]
    pub fn fair_share(self, live_guests: u32) -> u32 {
        (self.free() / live_guests.max(1)).max(1)
    }
}

/// The physical pids limit for one guest: the larger of the manifest count
/// and what its memory can hold, bounded by the host's fair share. Never 0.
#[must_use]
pub fn physical_pids_limit(
    manifest_pids: u32,
    memory_mib: u32,
    host: Option<HostPidSpace>,
    live_guests: u32,
) -> u32 {
    let memory_capacity = u64::from(memory_mib)
        .saturating_mul(1024 * 1024)
        .checked_div(TASK_KERNEL_MEMORY_FLOOR_BYTES)
        .unwrap_or(0)
        .min(u64::from(u32::MAX)) as u32;
    let base = manifest_pids.max(memory_capacity).max(1);
    match host {
        None => base,
        Some(space) => base.min(space.fair_share(live_guests)).max(1),
    }
}

/// Guests running in this process now, for the fair share's divisor.
/// Process-local: two server processes on one host each see a fraction.
pub fn live_guests() -> u32 {
    LIVE_GUESTS.load(Ordering::Relaxed)
}

static LIVE_GUESTS: AtomicU32 = AtomicU32::new(0);

/// Notes one more running guest. Only the launch paths call it.
pub(crate) fn note_spawned() {
    LIVE_GUESTS.fetch_add(1, Ordering::Relaxed);
}

/// Notes one guest's end. Only `GuestSession::drop` calls it.
pub(crate) fn note_dropped() {
    LIVE_GUESTS.fetch_sub(1, Ordering::Relaxed);
}

/// Pressure one session's guest showed before its container went away.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestPressure {
    /// The cgroup refused `hits` fork/clone calls (`pids.events`: `max N`).
    Processes { hits: u64 },
}

/// The `max N` count in a `pids.events` text: `None` unless N > 0 parses.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_pids_events(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let count = line.strip_prefix("max")?.trim().parse().ok()?;
        (count > 0).then_some(count)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        HostPidSpace, TASK_KERNEL_MEMORY_FLOOR_BYTES, parse_pids_events, physical_pids_limit,
    };

    const HOST_ROOMY: HostPidSpace = HostPidSpace {
        ceiling: 4_194_304,
        live_tasks: 1024,
    };

    #[test]
    fn memory_bound_wins_over_a_small_manifest_count() {
        // 512 MiB holds 512*32 = 16384 tasks at the 32 KiB floor.
        let limit = physical_pids_limit(64, 512, Some(HOST_ROOMY), 1);
        assert_eq!(limit, 16_384);
    }

    #[test]
    fn manifest_wins_over_a_small_memory() {
        // 64 MiB holds 2048 tasks; the manifest asks 4096.
        let limit = physical_pids_limit(4096, 64, Some(HOST_ROOMY), 1);
        assert_eq!(limit, 4096);
    }

    #[test]
    fn host_share_bounds_both() {
        // Free space is 2048; two live guests share 1024 each, under
        // both a 4096 manifest and a 512 MiB memory bound.
        let host = HostPidSpace {
            ceiling: 4096,
            live_tasks: 2048,
        };
        let limit = physical_pids_limit(4096, 512, Some(host), 2);
        assert_eq!(limit, 1024);
    }

    #[test]
    fn no_host_reading_keeps_the_larger_of_the_two() {
        // macOS / unreadable /proc: no bound from the host.
        assert_eq!(physical_pids_limit(64, 512, None, 1), 16_384);
        assert_eq!(physical_pids_limit(1_000_000, 8, None, 4), 1_000_000);
    }

    #[test]
    fn never_zero() {
        // Exhausted host, zero manifest, zero memory: still >= 1.
        let exhausted = HostPidSpace {
            ceiling: 1024,
            live_tasks: 4096,
        };
        assert_eq!(physical_pids_limit(0, 0, Some(exhausted), 8), 1);
        assert_eq!(physical_pids_limit(0, 0, None, 0), 1);
        // A zero live-guest divisor counts one, not a panic.
        assert_eq!(physical_pids_limit(64, 512, Some(HOST_ROOMY), 0), 16_384);
    }

    #[test]
    fn floor_is_thirty_two_kib() {
        assert_eq!(TASK_KERNEL_MEMORY_FLOOR_BYTES, 32 * 1024);
        // ... so one MiB of guest memory holds exactly 32 tasks.
        assert_eq!(physical_pids_limit(0, 1, None, 1), 32);
    }

    #[test]
    fn huge_memory_saturates_at_u32_max() {
        assert_eq!(physical_pids_limit(0, u32::MAX, None, 1), u32::MAX);
    }

    #[test]
    fn pids_events_counts_only_a_positive_max() {
        assert_eq!(parse_pids_events("max 7\n"), Some(7));
        assert_eq!(parse_pids_events("max 0\n"), None);
        assert_eq!(parse_pids_events(""), None);
        assert_eq!(parse_pids_events("max lots\n"), None);
    }
}
