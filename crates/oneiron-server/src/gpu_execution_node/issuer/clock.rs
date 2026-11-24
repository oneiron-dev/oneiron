//! The issuer's clocks (pass 33 section 8.4): the wall clock its job rows use, and the boot
//! clock its billing bracket reads. The bracket is the time between two marks of one boot on
//! `CLOCK_BOOTTIME`, which counts a suspend and which no wall-clock step moves.
use oneiron::job_dispatch::BootMark;

/// Where Linux names this boot.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// The issuer's clocks. A test scripts them.
pub trait IssuerClock: Send + Sync {
    /// The wall clock, in Unix milliseconds: the time a job row and a dispatch window use.
    fn now_ms(&self) -> u64;

    /// This moment on the boot clock, with the boot's id and the wall clock.
    fn boot_mark(&self) -> BootMark;
}

/// The host's own clocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemIssuerClock;

impl IssuerClock for SystemIssuerClock {
    fn now_ms(&self) -> u64 {
        crate::gpu_host::now_ms()
    }

    fn boot_mark(&self) -> BootMark {
        BootMark {
            boot_id: boot_id(),
            boot_ns: boot_clock_ns().unwrap_or(0),
            wall_ms: self.now_ms(),
        }
    }
}

/// This boot's id, empty where the system names none.
#[must_use]
pub fn boot_id() -> String {
    std::fs::read_to_string(BOOT_ID_PATH)
        .map(|id| id.trim().to_owned())
        .unwrap_or_default()
}

/// Nanoseconds since boot, the time suspended included: `CLOCK_BOOTTIME` on Linux and Android,
/// `CLOCK_MONOTONIC` on Apple systems, which counts sleep. `None` elsewhere.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn boot_clock_ns() -> Option<u64> {
    use rustix::time::{ClockId, clock_gettime};
    std::time::Duration::try_from(clock_gettime(ClockId::Boottime))
        .ok()
        .and_then(|since_boot| u64::try_from(since_boot.as_nanos()).ok())
}

#[cfg(target_vendor = "apple")]
fn boot_clock_ns() -> Option<u64> {
    use rustix::time::{ClockId, clock_gettime};
    std::time::Duration::try_from(clock_gettime(ClockId::Monotonic))
        .ok()
        .and_then(|since_boot| u64::try_from(since_boot.as_nanos()).ok())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn boot_clock_ns() -> Option<u64> {
    None
}
