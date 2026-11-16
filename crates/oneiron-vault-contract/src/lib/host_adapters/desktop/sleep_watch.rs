//! Watches this machine's sleep and wake so the host releases its executor
//! leases before it sleeps and takes them up again when it wakes.
//!
//! logind's sleep signals on Linux, IOKit's system power notifications on
//! macOS. A manual sleep, a closed lid and display sleep always win: the
//! watch never blocks or vetoes sleep, it only releases first while the OS
//! waits a bounded time.

use std::sync::Arc;

#[cfg(target_os = "macos")]
mod iokit;
#[cfg(target_os = "linux")]
mod logind;

#[cfg(target_os = "linux")]
pub use logind::prepare_for_sleep_line;

/// What a sleep watch calls as this machine goes to sleep and as it wakes.
pub trait SleepHooks: Send + Sync + 'static {
    /// Runs before the machine sleeps, while the OS waits for it. It must
    /// return promptly: the OS waits only a bounded time.
    fn will_sleep(&self);
    /// Runs once the machine is awake again, or a sleep it announced did
    /// not happen.
    fn woke(&self);
}

/// The platform watch a sleep watch holds: logind's sleep signals on Linux.
#[cfg(target_os = "linux")]
type PlatformWatch = logind::LogindWatch;
/// The platform watch a sleep watch holds: IOKit's system power
/// notifications on macOS.
#[cfg(target_os = "macos")]
type PlatformWatch = iokit::IokitWatch;

/// Watches this machine's sleep and wake and calls the hooks; dropping it
/// stops the watch.
pub struct SleepWatch {
    /// The platform watch, stopped when it drops.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    _watch: PlatformWatch,
}

impl SleepWatch {
    /// Starts the watch on this platform's source: logind on Linux, IOKit's
    /// system power notifications on macOS. `None` where no source runs:
    /// another platform, or a source that did not start, which `unobserved`
    /// hears once with its reason.
    pub fn start(
        hooks: Arc<dyn SleepHooks>,
        unobserved: impl FnOnce(&'static str),
    ) -> Option<Self> {
        Self::start_platform(hooks, unobserved)
    }

    /// Starts the platform watch.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn start_platform(
        hooks: Arc<dyn SleepHooks>,
        unobserved: impl FnOnce(&'static str),
    ) -> Option<Self> {
        let watch = PlatformWatch::start(hooks, unobserved)?;
        Some(Self { _watch: watch })
    }

    /// Starts the platform watch.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn start_platform(
        hooks: Arc<dyn SleepHooks>,
        unobserved: impl FnOnce(&'static str),
    ) -> Option<Self> {
        let _ = hooks;
        unobserved("no sleep source on this platform");
        None
    }
}
