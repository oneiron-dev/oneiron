//! The fake clock: time that moves only when the test moves it.
//!
//! A vault reads time through the clock in its `VaultConfig::store_clock`
//! (the public `oneiron::store::ports::Clock` seam). [`FakeClock`] is a
//! [`ManualClock`] with arithmetic on top: a test opens its vault with
//! [`FakeClock::store_clock`] (or [`FakeClock::vault_config`]) and passes
//! [`FakeClock::now`] wherever a public call takes an explicit `now`. No test
//! reads the wall clock, so no test depends on when it runs.

use std::sync::{Arc, Mutex, PoisonError};

use oneiron::VaultConfig;
use oneiron::store::ports::{ManualClock, StoreClock};

/// The second every fake clock starts at unless the test names another:
/// 2027-01-15T08:00:00Z. Fixed, so ids and stamps repeat from run to run.
pub const FAKE_EPOCH: u64 = 1_800_000_000;

/// A shared, explicitly advanced clock. Clones share one time.
///
/// Each store opened with [`Self::store_clock`] keeps its own monotonic floor
/// (the store's rule), so setting the clock backwards never moves a vault's
/// recorded time backwards; it only stops it advancing until the clock passes
/// the floor again.
#[derive(Clone)]
pub struct FakeClock {
    source: Arc<ManualClock>,
    now: Arc<Mutex<u64>>,
}

impl std::fmt::Debug for FakeClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeClock")
            .field("now", &self.now())
            .finish()
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::at(FAKE_EPOCH)
    }
}

impl FakeClock {
    /// A clock that reads `secs` (Unix seconds) until the test moves it.
    #[must_use]
    pub fn at(secs: u64) -> Self {
        Self {
            source: ManualClock::new(secs),
            now: Arc::new(Mutex::new(secs)),
        }
    }

    /// The current fake time, in Unix seconds.
    #[must_use]
    pub fn now(&self) -> u64 {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The current fake time, in Unix milliseconds.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now().saturating_mul(1000)
    }

    /// Moves the clock forward by `secs` and returns the new time.
    pub fn advance(&self, secs: u64) -> u64 {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        *now = now.saturating_add(secs);
        self.source.set(*now);
        *now
    }

    /// Sets the clock to `secs`, forwards or backwards.
    pub fn set(&self, secs: u64) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        *now = secs;
        self.source.set(secs);
    }

    /// The clock and id source to put in `VaultConfig::store_clock`. Ids come
    /// from a counter, so they repeat from run to run as the time does.
    #[must_use]
    pub fn store_clock(&self) -> StoreClock {
        self.source.bundle()
    }

    /// `VaultConfig::device()` reading this clock.
    #[must_use]
    pub fn vault_config(&self) -> VaultConfig {
        let mut config = VaultConfig::device();
        config.store_clock = self.store_clock();
        config
    }
}
