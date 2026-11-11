//! Moved from `crates/oneiron/src/dreamer_runner/progress.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use loro::awareness::EphemeralStore;
use oneiron_base::error::Result;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::dreamer_attempt_payload::invalid_dreamer_runner;
use std::collections::HashMap;

/// Default per-attempt live progress throttle: at most one update per second.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_THROTTLE_MS: u64 = 1_000;

/// Default in-process terminal-stop retention, matching the sync lane TTL.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_TERMINAL_RETENTION_MS: u64 = 30_000;

/// In-process producer for Dreamer live progress on the Loro ephemeral lane.
///
/// The producer keeps only bounded throttle/terminal-stop bookkeeping. The
/// sync-visible state remains exactly one mutable `job:{job_id}` row in the
/// provided [`EphemeralStore`].
#[cfg(feature = "sync")]
#[derive(Debug, Clone)]
pub struct DreamerAttemptProgressProducer {
    pub throttle_ms: u64,
    terminal_retention_ms: u64,
    pub last_emitted_at_ms: HashMap<AttemptId, u64>,
    pub terminal_at_ms: HashMap<AttemptId, u64>,
}

#[cfg(feature = "sync")]
impl Default for DreamerAttemptProgressProducer {
    fn default() -> Self {
        Self::with_limits(
            DREAMER_ATTEMPT_PROGRESS_THROTTLE_MS,
            DREAMER_ATTEMPT_PROGRESS_TERMINAL_RETENTION_MS,
        )
        .expect("default dreamer progress limits are valid")
    }
}

#[cfg(feature = "sync")]
impl DreamerAttemptProgressProducer {
    /// Creates a producer with the contract-pinned 1Hz throttle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a producer with explicit limits. `terminal_retention_ms` should
    /// match the [`EphemeralStore`] timeout so stopped attempts cannot resume
    /// ticking before their last live row ages out.
    pub fn with_limits(throttle_ms: u64, terminal_retention_ms: u64) -> Result<Self> {
        if throttle_ms == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer progress throttle_ms must be > 0",
            ));
        }
        if terminal_retention_ms == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer progress terminal_retention_ms must be > 0",
            ));
        }
        Ok(Self {
            throttle_ms,
            terminal_retention_ms,
            last_emitted_at_ms: HashMap::new(),
            terminal_at_ms: HashMap::new(),
        })
    }

    /// Marks an attempt terminal without producing a live progress frame.
    pub fn mark_terminal(&mut self, attempt_id: AttemptId, now_ms: u64) {
        self.last_emitted_at_ms.remove(&attempt_id);
        self.terminal_at_ms.insert(attempt_id, now_ms);
    }

    /// Runs the Rust-side `EphemeralStore` TTL pass and prunes old terminal
    /// stop markers from this producer.
    pub fn remove_outdated(&mut self, store: &EphemeralStore, now_ms: u64) {
        store.remove_outdated();
        self.retain_terminal_stops(now_ms);
    }

    pub fn retain_terminal_stops(&mut self, now_ms: u64) {
        let retention = self.terminal_retention_ms;
        self.terminal_at_ms
            .retain(|_, terminal_at| now_ms.saturating_sub(*terminal_at) < retention);
    }
}
