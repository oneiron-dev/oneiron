//! Writer closure timing and the Dreamer writer-hold trace.

use std::time::Instant;

/// Wall ms since `started`.
pub(crate) fn ms_since(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// A Dreamer write that holds the vault's writer at least this long logs a
/// `dreamer writer hold` line: the writes a recall queues behind (FIX 12254).
const WRITER_HOLD_LOG_MS: u64 = 20;

/// Times one grouped write's closure, which runs while the vault's writer is
/// held, and logs the hold when dropped if it reached [`WRITER_HOLD_LOG_MS`].
/// The site name and ms only. The shared group-commit wait after the closure
/// is the write door's, not this site's hold, so it stays out of the timing.
pub(crate) struct WriterHold {
    site: &'static str,
    started: Instant,
}

impl WriterHold {
    pub(crate) fn start(site: &'static str) -> Self {
        Self {
            site,
            started: Instant::now(),
        }
    }
}

impl Drop for WriterHold {
    fn drop(&mut self) {
        let hold_ms = ms_since(self.started);
        if hold_ms >= WRITER_HOLD_LOG_MS {
            tracing::info!(
                target: "oneiron::dreamer::stages",
                site = self.site,
                hold_ms,
                "dreamer writer hold"
            );
        }
    }
}
