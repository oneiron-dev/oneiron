//! A blocking host can join the pass its full window is already waiting on.

use std::time::Duration;

use super::EngineNativeExecutor;

impl EngineNativeExecutor<'_> {
    /// Waits at most `timeout` for this run's existing compaction flight.
    ///
    /// Call on a blocking worker after `WindowFullReason::InFlight`. No pass
    /// starts and no swap lands here: the next `run` takes the same result
    /// through the usual admission and landing path. A disconnected pass is
    /// ready too, so that path can record its original refusal. Returns false
    /// with no flight or when the wait expires.
    #[must_use]
    pub fn wait_for_compaction(&mut self, timeout: Duration) -> bool {
        self.compaction
            .as_mut()
            .is_some_and(|seat| seat.wait_for_flight(timeout))
    }
}
