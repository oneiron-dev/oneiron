use super::*;

impl PolicyManifestResolution {
    /// The ONE-1453 burst-breaker thresholds this resolution applies.
    ///
    /// Engine defaults cover an absent dial, an all-malformed set of
    /// overrides, and two-or-more distinct valid overrides. A malformed dial
    /// never disables accounting and never yields a zero threshold.
    #[must_use]
    pub(in crate::gate) fn actor_burst_breaker_thresholds(&self) -> GateBreakerThresholds {
        self.actor_burst_breaker.unwrap_or_default()
    }

    pub(super) fn hash_actor_burst_breaker(&self, hasher: &mut Sha256) {
        // ONE-1453: the resolved optional burst-breaker dial. Absence, one
        // resolved override, and a DIFFERENT resolved override are frontier-
        // distinct, so editing the dial stales every consent bundle reviewed under
        // the old one (ONE-1452 binds each member's `read_frontier_hash` into the
        // bundle id). Pre-release no-legacy law covers the domain change: no
        // migration or compatibility branch.
        match self.actor_burst_breaker {
            Some(thresholds) => {
                hash_bool(hasher, true);
                hasher.update(thresholds.max_events.to_be_bytes());
                hasher.update(thresholds.window_secs.to_be_bytes());
            }
            None => hash_bool(hasher, false),
        }
    }
}
