//! Relative signals for one peer; policy compares ratios, never write counts.

use crate::llm::NormalizedBurstInputs;

#[derive(Clone, Copy)]
pub(super) struct PeerHealth {
    pub(super) inputs: NormalizedBurstInputs,
    pub(super) streak_ratio: f32,
}

impl PeerHealth {
    pub(super) fn unusual_rate(self) -> bool {
        self.inputs.rate_ratio > 1.0
    }

    pub(super) fn isolate(self) -> bool {
        self.unusual_rate() && self.streak_ratio > 1.0
    }
}
