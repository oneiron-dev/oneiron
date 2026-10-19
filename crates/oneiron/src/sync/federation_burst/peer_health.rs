//! Relative signals for one peer; policy compares ratios, never write counts.

use super::{FederationBurstBaselineState, FederationBurstOutcome, FederationBurstPolicy};
use crate::llm::NormalizedBurstInputs;

pub(super) struct PeerHealth {
    pub(super) inputs: NormalizedBurstInputs,
    pub(super) streak_ratio: f32,
    pub(super) baseline: FederationBurstBaselineState,
    pub(super) policy: FederationBurstPolicy,
}

impl PeerHealth {
    pub(super) fn outcome(&self) -> FederationBurstOutcome {
        if self.inputs.rate_ratio <= 1.0 {
            FederationBurstOutcome::Allow
        } else if self.streak_ratio > 1.0 {
            self.policy.unusual_streak
        } else {
            self.policy.unusual_rate
        }
    }
}
