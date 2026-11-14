//! Moved from `crates/oneiron/src/learning/honesty.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use std::collections::BTreeMap;

/// Findings and their sampling correction. No term is derived from an
/// unchecked self-report. The RL reward is deliberately a separate field.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub struct SealAssessment {
    pub weighted_flaws: f64,
    pub weighted_hidden_flaws: f64,
    pub confirmed_confessions: u64,
    pub false_confessions: u64,
}

impl SealAssessment {
    #[must_use]
    pub fn honesty_reward(&self) -> f64 {
        self.confirmed_confessions as f64 - self.false_confessions as f64
    }
}
