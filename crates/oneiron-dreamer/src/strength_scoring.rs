//! Shared consolidation strength scoring (F6 subset).
//!
//! [`SelectionConfig`] is the scoring subset of the engine's
//! `oneiron::dreamer_consolidation::selection::SelectionConfig`: the weights,
//! type priors and scales the strength score reads, without timing,
//! threshold or scheduling fields. [`StrengthSignals`] and [`StrengthWeights`]
//! are the four signals and their weights. The strength archive and the later
//! extraction selection share these types so both compute the engine's score
//! operation for operation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Holds the four strength signals a score carries.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub(crate) struct StrengthSignals {
    pub(crate) type_prior: f64,
    pub(crate) frequency: f64,
    pub(crate) recency: f64,
    pub(crate) diversity: f64,
}

impl StrengthSignals {
    /// The engine's signals for raw evidence counts, computed as the engine
    /// computes them (`StrengthSignals::from_evidence` in
    /// `oneiron::dreamer_consolidation::selection`), operation for operation.
    pub(crate) fn from_evidence(
        predicate: &str,
        count: u64,
        latest_ms: u64,
        diversity: u64,
        now_ms: u64,
        config: &SelectionConfig,
    ) -> Self {
        Self {
            type_prior: config
                .type_priors
                .get(predicate)
                .copied()
                .unwrap_or(config.default_type_prior),
            frequency: (count as f64 / config.frequency_scale as f64).min(1.0),
            recency: 1.0
                - (now_ms.saturating_sub(latest_ms) as f64 / config.recency_window_ms as f64)
                    .min(1.0),
            diversity: (diversity as f64 / config.diversity_scale as f64).min(1.0),
        }
    }

    /// The weighted sum the engine's `strength_score` computes, in its order.
    pub(crate) fn score(self, weights: &StrengthWeights) -> f64 {
        self.type_prior * weights.type_prior
            + self.frequency * weights.frequency
            + self.recency * weights.recency
            + self.diversity * weights.diversity
    }
}

/// Holds the scoring subset of the live selection config: the fields the strength
/// score reads.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub(crate) struct SelectionConfig {
    pub(crate) weights: StrengthWeights,
    pub(crate) type_priors: BTreeMap<String, f64>,
    pub(crate) default_type_prior: f64,
    pub(crate) frequency_scale: u64,
    pub(crate) diversity_scale: u64,
    pub(crate) recency_window_ms: u64,
}

/// Holds the four strength weights.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub(crate) struct StrengthWeights {
    pub(crate) type_prior: f64,
    pub(crate) frequency: f64,
    pub(crate) recency: f64,
    pub(crate) diversity: f64,
}
