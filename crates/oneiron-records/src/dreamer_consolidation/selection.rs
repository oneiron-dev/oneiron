//! Moved from `crates/oneiron/src/dreamer_consolidation/selection.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrengthWeights {
    pub type_prior: f64,
    pub frequency: f64,
    pub recency: f64,
    pub diversity: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionConfig {
    pub version: u8,
    pub soak_ms: u64,
    pub evidence_minimum: usize,
    pub cosine_threshold: f64,
    pub weights: StrengthWeights,
    pub type_priors: BTreeMap<String, f64>,
    pub default_type_prior: f64,
    pub frequency_scale: u64,
    pub diversity_scale: u64,
    pub recency_window_ms: u64,
    /// Maximum extraction calls in flight; a partition with a tool-output,
    /// imported or unknown-lineage member still runs serially.
    pub extraction_parallelism: usize,
    /// Maximum TURNs in one neighbourhood child.
    pub extraction_turns_per_child: usize,
    /// Maximum Micro or Meso partitions extracting side by side in one
    /// wake pass ([`windowed_partition`]); their resolves and commits stay
    /// serial in admission order.
    #[serde(default = "default_partition_extraction_parallelism")]
    pub partition_extraction_parallelism: usize,
}

/// The shipped partition width, for a stored selection row written before
/// the field existed.
pub fn default_partition_extraction_parallelism() -> usize {
    8
}

impl Default for SelectionConfig {
    fn default() -> Self {
        serde_json::from_str(include_str!("selection_defaults.json"))
            .expect("checked selection defaults")
    }
}

impl SelectionConfig {
    pub fn validate(&self) -> Result<()> {
        let w = self.weights;
        if self.version != 1
            || self.frequency_scale == 0
            || self.diversity_scale == 0
            || self.recency_window_ms == 0
            || self.extraction_parallelism == 0
            || self.extraction_turns_per_child == 0
            || self.partition_extraction_parallelism == 0
            || !unit(self.cosine_threshold)
            || !unit(self.default_type_prior)
            || self.type_priors.values().any(|n| !unit(*n))
            || [w.type_prior, w.frequency, w.recency, w.diversity]
                .iter()
                .any(|n| !unit(*n))
            || w.type_prior <= w.frequency + w.recency + w.diversity
        {
            return Err(Error::InvalidConfig(
                "invalid consolidation selection policy".into(),
            ));
        }
        Ok(())
    }
}

pub fn unit(n: f64) -> bool {
    n.is_finite() && (0.0..=1.0).contains(&n)
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrengthSignals {
    pub type_prior: f64,
    pub frequency: f64,
    pub recency: f64,
    pub diversity: f64,
}

impl StrengthSignals {
    /// Shared by live candidate ordering and the nightly archive recipe.
    pub fn from_evidence(
        predicate: &str,
        count: usize,
        latest_ms: u64,
        diversity: usize,
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

    /// Only the four contract signals are accepted. Surprise/perplexity have no
    /// score input, even when a producer supplies them alongside its signals.
    pub fn from_named(values: &BTreeMap<String, f64>) -> Self {
        let get = |key| values.get(key).copied().unwrap_or_default();
        Self {
            type_prior: get("type_prior"),
            frequency: get("frequency"),
            recency: get("recency"),
            diversity: get("diversity"),
        }
    }
}
