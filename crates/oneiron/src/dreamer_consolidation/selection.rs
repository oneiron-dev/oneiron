//! Mechanical candidate selection. Numeric policy is a reloadable row, not a judge instruction.
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Operator-set candidate-selection policy row. Key: ().
const SELECTION: SideTable<(), SelectionConfig, LegacyJson> =
    SideTable::new(&side_table::DREAMER_CONSOLIDATION_SELECTION);

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
fn unit(n: f64) -> bool {
    n.is_finite() && (0.0..=1.0).contains(&n)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StrengthSignals {
    pub type_prior: f64,
    pub frequency: f64,
    pub recency: f64,
    pub diversity: f64,
}
impl StrengthSignals {
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

pub fn strength_score(signals: StrengthSignals, config: &SelectionConfig) -> Result<f64> {
    config.validate()?;
    let s = signals;
    if [s.type_prior, s.frequency, s.recency, s.diversity]
        .iter()
        .any(|n| !unit(*n))
    {
        return Err(Error::InvalidConfig(
            "strength signals must be finite unit values".into(),
        ));
    }
    let w = config.weights;
    Ok(s.type_prior * w.type_prior
        + s.frequency * w.frequency
        + s.recency * w.recency
        + s.diversity * w.diversity)
}

#[derive(Debug, Clone, PartialEq)]
pub struct SelectionCandidate {
    pub claim_id: EntityId,
    pub first_seen_ms: u64,
    pub evidence_count: usize,
    pub fan_in: u64,
    pub new_refs: u64,
    pub signals: StrengthSignals,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionHold {
    Soak,
    EvidenceCount,
}
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionPlan {
    /// Strength first, cheap fan-in ranking second, stable identity last.
    pub ready: Vec<EntityId>,
    pub held: Vec<(EntityId, SelectionHold)>,
}

pub fn select_candidates(
    candidates: &[SelectionCandidate],
    now_ms: u64,
    config: &SelectionConfig,
) -> Result<SelectionPlan> {
    config.validate()?;
    let mut ready = Vec::new();
    let mut held = Vec::new();
    for c in candidates {
        let score = strength_score(c.signals, config)?;
        if now_ms < c.first_seen_ms || now_ms - c.first_seen_ms < config.soak_ms {
            held.push((c.claim_id, SelectionHold::Soak));
        } else if c.evidence_count < config.evidence_minimum {
            held.push((c.claim_id, SelectionHold::EvidenceCount));
        } else {
            let rank = u128::from(c.fan_in) * (1 + u128::from(c.new_refs));
            ready.push((c.claim_id, score, rank));
        }
    }
    ready.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.0.cmp(&b.0))
    });
    held.sort_by_key(|h| h.0);
    Ok(SelectionPlan {
        ready: ready.into_iter().map(|r| r.0).collect(),
        held,
    })
}

impl Vault {
    /// Operator configuration seam, like the prefilter row. It is not an agent verb.
    pub fn set_consolidation_selection(&self, config: &SelectionConfig) -> Result<()> {
        config.validate()?;
        self.with_write_txn(|txn| {
            SELECTION.put(&self.store, txn, &(), config)?;
            Ok(())
        })
    }
    pub fn consolidation_selection(&self) -> Result<SelectionConfig> {
        let txn = self.store.env.read_txn()?;
        let config = SELECTION.get(&self.store, &txn, &())?.unwrap_or_default();
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests;
