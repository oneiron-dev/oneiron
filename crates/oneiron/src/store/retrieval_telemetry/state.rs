//! Query-free retrieval context, preserved verbatim for offline replay.

use super::types::{RetrievalScoreBreakdown, RetrievalSignal};
use serde::{Deserialize, Serialize};

/// The sixteen ARCH-0037 inputs. Missing named-msgpack fields have zero
/// defaults; outcome-dependent features never enter this hot-path bus.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RetrievalState {
    pub top_score_norm: f32,
    pub score_gap_ratio: f32,
    pub mean_score_norm: f32,
    pub entity_coverage: f32,
    pub novelty_vs_prior: f32,
    pub signal_agreement: u8,
    pub result_count: u8,
    pub iteration: u8,
    pub budget_remaining: u8,
    pub frontier_size: u32,
    pub avg_edge_weight: f32,
    pub graph_degree: u16,
    pub temporal_spread: f32,
    pub hops: u8,
    pub last_action: u8,
    pub intent_class: u8,
}
impl RetrievalState {
    /// One-shot Stop decision context. Final scores use one bounded link;
    /// raw channel components are never added together. Iterative callers carry their exact
    /// pre-decision state through `PipelineBuilder::retrieval_state` instead.
    pub(crate) fn one_shot(scores: &[RetrievalScoreBreakdown]) -> Self {
        let mut values: Vec<f32> = scores
            .iter()
            .map(|row| row.final_score)
            .filter(|s| s.is_finite())
            .map(|s| s.max(0.0))
            .collect();
        values.sort_by(|a, b| b.total_cmp(a));
        let top = values.first().copied().unwrap_or(0.0);
        let second = values.get(1).copied().unwrap_or(0.0);
        // The log-blend's neutral score is 1. This bounded link retains its
        // strength (neutral -> 0.5), unlike division by top, which always gave
        // 1. Raw single-channel observations remain conditioned on their signal;
        // bounding them does not make different raw channel units comparable.
        let squash = |x: f32| x / (1.0 + x);
        let top_row = scores.iter().min_by(|a, b| {
            a.final_rank
                .cmp(&b.final_rank)
                .then_with(|| b.final_score.total_cmp(&a.final_score))
                .then_with(|| a.result_id.cmp(&b.result_id))
        });
        let mut signals = Vec::new();
        if let Some(row) = top_row {
            for component in &row.components {
                // HyDE retries can repeat Text. Rerank is a host override,
                // not a corroborating retrieval/blend signal.
                if component.signal != RetrievalSignal::Rerank
                    && !signals.contains(&component.signal)
                {
                    signals.push(component.signal);
                }
            }
        }
        Self {
            top_score_norm: squash(top),
            score_gap_ratio: ((top - second) / top.max(f32::EPSILON)).clamp(0.0, 1.0),
            mean_score_norm: if values.is_empty() {
                0.0
            } else {
                (values.iter().map(|v| f64::from(squash(*v))).sum::<f64>() / values.len() as f64)
                    as f32
            },
            result_count: scores.len().min(u8::MAX as usize) as u8,
            novelty_vs_prior: if scores.is_empty() { 0.0 } else { 1.0 },
            signal_agreement: signals.len().min(u8::MAX as usize) as u8,
            ..Default::default()
        }
    }
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if [
            self.top_score_norm,
            self.score_gap_ratio,
            self.mean_score_norm,
            self.entity_coverage,
            self.novelty_vs_prior,
            self.avg_edge_weight,
            self.temporal_spread,
        ]
        .iter()
        .any(|v| !v.is_finite())
        {
            return Err(crate::Error::InvalidConfig(
                "non-finite retrieval state".into(),
            ));
        }
        Ok(())
    }
}

/// A caller's turn identity. Each run remains independent; grouping is a read
/// projection, never a collapsing write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalTurn {
    pub turn_id: [u8; 16],
    pub episode_id: [u8; 16],
    pub turn_idx: u64,
}
