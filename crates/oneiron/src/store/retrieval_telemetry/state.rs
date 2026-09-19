//! Query-free retrieval context, preserved verbatim for offline replay.

use super::types::RetrievalScoreBreakdown;
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
    /// One-shot Stop decision context. Scores are normalized together rather
    /// than mixing raw channel scales. Iterative callers carry their exact
    /// pre-decision state through `PipelineBuilder::retrieval_state` instead.
    pub(crate) fn one_shot(scores: &[RetrievalScoreBreakdown]) -> Self {
        let mut values: Vec<f32> = scores
            .iter()
            .map(|row| row.final_score)
            .filter(|s| s.is_finite())
            .collect();
        values.sort_by(|a, b| b.total_cmp(a));
        let top = values.first().copied().unwrap_or(0.0).max(0.0);
        let scale = top.max(f32::EPSILON);
        let second = values.get(1).copied().unwrap_or(0.0).max(0.0);
        Self {
            top_score_norm: top / scale,
            score_gap_ratio: ((top - second) / scale).clamp(0.0, 1.0),
            mean_score_norm: if values.is_empty() {
                0.0
            } else {
                (values
                    .iter()
                    .map(|v| f64::from((*v / scale).clamp(0.0, 1.0)))
                    .sum::<f64>()
                    / values.len() as f64) as f32
            },
            result_count: values.len().min(u8::MAX as usize) as u8,
            novelty_vs_prior: if values.is_empty() { 0.0 } else { 1.0 },
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
