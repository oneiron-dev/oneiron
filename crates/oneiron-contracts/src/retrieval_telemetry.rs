//! The retrieval signal and blend-weight vocabulary: what retrieval's fusion scores with,
//! what the retrieval trace and quality report record, and what the stored weight table
//! holds. `oneiron` re-exports these at `oneiron::store`, beside the telemetry records and
//! the weight table.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalSignal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
    Recency,
    Salience,
    Confidence,
    Gravity,
    /// RET-010 host-injected reranker component. Never a channel and never
    /// a blend signal: the blend weight table must not train on reranker
    /// output.
    Rerank,
    Hyde,
    /// HyDE retry subquery channel, retained only in retrieval traces.
    HydeRetry,
}

impl RetrievalSignal {
    #[must_use]
    pub fn as_blend_signal(self) -> Option<RetrievalBlendSignal> {
        match self {
            Self::Recency => Some(RetrievalBlendSignal::Recency),
            Self::Salience => Some(RetrievalBlendSignal::Salience),
            Self::Confidence => Some(RetrievalBlendSignal::Confidence),
            Self::Gravity => Some(RetrievalBlendSignal::Gravity),
            Self::Vector
            | Self::Text
            | Self::Phonetic
            | Self::Temporal
            | Self::Ppr
            | Self::Rerank
            | Self::Hyde
            | Self::HydeRetry => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalBlendSignal {
    Recency,
    Salience,
    Confidence,
    Gravity,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RetrievalBlendWeights {
    pub recency: f32,
    pub salience: f32,
    pub confidence: f32,
    pub gravity: f32,
}

impl RetrievalBlendWeights {
    #[must_use]
    pub const fn bootstrap() -> Self {
        Self {
            recency: 0.35,
            salience: 0.30,
            confidence: 0.20,
            gravity: 0.15,
        }
    }

    #[must_use]
    pub const fn new(recency: f32, salience: f32, confidence: f32, gravity: f32) -> Self {
        Self {
            recency,
            salience,
            confidence,
            gravity,
        }
    }

    #[must_use]
    pub fn weight(self, signal: RetrievalBlendSignal) -> f32 {
        match signal {
            RetrievalBlendSignal::Recency => self.recency,
            RetrievalBlendSignal::Salience => self.salience,
            RetrievalBlendSignal::Confidence => self.confidence,
            RetrievalBlendSignal::Gravity => self.gravity,
        }
    }

    /// The weights scaled to sum to one, after [`validate_retrieval_blend_weights`]
    /// accepts them. Public so `oneiron`'s blend tuner can call it across the crate line;
    /// it refuses exactly what the validator refuses.
    pub fn normalized(self) -> Result<Self> {
        validate_retrieval_blend_weights(self).map_err(Error::InvalidConfig)?;
        let sum = self.sum();
        Ok(Self {
            recency: self.recency / sum,
            salience: self.salience / sum,
            confidence: self.confidence / sum,
            gravity: self.gravity / sum,
        })
    }

    fn sum(self) -> f32 {
        self.recency + self.salience + self.confidence + self.gravity
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalScoreComponent {
    pub signal: RetrievalSignal,
    pub rank: u32,
    pub score: f32,
}

/// Refuses weights that are not finite and non-negative or that sum to zero. Public so
/// `oneiron`'s weight-table decoder and tuner (the only callers) run the same check
/// across the crate line.
pub fn validate_retrieval_blend_weights(
    weights: RetrievalBlendWeights,
) -> std::result::Result<(), String> {
    let values = [
        ("recency", weights.recency),
        ("salience", weights.salience),
        ("confidence", weights.confidence),
        ("gravity", weights.gravity),
    ];
    for (name, value) in values {
        if !value.is_finite() || value < 0.0 {
            return Err(format!(
                "retrieval blend {name} weight must be finite and non-negative"
            ));
        }
    }
    if weights.sum() <= 0.0 {
        return Err("retrieval blend weights must have positive total mass".to_owned());
    }
    Ok(())
}
