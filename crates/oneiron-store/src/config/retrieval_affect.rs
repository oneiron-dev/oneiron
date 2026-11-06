//! Per-vault read-side affect retrieval policy.

use oneiron_contracts::affect::Vad;
use oneiron_contracts::error::{Error, Result};

/// Highest arousal stretch: a claim at arousal 1 ages over at most
/// `1 + 4 = 5` half-lives' worth of its class half-life.
pub const AFFECT_AROUSAL_STRETCH_MAX: f32 = 4.0;
/// Highest emotion-congruence weight, the same validated span as PPR's VAD α.
pub const AFFECT_EMOTION_WEIGHT_MAX: f32 = 0.4;
/// Default stored arousal at which a claim joins the sensitivity floor.
pub const AFFECT_FLOOR_AROUSAL_DEFAULT: f32 = 0.7;
/// Per-vault affect retrieval policy. Every dial defaults off: like PPR's
/// VAD α, enabling one is a deliberate per-vault decision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AffectRetrievalPolicy {
    /// Arousal stretch of read-side aging: a live claim's class half-life is
    /// multiplied by `1 + arousal_stretch × arousal`. `0` is off. Validated
    /// in `0..=AFFECT_AROUSAL_STRETCH_MAX`.
    pub arousal_stretch: f32,
    /// Minimum read-side factor for a live claim that is critical or
    /// aroused (see [`Self::floor_arousal`]). `None` is off. In `0..=1`.
    pub availability_floor: Option<f32>,
    /// Stored arousal at which a claim joins the sensitivity floor beside
    /// predicate criticality. In `0..=1`.
    pub floor_arousal: f32,
    /// Emotion-congruence weight: a claim with stored VAD is multiplied by
    /// `1 + emotion_weight × (2 × similarity − 1)`. `0` is off. Validated in
    /// `0..=AFFECT_EMOTION_WEIGHT_MAX`.
    pub emotion_weight: f32,
}

impl Default for AffectRetrievalPolicy {
    fn default() -> Self {
        Self {
            arousal_stretch: 0.0,
            availability_floor: None,
            floor_arousal: AFFECT_FLOOR_AROUSAL_DEFAULT,
            emotion_weight: 0.0,
        }
    }
}

impl AffectRetrievalPolicy {
    /// Rejects non-finite or out-of-range dials without clamping.
    pub fn validate(&self) -> Result<()> {
        let within = |value: f32, max: f32| value.is_finite() && (0.0..=max).contains(&value);
        if !within(self.arousal_stretch, AFFECT_AROUSAL_STRETCH_MAX) {
            return Err(Error::InvalidConfig(format!(
                "affect arousal_stretch must be finite and within 0..={AFFECT_AROUSAL_STRETCH_MAX}, got {}",
                self.arousal_stretch
            )));
        }
        if self
            .availability_floor
            .is_some_and(|floor| !within(floor, 1.0))
        {
            return Err(Error::InvalidConfig(format!(
                "affect availability_floor must be finite and within 0..=1, got {:?}",
                self.availability_floor
            )));
        }
        if !within(self.floor_arousal, 1.0) {
            return Err(Error::InvalidConfig(format!(
                "affect floor_arousal must be finite and within 0..=1, got {}",
                self.floor_arousal
            )));
        }
        if !within(self.emotion_weight, AFFECT_EMOTION_WEIGHT_MAX) {
            return Err(Error::InvalidConfig(format!(
                "affect emotion_weight must be finite and within 0..={AFFECT_EMOTION_WEIGHT_MAX}, got {}",
                self.emotion_weight
            )));
        }
        Ok(())
    }

    /// Whether the read-side factor stage reads claim affect at all.
    pub fn shapes_access_factor(&self) -> bool {
        self.arousal_stretch > 0.0 || self.availability_floor.is_some()
    }

    /// Whether the emotion-congruence stage runs for `query`.
    pub fn congruence_query(&self, query: Option<Vad>) -> Option<Vad> {
        query.filter(|_| self.emotion_weight > 0.0)
    }
}
