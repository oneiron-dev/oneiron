//! Core VAD value types: ranges, validation, and annotation records shared by every affect child.

use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Vad {
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}
/// VAD coordinate rejected during validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VadComponent {
    Valence,
    Arousal,
    Dominance,
}
impl Vad {
    pub const NEUTRAL: Self = Self {
        valence: 0.0,
        arousal: 0.0,
        dominance: 0.0,
    };

    pub fn is_finite(&self) -> bool {
        self.non_finite_component().is_none()
    }

    pub fn is_in_range(&self) -> bool {
        self.out_of_range_component().is_none()
    }

    pub fn validate(&self) -> crate::error::Result<()> {
        if let Some((component, value)) = self.invalid_component() {
            return Err(crate::error::Error::InvalidVad { component, value });
        }
        Ok(())
    }

    pub(crate) fn invalid_component(&self) -> Option<(VadComponent, f32)> {
        self.non_finite_component()
            .or_else(|| self.out_of_range_component())
    }

    fn non_finite_component(&self) -> Option<(VadComponent, f32)> {
        if !self.valence.is_finite() {
            return Some((VadComponent::Valence, self.valence));
        }
        if !self.arousal.is_finite() {
            return Some((VadComponent::Arousal, self.arousal));
        }
        if !self.dominance.is_finite() {
            return Some((VadComponent::Dominance, self.dominance));
        }
        None
    }

    fn out_of_range_component(&self) -> Option<(VadComponent, f32)> {
        if !(-1.0..=1.0).contains(&self.valence) {
            return Some((VadComponent::Valence, self.valence));
        }
        if !(0.0..=1.0).contains(&self.arousal) {
            return Some((VadComponent::Arousal, self.arousal));
        }
        if !(0.0..=1.0).contains(&self.dominance) {
            return Some((VadComponent::Dominance, self.dominance));
        }
        None
    }
}
/// Source that produced a turn/message VAD annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VadAnnotationSource {
    ModelInference,
    UserSelfReport,
}
impl VadAnnotationSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelInference => "model_inference",
            Self::UserSelfReport => "user_self_report",
        }
    }
}
/// Persisted VAD metadata attached to a TURN or MESSAGE entity.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VadAnnotation {
    pub vad: Vad,
    pub source: VadAnnotationSource,
    pub annotated_at: u64,
}
impl VadAnnotation {
    pub fn new(
        vad: Vad,
        source: VadAnnotationSource,
        annotated_at: u64,
    ) -> crate::error::Result<Self> {
        vad.validate()?;
        Ok(Self {
            vad,
            source,
            annotated_at,
        })
    }
}
