//! Shared retrieval execution quality, independent of result counts and ranking.
//!
//! Diagnostics describe completed channels even when they find no candidates.
//! Confidence adjustments are optional presentation metadata, never score rewrites.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::store::RetrievalSignal;

/// Execution health, not the semantic truth of retrieved content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalQuality {
    Full,
    Degraded,
    #[default]
    Passthrough,
}

impl RetrievalQuality {
    /// The pinned presentation adjustment for this execution tier.
    #[must_use]
    pub const fn confidence_adjustment(self) -> ConfidenceAdjustment {
        match self {
            Self::Full => ConfidenceAdjustment::FULL,
            Self::Degraded => ConfidenceAdjustment::DEGRADED,
            Self::Passthrough => ConfidenceAdjustment::PASSTHROUGH,
        }
    }
}

/// Observed reasons for degraded execution. Absence is not proof of success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalDegradation {
    PprCacheMiss,
    EmbeddingTimeout,
    Bm25Stale,
    TemporalSignalSkipped,
}

/// Fixed-point units per whole confidence point.
pub const CONFIDENCE_ADJUSTMENT_SCALE: i16 = 10_000;

/// A pinned fixed-point adjustment that preserves `Eq` on response DTOs.
///
/// Serialization emits a floating-point number, not the internal scaled integer.
/// Decode accepts only 0, -0.15, and -0.35 in the input's native float width
/// (or integer zero). It rejects non-finite values and does not round or use an
/// epsilon to admit nearby numbers. Negative zero normalizes to [`Self::FULL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidenceAdjustment(i16);

impl ConfidenceAdjustment {
    pub const FULL: Self = Self(0);
    pub const DEGRADED: Self = Self(-1500);
    pub const PASSTHROUGH: Self = Self(-3500);

    #[must_use]
    pub const fn as_f32(self) -> f32 {
        self.0 as f32 / CONFIDENCE_ADJUSTMENT_SCALE as f32
    }

    /// Add to a copy of a confidence and then clamp to `[0, 1]`.
    ///
    /// Non-finite input returns zero rather than inventing confidence. This
    /// helper does not read or change ranking scores or stored claim confidence.
    #[must_use]
    pub fn apply_to(self, confidence: f32) -> f32 {
        if !confidence.is_finite() {
            return 0.0;
        }
        (confidence + self.as_f32()).clamp(0.0, 1.0)
    }

    fn as_f64(self) -> f64 {
        f64::from(self.0) / f64::from(CONFIDENCE_ADJUSTMENT_SCALE)
    }
}

impl Default for ConfidenceAdjustment {
    fn default() -> Self {
        Self::PASSTHROUGH
    }
}

impl Serialize for ConfidenceAdjustment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Do not widen as_f32(): that would emit -0.15000000596046448 in JSON.
        serializer.serialize_f64(self.as_f64())
    }
}

struct ConfidenceAdjustmentVisitor;

impl Visitor<'_> for ConfidenceAdjustmentVisitor {
    type Value = ConfidenceAdjustment;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a pinned confidence adjustment: 0.0, -0.15, or -0.35")
    }

    fn visit_f32<E>(self, value: f32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // MessagePack preserves f32 width. Compare before widening so the
        // canonical f32 encodings round-trip without accepting nearby f64s.
        [
            ConfidenceAdjustment::FULL,
            ConfidenceAdjustment::DEGRADED,
            ConfidenceAdjustment::PASSTHROUGH,
        ]
        .into_iter()
        .find(|adjustment| value.is_finite() && value == adjustment.as_f32())
        .ok_or_else(|| E::invalid_value(de::Unexpected::Float(f64::from(value)), &self))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        [
            ConfidenceAdjustment::FULL,
            ConfidenceAdjustment::DEGRADED,
            ConfidenceAdjustment::PASSTHROUGH,
        ]
        .into_iter()
        .find(|adjustment| value.is_finite() && value == adjustment.as_f64())
        .ok_or_else(|| E::invalid_value(de::Unexpected::Float(value), &self))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value == 0 {
            Ok(ConfidenceAdjustment::FULL)
        } else {
            Err(E::invalid_value(de::Unexpected::Signed(value), &self))
        }
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value == 0 {
            Ok(ConfidenceAdjustment::FULL)
        } else {
            Err(E::invalid_value(de::Unexpected::Unsigned(value), &self))
        }
    }
}

impl<'de> Deserialize<'de> for ConfidenceAdjustment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ConfidenceAdjustmentVisitor)
    }
}

/// Shared source for retrieval response and telemetry projections.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalQualityReport {
    pub quality: RetrievalQuality,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degradation: Vec<RetrievalDegradation>,
    #[serde(rename = "confidenceAdjustment")]
    pub confidence_adjustment: ConfidenceAdjustment,
}

/// Execution facts; a completed channel may return zero candidates.
///
/// `attempted` includes requested channels that were skipped or failed. Only
/// distinct original channels present in both lists count as completed. Blend
/// components, reranking, HyDE, and unsolicited successes do not raise quality.
/// Explicit degradation markers remain authoritative even on inconsistent input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetrievalDiagnostics {
    pub attempted: Vec<RetrievalSignal>,
    pub succeeded: Vec<RetrievalSignal>,
    pub ppr_cache: Option<PprCacheOutcome>,
    pub degradation: Vec<RetrievalDegradation>,
}

/// Public here so diagnostic reports do not expose a private PPR module type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PprCacheOutcome {
    Hit,
    Miss,
    Disabled,
}

const ORIGINAL_SIGNALS: [RetrievalSignal; 5] = [
    RetrievalSignal::Vector,
    RetrievalSignal::Text,
    RetrievalSignal::Phonetic,
    RetrievalSignal::Temporal,
    RetrievalSignal::Ppr,
];

/// Classify execution diagnostics without inspecting any result or score.
///
/// Full requires all five original channels attempted and completed, a PPR cache
/// hit, and no marker. Two or more completed original channels otherwise yield
/// degraded; zero or one yields passthrough. The zero-success case is a
/// conservative extension of the single-channel tier, not a claim of success.
/// A healthy two-to-four-channel request is degraded with no invented marker.
///
/// Markers keep first-observed order. Derived markers follow supplied markers:
/// an attempted PPR cache miss, then an attempted Temporal channel that did not
/// complete. Unattempted cache outcomes are ignored; disabled/unknown caches
/// prevent full but do not imply a miss. Missing Vector, Text, or Phonetic
/// completion cannot prove a timeout or stale index, so callers must supply
/// those causes. The pinned taxonomy has no generic channel-failure marker.
#[must_use]
pub fn classify_retrieval_quality(diagnostics: &RetrievalDiagnostics) -> RetrievalQualityReport {
    let completed = ORIGINAL_SIGNALS
        .iter()
        .filter(|signal| {
            diagnostics.attempted.contains(signal) && diagnostics.succeeded.contains(signal)
        })
        .count();
    let mut degradation = deduplicate_degradation(&diagnostics.degradation);
    if diagnostics.attempted.contains(&RetrievalSignal::Ppr)
        && diagnostics.ppr_cache == Some(PprCacheOutcome::Miss)
    {
        push_degradation(&mut degradation, RetrievalDegradation::PprCacheMiss);
    }
    if diagnostics.attempted.contains(&RetrievalSignal::Temporal)
        && !diagnostics.succeeded.contains(&RetrievalSignal::Temporal)
    {
        push_degradation(
            &mut degradation,
            RetrievalDegradation::TemporalSignalSkipped,
        );
    }

    let quality = if completed == ORIGINAL_SIGNALS.len()
        && diagnostics.ppr_cache == Some(PprCacheOutcome::Hit)
        && degradation.is_empty()
    {
        RetrievalQuality::Full
    } else if completed >= 2 {
        RetrievalQuality::Degraded
    } else {
        RetrievalQuality::Passthrough
    };
    RetrievalQualityReport {
        quality,
        degradation,
        confidence_adjustment: quality.confidence_adjustment(),
    }
}

fn deduplicate_degradation(markers: &[RetrievalDegradation]) -> Vec<RetrievalDegradation> {
    let mut unique = Vec::new();
    for &marker in markers {
        push_degradation(&mut unique, marker);
    }
    unique
}

fn push_degradation(markers: &mut Vec<RetrievalDegradation>, marker: RetrievalDegradation) {
    if !markers.contains(&marker) {
        markers.push(marker);
    }
}

#[cfg(test)]
mod tests;
