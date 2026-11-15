//! Moved from `crates/oneiron/src/conversation/voice_roster.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How well spread a stored centroid's enrollment material is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoicePrintCalibration {
    /// Fewer than two distinct language tags: usable, never called calibrated.
    Collecting,
    /// Mixed-language enrollment material.
    Calibrated,
}

impl VoicePrintCalibration {
    /// Returns the pinned on-disk string for this calibration state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Calibrated => "calibrated",
        }
    }

    /// Parses a pinned on-disk calibration string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "collecting" => Some(Self::Collecting),
            "calibrated" => Some(Self::Calibrated),
            _ => None,
        }
    }
}
