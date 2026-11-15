//! Moved from `crates/oneiron/src/conversation/voice_roster.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::register::Register;
use serde::Deserialize;
use serde::Serialize;

/// How well spread a stored centroid's enrollment material is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "snake_case")]
#[register("voice.print.calibration")]
pub enum VoicePrintCalibration {
    /// Fewer than two distinct language tags: usable, never called calibrated.
    Collecting,
    /// Mixed-language enrollment material.
    Calibrated,
}

impl VoicePrintCalibration {
    /// Parses a pinned on-disk calibration string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
    }
}
