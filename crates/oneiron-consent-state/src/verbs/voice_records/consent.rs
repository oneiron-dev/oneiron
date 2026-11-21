//! Moved from `crates/oneiron/src/verbs/voice_records/consent.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::register::Register;
use serde::Deserialize;
use serde::Serialize;

/// Whether a consent record grants or withdraws.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Register,
)]
#[serde(rename_all = "snake_case")]
#[register("voice.consent.state")]
pub enum VoiceConsentState {
    Granted,
    Withdrawn,
}

impl VoiceConsentState {
    /// Parses a pinned on-disk state string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
    }
}

/// How a consent decision was captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum VoiceConsentBasis {
    ConversationalNotice {
        notice: String,
    },
    /// A spoken grant inside a named recording at a named time span. A first
    /// class basis, not a placeholder.
    VerbalOnRecording {
        recording_ref: String,
        start_ms: u64,
        end_ms: u64,
        words: String,
    },
    SettingsToggle {
        surface_ref: String,
    },
}

impl VoiceConsentBasis {
    /// Returns the recording this basis names, when it names one.
    #[must_use]
    pub fn recording_ref(&self) -> Option<&str> {
        match self {
            Self::VerbalOnRecording { recording_ref, .. } => Some(recording_ref.as_str()),
            Self::ConversationalNotice { .. } | Self::SettingsToggle { .. } => None,
        }
    }
}
