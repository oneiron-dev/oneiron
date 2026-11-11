//! Moved from `crates/oneiron/src/verbs/voice_records/consent.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Whether a consent record grants or withdraws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VoiceConsentState {
    Granted,
    Withdrawn,
}

impl VoiceConsentState {
    /// Returns the pinned on-disk string for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Withdrawn => "withdrawn",
        }
    }

    /// Parses a pinned on-disk state string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "granted" => Some(Self::Granted),
            "withdrawn" => Some(Self::Withdrawn),
            _ => None,
        }
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
