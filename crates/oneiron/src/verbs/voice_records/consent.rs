//! Voice consent values and pure basis validation.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

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
    /// Validates the shape-specific requirements of this basis.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ConversationalNotice { notice } => {
                require_non_empty(notice, "voice consent notice")
            }
            Self::VerbalOnRecording {
                recording_ref,
                start_ms,
                end_ms,
                words,
            } => {
                require_non_empty(recording_ref, "voice consent recording ref")?;
                require_non_empty(words, "voice consent words")?;
                if start_ms >= end_ms {
                    return Err(invalid_voice(
                        "verbal-on-recording consent needs start_ms < end_ms",
                    ));
                }
                Ok(())
            }
            Self::SettingsToggle { surface_ref } => {
                require_non_empty(surface_ref, "voice consent surface ref")
            }
        }
    }

    /// Returns the recording this basis names, when it names one.
    #[must_use]
    pub fn recording_ref(&self) -> Option<&str> {
        match self {
            Self::VerbalOnRecording { recording_ref, .. } => Some(recording_ref.as_str()),
            Self::ConversationalNotice { .. } | Self::SettingsToggle { .. } => None,
        }
    }
}

pub(crate) fn invalid_voice(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

pub(crate) fn require_non_empty(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid_voice(&format!("{what} must be non-empty")));
    }
    Ok(())
}
