//! Voice consent values and pure basis validation.

use crate::error::{Error, Result};

#[doc(hidden)]
pub use oneiron_consent_state::verbs::voice_records::consent::{
    VoiceConsentBasis, VoiceConsentState,
};

/// Validates the shape-specific requirements of this basis.
pub fn voice_consent_basis_validate(voice_consent_basis: &VoiceConsentBasis) -> Result<()> {
    match voice_consent_basis {
        VoiceConsentBasis::ConversationalNotice { notice } => {
            require_non_empty(notice, "voice consent notice")
        }
        VoiceConsentBasis::VerbalOnRecording {
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
        VoiceConsentBasis::SettingsToggle { surface_ref } => {
            require_non_empty(surface_ref, "voice consent surface ref")
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
