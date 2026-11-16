//! `vault.voices.recognition.withdraw`'s wire (VOICE-RECOGNITION-CONSENT-NO-DOOR):
//! a person withdraws voice-recognition consent, which deletes the voiceprint
//! and its samples and keeps the consent record (ARCH-0061 promise-dura-13).
//! `oneiron` re-exports each item from `verbs::voice_recognition`.
use oneiron_consent_state::verbs::voice_records::consent::VoiceConsentBasis;
use serde::Deserialize;
use serde::Serialize;

/// `vault.voices.recognition.withdraw`'s input: one withdrawal of
/// voice-recognition consent, for every purpose. The acting person records
/// it. With no `subject` it is of their own voice; naming another subject
/// takes the vault owner's authority. A replay of a recorded withdrawal
/// answers `replayed` and deletes nothing; a different decision under its
/// event id refuses. Render consent (`vault.voices.render_consent`) never
/// stands in for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRecognitionWithdrawRequest {
    /// The person whose voice stops being recognized, lowercase hex: the
    /// acting person's own when absent.
    #[serde(default)]
    pub subject: Option<String>,
    /// The withdrawal's own id, unique within the subject's consent log.
    pub event_id: String,
    /// When the subject withdrew, in unix seconds.
    pub occurred_at: u64,
    /// How the withdrawal was captured.
    pub basis: VoiceConsentBasis,
}

/// What a withdrawal removed: the subject's print, its sample and vector
/// rows and its active pointer. The withdrawal event stays in the consent
/// log, and the subject's render bank (`vault.voices.*`) is untouched.
/// `already_absent` when there was nothing to delete; `replayed` when
/// the same withdrawal was recorded before, which deletes nothing, even a
/// print enrolled since.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRecognitionWithdrawReceipt {
    pub event_id: String,
    /// Lowercase hex.
    pub subject: String,
    /// The acting person, lowercase hex.
    pub recorded_by: String,
    pub replayed: bool,
    pub already_absent: bool,
    pub deleted_print: bool,
    pub deleted_sample_count: u64,
    pub deleted_vector_count: u64,
    pub deleted_active_pointer: bool,
}
