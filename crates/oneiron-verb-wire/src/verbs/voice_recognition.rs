//! `vault.voices.recognition.withdraw`'s and `vault.voices.recognition.consent`'s wire
//! (VOICE-RECOGNITION-CONSENT-NO-DOOR, VOICE-CONSENT-LOG-WHO = A): a person withdraws
//! voice-recognition consent, which deletes the voiceprint and its samples and keeps the
//! consent record (ARCH-0061 promise-dura-13), and a person logs voice-recognition consent,
//! which enrols no print. `oneiron` re-exports each item from `verbs::voice_recognition`.
use oneiron_consent_state::verbs::voice_records::consent::VoiceConsentBasis;
use serde::Deserialize;
use serde::Serialize;

/// One purpose voice recognition may serve: the same two the engine's
/// `VoicePrintPurpose` names, spelled the same on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VoiceRecognitionPurpose {
    MeetingAttribution,
    LiveInterlocutor,
}

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

/// `vault.voices.recognition.consent`'s input: one grant of voice-recognition
/// consent (VOICE-CONSENT-LOG-WHO = A; oneiron-arch-0061 "the agent logs
/// who/when/what"). The acting person records it, or an agent its
/// counterparty's spoken word. With no `subject` it is of the acting person's
/// own voice; naming another subject takes the vault owner's authority, or an
/// agent's consent-log Grant for a counterparty. A replay of a recorded
/// consent answers `replayed`; a different decision under its event id
/// refuses. Logging consent enrols no print.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRecognitionConsentRequest {
    /// The person whose voice may be recognized, lowercase hex: the acting
    /// person's own when absent.
    #[serde(default)]
    pub subject: Option<String>,
    /// The consent's own id, unique within the subject's consent log.
    pub event_id: String,
    /// When the subject consented, in unix seconds.
    pub occurred_at: u64,
    /// The purposes the consent covers.
    pub purposes: Vec<VoiceRecognitionPurpose>,
    /// How the consent was captured.
    pub basis: VoiceConsentBasis,
}

/// What a consent grant recorded: the subject whose voice may be recognized,
/// for which purposes, and who recorded it. `replayed` when the same consent
/// was recorded before. The consent enrols no print; enrolment stays
/// engine-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRecognitionConsentReceipt {
    pub event_id: String,
    /// Lowercase hex.
    pub subject: String,
    /// The recorder, lowercase hex: the acting person, or the agent that
    /// logged a counterparty's spoken consent.
    pub recorded_by: String,
    /// The purposes the consent covers, as answered back.
    pub purposes: Vec<VoiceRecognitionPurpose>,
    pub replayed: bool,
}
