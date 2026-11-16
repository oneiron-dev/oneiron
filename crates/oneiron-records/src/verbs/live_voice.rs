//! Moved from `crates/oneiron/src/verbs/live_voice.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceAckKind;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceAckRequest;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceAudioRequest;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceEventsRequest;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceProcessed;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceSession;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceSessionRequest;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceStartRequest;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceStopReason;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceToolRequest;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceUsage;
pub use oneiron_verb_wire::verbs::live_voice::LiveVoiceUsageRequest;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveVoiceToolReply {
    pub processed: LiveVoiceProcessed,
    pub reply: LiveVoiceToolCallReply,
}

/// The connector's reply an `ai.voice.tool` answer carries beside the
/// session's processing (FIX 11725): whole, or, for a caller off this device
/// whose `awaiting_input` questions name a row that stays here, those
/// questions narrowed as `connector.call` narrows them, their answer path
/// whole.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LiveVoiceToolCallReply {
    /// The connector's questions, the text of each naming a row that stays
    /// on this device left here.
    QuestionsNarrowed(oneiron_verb_wire::verbs::act_answer::NarrowedQuestions),
    /// The connector's reply, whole.
    Done(super::connector_call::ConnectorCallReply),
}
