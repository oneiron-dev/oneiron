//! The owner-bound live media session (ARCH-0061, OF-139 and OF-078).
//! Epochs are meaningful only within their session; no input can mint one,
//! clear external taint, supply a policy verdict or declare provider usage.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveVoiceStartRequest {
    pub sample_rate: u32,
    pub channels: u16,
    #[serde(default)]
    pub room_ref: Option<String>,
    #[serde(default)]
    pub roster_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveVoiceSessionRequest {
    pub session_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiveVoiceSession {
    pub session_ref: String,
    pub sample_rate: u32,
    pub channels: u16,
}

/// PCM16LE in STANDARD base64. The admitted owner's media client supplies
/// VAD observations, not timestamps: the host's monotonic clock measures
/// sustained speech. `end_utterance` cuts ASR, never the assistant's epoch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveVoiceAudioRequest {
    pub session_ref: String,
    pub utterance_id: String,
    pub pcm_base64: String,
    pub speaking: bool,
    #[serde(default)]
    pub end_utterance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveVoiceEventsRequest {
    pub session_ref: String,
    #[serde(default)]
    pub after: u64,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiveVoiceAckKind {
    /// All audio through the epoch's playout_end played on the client.
    Drained,
    /// The epoch's flush and playout_stop were applied on the client.
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveVoiceAckRequest {
    pub session_ref: String,
    pub generation: u64,
    /// The exact playout_end or playout_stop event being acknowledged.
    pub event_sequence: u64,
    pub kind: LiveVoiceAckKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveVoiceUsageRequest {
    pub session_ref: String,
    pub generation: u64,
}

/// A processing boundary, not a provider completion or client playout ACK.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiveVoiceProcessed {
    pub session_ref: String,
    pub cursor: u64,
    pub ended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiveVoiceStopReason {
    UserBargeIn,
    Safeguard,
    RosterChanged,
    OutputFailed,
    SessionEnd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveVoiceEvent {
    pub sequence: u64,
    pub utterance_id: Option<String>,
    pub generation: Option<u64>,
    pub event: LiveVoiceEventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LiveVoiceEventKind {
    GenerationStarted {
        run: String,
        context_sources: Vec<String>,
    },
    Pcm {
        sample_rate: u32,
        pcm_base64: String,
    },
    PlayoutEnd,
    Flush,
    PlayoutStop {
        reason: LiveVoiceStopReason,
    },
    MediaCancelled,
    Safeguard {
        action: crate::policy_model::PolicyEnforcementAction,
        receipt_ref: Option<String>,
        custom_tier_skipped: bool,
    },
    Notice {
        notice: crate::store::GateSystemNoticeRecord,
    },
    Memories {
        found: usize,
        heard: usize,
        receipts: Vec<crate::claim::ScopedReadReceipt>,
    },
    ToolContext {
        source: String,
    },
    Finished,
    Error {
        code: String,
    },
    SessionEnded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveVoiceEvents {
    pub session_ref: String,
    /// Advance to this cursor, including stale PCM omitted from the page.
    pub cursor: u64,
    pub ended: bool,
    pub events: Vec<LiveVoiceEvent>,
}

/// Observes the existing run ledger; this call never settles or charges.
/// `terminal` requires producer teardown, TTS cancellation (when stopped),
/// the engine's epoch retirement and the client's correlated playout ACK.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiveVoiceUsage {
    pub session_ref: String,
    pub utterance_id: String,
    pub generation: u64,
    pub run: String,
    pub terminal: bool,
    pub metering_enabled: bool,
    pub settlements: Vec<crate::agent_dispatch::budget_doors::RunRungSettlement>,
}

/// Calls a real connector under the caller's own grant, before the next
/// utterance. Only its delivered result enters the brain, always foreign.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveVoiceToolRequest {
    pub session_ref: String,
    pub call: crate::outbound_consent::ConnectorCallRequest,
}

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
    QuestionsNarrowed(super::act_answer::NarrowedQuestions),
    /// The connector's reply, whole.
    Done(super::connector_call::ConnectorCallReply),
}
