//! Moved from `crates/oneiron/src/verbs/live_voice.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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
    /// How many samples of this generation the client actually played,
    /// counted over its `pcm` events in order, each at its own rate (FIX
    /// 4899). The generation's `heard` event rests on it; without it, the
    /// record counts the samples the server sent, an upper bound. A count
    /// past what was sent counts as what was sent.
    #[serde(default)]
    pub played_samples: Option<u64>,
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
    pub call: crate::outbound_consent::connector_call_types::ConnectorCallRequest,
}
