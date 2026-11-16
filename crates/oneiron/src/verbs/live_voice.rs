//! The owner-bound live media session (ARCH-0061, OF-139 and OF-078).
//! Epochs are meaningful only within their session; no input can mint one,
//! clear external taint, supply a policy verdict or declare provider usage.
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::live_voice::{
    LiveVoiceAckKind, LiveVoiceAckRequest, LiveVoiceAudioRequest, LiveVoiceEventsRequest,
    LiveVoiceProcessed, LiveVoiceSession, LiveVoiceSessionRequest, LiveVoiceStartRequest,
    LiveVoiceStopReason, LiveVoiceToolRequest, LiveVoiceUsage, LiveVoiceUsageRequest,
};

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
    /// What the person heard of a stopped or drained generation, by
    /// utterance, apart from the text it generated (FIX 4899). Once per
    /// generation: after the client's `ack`, or, when none came, at the next
    /// generation or the session's end, counted on what the server sent.
    Heard {
        playback: crate::voice_cascade::HeardPlayback,
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

#[doc(hidden)]
pub use oneiron_records::verbs::live_voice::{LiveVoiceToolCallReply, LiveVoiceToolReply};
