//! Small local contracts for provider adapters; no transport or provider selection.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::claim::ScopedReadReceipt;
use crate::error::Result;
use crate::interlocutor::InterlocutorSet;
use crate::policy_model::PolicyEnforcementAction;
use crate::store::GateSystemNoticeRecord;

use super::retrieval::invalid;
use super::{HeardPlayback, SafeguardRequest, StopReason};

/// A session-local generation token. Pair with the session ref across processes.
/// Only the session mints tokens; adapters echo the token of the request they got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenerationEpoch {
    pub(super) session: uuid::Uuid,
    pub(super) value: u64,
}

impl GenerationEpoch {
    #[must_use]
    pub fn value(self) -> u64 {
        self.value
    }
}

#[doc(hidden)]
pub use oneiron_records::voice_cascade::protocol::{AsrEventKind, AsrToken, RetrievalContext};

/// ONE-1805 normalized event contract. An endpoint is NOT a final transcript.
/// The host attaches an utterance handle and revision outside this provider DTO.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AsrEvent {
    pub kind: AsrEventKind,
    pub text: String,
    #[serde(default)]
    pub tokens: Vec<AsrToken>,
    pub provider_latency_ms: Option<f64>,
    pub endpoint_delay_ms: Option<f64>,
    pub error: Option<String>,
}

impl AsrEvent {
    /// Validate before the session consumes a revision or performs any work.
    pub(super) fn validate(&self) -> Result<()> {
        if self.kind == AsrEventKind::Final && self.text.trim().is_empty() {
            return Err(invalid("final ASR transcript must be nonempty"));
        }
        if [self.provider_latency_ms, self.endpoint_delay_ms]
            .into_iter()
            .flatten()
            .any(|value| !value.is_finite() || value < 0.0)
        {
            return Err(invalid("ASR latencies must be finite and nonnegative"));
        }
        for token in &self.tokens {
            if [token.start_ms, token.end_ms]
                .into_iter()
                .flatten()
                .any(|value| !value.is_finite() || value < 0.0)
            {
                return Err(invalid("ASR token times must be finite and nonnegative"));
            }
            if token
                .confidence
                .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
            {
                return Err(invalid(
                    "ASR token confidence must be finite and within 0..=1",
                ));
            }
            if let (Some(start), Some(end)) = (token.start_ms, token.end_ms)
                && end < start
            {
                return Err(invalid("ASR token end must not precede its start"));
            }
        }
        Ok(())
    }
}

/// Host-owned entity-spot/term-extraction result. An optional vector is also
/// host-embedded. The bridge trims/deduplicates lists, but the engine alone
/// derives meaning signatures. Empty labels/terms are valid: the real
/// speculative session skips empty partial signatures and retrieves on final.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PartialEnrichment {
    pub entity_labels: Vec<String>,
    pub salient_terms: Vec<String>,
    pub query_vector: Option<Vec<f32>>,
}

/// Implement this with the host's concrete TINY entity-spot and salient-term
/// extraction pass. Provider hints, including empty lists, cannot bypass it.
pub trait PartialEnricher {
    fn enrich_speculative_partial(&mut self, text: &str) -> Result<PartialEnrichment>;
}

/// Tool events are context, not authority to run a tool. The host executes tools
/// through the existing engine gates and supplies results in call-before-result
/// order. A result's taint is supplied separately by the trusted context host.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolEvent {
    Call {
        call_id: String,
        name: String,
        input: Value,
    },
    /// Preserves arbitrary JSON and error metadata from
    /// [`crate::llm::ContentPart::ToolResult`]; neither grants tool authority.
    Result {
        call_id: String,
        output: Value,
        is_error: bool,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum BrainEvent {
    TextDelta(String),
    Tool(ToolEvent),
    /// The turn's stream reported a stop: the answer is whole (FIX 7808).
    Done,
    /// The turn's stream ended without a stop: a length cut, a filtered
    /// answer, or a provider that reported no reason. Every word it already
    /// said stands and is spoken to its end; nothing follows it, and the
    /// answer never reads as a whole one.
    Incomplete,
    Error(String),
}

/// Ephemeral context for the text brain. No prompt/persona or tool authority is
/// minted here. The host must disclosure-filter any dereferenced retrieval refs.
#[derive(Debug, Clone, PartialEq)]
pub struct BrainRequest {
    pub generation: GenerationEpoch,
    pub transcript: String,
    pub retrieval: RetrievalContext,
    pub session_ref: String,
    pub tools_enabled: bool,
    pub interlocutors: InterlocutorSet,
    /// The session's audience revision these interlocutors were read at. An
    /// audience change moves it; context assembled for an older revision is
    /// rebuilt, never reused.
    pub audience_revision: u64,
    pub tool_events: Vec<ToolEvent>,
    pub externally_tainted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtsCommand {
    Start {
        generation: GenerationEpoch,
    },
    Text {
        generation: GenerationEpoch,
        text: String,
    },
    Flush {
        generation: GenerationEpoch,
    },
    End {
        generation: GenerationEpoch,
    },
    Cancel {
        generation: GenerationEpoch,
    },
}

/// Transient PCM owned by the audio sibling, not queued or persisted by the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcmFrame {
    pub generation: GenerationEpoch,
    pub sample_rate: u32,
    pub samples: Vec<i16>,
}

/// Backend control, not persona text. The successor maps this to its client wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEvent {
    PlayoutStop {
        generation: GenerationEpoch,
        reason: StopReason,
    },
    SessionEnded,
    Safeguard {
        generation: GenerationEpoch,
        action: PolicyEnforcementAction,
        receipt_ref: Option<String>,
        custom_tier_skipped: bool,
    },
    /// A safeguard's notice to the person, said by the client. Every one is
    /// delivered, a stale sentence's too; none is silent.
    Notice {
        generation: GenerationEpoch,
        notice: GateSystemNoticeRecord,
    },
    /// What a turn's memories read found and what its audience heard, for
    /// the owner's client to show; never said.
    Memories {
        generation: GenerationEpoch,
        memories: TurnMemories,
    },
    /// What the person heard of a stopped or drained generation (FIX
    /// 4899), apart from the text it generated: for the owner's client and
    /// the call's journal; never said.
    Heard {
        generation: GenerationEpoch,
        playback: HeardPlayback,
    },
}

/// What one turn's memories read found and what its audience heard: the
/// read's narrowing receipts, one per row it looked up, those withheld from
/// the audience included, even when the brain heard none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnMemories {
    /// Rows the turn's retrieval found.
    pub found: usize,
    /// Rows the brain heard.
    pub heard: usize,
    pub receipts: Vec<ScopedReadReceipt>,
}

/// Adapter methods SUBMIT work; they must not wait for a provider's response.
/// Provider results return through `handle_asr`, `handle_brain`, `filter_pcm`
/// and `apply_safeguard`. The sibling owns scheduling, queues and retries.
pub trait AsrStream {
    fn accept_audio(&mut self, pcm: &[u8]) -> Result<()>;
    fn end(&mut self) -> Result<()>;
}

pub trait Brain {
    fn start(&mut self, request: &BrainRequest) -> Result<()>;
    /// Called after an accepted tool event, with the full ordered tool context.
    fn update_context(&mut self, request: &BrainRequest) -> Result<()>;
    fn cancel(&mut self, generation: GenerationEpoch) -> Result<()>;
    /// A safeguard notice said to the person, which the model hears too: a
    /// brain that keeps the call's history keeps it there, and its next turn
    /// hears it. A turn already answering is not interrupted for it.
    /// `generation` is the turn whose sentence the notice judged, so the
    /// history lists it as made from that turn alone (FIX 5484).
    fn notice(
        &mut self,
        generation: GenerationEpoch,
        notice: &GateSystemNoticeRecord,
    ) -> Result<()> {
        let _ = (generation, notice);
        Ok(())
    }

    /// What the person heard of `generation`'s answer (FIX 4899), kept
    /// apart from the text it generated: a brain that keeps the call's
    /// history notes it there, so its next turn knows what the person
    /// heard. A turn already answering is not interrupted for it.
    fn heard(&mut self, generation: GenerationEpoch, playback: &HeardPlayback) -> Result<()> {
        let _ = (generation, playback);
        Ok(())
    }
}

pub trait TtsSeamClient {
    fn submit(&mut self, command: TtsCommand) -> Result<()>;
}

/// A small submission seam. Evaluate requests through their real engine
/// enforcement methods, then deliver the correlated `SentenceEnforcement`.
pub trait Safeguard {
    fn submit(&mut self, request: SafeguardRequest) -> Result<()>;
}

pub trait CascadeControl {
    /// Drop ALL queued PCM for this generation, including packets waiting for
    /// transport. Must happen before the next dequeue, even if another stop arm
    /// fails. Client-side queues are stopped by the control event independently.
    fn flush_queued_pcm(&mut self, generation: GenerationEpoch) -> Result<()>;
    fn submit(&mut self, event: ControlEvent) -> Result<()>;
}
