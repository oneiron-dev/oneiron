//! Small local contracts for provider adapters; no transport or provider selection.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;
use crate::interlocutor::InterlocutorSet;
use crate::policy_model::PolicyEnforcementAction;

use super::{SafeguardRequest, StopReason};

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

/// ONE-1805 normalized token fields. Times and confidence are provider metadata,
/// never turn authority or evidence of identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AsrToken {
    pub text: String,
    pub is_final: bool,
    pub start_ms: Option<f64>,
    pub end_ms: Option<f64>,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsrEventKind {
    Partial,
    Final,
    Endpoint,
    Error,
    Closed,
}

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

/// Host-owned entity-spot/term-extraction result. An optional vector is also
/// host-embedded. The bridge trims/deduplicates lists, but the engine alone
/// derives meaning signatures. At least one nonblank label or term is required.
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

/// Ordered refs only: no raw entity bodies, vectors or retrieval score scale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalContext {
    pub result_refs: Vec<String>,
    pub promoted: bool,
    pub run_id: Option<String>,
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
    Result {
        call_id: String,
        output: Value,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum BrainEvent {
    TextDelta(String),
    Tool(ToolEvent),
    Done,
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
