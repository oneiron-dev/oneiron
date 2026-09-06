//! ONE-1807: the engine half of a transport-neutral text-brain voice cascade.
//!
//! This is a synchronous, in-memory session boundary, not an audio runner.
//! The host serializes calls and schedules provider work outside the session
//! lock. Pipecat owns frames, provider adapters, turn/sentence detection,
//! cancellation delivery and latency telemetry. It never owns durable memory,
//! policy, tool authority or voice identity. Provider speech-to-speech is not
//! a substitute for the text brain.
//!
//! [`SpeculativeRetrievalBridge`] owns a real [`crate::speculative::SpeculativeSession`].
//! Every accepted partial/final invokes the host's [`PartialEnricher`]; there
//! is no token-based retrieval, fallback search, or second meaning signature.
//! Responses project ordered refs only. Resolving those refs for a model still
//! requires the ordinary context/disclosure gates; refs are not read authority.
//! Interlocutors are resolved by the existing vault API, including the existing
//! consent-gated voice roster. Voice attribution never authenticates an owner.
//!
//! [`VoiceCascadeSession::complete_sentence`] returns TTS and (only for tainted
//! context) safeguard work together. Submission never waits for a verdict.
//! A blocking engine enforcement and sustained barge-in share [`OutputStop`].
//! Epoch invalidation is atomic within the session; cross-process delivery is
//! NOT atomic. Hosts must dispatch the stop before another dequeue, reject old
//! epochs at BOTH enqueue and playback, and fail closed on dispatch failure.
//! [`VoiceCascadeSession::end`] is separate from user barge-in and is idempotent.
//!
//! No audio, ASR intermediate, tool history or turn is persisted here. Retrieval
//! telemetry and policy receipts retain their existing engine semantics. A host
//! that persists a final turn must use the ordinary session/off-record fence;
//! `session_ref` is correlation, not a persistence capability. Explicit end or
//! disconnect drops utterance handles and ephemeral brain context. Dropping the
//! object frees memory, but cannot deliver remote cancellation: hosts must end
//! explicitly on disconnect.
//!
//! # Retained deployment pins (requirements, not runtime evidence)
//!
//! ```text
//! transport: livekit
//! production_deployment: self_hosted_regional_tokyo
//! orchestrator: pipecat_sibling_process
//! voice_cgroup: {memory_high_mib: 256, memory_max_mib: 384}
//! voice_active_bundle: {reservation_mib: 768, p95_gate_mib: 640, teardown_retained_max_mib: 16}
//! ```
//!
//! LiveKit Cloud is development/smoke only. Repeat the regional deployment in
//! later home regions. Daily and a parallel custom orchestrator are rejected.
//! Bundle soak gates: combined p95 RSS <=640 MiB, peak <768 MiB, retained above
//! pre-call baseline <=16 MiB. Regional media-service RSS is measured separately.
//!
//! Remaining successor gates: real Pipecat/provider/LiveKit wiring; a private
//! per-vault UDS bridge below the active runtime directory (0600, no TCP,
//! disconnect cleanup); client playout-stop acknowledgement; 250–400 ms
//! end-to-end interruption proof; a 30-minute call overlapping Dreamer and a
//! machine-readable RSS trace. Local typed interfaces are not a shipped wire
//! codec or evidence that any runtime/latency/soak gate passed.

mod cancellation;
mod protocol;
mod retrieval;
mod safeguard;
mod session;

pub mod tts_spikes;

pub use cancellation::{OutputStop, StopReason};
pub use protocol::*;
pub use retrieval::{PartialRetrieval, SpeculativeRetrievalBridge, UtteranceHandle};
pub use safeguard::{SafeguardRequest, SentenceEnforcement, SentenceWork};
pub use session::{AsrUpdate, SafeguardUpdate, VoiceCascadeSession, VoiceSessionConfig};

#[cfg(test)]
mod tests;
