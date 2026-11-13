//! Moved from `crates/oneiron/src/llm/model_stream.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::LlmRequest;
use oneiron_model::llm::LlmResponse;
use oneiron_model::llm::LlmStreamEvent;
use oneiron_model::llm::LlmUsage;
use oneiron_model::llm::ModelId;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelStreamStatus {
    /// Subscribers are attached, but no producer has been opened yet.
    Pending,
    Live,
    Finished,
    Failed,
}

/// A caller-owned stable key freezes one exact request for one producer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStreamOpen {
    pub stream_key: String,
    pub request: LlmRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStreamOpened {
    pub stream_ref: String,
    pub stream_key: String,
    pub model: ModelId,
    pub status: ModelStreamStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStreamSubscribe {
    pub stream_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStreamSubscribed {
    pub stream_ref: String,
    pub stream_key: String,
    /// Server-minted subscription handle; detach drops only this one.
    pub handle: String,
    pub status: ModelStreamStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStreamEventsRequest {
    pub stream_key: String,
    pub handle: String,
    /// Most events to drain now (default 64, capped at 512); never blocks.
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStreamEvents {
    pub stream_ref: String,
    pub stream_key: String,
    pub handle: String,
    pub events: Vec<LlmStreamEvent>,
    /// The producer closed and this subscription is drained.
    pub closed: bool,
    pub status: ModelStreamStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStreamDetach {
    pub stream_key: String,
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStreamDetached {
    pub stream_ref: String,
    pub stream_key: String,
    pub handle: String,
    pub detached: bool,
}

/// Explicitly discards this credential's transient replay and outstanding
/// subscription handles, without cancelling its producer or durable terminal.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStreamRelease {
    pub stream_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStreamReleased {
    pub stream_ref: String,
    pub stream_key: String,
    pub status: ModelStreamStatus,
    pub released: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStreamAbort {
    pub stream_key: String,
    /// Actual usage the host supplies on cancellation.
    pub usage: LlmUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStreamTerminalRequest {
    pub stream_key: String,
}

/// The one durable terminal of a stream: present after restart, while no
/// delta ever lands here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStreamTerminal {
    pub stream_ref: String,
    pub stream_key: String,
    pub model: ModelId,
    pub status: ModelStreamStatus,
    /// The terminal `Done` payload, once the producer finished or aborted.
    pub response: Option<LlmResponse>,
    /// Why the producer ended without a terminal, when it did.
    pub failure: Option<String>,
}
