//! Moved from `crates/oneiron/src/engine_executor/reply_evidence.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// One byte range of one step's kept reply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplyEvidenceRequest {
    /// 32-hex code-run id (the executor run, not an attempt's run
    /// correlation id).
    pub run_ref: String,
    /// The step whose model reply to read.
    pub step: u64,
    /// First stored byte to read, inclusive.
    #[serde(default)]
    pub byte_offset: u64,
    /// Bytes in this read; [`REPLY_EVIDENCE_MAX_BYTES`] when absent, at most
    /// that. Must be positive.
    #[serde(default)]
    pub byte_limit: Option<u32>,
}

/// What a reply is to its reader: evidence a model produced, never a
/// program, an observation or an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTrust {
    Untrusted,
}

/// How the stored bytes encode the reply: the provider-neutral model
/// message (`LlmMessage`) as JSON, not the provider's wire reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplyEvidenceEncoding {
    LlmMessageJson,
}

/// Why a read serves nothing of a kept reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplyEvidenceWithheld {
    /// The secret scan marked the reply, it is under live or stale taint,
    /// or a row it was produced from was erased or withdrawn.
    SecretOrTaint,
    /// The run's placement was never witnessed and the reader is not the
    /// owner's own key: an unknown placement is never read as base reality.
    UnknownPlacement,
}

/// One read of one step's kept reply. When `withheld` names a reason, no
/// metadata and no byte of the reply is served.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReplyEvidenceView {
    pub run_ref: String,
    pub step: u64,
    /// Always `untrusted`.
    pub trust: EvidenceTrust,
    pub encoding: ReplyEvidenceEncoding,
    pub withheld: Option<ReplyEvidenceWithheld>,
    /// The run's handle on the stored reply.
    pub output_handle: Option<String>,
    /// Bytes of the stored reply.
    pub total_bytes: Option<u64>,
    /// First stored byte of this read.
    pub byte_offset: u64,
    /// This read's bytes, base64 (standard alphabet, padded).
    pub body_base64: Option<String>,
    /// Where the next read starts; none past the reply's end.
    pub next_byte_offset: Option<u64>,
}
