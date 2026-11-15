//! Moved from `crates/oneiron/src/query_expansion/host.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::query_expansion::EvidenceVerdict;
use crate::query_expansion::GroundingContext;
use crate::query_expansion::HydeExpansion;
use crate::query_expansion::HydeOptions;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HydeHostConfig {
    pub expander: String,
    pub grounding: GroundingContext,
    pub options: HydeOptions,
}

/// A null binding disables expansion and cancels unanswered work. Host state lasts one serve.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HydeHostConfigureRequest {
    pub binding: Option<HydeHostConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HydeHostConfiguration {
    pub binding: Option<HydeHostConfig>,
}

/// Both halves of HydeExpander have a typed answer. A host failure refuses recall, never
/// substitutes generated text for evidence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum HydeHostAnswer {
    Expansion { expansion: HydeExpansion },
    Evidence { verdict: EvidenceVerdict },
    Failed { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HydeHostCompleteRequest {
    pub request_id: String,
    pub answer: HydeHostAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HydeHostReceiptRequest {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HydeHostPendingRequest {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HydeHostStatus {
    Pending,
    Expired,
    Completed,
    Failed,
    DiscardedDeadline,
    Cancelled,
}

/// Completion records arrival, not application. A late answer is explicitly discarded.
/// No completion writes a claim or mutates an already delivered MemoryPack.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HydeHostReceipt {
    pub request_id: String,
    pub expander: String,
    pub requested_at_ms: u64,
    pub deadline_at_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
    pub status: HydeHostStatus,
    pub received_bytes: usize,
}
