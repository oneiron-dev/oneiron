//! Typed transport for a host that implements the HyDE expansion seam.
//! The host answers pending work; the engine never chooses or calls a model here.
use serde::{Deserialize, Serialize};

use super::{CompletionRequest, EvidenceVerdict, GroundingContext, HydeExpansion, HydeOptions, HydeRequest};
use crate::memory::{ClaimView, Memory, MemoryResult};

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

/// An admitted candidate at the words assessed by the engine. Claim values use the normal
/// redacted ClaimView projection, not a raw storage body.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HydeHostCandidate {
    pub id: String,
    pub score: f32,
    pub claim: Option<ClaimView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum HydeHostInput {
    Expansion { request: HydeRequest },
    Evidence { query: String, candidates: Vec<HydeHostCandidate> },
}

impl HydeHostInput {
    /// Projects the evidence the pipeline already admitted through its caller's own facade.
    pub fn evidence(memory: &Memory<'_>, request: &CompletionRequest) -> MemoryResult<Self> {
        let candidates = request.candidates.iter().map(|candidate| {
            Ok(HydeHostCandidate {
                id: candidate.id.to_hex(),
                score: candidate.score,
                claim: candidate.claim.as_ref()
                    .map(|body| memory.served_claim_view(&candidate.id, body))
                    .transpose()?,
            })
        }).collect::<MemoryResult<Vec<_>>>()?;
        Ok(Self::Evidence { query: request.query.clone(), candidates })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HydeHostWork {
    pub request_id: String,
    pub expander: String,
    pub requested_at_ms: u64,
    pub deadline_at_ms: Option<u64>,
    pub input: HydeHostInput,
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
