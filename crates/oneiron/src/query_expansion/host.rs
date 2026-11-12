//! Typed transport for a host that implements the HyDE expansion seam.
//! The host answers pending work; the engine never chooses or calls a model here.
use serde::{Deserialize, Serialize};

use super::{
    CompletionRequest, EvidenceVerdict, GroundingContext, HydeExpansion, HydeOptions, HydeRequest,
};
use crate::memory::{ClaimView, Memory, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::query_expansion::host::{
    HydeHostAnswer, HydeHostCompleteRequest, HydeHostConfig, HydeHostConfiguration,
    HydeHostConfigureRequest, HydeHostPendingRequest, HydeHostReceipt, HydeHostReceiptRequest,
    HydeHostStatus,
};

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
    Expansion {
        request: HydeRequest,
    },
    Evidence {
        query: String,
        candidates: Vec<HydeHostCandidate>,
    },
}

impl HydeHostInput {
    /// Projects the evidence the pipeline already admitted through its caller's own facade.
    pub fn evidence(memory: &Memory<'_>, request: &CompletionRequest) -> MemoryResult<Self> {
        let candidates = request
            .candidates
            .iter()
            .map(|candidate| {
                Ok(HydeHostCandidate {
                    id: candidate.id.to_hex(),
                    score: candidate.score,
                    claim: candidate
                        .claim
                        .as_ref()
                        .map(|body| memory.served_claim_view(&candidate.id, body))
                        .transpose()?,
                })
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        Ok(Self::Evidence {
            query: request.query.clone(),
            candidates,
        })
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
