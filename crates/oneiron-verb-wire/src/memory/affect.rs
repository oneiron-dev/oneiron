//! Moved from `crates/oneiron/src/memory/affect.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::claim_admission::ClaimScope;
use oneiron_contracts::affect::VadAnnotationSource;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// A query's affect: valence in -1..=1, arousal and dominance in 0..=1.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryAffect {
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}

impl QueryAffect {
    /// The affect as the engine takes it, refused out of range.
    pub fn vad(self) -> MemoryResult<oneiron_contracts::affect::Vad> {
        let vad = oneiron_contracts::affect::Vad {
            valence: self.valence,
            arousal: self.arousal,
            dominance: self.dominance,
        };
        vad.validate()
            .map_err(|error| MemoryError::bad_request(format!("query_affect: {error}")))?;
        Ok(vad)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffectAnnotationPut {
    pub turn_ref: String,
    pub vad: QueryAffect,
    pub source: VadAnnotationSource,
    pub annotated_at: u64,
    pub scope: ClaimScope,
    pub sensitivity: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffectClaimConsolidateRequest {
    pub claim_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AffectTurnEvidence {
    pub turn_ref: String,
    pub vad: QueryAffect,
    pub source: VadAnnotationSource,
    pub annotated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AffectClaimConsolidation {
    pub claim_ref: String,
    pub vad: Option<QueryAffect>,
    pub evidence_turns: Vec<AffectTurnEvidence>,
    pub semantic_edges_updated: usize,
    pub structural_edges_skipped: usize,
    pub active_state_ref: Option<String>,
    pub created_state_ref: Option<String>,
    pub superseded_state_refs: Vec<String>,
}
