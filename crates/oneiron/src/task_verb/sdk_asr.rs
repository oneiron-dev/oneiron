//! Host-enriched ASR observations over one owner-bound speculative recall session.
//! Labels, salient terms and vectors are observations supplied by the owner's
//! ASR host, not gate decisions or claims. Only the engine decides to fire/reuse.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AsrOpenRequest {
    pub utterance_id: String,
    #[serde(default)]
    pub scope: crate::memory::RecallScope,
    #[serde(default)]
    pub fire_limit: Option<usize>,
    #[serde(default)]
    pub final_limit: Option<usize>,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AsrSession {
    pub handle: String,
    pub utterance_id: String,
    pub scope: crate::memory::RecallScope,
    pub max_fires: u8,
    pub fire_limit: usize,
    pub final_limit: usize,
    pub limit_clamped: bool,
    pub deadline_ms: u64,
    pub narrowing: crate::claim::ScopedReadReceipt,
}

/// A strictly advancing revision within the server-minted handle. Cosmetic
/// transcript changes may advance the revision without changing the meaning.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AsrHypothesisRequest {
    pub handle: String,
    pub revision: u64,
    pub text: String,
    pub entity_labels: Vec<String>,
    pub salient_terms: Vec<String>,
    #[serde(default)]
    pub query_vector: Option<Vec<f32>>,
}

impl AsrHypothesisRequest {
    pub fn partial(&self) -> crate::speculative::SpeculativePartial<'_> {
        crate::speculative::SpeculativePartial {
            text: &self.text,
            entity_labels: &self.entity_labels,
            salient_terms: &self.salient_terms,
            query_vector: self.query_vector.as_deref(),
        }
    }

    pub fn validate(&self) -> crate::memory::MemoryResult<()> {
        if self.text.trim().is_empty() {
            return Err(crate::memory::MemoryError::bad_request("ASR text must be nonempty"));
        }
        crate::memory::caps::check_query(&self.text)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AsrFireDecision {
    Fired,
    MissedDeadline,
    SkippedUnchanged,
    SkippedEmptySignature,
    SkippedCapExhausted,
}

/// A completed observation boundary. Only `fired` exports prepared candidates;
/// missed deadlines count against the real engine budget but keep no new pack.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AsrHypothesisReceipt {
    pub receipt_ref: String,
    pub handle: String,
    pub utterance_id: String,
    pub revision: u64,
    pub text: String,
    pub scope: crate::memory::RecallScope,
    pub decision: AsrFireDecision,
    pub fires_used: u8,
    pub run_id: Option<String>,
    pub partial: bool,
    pub result_refs: Vec<String>,
    pub narrowing: crate::claim::ScopedReadReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AsrFinalDecision {
    Promoted,
    Finalized,
}

/// `promoted` names the exact fire receipt reused, with no new full recall.
/// A finalized pass may warm-fill a shortfall; its scores are not compared
/// across the fresh/warm boundary. Run ids are absent when telemetry is off.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AsrFinalReceipt {
    pub receipt_ref: String,
    pub handle: String,
    pub utterance_id: String,
    pub revision: u64,
    pub text: String,
    pub scope: crate::memory::RecallScope,
    pub decision: AsrFinalDecision,
    pub reused_fire_receipt: Option<String>,
    pub fires_used: u8,
    pub run_id: Option<String>,
    pub warm_appended: usize,
    pub partial: bool,
    pub result_refs: Vec<String>,
    pub narrowing: crate::claim::ScopedReadReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AsrCloseRequest {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AsrClosed {
    pub handle: String,
}
