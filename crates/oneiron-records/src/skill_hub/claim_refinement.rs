//! Moved from `crates/oneiron/src/skill_hub/claim_refinement.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_store::model_decision::DecisionQuestion;
use oneiron_store::write_envelope::claim_body::ClaimBody;
use oneiron_store::write_envelope::claim_body::decode_claim_body;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;

/// The edit stays under its session tag until independently admitted. IDs in
/// this row are canonical hex, not an alternate authority for the claim body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalClaimRefinement {
    pub candidate: String,
    pub base: String,
    pub resident: String,
    pub session_tag: String,
    pub body: Vec<u8>,
    pub base_binding: String,
    pub occurred_start: u64,
    pub occurred_end: u64,
    pub learned_at: u64,
}

impl LocalClaimRefinement {
    pub fn claim_body(&self) -> Result<ClaimBody> {
        decode_claim_body(&self.body, false)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRefinementMergeReceipt {
    pub receipt_id: String,
    pub candidate: String,
    pub base: String,
    pub resident: String,
    pub session_tag: String,
    pub question: DecisionQuestion,
    pub decision: TypedDecision,
    pub consent_digest: String,
    pub binding: String,
    pub held_out_digest: String,
    pub useful_upstream: bool,
    pub before: Option<f32>,
    pub after: Option<f32>,
    pub accepted: bool,
    pub at: u64,
}
