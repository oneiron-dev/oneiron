//! Moved from `crates/oneiron/src/memory/identity_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::write_envelope::provenance::made_by::MadeBy;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityConfidenceEvidence {
    pub claim_ref: String,
    pub effective_confidence: f32,
    pub source: Option<String>,
    pub evidence: Option<serde_json::Value>,
    pub made_by: Option<MadeBy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityLookupCandidate {
    pub entity_ref: String,
    pub matched_hints: Vec<String>,
    pub identity_evidence_refs: Vec<String>,
    pub identity_owner_ref: Option<String>,
    pub identity_recorded_at: Option<u64>,
    pub made_by: Option<MadeBy>,
    pub mention_evidence: Vec<IdentityConfidenceEvidence>,
}
