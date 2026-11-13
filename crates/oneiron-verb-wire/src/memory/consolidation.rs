//! Moved from `crates/oneiron/src/memory/consolidation.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_promotion::admission::PromotionEvidenceReason;
use crate::memory::claim_admission::ClaimScope;
use oneiron_store::write_envelope::claim_body::EvidenceRef;
use serde::Deserialize;
use serde::Serialize;

/// One generated proposal. Source, approval, actor, provenance and clocks are
/// deliberately absent: only the host promotion writer may stamp those axes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeneratedClaimInput {
    pub claim_ref: String,
    pub predicate: String,
    pub subject_ref: String,
    pub value: serde_json::Value,
    pub confidence: f32,
    pub scope: ClaimScope,
    pub sensitivity: Option<u8>,
    pub evidence_refs: Vec<EvidenceRef>,
    /// Visible claim candidates are assessed separately: a CLAIM is not a
    /// document EvidenceKind and generated claims contribute zero signals.
    #[serde(default)]
    pub claim_evidence_refs: Vec<String>,
    pub supersedes: Option<String>,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    /// The band and basis a calibrated producer gave `confidence`; absent
    /// means the house band of the number (FIX 7761).
    #[serde(default)]
    pub confidence_details: Option<oneiron_contracts::claim::ConfidenceDetails>,
}

/// Promote explicitly named candidates in an already admitted consolidation
/// attempt. The attempt must carry its real run_id; no alternate run is minted.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationPromoteRequest {
    pub job_ref: String,
    pub candidates: Vec<GeneratedClaimInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationEvidenceRequest {
    pub source_refs: Vec<String>,
}

/// A stored, parent-verified locator. content_hash is the engine's BLAKE3
/// hash, not a quote_sha256 or a newly invented document frontier.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationEvidenceLocator {
    pub source_ref: String,
    pub claim_ref: Option<String>,
    pub byte_range: Option<(usize, usize)>,
    pub content_hash: [u8; 32],
    pub messages: Vec<ConsolidationMessageEvidence>,
}

/// The exact MESSAGE-local slice and causal frontier retained by the parent
/// verifier. Byte offsets are not stable cursors; no current head is substituted.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationMessageEvidence {
    pub message_ref: String,
    pub start: usize,
    pub end: usize,
    pub revision: [u8; 32],
    pub frontier: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationEvidenceHop {
    pub kind: String,
    pub entity_ref: String,
    pub actor_ref: Option<String>,
}

/// One locally recorded delivery image, not current authority or proof that
/// the source's current bytes still match the recorded row hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationDeliveryOrigin {
    pub source_ref: String,
    pub delivering_pact: String,
    pub consent_epoch: u64,
    pub grant_ref: String,
    pub source_vault: String,
    pub delivered_row_hash: String,
}

/// The admitted source body, not the full stored row or a frozen citation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationSourceImage {
    pub learned_at: u64,
    /// Native domain-separated consolidation hash of the live projected body.
    pub body_hash: [u8; 32],
    /// The source's own document, when available in the same read snapshot.
    /// No pin is inferred for cited entities or joined MESSAGE children.
    pub document: Option<ConsolidationDocumentImage>,
}

/// An active source document and its native causal frontier, not a row hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationDocumentImage {
    pub doc: String,
    pub at: Vec<u8>,
}

/// Source facts and the engine's separate read-admission axes. Effector
/// evidence eligibility is not permission to perform any outbound action.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationEvidenceSource {
    pub source_ref: String,
    pub source: Option<String>,
    pub approval: Option<String>,
    pub lifecycle: Option<String>,
    pub evidence_taint: Option<String>,
    pub generated_origin: bool,
    pub writer_ref: Option<String>,
    pub foreign_world_ref: Option<String>,
    pub consolidation_eligible: bool,
    pub corroboration_eligible: bool,
    pub first_party_corroboration: bool,
    pub effector_evidence_eligible: bool,
    pub refusal: Option<PromotionEvidenceReason>,
    /// The exact stored promotion source ids, not equal-text matches or counts.
    pub source_refs: Vec<String>,
    /// Canonical document citations, at the versions the writer verified.
    pub evidence_refs: Vec<EvidenceRef>,
    pub source_meet: Option<String>,
    pub chain: Vec<ConsolidationEvidenceHop>,
    pub locators: Vec<ConsolidationEvidenceLocator>,
    /// The requested source's live projected body in this read snapshot.
    /// This does not version a TURN's joined MESSAGE transcript.
    pub current_image: ConsolidationSourceImage,
    /// Local receipt facts for readable sources. None means unavailable;
    /// an empty list means no matching facts were found, not complete history.
    pub delivery_history: Option<Vec<ConsolidationDeliveryOrigin>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationRejection {
    pub claim_ref: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationPromotion {
    pub job_ref: String,
    pub landed: Vec<String>,
    pub pended: Vec<String>,
    pub held: Vec<String>,
    pub rejected: Vec<ConsolidationRejection>,
    /// Decisions on the input refs before promotion, one per distinct source.
    pub input_evidence: Vec<ConsolidationEvidenceSource>,
    /// Evidence actually retained by the generated claims after the writer.
    pub output_evidence: Vec<ConsolidationEvidenceSource>,
}
