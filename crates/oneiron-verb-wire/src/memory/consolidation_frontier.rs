//! Moved from `crates/oneiron/src/memory/consolidation_frontier.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::consolidation::ConsolidationMessageEvidence;
use oneiron_contracts::claim::ClaimSource;
use serde::Deserialize;
use serde::Serialize;

/// The canon's six-axis consolidation bucket. References are full entity ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationRootBucket {
    pub subject: String,
    pub predicate_root: String,
    pub world: Option<String>,
    pub facet: Option<String>,
    /// The bucket's relationship key: absent for all, `[]` for the explicit
    /// empty set, otherwise every relationship of the set.
    pub relationship: Option<Vec<String>>,
    pub project: String,
}

/// A child's reference, never child-authored bytes, hashes or trust labels.
/// Exactly one of claim_id and byte_range must be present.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationReference {
    pub source_id: String,
    pub claim_id: Option<String>,
    pub byte_range: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationRootInput {
    pub bucket: ConsolidationRootBucket,
    pub evidence: Vec<ConsolidationReference>,
}

/// Admit every reference before children finish, at one root-owned revision.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationPinRequest {
    pub buckets: Vec<ConsolidationRootInput>,
}

/// Judgements remain proposals. This door cannot settle a belief or choose
/// the writer's source, actor, approval, evidence taint or provenance.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationJudgement {
    pub predicate: String,
    pub value: serde_json::Value,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationChildFrontier {
    pub child_ref: String,
    pub bucket_hash: [u8; 32],
    pub judgement: ConsolidationJudgement,
    pub evidence: Vec<ConsolidationReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationFrontierRequest {
    pub root_ref: String,
    pub children: Vec<ConsolidationChildFrontier>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationAccountingRequest {
    pub root_ref: String,
}

/// A stored ancestor's classification at the root's pin, including the
/// edge.provenance claims on each derived_from edge the root followed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationAncestor {
    pub source_ref: String,
    pub source_revision: [u8; 32],
    pub trust_class: ClaimSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationRootEvidence {
    pub reference: ConsolidationReference,
    pub source_revision: [u8; 32],
    pub content_hash: [u8; 32],
    pub trust_class: ClaimSource,
    pub corroborates: bool,
    pub refusal: Option<PromotionEvidenceReason>,
    pub ancestors: Vec<ConsolidationAncestor>,
    pub messages: Vec<ConsolidationMessageEvidence>,
}

/// The root keeps a digest, not another copy of child-authored prose.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationChildReceipt {
    pub child_ref: String,
    pub judgement_hash: [u8; 32],
    pub evidence: Vec<ConsolidationReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationBucketAccounting {
    pub bucket: ConsolidationRootBucket,
    pub bucket_hash: [u8; 32],
    pub pinned: Vec<ConsolidationRootEvidence>,
    pub children: Vec<ConsolidationChildReceipt>,
    pub independent: Vec<ConsolidationRootEvidence>,
    pub duplicates_collapsed: u32,
    pub excluded_references: u32,
    pub source_meet: ClaimSource,
}

/// revision is the committed LMDB revision the root read before pinning,
/// never a child-supplied cursor. Later reads return these original facts;
/// current read authority is still checked. No raw source text is copied.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationRootAccounting {
    pub root_ref: String,
    pub revision: u64,
    pub buckets: Vec<ConsolidationBucketAccounting>,
}
